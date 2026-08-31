"""Client-side cryptography for CredenShare.

This module implements the published wire specification. The specification is normative —
not this file, and not any other implementation. Where they disagree, the specification is
right and this is a bug.

    https://github.com/CredenShare/credenshare-sdk-python  (this SDK)
    CRYPTO_WIRE_SPEC.md sections 1-4                       (the contract, in this repo)

Nothing here talks to the network, and nothing here writes to disk. Encryption happens on
your machine, and the content key never leaves it: that is the entire point of the product,
and an SDK that quietly sent a key would be worse than no SDK.

WHY THIS IS WRITTEN FROM THE SPEC RATHER THAN PORTED
The application, this SDK and the three others are independent implementations that share no
code. That is a supply-chain decision: a package the production app depended on would mean a
compromised publish is a compromised app. The cost is drift, and drift here does not produce
a test failure — it produces content that can never be decrypted. The conformance vectors in
`conformance/vectors.v1.json` are what hold the implementations together, and they include
cases that decrypt material produced by a *different* implementation. Passing them is the
only meaningful definition of correct.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import (
    InvalidFieldError,
    MalformedKeyError,
    MissingKeyError,
    WireFormatError,
)

__all__ = [
    "FIELD_TYPES",
    "new_content_key",
    "encode_fragment",
    "decode_fragment",
    "encrypt_content",
    "decrypt_content",
    "access_token",
    "passcode_verifier",
    "keypair_from_seed",
    "custody_keypair",
    "wrap_to_public_key",
    "unwrap_with_seed",
    "SeedKeypair",
]

# ── section 1: primitives ────────────────────────────────────────────────────────────

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Lengths are exact, per section 0. Named rather than inlined so a truncated blob is rejected
# by arithmetic that reads like the specification.
_SALT_LEN = 16
_IV_LEN = 12
_TAG_LEN = 16
_KEY_LEN = 32
_PUBKEY_LEN = 65  # 0x04 || X(32) || Y(32)
_WRAP_VERSION = 1

#: Field types the recipient view knows how to render (section 2.2.1).
FIELD_TYPES = ("text", "password", "date", "multiline", "markdown", "source_code")


def _hkdf(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
    """HKDF-SHA-256, with ``info`` encoded as UTF-8.

    An empty salt is passed through as a zero-length byte string rather than being replaced
    with a block of zeros. RFC 5869 makes those equivalent for HMAC-SHA-256 — a zero-length
    HMAC key and a 32-zero-byte one both pad to the same 64-byte block — but the
    specification calls it out because an implementation that pads to some *other* length
    silently produces different output and fails conformance.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info.encode("utf-8"),
    ).derive(ikm)


def _b64(raw: bytes) -> str:
    """Standard base64, with padding (RFC 4648 section 4)."""
    return base64.b64encode(raw).decode("ascii")


def _b64url(raw: bytes) -> str:
    """URL-safe base64, no padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


def _unb64url(text: str) -> bytes:
    """Decode unpadded base64url, rejecting anything that is not valid.

    ``validate=True`` matters: without it Python silently discards characters outside the
    alphabet, so a mangled fragment would decode to *something* and fail later as a
    decryption error rather than as the malformed link it is.
    """
    # urlsafe_b64decode() takes no validate= parameter - it translates -_ to +/ and calls
    # b64decode() with validation off. Do the translation here so validate=True can be
    # passed to the call that accepts it; without it Python discards characters outside the
    # alphabet and a mangled fragment decodes to a plausible 32-byte key.
    standard = text.translate(_URLSAFE_TO_STANDARD)
    padding = "=" * (-len(standard) % 4)
    return base64.b64decode(standard + padding, validate=True)


# ── section 2.1: the content key and the fragment ────────────────────────────────────


def new_content_key() -> bytes:
    """A fresh 32-byte content key from the OS CSPRNG."""
    return os.urandom(_KEY_LEN)


def encode_fragment(content_key: bytes) -> str:
    """Encode a content key as a URL fragment: ``"1" + base64url(key)``.

    Bare, with a single leading version character and no ``k=`` prefix. A key=value appendix
    reads as optional and invites link-mangling clients to truncate it, and a truncated
    fragment must fail closed rather than look like a well-formed link missing a part.
    """
    if len(content_key) != _KEY_LEN:
        raise ValueError(f"a content key is {_KEY_LEN} bytes, got {len(content_key)}")
    return "1" + _b64url(content_key)


def decode_fragment(fragment: Optional[str]) -> bytes:
    """Parse a fragment back into a content key.

    Raises :class:`MissingKeyError` when there is no fragment at all and
    :class:`MalformedKeyError` when there is one but it is not usable. The distinction is not
    pedantry: "your link is incomplete" and "this share expired" look identical on screen and
    have opposite remedies.
    """
    if fragment is None:
        raise MissingKeyError("no key fragment was supplied")

    text = fragment.lstrip("#")
    if text == "":
        raise MissingKeyError("no key fragment was supplied")

    if text[0] != "1":
        raise MalformedKeyError(
            f"unsupported fragment version {text[0]!r}; this link needs a newer client"
        )

    try:
        raw = _unb64url(text[1:])
    # Any decode failure is the same answer, so the broad catch is deliberate.
    except Exception as exc:
        raise MalformedKeyError("the key fragment is not valid base64url") from exc

    if len(raw) != _KEY_LEN:
        raise MalformedKeyError(
            f"a content key is {_KEY_LEN} bytes; this fragment decoded to {len(raw)}, "
            "so the link is probably truncated"
        )
    return raw


# ── section 2.2: content encryption ──────────────────────────────────────────────────


def _content_key_for(content_key: bytes, salt: bytes, passcode: Optional[str]) -> bytes:
    # The passcode goes into `info`, never into the salt. They serve different purposes, and
    # a salt built from the passcode would make the derivation depend on a value that has to
    # stay reproducible from stored data alone.
    info = "content" if passcode is None else f"content|{passcode}"
    return _hkdf(content_key, salt, info, _KEY_LEN)


def encrypt_content(
    content_key: bytes,
    fields: Sequence[Dict[str, Any]],
    passcode: Optional[str] = None,
    *,
    _salt: Optional[bytes] = None,
    _iv: Optional[bytes] = None,
) -> str:
    """Encrypt a field array, returning the base64 blob the API accepts.

    ``fields`` is a list of objects whose label member is ``key`` — not ``label``, ``name``
    or ``title``. Those are silently ignored by the recipient view, which renders every field
    with a blank label while nothing errors anywhere. See :func:`validate_fields`.

    The blob uses standard base64, not base64url: it travels in a JSON body, never in a URL.

    ``_salt`` and ``_iv`` exist for the conformance vectors, which fix them so the fixture is
    reproducible. Production code must never pass them — a reused IV under the same key
    destroys AES-GCM's guarantees outright.
    """
    validate_fields(fields)
    salt = _salt if _salt is not None else os.urandom(_SALT_LEN)
    iv = _iv if _iv is not None else os.urandom(_IV_LEN)

    key = _content_key_for(content_key, salt, passcode)
    # ensure_ascii=False is REQUIRED, not cosmetic.
    #
    # Python escapes every non-ASCII character to a backslash-u sequence by default, and no
    # other implementation does. The blob still decrypts here and everywhere else — the
    # escapes decode back to the same string — so nothing errors and nothing looks wrong.
    # What breaks is byte-for-byte reproducibility: identical fields, key, salt and IV would
    # produce different ciphertext in Python than in the browser, or in the Node, Go and Rust
    # clients. The conformance vectors were pure ASCII until a case carrying unicode was
    # added, and this divergence had been sitting here unnoticed the whole time.
    plaintext = json.dumps(list(fields), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body = AESGCM(key).encrypt(iv, plaintext, None)
    return _b64(salt + iv + body)


def decrypt_content(
    content_key: bytes,
    blob: str,
    passcode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Decrypt a blob back into the field array.

    A wrong passcode and a tampered blob are indistinguishable, deliberately: both surface as
    :class:`WireFormatError`. Telling them apart would hand an attacker an oracle.
    """
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception as exc:
        raise WireFormatError("the content blob is not valid base64") from exc

    minimum = _SALT_LEN + _IV_LEN + _TAG_LEN
    if len(raw) < minimum:
        # Checked before anything else, so a truncated blob is reported as truncated rather
        # than as a decryption failure that sends somebody looking for a wrong passcode.
        raise WireFormatError(
            f"the content blob is {len(raw)} bytes; the smallest possible one is {minimum}"
        )

    salt = raw[:_SALT_LEN]
    iv = raw[_SALT_LEN : _SALT_LEN + _IV_LEN]
    body = raw[_SALT_LEN + _IV_LEN :]

    key = _content_key_for(content_key, salt, passcode)
    try:
        plaintext = AESGCM(key).decrypt(iv, body, None)
    except Exception as exc:
        raise WireFormatError(
            "could not decrypt: the passcode is wrong, or the content was altered"
        ) from exc

    fields = json.loads(plaintext.decode("utf-8"))
    if not isinstance(fields, list):
        raise WireFormatError("decrypted content is not a field array")
    return fields


def validate_fields(fields: Sequence[Dict[str, Any]]) -> None:
    """Check a field array against section 2.2.1 before it is encrypted.

    This exists because getting it wrong is invisible. A field object using ``label`` instead
    of ``key`` still encrypts, still posts, still decrypts and still renders — with every
    label blank and no error anywhere. The specification gained a section about it after that
    cost somebody an afternoon, so this SDK refuses rather than letting it through.

    Unknown members are allowed and preserved: a newer sender must not break an older reader.
    """
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            raise InvalidFieldError(f"field {index} is not an object")

        if "key" not in field:
            for wrong in ("label", "name", "title"):
                if wrong in field:
                    raise InvalidFieldError(
                        f"field {index} uses {wrong!r} for its label; the member is 'key'. "
                        f"{wrong!r} is silently ignored, and the field would render with a "
                        "blank label and no error."
                    )
            raise InvalidFieldError(f"field {index} has no 'key' (its visible label)")

        if "value" not in field:
            raise InvalidFieldError(f"field {index} has no 'value'")
        if "type" not in field:
            raise InvalidFieldError(f"field {index} has no 'type'; one of {', '.join(FIELD_TYPES)}")


# ── sections 2.3 and 2.4: tokens derived from the key ────────────────────────────────


def access_token(content_key: bytes) -> str:
    """The access token the server uses to admit a reader.

    The salt is empty so this is reproducible from the fragment alone, on any device, with
    nothing stored. The server keeps only a hash of it and learns nothing about the content
    key, because HKDF's domain separation makes the ``access`` output independent of the
    ``content`` one.
    """
    return _b64url(_hkdf(content_key, b"", "access", _KEY_LEN))


def passcode_verifier(passcode: str) -> str:
    """A one-way verifier that lets the server check a passcode it cannot use."""
    return _b64url(_hkdf(passcode.encode("utf-8"), b"", "verify", _KEY_LEN))


# ── section 3: seed-derived P-256 keypairs ───────────────────────────────────────────


@dataclass(frozen=True)
class SeedKeypair:
    """A P-256 keypair reconstructed from a 32-byte seed.

    Storing the seed rather than a serialized key is what lets an entire private key live in
    a URL fragment, and what lets ephemeral automation derive the same key with no local
    state.
    """

    seed: bytes
    scalar: int
    private_key: ec.EllipticCurvePrivateKey
    public_key_raw: bytes

    @property
    def public_key_b64url(self) -> str:
        return _b64url(self.public_key_raw)


def keypair_from_seed(seed: bytes) -> SeedKeypair:
    """Derive a P-256 keypair from a 32-byte seed (section 3).

    48 bytes of HKDF output rather than 32 is deliberate: the extra 128 bits make the modular
    bias negligible. Reducing mod ``n-1`` and adding one yields a scalar in ``[1, n-1]``,
    excluding zero, which is not a valid private key.
    """
    if len(seed) != _KEY_LEN:
        raise ValueError(f"a seed is {_KEY_LEN} bytes, got {len(seed)}")

    wide = _hkdf(seed, b"", "crs-ecdh-p256-scalar", 48)
    scalar = (int.from_bytes(wide, "big") % (_P256_ORDER - 1)) + 1

    private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    public_raw = private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    return SeedKeypair(seed=seed, scalar=scalar, private_key=private_key, public_key_raw=public_raw)


def custody_keypair(custody_secret: str) -> SeedKeypair:
    """Derive the custody keypair from the third part of an API credential (section 3.1).

    The custody secret is never transmitted. It is a *separate* secret from the auth secret
    precisely so that the server cannot reconstruct this private key: the auth secret goes
    over the wire on every request, so deriving custody from it would mean the server
    *could* decrypt. Not that it would — that it could, which is what zero-knowledge is meant
    to remove.

    The empty salt is deliberate: the derivation has to be reproducible from the credential
    alone, on any machine, with nothing stored.
    """
    seed = _hkdf(custody_secret.encode("utf-8"), b"", "custody", _KEY_LEN)
    return keypair_from_seed(seed)


# ── section 4: ECDH wrapping ─────────────────────────────────────────────────────────


def wrap_to_public_key(
    payload: bytes,
    recipient_public_key: bytes,
    *,
    _ephemeral_seed: Optional[bytes] = None,
    _salt: Optional[bytes] = None,
    _iv: Optional[bytes] = None,
) -> str:
    """Wrap a payload to a published P-256 public key.

    Layout: ``base64(0x01 || ephemeralPublic(65) || salt(16) || iv(12) || ciphertext+tag)``.
    Wrapping a 32-byte payload gives exactly 142 bytes, which is a useful field check.

    The ephemeral keypair is fresh per wrap. The underscored arguments exist only so the
    conformance fixture is reproducible; reusing an ephemeral key across wraps leaks the
    relationship between them.
    """
    if len(recipient_public_key) != _PUBKEY_LEN or recipient_public_key[0] != 0x04:
        raise ValueError(
            "a recipient public key is a 65-byte uncompressed P-256 point starting with 0x04"
        )

    ephemeral = (
        keypair_from_seed(_ephemeral_seed)
        if _ephemeral_seed is not None
        else keypair_from_seed(os.urandom(_KEY_LEN))
    )
    salt = _salt if _salt is not None else os.urandom(_SALT_LEN)
    iv = _iv if _iv is not None else os.urandom(_IV_LEN)

    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_public_key)
    shared = ephemeral.private_key.exchange(ec.ECDH(), peer)
    wrapping_key = _hkdf(shared, salt, "crs-request-submission", _KEY_LEN)
    body = AESGCM(wrapping_key).encrypt(iv, payload, None)

    return _b64(bytes([_WRAP_VERSION]) + ephemeral.public_key_raw + salt + iv + body)


def unwrap_with_seed(wrapped: str, seed: bytes) -> bytes:
    """Unwrap a blob using the recipient's seed-derived private key."""
    try:
        raw = base64.b64decode(wrapped, validate=True)
    except Exception as exc:
        raise WireFormatError("the wrapped blob is not valid base64") from exc

    minimum = 1 + _PUBKEY_LEN + _SALT_LEN + _IV_LEN + _TAG_LEN
    if len(raw) < minimum:
        raise WireFormatError(
            f"the wrapped blob is {len(raw)} bytes; the smallest possible one is {minimum}"
        )

    if raw[0] != _WRAP_VERSION:
        # Refused rather than guessed: a future format may place the fields differently, and
        # decrypting it as though it were version 1 would produce nonsense or worse.
        raise WireFormatError(f"unsupported wrap version {raw[0]}; this blob needs a newer client")

    offset = 1
    ephemeral_public = raw[offset : offset + _PUBKEY_LEN]
    offset += _PUBKEY_LEN
    salt = raw[offset : offset + _SALT_LEN]
    offset += _SALT_LEN
    iv = raw[offset : offset + _IV_LEN]
    offset += _IV_LEN
    body = raw[offset:]

    recipient = keypair_from_seed(seed)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public)
    shared = recipient.private_key.exchange(ec.ECDH(), peer)
    wrapping_key = _hkdf(shared, salt, "crs-request-submission", _KEY_LEN)

    try:
        return AESGCM(wrapping_key).decrypt(iv, body, None)
    except Exception as exc:
        raise WireFormatError("could not unwrap: wrong key, or the blob was altered") from exc
