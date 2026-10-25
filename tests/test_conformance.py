"""The conformance suite. This is the only meaningful definition of correct.

`credenshare/conformance/vectors.v1.json` is normative and is vendored from the published
fixture. The application, this SDK and the three others share no code by design, so
nothing but these vectors holds the five implementations together — and drift between
them does not produce a test failure in normal use, it produces content that can never be
decrypted.

The derivation cases catch drift early. The decrypt and unwrap cases are the ones that
actually prove interoperability, because passing them means this implementation can read what
a *different* one wrote.
"""

from __future__ import annotations

import base64
import json

import pytest

from credenshare import crypto

# The fixture is read from inside the package, which is the only copy. Vendoring a second
# one beside the tests would mean the suite could pass against a fixture the shipped wheel
# does not contain.
from credenshare.conformance import VECTORS_PATH, checks
from credenshare.errors import MalformedKeyError, MissingKeyError, WireFormatError

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def unhex(text: str) -> bytes:
    return bytes.fromhex(text)


def test_vectors_are_the_expected_version() -> None:
    # A silent version bump would mean the suite below is asserting against a contract this
    # code was never written to.
    assert VECTORS["version"] == 1


# ── section 1: HKDF ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", VECTORS["hkdf"], ids=lambda c: c["name"])
def test_hkdf(case) -> None:
    out = crypto._hkdf(
        unhex(case["ikm"]),
        unhex(case["salt"]),
        case["info"],
        case["length"],
    )
    assert out.hex() == case["out"]


def test_empty_salt_is_not_a_block_of_zeros() -> None:
    """The specification calls this out, so it is asserted rather than assumed.

    RFC 5869 makes an empty salt and a 32-zero-byte salt equivalent for SHA-256 — both pad to
    the same 64-byte HMAC block — but an implementation that padded to some other length
    would silently produce different output, and the failure would appear as undecryptable
    content rather than as a test failure.
    """
    ikm = bytes(range(32))
    assert crypto._hkdf(ikm, b"", "access", 32) == crypto._hkdf(ikm, b"\x00" * 32, "access", 32)


# ── section 2.1: the fragment ────────────────────────────────────────────────────────


def test_fragment_encoding() -> None:
    case = VECTORS["fragment"]
    assert crypto.encode_fragment(unhex(case["key"])) == case["encoded"]
    assert crypto.decode_fragment(case["encoded"]) == unhex(case["key"])


def test_fragment_round_trips_with_a_leading_hash() -> None:
    # Callers paste what the browser gives them, which includes the '#'.
    case = VECTORS["fragment"]
    assert crypto.decode_fragment("#" + case["encoded"]) == unhex(case["key"])


@pytest.mark.parametrize("case", VECTORS["fragment"]["rejects"], ids=lambda c: c["reason"])
def test_fragment_rejections(case) -> None:
    """Rejections must be DISTINGUISHABLE, not merely present.

    "your link is incomplete" and "this share expired" look identical on screen and have
    opposite remedies, so a single generic error would send people to the wrong fix.
    """
    expected = MissingKeyError if case["reason"] == "missing-key" else MalformedKeyError
    with pytest.raises(expected):
        crypto.decode_fragment(case["input"])


# ── sections 2.3 and 2.4 ─────────────────────────────────────────────────────────────


def test_access_token() -> None:
    case = VECTORS["access_token"]
    assert crypto.access_token(unhex(case["key"])) == case["token"]


@pytest.mark.parametrize("case", VECTORS["passcode_verifier"], ids=lambda c: c["passcode"])
def test_passcode_verifier(case) -> None:
    assert crypto.passcode_verifier(case["passcode"]) == case["verifier"]


# ── section 2.2: content ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", VECTORS["content"], ids=lambda c: c["name"])
def test_content_encryption_matches_the_fixture(case) -> None:
    fields = json.loads(case["plaintext"])
    blob = crypto.encrypt_content(
        unhex(case["key"]),
        fields,
        case.get("passcode"),
        _salt=unhex(case["salt"]),
        _iv=unhex(case["iv"]),
    )
    assert blob == case["blob"]


@pytest.mark.parametrize("case", VECTORS["content"], ids=lambda c: c["name"])
def test_content_decrypts_material_written_elsewhere(case) -> None:
    """THE interoperability case: this blob was produced by a different implementation."""
    fields = crypto.decrypt_content(unhex(case["key"]), case["blob"], case.get("passcode"))
    assert fields == json.loads(case["plaintext"])


def test_the_fixture_uses_key_not_label() -> None:
    """A guard on the fixture itself.

    The label member is `key`. `label`, `name` and `title` are silently ignored: a share
    built with one still encrypts, posts, decrypts and renders, with every field blank and no
    error anywhere. The fixture shipped with `label` at one point, which would have taught
    exactly that mistake to every SDK reading it for the payload shape — so this asserts the
    vendored copy has not regressed.
    """
    for case in VECTORS["content"]:
        for field in json.loads(case["plaintext"]):
            assert "key" in field, "the fixture must model the field label as 'key'"
            assert "label" not in field


def test_field_types_match_the_app_and_only_presence_is_checked() -> None:
    """``url`` and ``qr`` reached the app on 2026-10-24.

    The type rides inside the ciphertext, so the server never sees it and this SDK does not
    police it: the 2,300-character QR limit is the app editor's, not a wire rule.
    """
    assert crypto.FIELD_TYPES == (
        "text",
        "password",
        "date",
        "multiline",
        "markdown",
        "source_code",
        "url",
        "qr",
    )
    crypto.validate_fields(
        [
            {"key": "Docs", "value": "not a link", "type": "url"},
            {"key": "Wi-Fi", "value": "x" * 2301, "type": "qr"},
        ]
    )


def test_a_wrong_passcode_is_indistinguishable_from_tampering() -> None:
    case = VECTORS["content"][1]  # the passcode case
    with pytest.raises(WireFormatError):
        crypto.decrypt_content(unhex(case["key"]), case["blob"], "not-the-passcode")

    tampered = bytearray(base64.b64decode(case["blob"]))
    tampered[-1] ^= 0x01
    with pytest.raises(WireFormatError):
        crypto.decrypt_content(
            unhex(case["key"]),
            base64.b64encode(bytes(tampered)).decode(),
            case["passcode"],
        )


def test_a_truncated_blob_is_rejected_before_decryption() -> None:
    with pytest.raises(WireFormatError, match="smallest possible"):
        crypto.decrypt_content(bytes(32), base64.b64encode(b"tooshort").decode())


# ── section 3: seed-derived keypairs ─────────────────────────────────────────────────


@pytest.mark.parametrize("case", VECTORS["seed_keypair"], ids=lambda c: c["name"])
def test_seed_keypair(case) -> None:
    pair = crypto.keypair_from_seed(unhex(case["seed"]))
    assert format(pair.scalar, "064x") == case["scalar"]
    assert pair.public_key_raw.hex() == case["public_key"]
    assert pair.public_key_b64url == case["public_key_b64url"]


def test_seed_keypair_public_key_is_uncompressed_and_65_bytes() -> None:
    pair = crypto.keypair_from_seed(bytes(range(32)))
    assert len(pair.public_key_raw) == 65
    assert pair.public_key_raw[0] == 0x04


# ── section 3.1: credential custody ──────────────────────────────────────────────────


def test_custody_keypair() -> None:
    case = VECTORS["custody_keypair"]
    pair = crypto.custody_keypair(case["custody_secret"])
    assert pair.seed.hex() == case["seed"]
    assert pair.public_key_raw.hex() == case["public_key"]
    assert pair.public_key_b64url == case["public_key_b64url"]


def test_custody_derivation_is_reproducible_anywhere() -> None:
    """The property the empty salt exists for: same credential, same keypair, no state."""
    case = VECTORS["custody_keypair"]
    first = crypto.custody_keypair(case["custody_secret"])
    second = crypto.custody_keypair(case["custody_secret"])
    assert first.public_key_raw == second.public_key_raw


# ── section 4: ECDH wrapping ─────────────────────────────────────────────────────────


def test_ecdh_wrap_matches_the_fixture() -> None:
    case = VECTORS["ecdh_wrap"]
    wrapped = crypto.wrap_to_public_key(
        unhex(case["payload"]),
        unhex(case["recipient_public_key"]),
        _ephemeral_seed=unhex(case["ephemeral_seed"]),
        _salt=unhex(case["salt"]),
        _iv=unhex(case["iv"]),
    )
    assert wrapped == case["wrapped"]


def test_ecdh_unwrap_reads_material_written_elsewhere() -> None:
    """The other interoperability case."""
    case = VECTORS["ecdh_wrap"]
    payload = crypto.unwrap_with_seed(case["wrapped"], unhex(case["recipient_seed"]))
    assert payload.hex() == case["payload"]


def test_wrapping_32_bytes_produces_142() -> None:
    # 1 + 65 + 16 + 12 + 32 + 16. The specification calls this a useful field check.
    case = VECTORS["ecdh_wrap"]
    wrapped = crypto.wrap_to_public_key(bytes(32), unhex(case["recipient_public_key"]))
    assert len(base64.b64decode(wrapped)) == 142


def test_a_fresh_ephemeral_key_is_used_per_wrap() -> None:
    """Reusing one across wraps leaks the relationship between them."""
    case = VECTORS["ecdh_wrap"]
    pub = unhex(case["recipient_public_key"])
    first = base64.b64decode(crypto.wrap_to_public_key(bytes(32), pub))
    second = base64.b64decode(crypto.wrap_to_public_key(bytes(32), pub))
    assert first[1:66] != second[1:66], "the ephemeral public key must differ per wrap"


def test_an_unknown_wrap_version_is_refused_not_guessed() -> None:
    case = VECTORS["ecdh_wrap"]
    raw = bytearray(base64.b64decode(case["wrapped"]))
    raw[0] = 2
    with pytest.raises(WireFormatError, match="unsupported wrap version"):
        crypto.unwrap_with_seed(
            base64.b64encode(bytes(raw)).decode(), unhex(case["recipient_seed"])
        )


def test_a_truncated_wrap_is_rejected() -> None:
    with pytest.raises(WireFormatError, match="smallest possible"):
        crypto.unwrap_with_seed(base64.b64encode(b"short").decode(), bytes(32))


# ── round trips, which the fixture cannot cover ──────────────────────────────────────


def test_content_round_trip_with_random_material() -> None:
    key = crypto.new_content_key()
    fields = [{"key": "Token", "value": "s3cr3t", "type": "password"}]
    assert crypto.decrypt_content(key, crypto.encrypt_content(key, fields)) == fields


def test_wrap_round_trip_with_random_material() -> None:
    seed = crypto.new_content_key()
    recipient = crypto.keypair_from_seed(seed)
    payload = b"a" * 32
    wrapped = crypto.wrap_to_public_key(payload, recipient.public_key_raw)
    assert crypto.unwrap_with_seed(wrapped, seed) == payload


# -- the checker that ships with the package --------------------------------------------


@pytest.mark.parametrize("case", list(checks()), ids=lambda c: c[0])
def test_the_packaged_self_check_passes(case) -> None:
    """`python -m credenshare.conformance` is what a user runs to verify their install.

    It is exercised here so a broken checker cannot ship quietly. A self-check that always
    passes is worse than no self-check: it converts an unverified installation into one
    somebody believes is verified.
    """
    _, check = case
    check()


def test_non_ascii_is_not_escaped_on_the_wire() -> None:
    """The Python-specific trap.

    `json.dumps` escapes every non-ASCII character to a backslash-u sequence by default, and
    no other implementation does. The blob still decrypts — here and everywhere else, because
    the escapes decode back to the same string — so nothing errors and a round-trip test
    passes. What breaks is byte-for-byte reproducibility with every other client.

    This sat undetected until a conformance vector carrying unicode was added: the fixture was
    pure ASCII, so all of it passed either way. The check is on the WIRE PLAINTEXT, because
    decrypting gives back Python objects that say nothing about the bytes.
    """
    key = crypto.new_content_key()
    fields = [{"key": "ünïcödé", "value": "πασσ — em dash 🔐", "type": "text"}]

    blob = crypto.encrypt_content(key, fields)
    raw = base64.b64decode(blob)
    salt, iv, body = raw[:16], raw[16:28], raw[28:]

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    derived = crypto._content_key_for(key, salt, None)
    plaintext = AESGCM(derived).decrypt(iv, body, None).decode("utf-8")

    escaped = chr(92) + "u"  # backslash-u, not an escape sequence in this source
    assert escaped not in plaintext, f"the wire plaintext is escaped: {plaintext}"
    assert "ünïcödé" in plaintext and "🔐" in plaintext
    assert crypto.decrypt_content(key, blob) == fields
