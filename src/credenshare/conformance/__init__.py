"""The conformance fixture, and a self-check that runs against it.

`vectors.v1.json` is normative. It ships inside the package rather than sitting beside it in
the repository so that anyone who installs this SDK can verify the exact artifact they
installed:

    python -m credenshare.conformance

That matters more here than in most libraries. The application and the four SDKs share no
code by design — a package the production application depended on would mean a compromised
publish is a compromised application — so nothing but these vectors holds the five
implementations together. Drift between them does not surface as a test failure in normal
use. It surfaces as content that can never be decrypted.

This module is deliberately dependency-free beyond the SDK itself: a user checking whether
their installed copy is sound should not have to install a test runner to find out. The
pytest suite in `tests/` runs these same checks and adds the ones that are properties of this
implementation rather than of the fixture — error types, argument validation, reprs that
withhold secrets.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Tuple

__all__ = ["VECTORS_PATH", "load", "checks", "run", "say"]

VECTORS_PATH = Path(__file__).resolve().parent / "vectors.v1.json"

#: The fixture version this code was written against. A silent bump would mean every check
#: below is asserting against a contract nobody wrote it for, which is worse than failing.
SUPPORTED_VERSION = 1


def load() -> Dict[str, Any]:
    """Read the packaged fixture."""
    data: Dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    if data.get("version") != SUPPORTED_VERSION:
        raise RuntimeError(
            f"the packaged fixture is version {data.get('version')!r}, but this SDK "
            f"implements version {SUPPORTED_VERSION}"
        )
    return data


def _unhex(text: str) -> bytes:
    return bytes.fromhex(text)


def _expect(what: str, got: Any, want: Any) -> None:
    if got != want:
        raise AssertionError(f"{what}\n  expected: {want!r}\n  actual:   {got!r}")


def checks() -> Iterator[Tuple[str, Callable[[], None]]]:
    """Yield ``(name, check)`` pairs, one per vector.

    Each check raises on failure and returns nothing on success. They are yielded rather than
    run so a caller — the CLI, or a test runner — can report them individually instead of
    stopping at the first, which matters when a derivation change breaks a whole section.
    """
    from .. import crypto

    v = load()

    for case in v["hkdf"]:
        yield "hkdf/" + case["name"], _hkdf(crypto, case)

    frag = v["fragment"]
    yield "fragment/encode", _fragment_encode(crypto, frag)
    yield "fragment/decode", _fragment_decode(crypto, frag)
    for index, reject in enumerate(frag["rejects"]):
        # Refusals are part of the contract, not extra credit: a client that accepts a
        # truncated fragment produces a key that decrypts nothing, and reports it as a
        # content error somewhere far away from the mangled link that caused it.
        yield (
            f"fragment/rejects/{index}/" + reject["reason"],
            _fragment_reject(crypto, reject),
        )

    yield "access_token", _access_token(crypto, v["access_token"])

    for index, case in enumerate(v["passcode_verifier"]):
        # Numbered rather than named after the passcode: one of these cases is deliberately
        # non-ASCII, and a legacy console code page would turn printing its name into a
        # crash in the tool that is meant to be diagnosing crashes.
        yield f"passcode_verifier/{index}", _verifier(crypto, case)

    for case in v["content"]:
        yield "content/" + case["name"] + "/encrypt", _content_encrypt(crypto, case)
        # The decrypt direction is the one that proves interoperability: the blob in the
        # fixture was produced by a different implementation, so reading it means this client
        # can read what that one wrote.
        yield "content/" + case["name"] + "/decrypt", _content_decrypt(crypto, case)

    for case in v["seed_keypair"]:
        yield "seed_keypair/" + case["name"], _seed_keypair(crypto, case)

    yield "custody_keypair", _custody(crypto, v["custody_keypair"])

    wrap = v["ecdh_wrap"]
    yield "ecdh_wrap/wrap", _wrap(crypto, wrap)
    yield "ecdh_wrap/unwrap", _unwrap(crypto, wrap)
    yield "ecdh_wrap/roundtrip", _wrap_roundtrip(crypto, wrap)


def _hkdf(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        out = crypto._hkdf(_unhex(case["ikm"]), _unhex(case["salt"]), case["info"], case["length"])
        _expect("HKDF output", out.hex(), case["out"])

    return check


def _fragment_encode(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        _expect("encoded fragment", crypto.encode_fragment(_unhex(case["key"])), case["encoded"])

    return check


def _fragment_decode(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        _expect(
            "decoded content key",
            crypto.decode_fragment(case["encoded"]).hex(),
            case["key"],
        )

    return check


def _fragment_reject(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    from ..errors import MalformedKeyError, MissingKeyError

    wanted = {"missing-key": MissingKeyError, "malformed-key": MalformedKeyError}[case["reason"]]

    def check() -> None:
        try:
            crypto.decode_fragment(case["input"])
        except wanted:
            return
        except Exception as exc:  # noqa: BLE001
            # The distinction is not pedantry. "Your link is incomplete" and "this link is
            # damaged" have different remedies, and both look identical on screen.
            raise AssertionError(
                f"expected {wanted.__name__} for {case['input']!r}, got {type(exc).__name__}: {exc}"
            ) from None
        raise AssertionError(
            f"{case['input']!r} was accepted; the fixture requires {wanted.__name__}"
        )

    return check


def _access_token(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        _expect("access token", crypto.access_token(_unhex(case["key"])), case["token"])

    return check


def _verifier(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        _expect(
            "passcode verifier",
            crypto.passcode_verifier(case["passcode"]),
            case["verifier"],
        )

    return check


def _content_encrypt(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        blob = crypto.encrypt_content(
            _unhex(case["key"]),
            json.loads(case["plaintext"]),
            case.get("passcode"),
            _salt=_unhex(case["salt"]),
            _iv=_unhex(case["iv"]),
        )
        # Byte-identical, not merely decryptable. A blob that differs while still decrypting
        # here would hide a JSON-serialisation difference — key order, separators — that
        # another implementation may not tolerate.
        _expect("content blob", blob, case["blob"])

    return check


def _content_decrypt(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        fields = crypto.decrypt_content(_unhex(case["key"]), case["blob"], case.get("passcode"))
        _expect("decrypted fields", fields, json.loads(case["plaintext"]))

    return check


def _seed_keypair(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        pair = crypto.keypair_from_seed(_unhex(case["seed"]))
        # The scalar is checked as well as the public key. Both would have to be wrong
        # together for a bias in the reduction to slip through unnoticed.
        _expect("scalar", format(pair.scalar, "x").zfill(64), case["scalar"])
        _expect("public key", pair.public_key_raw.hex(), case["public_key"])
        _expect("public key (base64url)", pair.public_key_b64url, case["public_key_b64url"])

    return check


def _custody(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        pair = crypto.custody_keypair(case["custody_secret"])
        # The seed is checked too: it is the value a different implementation has to arrive
        # at independently, and a mismatch here explains a public-key mismatch below it.
        _expect("custody seed", pair.seed.hex(), case["seed"])
        _expect("custody public key", pair.public_key_raw.hex(), case["public_key"])
        _expect("custody public key (base64url)", pair.public_key_b64url, case["public_key_b64url"])

    return check


def _wrap(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        wrapped = crypto.wrap_to_public_key(
            _unhex(case["payload"]),
            _unhex(case["recipient_public_key"]),
            _ephemeral_seed=_unhex(case["ephemeral_seed"]),
            _salt=_unhex(case["salt"]),
            _iv=_unhex(case["iv"]),
        )
        _expect("wrapped blob", wrapped, case["wrapped"])

    return check


def _unwrap(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        payload = crypto.unwrap_with_seed(case["wrapped"], _unhex(case["recipient_seed"]))
        _expect("unwrapped payload", payload.hex(), case["payload"])

    return check


def _wrap_roundtrip(crypto: Any, case: Dict[str, Any]) -> Callable[[], None]:
    def check() -> None:
        recipient = crypto.keypair_from_seed(_unhex(case["recipient_seed"]))
        payload = _unhex(case["payload"])
        wrapped = crypto.wrap_to_public_key(payload, recipient.public_key_raw)

        raw = base64.b64decode(wrapped, validate=True)
        # 1 version + 65 public + 16 salt + 12 iv + payload + 16 tag. A 32-byte payload
        # wraps to exactly 142 bytes, which is a useful field check when something
        # downstream rejects a wrap without saying why.
        _expect("wrap length", len(raw), 1 + 65 + 16 + 12 + len(payload) + 16)
        _expect("version byte", raw[0], case["wrap_version"])
        _expect(
            "unwrapped payload",
            crypto.unwrap_with_seed(wrapped, _unhex(case["recipient_seed"])).hex(),
            case["payload"],
        )

    return check


def say(text: str) -> None:
    """Print, surviving a console that cannot represent the characters.

    A failure message quotes actual values, and those can be any text somebody put in a
    field — one of the fixture's own passcodes is deliberately non-ASCII. A self-check that
    raises UnicodeEncodeError while reporting a failure is worse than useless: it replaces
    the diagnosis with a crash inside the tool meant to produce it, on exactly the legacy
    console code pages where the report is most needed.
    """
    stream = sys.stdout
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(text.encode(encoding, "replace").decode(encoding, "replace") + "\n")


def run(verbose: bool = False) -> Tuple[int, List[Tuple[str, str]]]:
    """Run every check. Returns ``(passed, failures)``.

    Every failure is collected rather than raised: a derivation change usually breaks a whole
    section at once, and stopping at the first would hide the shape of the problem.
    """
    passed = 0
    failures: List[Tuple[str, str]] = []
    for name, check in checks():
        try:
            check()
        # Blind on purpose: a check can fail with anything, and the caller wants a report
        # covering every vector rather than a traceback from the first one.
        except Exception as exc:  # noqa: BLE001
            failures.append((name, str(exc)))
            if verbose:
                say("FAIL " + name + "\n" + str(exc))
        else:
            passed += 1
            if verbose:
                say("ok   " + name)
    return passed, failures
