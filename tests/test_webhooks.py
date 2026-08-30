"""Webhook verification.

Most of these assert refusals. A verifier that accepts too much is worse than none, because
it produces a system that looks verified and is not.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from credenshare.webhooks import (
    DEFAULT_TOLERANCE_SECONDS,
    WebhookVerificationError,
    verify,
)

SECRET = "whsec_5NIQiWnzkbjIRSAX0ilnFLBOoIfnDMi16D3F5jrhSbo"
OTHER = "whsec_someone-elses-secret-entirely-different-value"
BODY = b'{"event":"share.created","short_code":"abc123"}'
NOW = 1_700_000_000


def sign(secret: str, body: bytes = BODY, at: int = NOW) -> str:
    mac = hmac.new(secret.encode(), f"{at}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={at},v1={mac}"


def test_a_genuine_delivery_verifies() -> None:
    assert verify(BODY, sign(SECRET), SECRET, now=NOW) is True


def test_a_forged_signature_is_refused() -> None:
    with pytest.raises(WebhookVerificationError, match="no signature matched"):
        verify(BODY, sign(OTHER), SECRET, now=NOW)


def test_a_tampered_body_is_refused() -> None:
    header = sign(SECRET)
    with pytest.raises(WebhookVerificationError):
        verify(BODY + b" ", header, SECRET, now=NOW)


# ── the replay window ────────────────────────────────────────────────────────────────


def test_an_old_delivery_is_refused_even_though_its_signature_is_valid() -> None:
    """The signature alone is not enough.

    Without a timestamp check, anyone who captured one delivery could replay it forever.
    """
    old = NOW - (DEFAULT_TOLERANCE_SECONDS + 60)
    with pytest.raises(WebhookVerificationError, match="outside the"):
        verify(BODY, sign(SECRET, at=old), SECRET, now=NOW)


def test_the_window_is_symmetric() -> None:
    """A receiver's clock can be AHEAD as easily as behind.

    Rejecting only one direction fails for half the machines that are wrong.
    """
    future = NOW + (DEFAULT_TOLERANCE_SECONDS + 60)
    with pytest.raises(WebhookVerificationError, match="outside the"):
        verify(BODY, sign(SECRET, at=future), SECRET, now=NOW)

    inside = NOW + (DEFAULT_TOLERANCE_SECONDS - 10)
    assert verify(BODY, sign(SECRET, at=inside), SECRET, now=NOW) is True


def test_the_timestamp_cannot_be_swapped_for_a_fresh_one() -> None:
    """It is inside the signed material, so moving it invalidates the MAC."""
    header = sign(SECRET, at=NOW - 10_000)
    forward = header.replace(f"t={NOW - 10_000}", f"t={NOW}")
    with pytest.raises(WebhookVerificationError, match="no signature matched"):
        verify(BODY, forward, SECRET, now=NOW)


# ── the rotation grace window ────────────────────────────────────────────────────────


def test_either_secret_verifies_a_dual_signed_delivery() -> None:
    """During a rotation, deliveries carry both signatures for 24 hours.

    That is what lets a receiver roll its configuration without dropping anything — without
    it, the moment of rotation IS an outage.
    """
    old_mac = hmac.new(OTHER.encode(), f"{NOW}.".encode() + BODY, hashlib.sha256).hexdigest()
    dual = sign(SECRET) + f",v1={old_mac}"

    assert verify(BODY, dual, SECRET, now=NOW) is True
    assert verify(BODY, dual, OTHER, now=NOW) is True
    assert verify(BODY, dual, [OTHER, SECRET], now=NOW) is True


def test_an_unrelated_secret_still_fails_against_a_dual_signed_delivery() -> None:
    """Two signatures widen WHO can verify, not WHAT verifies."""
    old_mac = hmac.new(OTHER.encode(), f"{NOW}.".encode() + BODY, hashlib.sha256).hexdigest()
    dual = sign(SECRET) + f",v1={old_mac}"
    with pytest.raises(WebhookVerificationError):
        verify(BODY, dual, "whsec_a-third-unrelated-secret", now=NOW)


# ── malformed input ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "header,match",
    [
        ("", "missing"),
        ("   ", "missing"),
        (f"v1={'0' * 64}", "no timestamp"),
        (f"t={NOW}", "no v1 signature"),
        (f"t=notanumber,v1={'0' * 64}", "not a unix time"),
    ],
)
def test_malformed_headers_are_refused_with_a_reason(header: str, match: str) -> None:
    with pytest.raises(WebhookVerificationError, match=match):
        verify(BODY, header, SECRET, now=NOW)


def test_no_secret_is_an_error_not_a_pass() -> None:
    for secrets in ("", [], ["", "  "]):
        with pytest.raises(WebhookVerificationError, match="no signing secret"):
            verify(BODY, sign(SECRET), secrets, now=NOW)


def test_verify_never_returns_false() -> None:
    """It raises instead.

    A falsy return is too easy to drop with `if verify(...)` and no else, which produces a
    receiver that accepts everything and looks like it checks.
    """
    with pytest.raises(WebhookVerificationError):
        verify(BODY, sign(OTHER), SECRET, now=NOW)


def test_reserialised_json_does_not_verify() -> None:
    """The most common reason a correct implementation appears broken.

    Re-serialising parsed JSON changes the bytes — key order, spacing, escapes — so the MAC
    no longer matches. The docstring warns about it; this pins it.
    """
    header = sign(SECRET)
    reserialised = json.dumps(json.loads(BODY)).encode()
    assert reserialised != BODY
    with pytest.raises(WebhookVerificationError, match="RAW body"):
        verify(reserialised, header, SECRET, now=NOW)
