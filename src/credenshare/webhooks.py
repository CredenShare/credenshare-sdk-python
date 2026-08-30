"""Verifying webhook deliveries.

A signature you do not check is decoration. This module exists so that checking one is
easier than not checking it — including the parts people usually skip, which are the parts
that matter.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Iterable, Optional

__all__ = ["verify", "WebhookVerificationError", "DEFAULT_TOLERANCE_SECONDS"]

#: How far a delivery's timestamp may sit from your clock, in either direction.
#:
#: Symmetric because a receiver's clock can be behind OR ahead, and rejecting only one
#: direction fails for half the machines that are wrong. Five minutes is long enough to
#: survive ordinary drift and short enough that a captured delivery is not replayable for
#: long.
DEFAULT_TOLERANCE_SECONDS = 300

_SIGNATURE_HEADER = "X-CredenShare-Signature"


class WebhookVerificationError(Exception):
    """A delivery did not verify. Treat it as a forgery, not as a transient error."""


def verify(
    payload: bytes,
    header: str,
    secrets: "str | Iterable[str]",
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[int] = None,
) -> bool:
    """Verify a delivery signature.

    ``payload`` must be the RAW request body, exactly as received. Re-serialising parsed JSON
    changes the bytes — key order, spacing, unicode escapes — and the signature will not
    match. This is the single most common reason a correct implementation appears broken.

    ``header`` is the ``X-CredenShare-Signature`` value, of the form
    ``t=<unix>,v1=<hex>[,v1=<hex>]``.

    ``secrets`` accepts one secret or several. Pass BOTH during a rotation: for 24 hours
    after you rotate, deliveries are signed with the old and new secrets together, so a
    receiver holding either keeps working while you roll your configuration. Passing only the
    new one during that window is safe; passing only the old one stops working when the
    window closes, which is the point of rotating.

    Returns ``True`` or raises :class:`WebhookVerificationError` with a reason. It never
    returns ``False`` — a silent falsy result is too easy to drop on the floor with
    ``if verify(...)`` and no ``else``.
    """
    if isinstance(secrets, str):
        secrets = [secrets]
    candidates = [s for s in secrets if s and s.strip()]
    if not candidates:
        raise WebhookVerificationError("no signing secret was supplied")

    timestamp, signatures = _parse(header)

    # The timestamp is checked BEFORE the signatures, and it is inside the signed material,
    # so it cannot be swapped for a fresh one without invalidating the MAC. Verifying the
    # signature but ignoring the timestamp would let anyone who captured one delivery replay
    # it forever.
    current = int(time.time()) if now is None else now
    drift = abs(current - timestamp)
    if drift > tolerance_seconds:
        raise WebhookVerificationError(
            f"the delivery timestamp is {drift}s from this clock, outside the "
            f"{tolerance_seconds}s window; it may be a replay, or a clock may be wrong"
        )

    signed = f"{timestamp}.".encode("ascii") + payload
    for secret in candidates:
        expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
        for candidate in signatures:
            # Constant time: a byte-by-byte comparison leaks how much of a guess was right,
            # which is enough to forge a signature given enough attempts.
            if hmac.compare_digest(expected, candidate):
                return True

    raise WebhookVerificationError(
        "no signature matched. If you are mid-rotation, pass both secrets; otherwise check "
        "you are verifying the RAW body rather than re-serialised JSON"
    )


def _parse(header: str) -> "tuple[int, list[str]]":
    if not header or not header.strip():
        raise WebhookVerificationError(f"the {_SIGNATURE_HEADER} header is missing")

    timestamp: Optional[int] = None
    signatures: list[str] = []

    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise WebhookVerificationError(
                    f"the timestamp {value!r} is not a unix time"
                ) from exc
        elif key == "v1":
            # Several v1 entries is normal, not an error: it is how a rotation grace window
            # is expressed, so a receiver holding either secret keeps verifying.
            signatures.append(value)

    if timestamp is None:
        raise WebhookVerificationError("the signature header carries no timestamp")
    if not signatures:
        raise WebhookVerificationError("the signature header carries no v1 signature")
    return timestamp, signatures
