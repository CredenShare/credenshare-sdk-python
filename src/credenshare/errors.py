"""Errors raised by the CredenShare SDK.

The hierarchy is shallow on purpose. What matters is that a caller can distinguish the cases
that have *different remedies* — an incomplete link, an expired share, a wrong passcode, a
plan limit — because on screen several of these look identical and sending somebody to the
wrong fix is worse than a generic failure.
"""

from __future__ import annotations

from typing import Any, Optional

__all__ = [
    "CredenShareError",
    "MissingKeyError",
    "MalformedKeyError",
    "WireFormatError",
    "ApiError",
    "AuthenticationError",
    "PermissionError_",
    "NotFoundError",
    "RateLimitError",
    "QuotaExceededError",
    "IdempotencyConflictError",
    "ServiceUnavailableError",
    "DeliveryUnknownError",
    "CredentialFormatError",
    "CustodySecretTransmittedError",
    "CustodySecretMissingError",
    "InvalidFieldError",
    "InvalidArgumentError",
]


class CredenShareError(Exception):
    """Base class for everything this SDK raises."""


# ── link and payload problems ────────────────────────────────────────────────────────


class MissingKeyError(CredenShareError):
    """No key fragment at all.

    Kept distinct from :class:`MalformedKeyError` because the remedies differ: this one means
    "you were sent a link without its key", which usually means a chat client or an email
    scanner stripped it.
    """


class MalformedKeyError(CredenShareError):
    """A fragment is present but unusable — wrong version, bad encoding, wrong length.

    Most often a truncated link. Distinguishing it from an expired share matters, because the
    two are indistinguishable on screen and have opposite fixes: ask for the link again
    versus ask for a new share.
    """


class WireFormatError(CredenShareError):
    """A blob could not be parsed or decrypted.

    Deliberately covers both "the passcode is wrong" and "the bytes were altered". They are
    indistinguishable by design — telling them apart would hand an attacker an oracle.
    """


# ── credential problems ──────────────────────────────────────────────────────────────


class CredentialFormatError(CredenShareError):
    """An API credential is not in the expected form."""


class CustodySecretTransmittedError(CredenShareError):
    """The full three-part credential was about to be sent.

    Raised locally, before any request. The custody half must never reach the server: it is a
    separate secret precisely so that the server *cannot* reconstruct the private key, and a
    credential that has been transmitted whole should be rotated rather than reused.
    """


# ── API responses ────────────────────────────────────────────────────────────────────


class ApiError(CredenShareError):
    """A non-success response from the API."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        #: The API's own numeric error code, when it sent one.
        self.code = code
        #: Worth quoting in a support conversation.
        self.request_id = request_id

    def __str__(self) -> str:  # pragma: no cover - formatting only
        parts = [super().__str__()]
        if self.status is not None:
            parts.append(f"HTTP {self.status}")
        if self.code is not None:
            parts.append(f"code {self.code}")
        if self.request_id:
            parts.append(f"request {self.request_id}")
        return " (".join([parts[0], ", ".join(parts[1:]) + ")"]) if len(parts) > 1 else parts[0]


class AuthenticationError(ApiError):
    """The credential was rejected — unknown, revoked, or malformed."""


class PermissionError_(ApiError):
    """Authenticated, but not allowed: a missing scope, or a plan without API access.

    Named with a trailing underscore to avoid shadowing the built-in ``PermissionError``,
    which would be a genuinely confusing thing to do in a library people import broadly.
    """


class NotFoundError(ApiError):
    """No such resource — or one belonging to another account.

    The API reports those identically on purpose, so a credential cannot be used to discover
    which short codes exist elsewhere.
    """


class RateLimitError(ApiError):
    """Too many requests."""

    def __init__(self, message: str, *, retry_after: Optional[int] = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        #: Seconds to wait, from the ``Retry-After`` header. Always present on a 429.
        self.retry_after = retry_after


class QuotaExceededError(ApiError):
    """The plan's share allowance is spent.

    Distinct from :class:`RateLimitError`: waiting does not help, and the fix is a plan
    change or expiring old shares.
    """


class ServiceUnavailableError(ApiError):
    """Entitlements could not be resolved, so nothing was created.

    Transient and safe to retry. The API returns this rather than guessing, because guessing
    "unlimited" would let an account exceed its plan and guessing "exhausted" would break a
    healthy one during a billing hiccup.
    """


class InvalidFieldError(CredenShareError, ValueError):
    """A field object does not match the wire format.

    Also a ``ValueError``, so code that already caught one keeps working; being a
    :class:`CredenShareError` is what makes the README's blanket ``except CredenShareError``
    the genuine catch-all it is described as. Node's twin is ``InvalidFieldError`` too.
    """


class InvalidArgumentError(CredenShareError, ValueError):
    """Arguments to an SDK call contradict each other.

    Separate from :class:`InvalidFieldError`, which is specifically about a field object not
    matching the wire format. Collapsing the two would leave one of them with a docstring that
    does not describe half its call sites.

    Also a ``ValueError``, so code that already caught one keeps working.
    """


class CustodySecretMissingError(CredenShareError):
    """Custody was requested but the credential carries no custody secret.

    Custody wrapping needs the third part of ``crs_sk_live_<keyId>.<authSecret>.<custodySecret>``.
    A two-part credential can create shares, but only ones whose link is the sole way back to
    the content.
    """


class DeliveryUnknownError(ApiError):
    """The request reached the API but its outcome could not be read.

    Deliberately an :class:`ApiError` even though no response was read. It replaced
    :class:`ServiceUnavailableError` on the read-timeout path, and that is an ApiError — a
    caller with ``except ApiError`` around a create would otherwise have stopped catching a
    case it caught before, and found out in production.

    Distinct from :class:`ServiceUnavailableError`, which means nothing was created. Here the
    bytes were delivered and the server may well have committed — a create that raises this
    may have produced a share whose link this process never saw.

    Do not retry with a fresh ``idempotency_key``: that is how one secret becomes two, each
    with its own link and audit trail. Repeat the identical request (same key) so the API can
    recognise it, or reconcile by listing before retrying.
    """

    def __init__(self, message: str, *, attempts: int = 1, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        #: How many times delivery was attempted before giving up.
        self.attempts = attempts


class IdempotencyConflictError(ApiError):
    """The Idempotency-Key was reused with a different request body.

    Almost always this means a caller passed the same ``idempotency_key`` to two separate
    ``create()`` calls expecting the second to be a no-op. It cannot be, and no argument to
    ``create()`` makes it one: encryption is randomised per call — a fresh salt and IV every
    time, which AES-GCM requires — so two calls with identical arguments, and even with the
    same ``content_key``, still produce different ciphertext. The API is right to refuse.

    What the header actually protects is a NETWORK retry, where the body is byte-identical
    because it is the same already-encrypted request being sent again. This client performs
    those retries itself, so the protection is already in place without a caller-supplied
    key. Pass ``idempotency_key`` to control the value for your own tracing; do not pass it
    expecting a second call to be deduplicated.

    The API also answers 409 with error code 106 when an identical request is still IN
    FLIGHT. That is a different situation with the opposite remedy: the first call has not
    finished, so wait briefly and repeat the same request unchanged. Changing the key or the
    body there turns a retry into a duplicate. Both arrive as this class; ``err.code``
    separates them.
    """
