"""The CredenShare API client.

Everything sensitive happens before a request is built. By the time anything reaches the
network it is ciphertext plus metadata, and the content key exists only in the link this
client hands back to you.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    overload,
)
from urllib.parse import quote

import httpx

from . import crypto
from .errors import (
    ApiError,
    AuthenticationError,
    CredentialFormatError,
    CustodySecretMissingError,
    CustodySecretTransmittedError,
    DeliveryUnknownError,
    IdempotencyConflictError,
    InvalidArgumentError,
    InvalidFieldError,
    MalformedKeyError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
    RequestSeedTransmittedError,
    ServiceUnavailableError,
)

__all__ = [
    "CredenShare",
    "Credential",
    "Share",
    "ShareList",
    "ShareSummary",
    "SecureRequest",
    "RequestSummary",
    "RequestList",
    "RequestDeletion",
    "Submission",
    "SubmissionPage",
    "Stats",
    "ShareCounts",
    "DailyView",
]

DEFAULT_BASE_URL = "https://api.credenshare.io/v1"
DEFAULT_LINK_ORIGIN = "https://crs.sh"

#: The most pages a paged walk will make before giving up - :meth:`_Shares.iter_all` and
#: :meth:`_Requests.iter_all`. :meth:`_Requests.iter_submissions` does not page at all, so
#: it cannot reach this.
#:
#: The end of a result set is not always knowable: a server that omits every paging figure and
#: returns full pages forever cannot be told from a very large account. An unbounded walk
#: against one never returns. At the default page size of 100 this is ten million shares.
MAX_PAGES = 100_000

#: The only accepted encryption type. Plaintext creates are refused by the server, and this
#: client has no way to express one.
ENCRYPTION_TYPE = "e2ee-aes256-gcm"

#: The header the API consults on a CREATE. Named once because three call sites send it and
#: :meth:`CredenShare._request` fills it in for the rest; three spellings of one header is
#: how a caller-supplied value ends up alongside a generated one instead of replacing it.
_IDEMPOTENCY_HEADER = "Idempotency-Key"

#: The methods :meth:`CredenShare._request` will generate a key for. POST, PUT and PATCH
#: only — NOT every non-GET.
#:
#: The backend consults the header on creates. On ``DELETE /shares/{code}`` it is inert: the
#: endpoint is idempotent by construction, a repeat is a 404, and there is no second copy of
#: anything for the header to prevent. Sending one there would add a header to bytes already
#: published at 0.1.4 — a silent wire change to a shipped surface, which is the one thing a
#: patch to this transport must not do. A caller who supplies their own key on a DELETE still
#: has it forwarded untouched; this governs only what is GENERATED.
_IDEMPOTENT_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: The API's numeric code for an exhausted plan allowance. Distinguished from other 403s
#: because waiting does not help and the remedy is a plan change, not a retry.
_QUOTA_EXCEEDED_CODE = 61

#: The API's numeric code for an Idempotency-Key replayed with a different body.
_IDEMPOTENCY_CONFLICT_CODE = 105

#: The identical request is still in flight. Wait briefly and repeat it unchanged - the
#: opposite remedy to 105, which means the body genuinely differed.
_IDEMPOTENCY_IN_FLIGHT_CODE = 106

#: Retries for network failures. Only connection and timeout errors are retried, never an
#: HTTP status: a 5xx may have committed, and this client cannot tell. A create is safe to
#: retry because the Idempotency-Key and the body are both identical on the second attempt —
#: which is the entire reason the header is mandatory on a create.
DEFAULT_MAX_RETRIES = 2


class _Seed(bytes):
    """A 32-byte request seed that does not print itself.

    A ``bytes`` subclass rather than a wrapper, so everything a caller has to do with a seed
    keeps working — ``len``, ``==``, ``.hex()``, :func:`credenshare.keypair_from_seed`,
    writing it to a file — while the paths Python reaches for reflexively do not spill it.
    ``print(req.seed)``, an f-string, ``logging.info("%s", req.seed)``, ``pprint``, a failed
    pytest assertion's diff and ``dataclasses.asdict(req)`` all render the redaction, because
    every one of them goes through ``__repr__`` or ``__str__``.

    Which is the part a ``__repr__`` on :class:`SecureRequest` alone does not cover: that
    hides the seed when the REQUEST is printed, and does nothing when the seed itself is.

    Storing one takes an explicit encoding — ``req.seed.hex()``, or base64. That is the
    point. A seed that ended up in a log because somebody interpolated an object is the
    accident this type exists to prevent; ``.hex()`` is not an accident.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{len(self)} bytes withheld>"

    def __str__(self) -> str:
        return self.__repr__()

    # `dataclasses.asdict` deep-copies every field value that is not itself a dataclass, and
    # the COPY is what a caller then renders. So the copy has to come back a `_Seed` and not a
    # plain `bytes`: the moment the subclass is lost, `repr(asdict(req))` prints all 32 bytes,
    # in the one call the redaction most needs to survive.
    #
    # It survives today by accident — CPython reconstructs a bytes subclass through
    # `__reduce_ex__` — and an accident is the wrong thing to rest a secret on. These pin it.
    # Returning `self` is exactly what `copy` does for `bytes` (`_deepcopy_atomic`), and it is
    # sound for the same reason: a seed is immutable, so there is nothing to copy.
    def __copy__(self) -> "_Seed":
        return self

    def __deepcopy__(self, memo: Dict[int, Any]) -> "_Seed":
        return self


def _seed_renderings(seed: bytes) -> Tuple[str, ...]:
    """Every encoding a 32-byte seed could plausibly be rendered in, for the boundary check.

    Three rather than one because the point is to catch a seed that reached the body through
    a route nobody anticipated, and somebody hand-rolling that would reach for whichever
    encoder was nearest.

    The unpadded spellings only: for 32 bytes the padded form is the unpadded one plus
    ``=``, so a substring search for the unpadded string matches both. The same three, in
    the same order, in all four SDKs.
    """
    return (
        base64.urlsafe_b64encode(seed).decode("ascii").rstrip("="),
        base64.b64encode(seed).decode("ascii").rstrip("="),
        seed.hex(),
    )


@dataclass(frozen=True)
class Credential:
    """A parsed API credential: ``crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]``.

    The custody secret is held here but is NEVER placed in a request. It is a separate secret
    precisely so the server cannot reconstruct the custody private key — deriving it from the
    auth secret, which is transmitted on every call, would mean the server *could* decrypt.
    Not that it would; that it could.
    """

    key_id: str
    auth_secret: str
    custody_secret: Optional[str] = None

    @classmethod
    def parse(cls, raw: str) -> "Credential":
        text = (raw or "").strip()
        if not text.startswith("crs_sk_live_"):
            raise CredentialFormatError(
                "a credential starts with 'crs_sk_live_'; this does not look like one"
            )
        parts = text.split(".")
        if len(parts) not in (2, 3) or not all(parts):
            raise CredentialFormatError(
                "a credential is 'crs_sk_live_<keyId>.<authSecret>' with an optional "
                f"'.<custodySecret>'; this has {len(parts)} part(s)"
            )
        return cls(
            key_id=parts[0][len("crs_sk_live_") :],
            auth_secret=parts[1],
            custody_secret=parts[2] if len(parts) == 3 else None,
        )

    @property
    def bearer(self) -> str:
        """The two-part value sent in the Authorization header.

        Assembled from the parts rather than by trimming the original string, so a third part
        cannot survive a formatting mistake and reach the wire.
        """
        return f"crs_sk_live_{self.key_id}.{self.auth_secret}"

    @property
    def has_custody(self) -> bool:
        return self.custody_secret is not None

    def custody_public_key(self) -> str:
        """The base64url custody public key to register for account custody.

        Only the public half leaves this machine.
        """
        if self.custody_secret is None:
            raise CredentialFormatError(
                "this credential has no custody secret, so no custody keypair exists"
            )
        return crypto.custody_keypair(self.custody_secret).public_key_b64url

    def __repr__(self) -> str:  # pragma: no cover - formatting only
        # Never render the secrets. A credential in a traceback or a log line is a credential
        # that has to be rotated.
        custody = "with custody" if self.has_custody else "no custody"
        return f"<Credential {self.key_id} ({custody})>"


@dataclass(frozen=True)
class Share:
    """A created share, and the only place its link exists."""

    short_code: str
    #: The full recipient link, INCLUDING the key fragment. Treat this as the secret itself:
    #: anyone holding it can read the content, and CredenShare cannot.
    link: str
    #: The content key, if you need to build your own link or decrypt later.
    content_key: bytes
    expired_at: Optional[str] = None
    custody: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover - formatting only
        # The link carries the key, so it is not printed by default.
        return f"<Share {self.short_code} (link withheld from repr)>"


@dataclass(frozen=True)
class ShareSummary:
    """Metadata for a share. Never content, and never a key.

    Deliberately thin, because the API is: `/v1` returns the short code and the expiry and
    nothing else. There is no `title` here even though you supply one on create — the server
    does not return it, and an attribute that is always ``None`` reads as a broken field
    rather than as an absent one.
    """

    short_code: str
    expired_at: Optional[str] = None


_Row = TypeVar("_Row")


class _PagedList(List[_Row]):
    """A page of rows, with the paging figures attached.

    A plain list would leave a caller guessing whether more exists, and a caller who has to
    guess guesses wrong — usually by stopping at the first short page.

    Shared by every paged surface rather than copied per surface. The termination rule below
    is subtle enough that this SDK already shipped one wrong copy of it, and a second copy is
    a second place for that to happen out of sight of the first.
    """

    def __init__(
        self,
        rows: Sequence[_Row],
        *,
        page: int = 1,
        limit: int = 25,
        total: Optional[int] = None,
        total_pages: Optional[int] = None,
    ) -> None:
        super().__init__(rows)
        self.page = page
        self.limit = limit
        self.total = total
        self.total_pages = total_pages

    @property
    def has_more(self) -> bool:
        """Whether another page exists.

        Falls back rather than answering ``False`` when the server sends no paging figures:
        reporting "no more" on a full page is what makes a walk stop after page one and
        return a fraction of the account as though it were all of it. Node, Go and Rust all
        fall back; Python was the only one that did not.
        """
        if self.total_pages is not None:
            return self.page < self.total_pages
        if self.total is not None:
            return self.page * self.limit < self.total
        # Nothing to go on but the page itself: a full page probably has a successor.
        return len(self) >= self.limit > 0


class ShareList(_PagedList[ShareSummary]):
    """A page of shares, with the paging figures attached."""


#: The events ``crs.shares.create(notify_on=...)`` accepts, in the API's order.
NOTIFY_ON_EVENTS = ("viewed", "denied", "expired", "deleted")

#: What a limit reads when the plan sets none, in :class:`CapabilityLimits` and
#: :attr:`AccessLogPage.retention_days`.
UNLIMITED = -1

_LIST_STATUSES = ("active", "expired")


def _validate_notify_on(events: Optional[Sequence[str]]) -> None:
    """The API's rule for ``notify_on`` (at most four, no repeats, each a known event), applied
    before anything is encrypted, so a typo is refused here rather than after a share is sent."""
    if events is None:
        return
    if isinstance(events, str):
        raise InvalidArgumentError("notify_on is a list of events, not one string")
    seen = set()
    for event in events:
        if event not in NOTIFY_ON_EVENTS:
            raise InvalidArgumentError(
                f"notify_on {event!r} is not one of {', '.join(NOTIFY_ON_EVENTS)}"
            )
        if event in seen:
            raise InvalidArgumentError(f"notify_on lists {event!r} twice")
        seen.add(event)


def _list_params(limit: int, page: int, status: Optional[str]) -> Dict[str, Any]:
    """A list's query. ``status`` goes out only when asked for, so a plain ``list()`` sends
    exactly what it always has."""
    if status is None:
        return {"limit": limit, "page": page}
    if status not in _LIST_STATUSES:
        raise InvalidArgumentError(f"a list status is 'active' or 'expired', not {status!r}")
    return {"limit": limit, "page": page, "status": status}


def _time_param(value: Union[str, datetime, None], name: str) -> Optional[str]:
    """A datetime as RFC 3339 in UTC; a string as given. A naive datetime is refused, because
    nothing here can know which zone it meant."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidArgumentError(
                f"{name} is a naive datetime; give it a timezone, such as timezone.utc"
            )
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raise InvalidArgumentError(f"{name} is an RFC 3339 string or a datetime")


def _parsed_time(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class AccessLogEntry:
    """One opening of a share."""

    #: RFC 3339, as the API sent it.
    accessed_at: str
    accessed_ip: str
    platform: str
    #: The raw user agent, or ``None`` when none was recorded. Link previews show up here.
    user_agent: Optional[str]
    #: The viewer entered a wrong passcode.
    failed_passcode: bool
    #: The viewer was signed in to CredenShare. Whose account it was is not disclosed.
    signed_in: bool


@dataclass(frozen=True)
class AccessLogPage:
    """One page of a share's access log, newest first.

    When ``not_modified`` is true the API answered 304 to ``if_none_match``: the page already
    held is still current, and nothing here but ``short_code`` and ``etag`` is set.
    """

    short_code: str
    entries: Tuple[AccessLogEntry, ...]
    #: Reads the next, older page. ``None`` on the last page.
    next_cursor: Optional[str]
    #: The plan's access-log retention in days, or :data:`UNLIMITED`.
    retention_days: int
    #: The window the API applied after retention. When ``from_`` and ``to`` are not set they
    #: move with the clock, so the ``etag`` of an unbounded read changes from one second to
    #: the next.
    effective_from: Optional[str]
    effective_to: Optional[str]
    etag: Optional[str]
    not_modified: bool

    @property
    def has_more(self) -> bool:
        """Whether an older page exists."""
        return self.next_cursor is not None


def _walk(fetch: Callable[[int], _PagedList[_Row]]) -> Iterator[_Row]:
    """Walk a paged surface page by page, yielding rows.

    Written once because the hand-rolled version is usually wrong in the same way: it stops
    on the first page shorter than the limit, which is a page the server is entitled to
    return in the middle of a result set.
    """
    page = 1
    while True:
        batch = fetch(page)
        yield from batch
        if not batch.has_more:
            return

        # The API echoing a page number other than the one asked for makes progress
        # unobservable, so no termination condition can be trusted. Refuse rather than
        # loop - Go and Rust do the same.
        if batch.page != page:
            raise ApiError(
                f"asked for page {page} and the API answered with page {batch.page}, so "
                f"paging cannot be trusted to terminate"
            )
        if page >= MAX_PAGES:
            raise ApiError(
                f"stopped after {MAX_PAGES} pages without the API signalling the end of "
                f"the result set. A walk that cannot terminate is worse than one that "
                f"stops and says so."
            )
        page += 1


class _Shares:
    """The ``/v1/shares`` surface."""

    def __init__(self, client: "CredenShare") -> None:
        self._client = client

    def create(
        self,
        *,
        title: str,
        fields: Sequence[Dict[str, Any]],
        description: Optional[str] = None,
        passcode: Optional[str] = None,
        expired_at: Optional[str] = None,
        access_counts_left: Optional[int] = None,
        timed_view: Optional[int] = None,
        idempotency_key: Optional[str] = None,
        content_key: Optional[bytes] = None,
        custody: bool = False,
        item_key_wrap: Optional[str] = None,
        organization_id: Optional[str] = None,
        notify_on: Optional[Sequence[str]] = None,
    ) -> Share:
        """Encrypt ``fields`` locally and create a share.

        Each field is ``{"key": <label>, "value": <content>, "type": <one of FIELD_TYPES>}``.
        ``key`` is the visible label — not ``label``, ``name`` or ``title``, which are
        silently ignored and would render every field blank. This client refuses those
        rather than letting the mistake through.

        Returns a :class:`Share` whose ``link`` contains the content key in its fragment.
        That link is the secret; CredenShare never sees the key and cannot recover it.

        ``idempotency_key`` is generated per call unless you pass one. Passing your own does
        NOT make a second call a no-op: encryption is randomised per call — a fresh salt and
        IV every time — so the body differs and the API refuses with
        :class:`IdempotencyConflictError`. That is the header working, not failing. What it
        protects is a network retry, where the same already-encrypted request is sent again;
        this client performs those itself. Pass a key to control the value for your own
        tracing, not to deduplicate calls.

        ``custody=True`` additionally wraps the content key to the custody public key derived
        from your credential's third part, so the share is readable from the dashboard later.
        Without it — the default — an API-created share is custody ``"none"``: the link is the
        only way back to the content, and losing it loses the secret. The custody secret is
        used locally to derive a public key and is never transmitted. Pass ``item_key_wrap``
        instead to supply a wrap you computed yourself.

        ``content_key`` lets you create a share under a key you already hold — a link you
        handed out before the create, or a fixed key in a test. It does not make the request
        body reproducible. Never reuse a key across shares whose content differs: this client
        draws a fresh IV each time, which is what keeps that safe, but nothing here can stop
        you from carrying a key somewhere that does not.

        ``notify_on`` emails the share's creator when it is viewed, when a view is refused,
        when it expires or when it is deleted: any of :data:`NOTIFY_ON_EVENTS`, each at most
        once, the same choice as the app's "Email me when". It is checked before anything is
        encrypted or sent, as the API checks it.
        """
        _validate_notify_on(notify_on)
        content_key = content_key if content_key is not None else crypto.new_content_key()

        if custody and item_key_wrap is not None:
            raise InvalidArgumentError("pass either custody=True or item_key_wrap, not both")
        if custody:
            secret = self._client.credential.custody_secret
            if not secret:
                raise CustodySecretMissingError(
                    "custody=True needs a three-part credential "
                    "'crs_sk_live_<keyId>.<authSecret>.<custodySecret>'; this one has two "
                    "parts, so there is no custody key to wrap to"
                )
            item_key_wrap = crypto.wrap_to_public_key(
                content_key, crypto.custody_keypair(secret).public_key_raw
            )

        blob = crypto.encrypt_content(content_key, fields, passcode)

        body: Dict[str, Any] = {
            "title": title,
            "encryption_type": ENCRYPTION_TYPE,
            "data": blob,
            "access_token": crypto.access_token(content_key),
        }
        if description is not None:
            body["description"] = description
        if passcode is not None:
            body["passcode_verifier"] = crypto.passcode_verifier(passcode)
        if expired_at is not None:
            body["expired_at"] = expired_at
        if access_counts_left is not None:
            body["access_counts_left"] = access_counts_left
        if timed_view is not None:
            body["timed_view"] = timed_view
        if item_key_wrap is not None:
            body["item_key_wrap"] = item_key_wrap
        if organization_id is not None:
            body["organization_id"] = organization_id
        if notify_on:
            body["notify_on"] = list(notify_on)

        # Required by the API, not optional. A retried automation must not create a second
        # copy of a credential in the world, with its own link and audit trail, that the
        # caller does not know exists.
        headers = {_IDEMPOTENCY_HEADER: idempotency_key or str(uuid.uuid4())}

        data = self._client._request("POST", "/shares", json=body, headers=headers)
        short_code = data["short_code"]
        return Share(
            short_code=short_code,
            link=self._client.link_for(short_code, content_key),
            content_key=content_key,
            expired_at=data.get("expired_at"),
            custody=data.get("custody"),
        )

    def list(self, *, limit: int = 25, page: int = 1, status: Optional[str] = None) -> ShareList:
        """One page of the account's shares, newest first. Metadata only.

        The returned list carries ``page``, ``limit``, ``total``, ``total_pages`` and
        ``has_more``. Use :meth:`iter_all` to walk every page.

        ``status="expired"`` lists the shares that have ended, by date, by views or by
        deletion, newest expiry first, in the same shape. Left out (or ``"active"``), this is
        the live list, and nothing new is sent.
        """
        data = self._client._request("GET", "/shares", params=_list_params(limit, page, status))
        rows = data.get("shares") or data.get("data") or []
        pagination = data.get("pagination") or {}
        return ShareList(
            [
                ShareSummary(short_code=r["short_code"], expired_at=r.get("expired_at"))
                for r in rows
            ],
            page=pagination.get("page", page),
            limit=pagination.get("limit", limit),
            total=pagination.get("total"),
            total_pages=pagination.get("total_pages"),
        )

    def iter_all(self, *, limit: int = 100, status: Optional[str] = None) -> Iterator[ShareSummary]:
        """Every share, page by page.

        Does not stop on a page shorter than ``limit`` — the server is entitled to return
        one in the middle of a result set, and stopping there silently truncates.
        ``status`` is as for :meth:`list`.
        """
        _list_params(limit, 1, status)
        return _walk(lambda page: self.list(limit=limit, page=page, status=status))

    def access_log(
        self,
        short_code: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        from_: Union[str, datetime, None] = None,
        to: Union[str, datetime, None] = None,
        if_none_match: Optional[str] = None,
    ) -> AccessLogPage:
        """One page of a share's access log: who opened it, newest first, the history the app
        shows under Access History.

        Needs the ``audit:read`` scope, which ``shares:read`` does not include because the log
        carries recipients' IP addresses; without it this raises :class:`PermissionError_`.
        Only the share's creator can read the log, for a live share or one that has ended, and
        any other short code raises :class:`NotFoundError`.

        ``limit`` is 1 to 100 (the API answers 50 when it is left out). ``cursor`` is a
        previous page's ``next_cursor``. ``from_`` and ``to`` bound the entries by time, as
        RFC 3339 strings or timezone-aware datetimes; the plan's retention applies whatever
        ``from_`` says. Pass an earlier ``etag`` as ``if_none_match`` and an unchanged page
        comes back with ``not_modified`` set rather than as an error.
        """
        params: Dict[str, Any] = {}
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
                raise InvalidArgumentError(f"an access log limit is 1 to 100, got {limit!r}")
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor
        start = _time_param(from_, "from_")
        end = _time_param(to, "to")
        if start is not None and end is not None:
            a, b = _parsed_time(start), _parsed_time(end)
            if a is not None and b is not None and a > b:
                raise InvalidArgumentError("the access log's from_ is after its to")
        if start is not None:
            params["from"] = start
        if end is not None:
            params["to"] = end
        headers = {"If-None-Match": if_none_match} if if_none_match else None

        reply = self._client._exchange(
            "GET",
            f"/shares/{quote(short_code, safe='')}/access-log",
            params=params or None,
            headers=headers,
            accept_not_modified=True,
        )
        data = reply.data
        next_cursor = data.get("next_cursor")
        effective_from = data.get("effective_from")
        effective_to = data.get("effective_to")
        return AccessLogPage(
            short_code=data.get("short_code") or short_code,
            entries=tuple(
                AccessLogEntry(
                    accessed_at=str(row.get("accessed_at") or ""),
                    accessed_ip=str(row.get("accessed_ip") or ""),
                    platform=str(row.get("platform") or ""),
                    user_agent=row["user_agent"]
                    if isinstance(row.get("user_agent"), str)
                    else None,
                    failed_passcode=row.get("failed_passcode") is True,
                    signed_in=row.get("signed_in") is True,
                )
                for row in (data.get("entries") or [])
            ),
            next_cursor=next_cursor if isinstance(next_cursor, str) and next_cursor else None,
            retention_days=int(data.get("retention_days") or 0),
            effective_from=effective_from if isinstance(effective_from, str) else None,
            effective_to=effective_to if isinstance(effective_to, str) else None,
            etag=reply.etag,
            not_modified=reply.not_modified,
        )

    def iter_access_log(
        self,
        short_code: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        from_: Union[str, datetime, None] = None,
        to: Union[str, datetime, None] = None,
    ) -> Iterator[AccessLogEntry]:
        """Every entry of a share's access log, newest first, following each page's
        ``next_cursor``.

        No ``if_none_match``: a walk reads every page, and a 304 on the first would end it
        having read nothing.
        """
        for _ in range(MAX_PAGES):
            page = self.access_log(short_code, limit=limit, cursor=cursor, from_=from_, to=to)
            yield from page.entries
            if page.next_cursor is None:
                return
            # A cursor that does not move would repeat the same page forever.
            if page.next_cursor == cursor:
                raise ApiError(
                    "the access log returned the cursor it was given, so paging cannot be "
                    "trusted to terminate"
                )
            cursor = page.next_cursor
        raise ApiError(f"the access log did not end within {MAX_PAGES} pages")

    def get(self, short_code: str) -> ShareSummary:
        """One share's metadata.

        Does not consume a view, evaluate a passcode, or return content. A share belonging to
        another account reports exactly as one that does not exist.
        """
        data = self._client._request("GET", f"/shares/{quote(short_code, safe='')}")
        return ShareSummary(
            short_code=data.get("short_code", short_code),
            expired_at=data.get("expired_at"),
        )

    def expire(self, short_code: str) -> None:
        """Expire a share immediately.

        Irreversible: afterwards the content is unrecoverable by anyone, including
        CredenShare — the key was never ours, and now the ciphertext is gone too.

        The share is REMOVED, not flagged. A later :meth:`get` raises
        :class:`NotFoundError` rather than returning a row with an expiry set, and it drops
        out of :meth:`list`. Worth knowing if you reconcile against your own records: a
        share you expired and one that never existed look identical afterwards.

        A key can only expire shares its own account created. A short code belonging to
        somebody else reports as not-found, so this cannot be used to probe for shares
        elsewhere — and an organization-scoped key cannot expire a colleague's share even
        though :meth:`list` shows it.
        """
        self._client._request("DELETE", f"/shares/{quote(short_code, safe='')}")


@dataclass(frozen=True)
class SecureRequest:
    """A created secure request, and the only place its seed exists.

    A secure request is the mirror image of a share. A share seals content you already hold
    and hands the key to a recipient; a request publishes a public key and collects content
    somebody else seals to it. Which means the private half has to survive until you read
    the submissions — and it only exists here, in ``seed``.

    CredenShare received the public half and nothing else. Losing ``seed`` loses every
    submission, including the ones not yet made, and no support conversation can recover
    them: there is nothing on our side to recover from.
    """

    short_code: str
    #: The 32-byte seed. THE thing to keep. It never reached the server, it is the only way
    #: to open a submission, and :func:`credenshare.decrypt_submission` is what opens one
    #: with it. Store it the way you would store a private key, because it is one.
    #:
    #: A :class:`_Seed`, which is ``bytes`` that renders as ``<32 bytes withheld>`` rather
    #: than printing itself — so an f-string or a log line cannot spill it by accident.
    #: Persist it with an explicit ``req.seed.hex()``.
    seed: bytes
    #: The public half that was sent, base64url and unpadded, as the API echoed it back.
    public_key: str
    #: The keyless collect link — the one you hand to a human. Deliberately without a
    #: fragment: holding it lets somebody SUBMIT and never read, which is what makes it safe
    #: to paste into a ticket. :attr:`access_link` is the other half.
    collect_link: str
    expired_at: Optional[str] = None

    @property
    def access_link(self) -> str:
        """Your own access link: the seed in the fragment, which browsers never transmit.

        Treat the result as the secret itself — it is the ability to read every submission,
        on any device, with nothing stored. CredenShare cannot rebuild it, because the seed
        was never ours.

        Computed rather than stored, and deliberately not a dataclass field: a field would
        put the seed into ``dataclasses.asdict(req)`` and into any repr of this object in
        string form, which is the one thing :attr:`seed` is careful not to do. Asking for
        this property is a deliberate act; printing the object is not.

        Byte-identical to what the app produces and to what the other three SDKs return:
        ``<origin>/r/<short_code>#1<base64url(seed)>``.
        """
        return f"{self.collect_link}#{crypto.encode_fragment(self.seed)}"

    def __repr__(self) -> str:  # pragma: no cover - formatting only
        # The seed is the whole private key, so it is not printed by default — and neither
        # is the access link, which carries the same seed in a fragment. The same reasoning
        # as Share withholding its link. `collect_link` IS printed: it is keyless, and it is
        # the value somebody reading a log is usually looking for.
        return f"<SecureRequest {self.short_code} {self.collect_link} (seed withheld)>"


@dataclass(frozen=True)
class RequestSummary:
    """Metadata for a secure request. Never a submission, and never a private key.

    ``public_key`` is returned deliberately, unlike anything about a share's key material:
    it is the PUBLIC half, you supplied it, and getting it back is how you confirm what was
    stored. It is ``None`` on a request the API answered about without one — an expired row
    reports its short code and nothing else.

    There is no ``title`` here for the same reason :class:`ShareSummary` has none: the API
    does not return one, and an attribute that is always ``None`` reads as a broken field
    rather than as an absent one.
    """

    short_code: str
    expired_at: Optional[str] = None
    public_key: Optional[str] = None


class RequestList(_PagedList[RequestSummary]):
    """A page of secure requests, with the paging figures attached."""


@dataclass(frozen=True)
class RequestDeletion:
    """What a :meth:`_Requests.delete` call actually did.

    Deleting a request is two calls, not one: the first expires an active request, which
    stops new submissions while preserving the ones already received, and a second call on
    the now-expired request removes it outright. ``outcome`` says which happened rather than
    leaving you to infer it from a 200.

    Two members and no more — ``short_code`` and ``outcome`` — the settled shape in all four
    SDKs. Deliberately no third ``deleted`` convenience: it would be one bit derived from
    ``outcome``, and a caller reading the boolean stops seeing that ``"expired"`` is not a
    failed delete but the first half of one. Compare ``outcome`` against the string the API
    sent.
    """

    short_code: str
    #: ``"expired"`` or ``"deleted"``. ``None`` only if the API answered without saying,
    #: which it does not do — but inferring silently is the thing this field exists to stop.
    outcome: Optional[str] = None


@dataclass(frozen=True)
class Submission:
    """One sealed submission — the only content ``/v1`` ever returns.

    That is the metadata-only rule working rather than an exception to it. ``data`` is
    sealed to the request's own public key, whose private half is the seed you kept, so what
    the API hands over is something it cannot read. Open it with
    :func:`credenshare.decrypt_submission` and the seed from :class:`SecureRequest`.

    Nothing is decrypted on the way through. A client that silently decrypted would have to
    be holding the seed, and the seed's whole value is that this SDK never asks you for it
    until you decide to read something.
    """

    short_code: str
    #: The sealed blob, verbatim: standard base64, with padding. Not base64url. A request's
    #: ``public_key`` travels as UNPADDED BASE64URL on this same feature, and the two are not
    #: interchangeable — re-encoding this string fails as a wrong key rather than as a wrong
    #: decoder. Pass it to :meth:`decrypt` or :func:`credenshare.decrypt_submission` as it is.
    data: str
    created_at: Optional[str] = None
    encryption_type: Optional[str] = None

    def decrypt(self, seed: bytes) -> List[Dict[str, Any]]:
        """Open this submission with the seed from :class:`SecureRequest`.

        The same call as :func:`credenshare.decrypt_submission`, reachable from the row so
        the seal and the key meet at one call site rather than two. The argument order of
        the free function is ``(data, seed)`` in all four SDKs; here there is only the seed
        to pass, so it cannot be transposed at all.

        Raises :class:`credenshare.WireFormatError` on the wrong seed — which is also what a
        blob re-encoded as base64url raises, because the bytes stop being the bytes that were
        sealed.
        """
        return crypto.decrypt_submission(self.data, seed)

    def __repr__(self) -> str:  # pragma: no cover - formatting only
        # About noise, not secrecy — the blob is sealed and printing it would leak nothing.
        # It is simply 200-odd characters that make a traceback unreadable.
        return f"<Submission {self.short_code} ({len(self.data)} sealed chars)>"


class SubmissionPage:
    """Every submission to one request, and the two figures the API sends beside them.

    NOT a page, whatever the name says, and deliberately not a :class:`_PagedList`.
    ``GET /requests/{code}/submissions`` answers with the whole set in one response: it reads
    neither ``page`` nor ``limit``, and it sends ``count`` where every other list sends a
    ``pagination`` block. Modelling it as a page would publish two parameters the server
    ignores and a ``has_more`` that could only ever guess — and guessing "a full page probably
    has a successor" is precisely how a walk over this endpoint re-requests the same rows
    until it hits its page cap. All four SDKs expose this one-shot shape, under these names.

    The name is carried for 4-of-4 parity, because Node, Go and Rust all call it
    ``SubmissionPage`` — not because there is a page here. There is nothing to walk: no
    cursor, no ``has_more``, no next call. One request returns everything, and
    :meth:`_Requests.iter_submissions` makes exactly that one request and stops.

    Iterable, indexable and sized, so ``for sub in subs``, ``subs[0]``, ``subs[:2]`` and
    ``len(subs)`` all work. Not a ``list`` subclass, because ``count`` here is the API's own
    figure and a list's ``count`` is a method: one of the two would have had to be renamed,
    and this name is shared with the other three SDKs.

    ``count`` is what the API said it returned, or ``None`` if it did not say. ``len(subs)``
    is how many rows were parsed. They agree unless a response was truncated in transit,
    which is the only reason to expose both.

    ``skipped_not_end_to_end_encrypted`` is not a curiosity: a submission stored before its
    request had a public key is held server-side in a form the API *could* decrypt, and it
    declines to — so a credential never becomes a way to read plaintext secrets. Those rows
    are missing from this list on purpose, and the count is here so a reconciliation against
    the dashboard can say why instead of reporting a short set.
    """

    def __init__(
        self,
        rows: Sequence[Submission],
        *,
        count: Optional[int] = None,
        skipped_not_end_to_end_encrypted: int = 0,
    ) -> None:
        self._rows: List[Submission] = list(rows)
        self.count = count
        self.skipped_not_end_to_end_encrypted = skipped_not_end_to_end_encrypted

    def __len__(self) -> int:
        return len(self._rows)

    def __iter__(self) -> Iterator[Submission]:
        return iter(self._rows)

    @overload
    def __getitem__(self, index: int) -> Submission: ...

    @overload
    def __getitem__(self, index: slice) -> List[Submission]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union[Submission, List[Submission]]:
        return self._rows[index]

    def __bool__(self) -> bool:
        return bool(self._rows)

    def __repr__(self) -> str:  # pragma: no cover - formatting only
        skipped = self.skipped_not_end_to_end_encrypted
        tail = f", {skipped} withheld" if skipped else ""
        return f"<SubmissionPage {len(self._rows)} sealed{tail}>"


def _validate_request_fields(fields: Sequence[Dict[str, Any]]) -> None:
    """Check the prompts on a secure request before anything is sent.

    Two silent failures live here, and neither shows up at the API.

    A request with NO fields is created successfully — 201, a real short code — and renders
    "Unable to Load Request" for the human you send it to. Nothing at the API level would
    ever have shown that.

    A field whose label member is ``key`` is the trap for anyone arriving from
    :meth:`_Shares.create`, where ``key`` is exactly right. Here the member is ``item``, and
    ``key`` is ignored: the request is created with a prompt that has no text.

    Unknown members are accepted without error but NOT STORED: the API unmarshals a request
    field into ``{item, type}`` and keeps only those two. This is the opposite of a share's
    fields, whose extras survive because they sit inside the ciphertext — a request's prompts
    are plaintext metadata, and anything the server has no column for is discarded on the way
    in. They are forwarded rather than rejected here so that a member the API learns tomorrow
    works without an SDK release, but nothing should be *kept* in one.
    """
    if len(fields) == 0:
        raise InvalidFieldError(
            "a secure request needs at least one field; a request with none is created "
            "successfully and renders 'Unable to Load Request' for whoever you send it to"
        )

    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            raise InvalidFieldError(f"field {index} is not an object")

        if "item" not in field:
            for wrong in ("key", "label", "name", "title", "prompt"):
                if wrong in field:
                    raise InvalidFieldError(
                        f"field {index} uses {wrong!r} for its prompt; the member is 'item'. "
                        f"{wrong!r} is silently ignored, and the field would render with no "
                        "prompt and no error. A share's fields use 'key'; a request's use "
                        "'item'."
                    )
            raise InvalidFieldError(f"field {index} has no 'item' (its visible prompt)")

        item = field["item"]
        if not isinstance(item, str) or not item.strip():
            raise InvalidFieldError(
                f"field {index} has an empty 'item'; the prompt is what the person filling "
                "the link reads, and a blank one renders as an unlabelled box"
            )


class _Requests:
    """The ``/v1/requests`` surface."""

    def __init__(self, client: "CredenShare") -> None:
        self._client = client

    def create(
        self,
        *,
        title: str,
        fields: Sequence[Dict[str, Any]],
        description: Optional[str] = None,
        seed: Optional[bytes] = None,
        passcode: Optional[str] = None,
        expired_at: Optional[str] = None,
        max_submission: Optional[int] = None,
        access_counts_left: Optional[int] = None,
        requires_login: Optional[bool] = None,
        requires_mfa: Optional[bool] = None,
        restricted_domain: Optional[Sequence[str]] = None,
        ip_whitelist: Optional[Sequence[str]] = None,
        organization_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> SecureRequest:
        """Mint a keypair, create a collect link, and hand you back the private seed.

        **The returned seed is the point of this call.** It is generated here, it never
        reaches the network, and it is the only thing that can ever open a submission. Store
        it before you do anything else with the result: a request whose seed was dropped
        keeps collecting submissions that nobody — you, us, or a court order — can read.
        Only the public half is sent, which is what makes a submitted secret unreadable to
        CredenShare and to every other submitter. That is asserted rather than reviewed: the
        serialized body and the outgoing ``Idempotency-Key`` are scanned for the seed in
        three encodings before anything is sent, and a match raises
        :class:`RequestSeedTransmittedError` instead of transmitting.

        The result carries both links. :attr:`SecureRequest.collect_link` is keyless — the
        one you hand to a human — and :attr:`SecureRequest.access_link` carries the seed in
        its fragment, so it is the ability to read every submission. Neither appears in the
        request's ``repr``, and the seed does not print itself at all.

        Each field is ``{"item": <the visible prompt>, "type": <how it renders>}``. ``item``
        is the label member here, NOT ``key`` — ``key`` is a share's, and using it produces
        a prompt with no text. ``type`` is optional and defaults to ``text`` server-side. At
        least one field is required; a request with none is created successfully and renders
        as an error page for whoever you send it to.

        ``seed`` accepts a 32-byte seed you already hold, for the custody-derived case: a
        runner that derives its keypair from its credential
        (``crypto.custody_keypair(secret).seed``) recreates the same keypair on any machine
        with nothing stored, which is what lets ephemeral automation read what it collected.
        Passing one does not by itself make the call replayable — see ``idempotency_key``.

        ``passcode`` is transmitted, and that is not an oversight to be worked around: a
        collect link's passcode gates a form the server renders for a stranger's browser, so
        the server has to be able to evaluate it. This is the opposite of a share's
        passcode, which is mixed into the content key and reaches us only as a one-way
        verifier. Do not reach for this expecting the share behaviour.

        ``expired_at`` defaults to 30 days server-side when omitted, matching the dashboard.
        Leaving it out does not create a collect link that stays open forever.

        ``idempotency_key`` is generated per call unless you pass one. It protects a network
        retry, where the byte-identical request is sent again; this client performs those
        itself. Passing your own does NOT make a second call a no-op unless you also pass
        the same ``seed`` — a fresh seed means a different ``public_key`` and therefore a
        different body, which the API refuses with :class:`IdempotencyConflictError`. It
        must not be derived from the seed: a header is the wire too, and that is refused
        along with a seed in the body.
        """
        _validate_request_fields(fields)

        # Wrapped in _Seed here rather than at the return, so that the value this method
        # works with for the rest of its body is already the one that will not print itself.
        seed = _Seed(seed if seed is not None else crypto.new_seed())
        # Checked before the keypair is derived, so a wrong-length seed is a typed SDK error
        # rather than the bare ValueError a crypto primitive would raise from two frames
        # down. A short seed that was quietly padded would produce a keypair nothing could
        # ever rederive.
        if len(seed) != crypto.SEED_LENGTH:
            raise MalformedKeyError(
                f"a request seed is {crypto.SEED_LENGTH} bytes; this one is {len(seed)}"
            )
        keypair = crypto.keypair_from_seed(seed)

        body: Dict[str, Any] = {
            "title": title,
            # The public half, and only ever the public half. Unpadded base64url here — a
            # submission's sealed blob travels as padded standard base64, on this same
            # feature. The two are not interchangeable.
            "public_key": keypair.public_key_b64url,
            # Copied rather than passed through, so a caller mutating their own list
            # afterwards cannot change what was sent under an already-claimed idempotency
            # key.
            "fields": [dict(f) for f in fields],
        }
        if description is not None:
            body["description"] = description
        if passcode is not None:
            body["passcode"] = passcode
        if expired_at is not None:
            body["expired_at"] = expired_at
        if max_submission is not None:
            body["max_submission"] = max_submission
        if access_counts_left is not None:
            body["access_counts_left"] = access_counts_left
        if requires_login is not None:
            body["requires_login"] = requires_login
        if requires_mfa is not None:
            body["requires_mfa"] = requires_mfa
        if restricted_domain is not None:
            body["restricted_domain"] = list(restricted_domain)
        if ip_whitelist is not None:
            body["ip_whitelist"] = list(ip_whitelist)
        if organization_id is not None:
            body["organization_id"] = organization_id

        # Required by the API, as it is on shares, and for a sharper reason: a duplicate
        # collect link is not inert. A person can fill it in, and then a secret exists in a
        # request the caller does not know it created.
        sent_key = idempotency_key or str(uuid.uuid4())
        headers = {_IDEMPOTENCY_HEADER: sent_key}

        # Belt and braces, at the boundary, in the manner of the custody assertion in
        # `_request`. Checked against the SERIALIZED body so a seed smuggled in through a
        # title, a description or an unknown field member is caught too — not only one added
        # to the body above by a later edit.
        #
        # The Idempotency-Key is scanned with it, and that is not hypothetical: `seed` and
        # `idempotency_key` are adjacent arguments to this one method, a caller who wants a
        # deterministic key has a deterministic seed in hand, and a body-only check would
        # watch the seed leave in a header.
        outgoing = json.dumps(body) + sent_key
        for rendering in _seed_renderings(seed):
            if rendering in outgoing:
                raise RequestSeedTransmittedError(
                    "the request seed was about to be transmitted; the submissions to a "
                    "request whose seed reached the server are not zero-knowledge, so "
                    "expire it and create a new one rather than retrying"
                )

        data = self._client._request("POST", "/requests", json=body, headers=headers)

        returned = data.get("public_key")
        if returned and returned != keypair.public_key_b64url:
            # A 200 replay returns the ORIGINAL body, so this can only happen if the request
            # was created under a different seed. Raised rather than returned, because the
            # alternative is handing back a SecureRequest whose seed cannot open a single
            # submission — discovered whenever somebody first tries to read one.
            raise ApiError(
                "the API reports this request under a different public key than the one "
                "sent, so the seed in hand cannot read its submissions. If this was an "
                "Idempotency-Key replay, the original request was created under another "
                "seed; use that seed instead."
            )

        short_code = data["short_code"]
        return SecureRequest(
            short_code=short_code,
            seed=seed,
            public_key=returned or keypair.public_key_b64url,
            collect_link=self._client.collect_link_for(short_code),
            expired_at=data.get("expired_at"),
        )

    def list(self, *, limit: int = 25, page: int = 1, status: Optional[str] = None) -> RequestList:
        """One page of the account's secure requests, newest first. Metadata only.

        The returned list carries ``page``, ``limit``, ``total``, ``total_pages`` and
        ``has_more``. Use :meth:`iter_all` to walk every page.

        ``limit`` defaults to 25 — the server's own default for every ``/v1`` list, which it
        applies when the parameter is absent, and capped by it at 100. The published spec
        says 10 for this endpoint and is wrong; sending 10 by default would make the same
        call return a different page in this SDK than in the other three.

        ``status="expired"`` lists the requests that have closed; a deleted request is in
        neither list. Left out, nothing new is sent.
        """
        data = self._client._request("GET", "/requests", params=_list_params(limit, page, status))
        rows = data.get("requests") or data.get("data") or []
        pagination = data.get("pagination") or {}
        return RequestList(
            [
                RequestSummary(
                    short_code=r["short_code"],
                    expired_at=r.get("expired_at"),
                    public_key=r.get("public_key"),
                )
                for r in rows
            ],
            page=pagination.get("page", page),
            limit=pagination.get("limit", limit),
            total=pagination.get("total"),
            total_pages=pagination.get("total_pages"),
        )

    def iter_all(
        self, *, limit: int = 100, status: Optional[str] = None
    ) -> Iterator[RequestSummary]:
        """Every secure request, page by page.

        Does not stop on a page shorter than ``limit`` — the server is entitled to return
        one in the middle of a result set, and stopping there silently truncates.
        ``status`` is as for :meth:`list`.
        """
        _list_params(limit, 1, status)
        return _walk(lambda page: self.list(limit=limit, page=page, status=status))

    def get(self, short_code: str) -> RequestSummary:
        """One request's metadata.

        A request belonging to another account reports exactly as one that does not exist.
        An expired request of your own reports its short code with ``expired_at`` and
        ``public_key`` both ``None`` — not a 404, because it is still yours.
        """
        data = self._client._request("GET", f"/requests/{quote(short_code, safe='')}")
        return RequestSummary(
            short_code=data.get("short_code", short_code),
            expired_at=data.get("expired_at"),
            public_key=data.get("public_key"),
        )

    def delete(self, short_code: str) -> RequestDeletion:
        """Expire a request, or delete an already-expired one.

        Two calls, not one, and the result says which happened. The first expires an active
        request: new submissions stop, the ones already received are preserved, and the audit
        trail survives. Calling it again on the now-expired request removes it outright, and
        that is irreversible — the sealed submissions go with it, and we never held the seed
        that could have opened them.

        A short code belonging to somebody else reports as not-found, so this cannot be used
        to probe for requests elsewhere.
        """
        data = self._client._request("DELETE", f"/requests/{quote(short_code, safe='')}")
        return RequestDeletion(
            short_code=data.get("short_code", short_code),
            outcome=data.get("outcome"),
        )

    def submissions(self, short_code: str) -> SubmissionPage:
        """Every sealed submission to one request, in one call.

        Returns the blobs, not the content. Decrypting here would mean this method needed the
        seed, and the whole arrangement is that the seed stays with you until you decide to
        read something::

            subs = crs.requests.submissions(req.short_code)
            for sub in subs:
                fields = sub.decrypt(req.seed)

        No ``page`` and no ``limit``, because there are no pages: this endpoint reads neither
        parameter and answers with the whole set plus a ``count``. Sending them would publish
        two arguments that do nothing and imply an ordering guarantee across calls that the
        API does not make. ``subs.count`` is the API's own figure; ``len(subs)`` is what was
        parsed.

        A blob comes back as PADDED STANDARD base64, while the request's ``public_key`` went
        out as UNPADDED BASE64URL. Two encodings on one feature: pass ``sub.data`` through
        verbatim, because re-encoding it fails as a wrong key rather than as a wrong decoder.

        Submissions stored before their request had a public key are withheld by the API
        rather than handed over as plaintext, and counted in
        ``skipped_not_end_to_end_encrypted``.
        """
        data = self._client._request("GET", f"/requests/{quote(short_code, safe='')}/submissions")
        rows = data.get("submissions") or []
        reported = data.get("count")
        return SubmissionPage(
            [
                Submission(
                    short_code=r["short_code"],
                    data=r.get("data") or "",
                    created_at=r.get("created_at"),
                    encryption_type=r.get("encryption_type"),
                )
                for r in rows
            ],
            count=int(reported) if isinstance(reported, int) else None,
            skipped_not_end_to_end_encrypted=data.get("skipped_not_end_to_end_encrypted") or 0,
        )

    def iter_submissions(self, short_code: str) -> Iterator[Submission]:
        """Every submission to one request, row by row.

        One HTTP call, and then it stops. Kept beside :meth:`submissions` because a caller
        who only wants the rows should not have to know whether the endpoint pages — but it
        is deliberately NOT a paged walk. This endpoint ignores ``page``, so a walk that
        inferred "another page exists" from a full one would re-request the identical rows
        until it hit :data:`MAX_PAGES` and hand every sealed submission back thousands of
        times over. Yielding the single response and returning is the whole behaviour.
        """
        return iter(self.submissions(short_code))


@dataclass(frozen=True)
class ShareCounts:
    """How many shares the account has, by state."""

    active: int
    expired: int
    total_viewed: int


@dataclass(frozen=True)
class DailyView:
    """Views on one day. ``date`` is ``YYYY-MM-DD``.

    ``DailyView`` rather than ``DailyViewCount``: one row type, one name, in all four SDKs.
    """

    date: str
    count: int


@dataclass(frozen=True)
class Stats:
    """The account's usage figures.

    The per-member breakdown the dashboard shows is deliberately absent from the API: a key
    scoped to read statistics should not become a way to enumerate colleagues.
    """

    shares: ShareCounts
    #: Oldest first, zero-filled, always present and possibly empty. A tuple rather than a
    #: list because this class is frozen, and a mutable member would make that a half-truth.
    daily_views: Tuple[DailyView, ...]


class _Stats:
    """The ``/v1/stats`` surface."""

    def __init__(self, client: "CredenShare") -> None:
        self._client = client

    def get(self) -> Stats:
        """The account's counts and its recent view series.

        Scoped to the organization when the key acts in one — a seat member's own figures
        are not what their automation is asking about.

        ``daily_views`` is zero-filled, so a day with no views is a row with ``count`` 0
        rather than a gap. It is always present and may be empty, which is why nothing here
        distinguishes "no data" from "field absent": a caller forced to tell those apart
        gets it wrong.
        """
        data = self._client._request("GET", "/stats")
        counts = data.get("shares") or {}
        return Stats(
            shares=ShareCounts(
                active=int(counts.get("active") or 0),
                expired=int(counts.get("expired") or 0),
                total_viewed=int(counts.get("total_viewed") or 0),
            ),
            daily_views=tuple(
                DailyView(date=str(row.get("date") or ""), count=int(row.get("count") or 0))
                for row in (data.get("daily_views") or [])
            ),
        )


@dataclass(frozen=True)
class CapabilityKey:
    """The credential itself, as the API sees it."""

    key_id: str
    scopes: Tuple[str, ...]
    custody_level: int
    #: The team a team key acts in, or ``None`` for a personal key.
    organization_id: Optional[str]
    rate_limit_rpm: int


@dataclass(frozen=True)
class CapabilityPlan:
    """The plan behind the key: the team's for a team key, the account's otherwise."""

    code: str
    name: str


@dataclass(frozen=True)
class CapabilityLimits:
    """The plan's numeric limits, any negotiated override included. :data:`UNLIMITED` (-1)
    means the plan sets none."""

    max_shares: int
    remaining_shares: int
    max_fields: int
    max_days_access_logs: int
    max_api_keys: int
    max_webhooks: int


@dataclass(frozen=True)
class Capabilities:
    """What a credential may do.

    When ``not_modified`` is true the API answered 304 to ``if_none_match``, and nothing but
    ``etag`` is set.
    """

    api_version: str
    key: CapabilityKey
    plan: CapabilityPlan
    limits: CapabilityLimits
    #: The plan's switches by the API's own names, such as ``secure_requests``. A mapping
    #: rather than attributes, so a feature the API adds later is readable without a release.
    features: Dict[str, bool]
    #: The team's sharing policy for a team key, in the API's shape; ``None`` for a personal
    #: key.
    sharing_policy: Optional[Dict[str, Any]]
    field_types: Tuple[str, ...]
    notify_on_events: Tuple[str, ...]
    etag: Optional[str]
    not_modified: bool


class _Capabilities:
    """The ``/v1/capabilities`` surface. No scope is needed."""

    def __init__(self, client: "CredenShare") -> None:
        self._client = client

    def get(self, *, if_none_match: Optional[str] = None) -> Capabilities:
        """The key's scopes and rate limit, its plan (the team's for a team key), the plan's
        limits and features, the team's sharing policy, and the lists the API accepts.

        Pass an earlier ``etag`` as ``if_none_match``: an unchanged answer comes back with
        ``not_modified`` set rather than as an error.
        """
        reply = self._client._exchange(
            "GET",
            "/capabilities",
            headers={"If-None-Match": if_none_match} if if_none_match else None,
            accept_not_modified=True,
        )
        data = reply.data
        key = _mapping(data.get("key"))
        plan = _mapping(data.get("plan"))
        limits = _mapping(data.get("limits"))
        policy = data.get("sharing_policy")
        organization = key.get("organization_id")
        return Capabilities(
            api_version=str(data.get("api_version") or ""),
            key=CapabilityKey(
                key_id=str(key.get("key_id") or ""),
                scopes=_strings(key.get("scopes")),
                custody_level=int(key.get("custody_level") or 0),
                organization_id=organization
                if isinstance(organization, str) and organization
                else None,
                rate_limit_rpm=int(key.get("rate_limit_rpm") or 0),
            ),
            plan=CapabilityPlan(code=str(plan.get("code") or ""), name=str(plan.get("name") or "")),
            limits=CapabilityLimits(
                max_shares=int(limits.get("max_shares") or 0),
                remaining_shares=int(limits.get("remaining_shares") or 0),
                max_fields=int(limits.get("max_fields") or 0),
                max_days_access_logs=int(limits.get("max_days_access_logs") or 0),
                max_api_keys=int(limits.get("max_api_keys") or 0),
                max_webhooks=int(limits.get("max_webhooks") or 0),
            ),
            features={str(k): v is True for k, v in _mapping(data.get("features")).items()},
            sharing_policy=policy if isinstance(policy, dict) else None,
            field_types=_strings(data.get("field_types")),
            notify_on_events=_strings(data.get("notify_on_events")),
            etag=reply.etag,
            not_modified=reply.not_modified,
        )


def _mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> Tuple[str, ...]:
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, list) else ()


class _Reply(NamedTuple):
    """A successful exchange: the decoded body, and what the conditional reads need."""

    data: Dict[str, Any]
    etag: Optional[str]
    not_modified: bool


class CredenShare:
    """The API client.

    Four surfaces, matching the API's own: ``crs.shares``, ``crs.requests``, ``crs.stats``
    and ``crs.capabilities``. Anything not modelled yet is reachable through :meth:`call`.

    ``credential`` accepts the two- or three-part form. If you pass the three-part one, the
    custody secret stays on this machine — it is used to derive a keypair locally and is
    never transmitted.
    """

    def __init__(
        self,
        credential: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        link_origin: str = DEFAULT_LINK_ORIGIN,
        timeout: float = 30.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.credential = Credential.parse(credential)
        self._max_retries = max(0, max_retries)
        self._base_url = base_url.rstrip("/")
        self._link_origin = link_origin.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {self.credential.bearer}",
                "Content-Type": "application/json",
                "User-Agent": _user_agent(),
            },
        )
        self.shares = _Shares(self)
        self.requests = _Requests(self)
        self.stats = _Stats(self)
        self.capabilities = _Capabilities(self)

    # ── context manager ──────────────────────────────────────────────────────────────

    def __enter__(self) -> "CredenShare":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ── links ────────────────────────────────────────────────────────────────────────

    def link_for(self, short_code: str, content_key: bytes) -> str:
        """Assemble a recipient link.

        The key lives in the fragment, which browsers never send to a server. That is what
        makes the link readable by its holder and opaque to us.
        """
        return f"{self._link_origin}/{short_code}#{crypto.encode_fragment(content_key)}"

    def collect_link_for(self, short_code: str) -> str:
        """The keyless collect link for a secure request — the one you hand to a human.

        Deliberately without a fragment. Holding this link lets somebody SUBMIT and never
        read, which is what makes it safe to paste into a ticket or a chat.
        :meth:`access_link_for` is the other half.

        ``/r/<short_code>`` is not derivable from anything the API returns, which is why this
        is a method rather than a note in the README telling you to assemble it yourself.
        """
        return f"{self._link_origin}/r/{short_code}"

    def access_link_for(self, short_code: str, seed: bytes) -> str:
        """Your own access link for a secure request: the seed in the fragment.

        Treat the result as the secret itself — it is the ability to read every submission,
        on any device, with nothing stored. CredenShare cannot rebuild it, because the seed
        was never ours. Useful for turning a seed you stored at create time back into a link;
        :attr:`SecureRequest.access_link` is the same string at create time.

        The fragment is ``"1" + base64url(seed)`` — the version prefix matters, and getting
        it wrong is the reason this is not left to hand-assembly.
        """
        return f"{self.collect_link_for(short_code)}#{crypto.encode_fragment(seed)}"

    def read_link(self, link: str, passcode: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch and decrypt a share from a full link.

        Not implemented against ``/v1``: the recipient path is deliberately absent from the
        API, because bearer auth skips the proof-of-work and captcha gates that protect it,
        and exposing it to a credential would be an enumeration bypass. Open the link in a
        browser, or decrypt a blob you already hold with
        :func:`credenshare.decrypt_content`.
        """
        raise NotImplementedError(
            "the recipient read path is not exposed over the API by design; open the link in "
            "a browser, or use decrypt_content() on a blob you already have"
        )

    # ── transport ────────────────────────────────────────────────────────────────────

    def call(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Call an endpoint this SDK does not model yet, over the transport it uses itself.

        ``path`` is relative to the API version, so ``"/shares"`` rather than a full URL.
        Returns the parsed JSON body, and raises the same error types the modelled methods
        do — an escape hatch that dropped the error mapping would be a reason to reach past
        this client entirely, which is worse.

        An ``Idempotency-Key`` is added on a POST, PUT or PATCH when you have not supplied
        one — the methods that can create, which are the ones the API consults it on. Never
        on a GET or a DELETE, where it is inert. Yours is never overwritten and is forwarded
        on any method, DELETE included: a retry repeats the byte-identical request, and
        replacing a caller's key would break exactly the protection the header exists for.

        Named ``call`` rather than ``request`` because ``crs.requests`` is the secure-request
        surface, and ``crs.request`` beside ``crs.requests`` is a typo that resolves.
        """
        return self._request(method, path, json=json, params=params, headers=headers)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return self._exchange(method, path, json=json, params=params, headers=headers).data

    def _exchange(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        accept_not_modified: bool = False,
    ) -> _Reply:
        """``_request`` with the envelope kept. With ``accept_not_modified``, a 304 is an
        answer rather than an error: the caller sent If-None-Match, and "unchanged" is what it
        asked. Everywhere else a 304 still raises, where an empty result would read as real."""
        # Belt and braces. `bearer` is assembled from parts so a custody secret cannot reach
        # the header, but this asserts the property at the boundary rather than trusting a
        # constructor three files away.
        if self.credential.custody_secret and self.credential.custody_secret in (
            self._client.headers.get("Authorization") or ""
        ):
            raise CustodySecretTransmittedError(
                "the custody secret was about to be transmitted; rotate this credential"
            )

        # POST, PUT and PATCH — the methods that can create — and nothing else. A caller
        # reaching `call()` for an endpoint this SDK does not model should not have to know
        # the API wants the header on a create; they should equally not find one appearing on
        # a DELETE, where the backend does not read it and where 0.1.4 already published the
        # request bytes without it.
        #
        # Filled in only when absent, matched case-insensitively because HTTP header names
        # are — checking `"Idempotency-Key" in headers` would miss a caller's lowercase
        # spelling and send two, and the API would then see a key the caller cannot reproduce
        # on retry. A caller's own key is forwarded on EVERY method, this one included: `sent`
        # starts as their headers, so a DELETE they chose to key keeps it verbatim.
        #
        # Generated ONCE, before the retry loop, so every attempt carries the same value.
        # A fresh key per attempt is how a network blip turns into a second copy of a
        # secret, which is the whole failure the header prevents.
        sent = dict(headers or {})
        if method.upper() in _IDEMPOTENT_METHODS and not any(
            name.lower() == _IDEMPOTENCY_HEADER.lower() for name in sent
        ):
            sent[_IDEMPOTENCY_HEADER] = str(uuid.uuid4())

        # Retry only the failures that prove nothing was received. A 5xx might have
        # committed and this client cannot tell, so it is surfaced rather than repeated. A
        # POST is safe to repeat here because the body and the Idempotency-Key are both
        # byte-identical on the second attempt — which is what the header is for. A DELETE is
        # safe to repeat without one: the second call finds nothing to remove.
        attempt = 0
        delivered = False
        while True:
            try:
                response = self._client.request(
                    method, path, json=json, params=params, headers=sent
                )
                break
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                # A read timeout is not a connect failure. The request was written to an
                # established connection, so the server may have committed it; saying
                # "nothing was created" here is what makes a caller retry with a new key
                # and end up with two copies of one secret.
                delivered = delivered or isinstance(exc, httpx.ReadTimeout)
                if attempt >= self._max_retries:
                    if delivered:
                        raise DeliveryUnknownError(
                            f"the request was delivered but no response was read after "
                            f"{attempt + 1} attempt(s): {exc}",
                            attempts=attempt + 1,
                        ) from exc
                    raise ServiceUnavailableError(
                        f"could not reach the API after {attempt + 1} attempt(s): {exc}"
                    ) from exc
                # Plain exponential backoff, no jitter: the retry count is 2 by default, so
                # a thundering herd is not the failure mode worth complicating this for.
                time.sleep(0.5 * (2**attempt))
                attempt += 1

        etag = response.headers.get("etag")
        if accept_not_modified and response.status_code == 304:
            return _Reply({}, etag, True)
        if response.is_success:
            if not response.content:
                return _Reply({}, etag, False)
            try:
                parsed: Dict[str, Any] = response.json()
            except ValueError:
                return _Reply({}, etag, False)
            return _Reply(parsed, etag, False)
        raise _error_for(response)


def _error_for(response: httpx.Response) -> ApiError:
    """Map a failed response onto an error whose type implies the remedy."""
    message = f"HTTP {response.status_code}"
    code: Optional[int] = None
    try:
        parsed = response.json()
        # A JSON body that is not an object (a bare string, a list) is still a failed
        # response. Reading .get off it would raise AttributeError from inside the error
        # path, replacing the API's error with a bug in this client.
        payload = parsed if isinstance(parsed, dict) else {}
        message = payload.get("message") or (
            parsed[:200] if isinstance(parsed, str) and parsed else message
        )
        code = payload.get("error_code")
    except ValueError:
        if response.text:
            message = response.text[:200]

    request_id = response.headers.get("x-request-id") or response.headers.get("x-amzn-requestid")
    kwargs = {"status": response.status_code, "code": code, "request_id": request_id}

    if response.status_code == 401:
        return AuthenticationError(message, **kwargs)
    if response.status_code == 403:
        # A spent allowance is a 403 like a missing scope, but the remedies are opposite:
        # one needs a plan change, the other a different key. The numeric code is what
        # separates them.
        if code == _QUOTA_EXCEEDED_CODE:
            return QuotaExceededError(message, **kwargs)
        return PermissionError_(message, **kwargs)
    if response.status_code == 404:
        return NotFoundError(message, **kwargs)
    if response.status_code == 409 and code in (
        _IDEMPOTENCY_CONFLICT_CODE,
        _IDEMPOTENCY_IN_FLIGHT_CODE,
    ):
        # Both arrive as IdempotencyConflictError so `except` keeps working; err.code
        # separates them, and the docstring says which is which. 106 previously fell through
        # to a bare ApiError, so the documented discrimination could not be performed at all.
        return IdempotencyConflictError(message, **kwargs)
    if response.status_code == 429:
        retry_after = response.headers.get("retry-after")
        return RateLimitError(
            message,
            retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None,
            **kwargs,
        )
    if response.status_code == 503:
        return ServiceUnavailableError(message, **kwargs)
    return ApiError(message, **kwargs)


def _user_agent() -> str:
    from . import __version__

    return f"credenshare-python/{__version__}"
