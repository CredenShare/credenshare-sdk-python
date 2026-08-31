"""The CredenShare API client.

Everything sensitive happens before a request is built. By the time anything reaches the
network it is ciphertext plus metadata, and the content key exists only in the link this
client hands back to you.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence
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
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
    ServiceUnavailableError,
)

__all__ = ["CredenShare", "Credential", "Share", "ShareList", "ShareSummary"]

DEFAULT_BASE_URL = "https://api.credenshare.io/v1"
DEFAULT_LINK_ORIGIN = "https://crs.sh"

#: The most pages :meth:`_Shares.iter_all` will walk before giving up.
#:
#: The end of a result set is not always knowable: a server that omits every paging figure and
#: returns full pages forever cannot be told from a very large account. An unbounded walk
#: against one never returns. At the default page size of 100 this is ten million shares.
MAX_PAGES = 100_000

#: The only accepted encryption type. Plaintext creates are refused by the server, and this
#: client has no way to express one.
ENCRYPTION_TYPE = "e2ee-aes256-gcm"

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
#: which is the entire reason the header is mandatory.
DEFAULT_MAX_RETRIES = 2


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


class ShareList(List[ShareSummary]):
    """A page of shares, with the paging figures attached.

    A plain list would leave a caller guessing whether more exists, and a caller who has to
    guess guesses wrong — usually by stopping at the first short page.
    """

    def __init__(
        self,
        rows: Sequence[ShareSummary],
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
        reporting "no more" on a full page is what makes :meth:`iter_all` stop after page one
        and return a fraction of the account as though it were all of it. Node, Go and Rust
        all fall back; Python was the only one that did not.
        """
        if self.total_pages is not None:
            return self.page < self.total_pages
        if self.total is not None:
            return self.page * self.limit < self.total
        # Nothing to go on but the page itself: a full page probably has a successor.
        return len(self) >= self.limit > 0


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
        """
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

        # Required by the API, not optional. A retried automation must not create a second
        # copy of a credential in the world, with its own link and audit trail, that the
        # caller does not know exists.
        headers = {"Idempotency-Key": idempotency_key or str(uuid.uuid4())}

        data = self._client._request("POST", "/shares", json=body, headers=headers)
        short_code = data["short_code"]
        return Share(
            short_code=short_code,
            link=self._client.link_for(short_code, content_key),
            content_key=content_key,
            expired_at=data.get("expired_at"),
            custody=data.get("custody"),
        )

    def list(self, *, limit: int = 25, page: int = 1) -> ShareList:
        """One page of the account's shares, newest first. Metadata only.

        The returned list carries ``page``, ``limit``, ``total``, ``total_pages`` and
        ``has_more``. Use :meth:`iter_all` to walk every page.
        """
        data = self._client._request("GET", "/shares", params={"limit": limit, "page": page})
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

    def iter_all(self, *, limit: int = 100) -> Iterator[ShareSummary]:
        """Every share, page by page.

        Written here because the hand-rolled version is usually wrong in the same way: it
        stops on the first page shorter than ``limit``, which is a page the server is
        entitled to return in the middle of a result set.
        """
        page = 1
        while True:
            batch = self.list(limit=limit, page=page)
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


class CredenShare:
    """The API client.

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

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        # Belt and braces. `bearer` is assembled from parts so a custody secret cannot reach
        # the header, but this asserts the property at the boundary rather than trusting a
        # constructor three files away.
        if self.credential.custody_secret and self.credential.custody_secret in (
            self._client.headers.get("Authorization") or ""
        ):
            raise CustodySecretTransmittedError(
                "the custody secret was about to be transmitted; rotate this credential"
            )

        # Retry only the failures that prove nothing was received. A 5xx might have
        # committed and this client cannot tell, so it is surfaced rather than repeated. A
        # POST is safe to repeat here because the body and the Idempotency-Key are both
        # byte-identical on the second attempt — which is what the header is for.
        attempt = 0
        delivered = False
        while True:
            try:
                response = self._client.request(
                    method, path, json=json, params=params, headers=headers
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

        if response.is_success:
            if not response.content:
                return {}
            try:
                parsed: Dict[str, Any] = response.json()
            except ValueError:
                return {}
            return parsed
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
