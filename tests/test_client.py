"""Client behaviour, against a stub transport.

The properties worth testing here are not "does it call the right URL" but the ones where
being wrong is silent or dangerous: the custody secret never leaving the machine, the content
key never appearing in a request, and error types that imply the right remedy.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import httpx
import pytest

from credenshare import crypto
from credenshare.client import CredenShare, Credential
from credenshare.errors import (
    ApiError,
    AuthenticationError,
    CredentialFormatError,
    IdempotencyConflictError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
    ServiceUnavailableError,
)

CREDENTIAL = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue"
TWO_PART = "crs_sk_live_abc123.authsecretvalue"


class Recorder:
    """A transport that records requests and replays canned responses."""

    def __init__(
        self,
        status: int = 201,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.requests: List[httpx.Request] = []
        self._status = status
        self._body = body if body is not None else {"short_code": "abc123"}
        self._headers = headers or {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status, json=self._body, headers=self._headers)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def make_client(rec: Recorder, credential: str = CREDENTIAL) -> CredenShare:
    return CredenShare(credential, transport=rec.transport, link_origin="https://crs.sh")


# ── credential handling ──────────────────────────────────────────────────────────────


def test_credential_parses_both_forms() -> None:
    three = Credential.parse(CREDENTIAL)
    assert three.key_id == "abc123"
    assert three.has_custody

    two = Credential.parse(TWO_PART)
    assert two.key_id == "abc123"
    assert not two.has_custody


@pytest.mark.parametrize(
    "bad",
    ["", "nope", "crs_sk_live_only-one-part", "crs_sk_live_a.b.c.d", "crs_sk_live_a..c"],
)
def test_malformed_credentials_are_refused(bad: str) -> None:
    with pytest.raises(CredentialFormatError):
        Credential.parse(bad)


def test_the_custody_secret_is_never_transmitted() -> None:
    """THE property of the split credential.

    The custody half exists so the server CANNOT reconstruct the private key. If it reaches
    the wire that guarantee is gone and the credential has to be rotated.
    """
    rec = Recorder()
    with make_client(rec) as crs:
        crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "password"}])

    request = rec.requests[0]
    raw = bytes(request.read()).decode()
    everything = raw + json.dumps(dict(request.headers)) + str(request.url)
    assert "custodysecretvalue" not in everything
    assert request.headers["authorization"] == f"Bearer {TWO_PART}"


def test_a_credential_never_appears_in_its_repr() -> None:
    # A credential in a traceback or a log line is a credential that must be rotated.
    text = repr(Credential.parse(CREDENTIAL))
    assert "authsecretvalue" not in text
    assert "custodysecretvalue" not in text
    assert "abc123" in text


def test_custody_public_key_is_derived_locally() -> None:
    cred = Credential.parse(CREDENTIAL)
    expected = crypto.custody_keypair("custodysecretvalue").public_key_b64url
    assert cred.custody_public_key() == expected


def test_custody_public_key_needs_a_custody_secret() -> None:
    with pytest.raises(CredentialFormatError):
        Credential.parse(TWO_PART).custody_public_key()


# ── create ───────────────────────────────────────────────────────────────────────────


def test_create_sends_ciphertext_and_never_the_key() -> None:
    rec = Recorder(body={"short_code": "xy12", "expired_at": None})
    with make_client(rec) as crs:
        share = crs.shares.create(
            title="Staging deploy credentials",
            fields=[{"key": "Password", "value": "correct horse", "type": "password"}],
        )

    body = json.loads(rec.requests[0].read())
    assert body["encryption_type"] == "e2ee-aes256-gcm"

    # The plaintext must not be recoverable from anything sent.
    serialised = json.dumps(body)
    assert "correct horse" not in serialised
    assert base64.urlsafe_b64encode(share.content_key).decode().rstrip("=") not in serialised

    # But the blob must decrypt with the key the caller was handed.
    fields = crypto.decrypt_content(share.content_key, body["data"])
    assert fields == [{"key": "Password", "value": "correct horse", "type": "password"}]


def test_the_link_carries_the_key_in_its_fragment() -> None:
    rec = Recorder(body={"short_code": "xy12"})
    with make_client(rec) as crs:
        share = crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "text"}])

    assert share.link.startswith("https://crs.sh/xy12#")
    fragment = share.link.split("#", 1)[1]
    assert crypto.decode_fragment(fragment) == share.content_key


def test_the_share_repr_withholds_the_link() -> None:
    # The link IS the secret; printing a Share should not spill it into a log.
    rec = Recorder(body={"short_code": "xy12"})
    with make_client(rec) as crs:
        share = crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "text"}])
    assert share.content_key.hex() not in repr(share)
    assert "#" not in repr(share)


def test_create_always_sends_an_idempotency_key() -> None:
    """Required by the API. A retried automation must not silently create a second copy of a
    credential in the world, with its own link and audit trail."""
    rec = Recorder()
    with make_client(rec) as crs:
        crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "text"}])
    assert rec.requests[0].headers.get("idempotency-key")


def test_a_passcode_sends_a_verifier_and_never_the_passcode() -> None:
    rec = Recorder()
    with make_client(rec) as crs:
        crs.shares.create(
            title="t",
            fields=[{"key": "k", "value": "v", "type": "text"}],
            passcode="hunter2",
        )
    body = json.loads(rec.requests[0].read())
    assert body["passcode_verifier"] == crypto.passcode_verifier("hunter2")
    assert "hunter2" not in json.dumps(body)


def test_a_field_using_label_is_refused_before_any_request() -> None:
    """Stricter than the spec, deliberately.

    'Silently ignored' means the share encrypts, posts, decrypts and renders with every label
    blank and nothing erroring. An SDK is the right place to make that loud.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(ValueError, match="the member is 'key'"):
        crs.shares.create(
            title="t", fields=[{"label": "Password", "value": "v", "type": "password"}]
        )
    assert rec.requests == [], "nothing should have been sent"


# ── reads ────────────────────────────────────────────────────────────────────────────


def test_list_returns_metadata_only() -> None:
    rec = Recorder(status=200, body={"shares": [{"short_code": "a1", "title": "one"}]})
    with make_client(rec) as crs:
        rows = crs.shares.list(limit=10)
    assert rows[0].short_code == "a1"
    assert "limit=10" in str(rec.requests[0].url)


def test_expire_issues_a_delete() -> None:
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.shares.expire("a1")
    assert rec.requests[0].method == "DELETE"
    assert rec.requests[0].url.path.endswith("/shares/a1")


def test_the_recipient_read_path_is_refused_with_a_reason() -> None:
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(NotImplementedError, match="by design"):
        crs.read_link("https://crs.sh/abc#1AAA")


# ── errors imply remedies ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (401, {"message": "bad credential"}, AuthenticationError),
        (403, {"message": "no api access"}, PermissionError_),
        (403, {"message": "limit reached", "error_code": 61}, QuotaExceededError),
        (404, {"message": "not found"}, NotFoundError),
        (503, {"message": "unavailable"}, ServiceUnavailableError),
        (500, {"message": "boom"}, ApiError),
    ],
)
def test_error_mapping(status: int, body: Dict[str, Any], expected: type) -> None:
    rec = Recorder(status=status, body=body)
    with make_client(rec) as crs, pytest.raises(expected):
        crs.shares.list()


def test_a_spent_quota_is_not_a_rate_limit() -> None:
    """Both are 403/429-ish refusals, but waiting fixes one and not the other."""
    rec = Recorder(status=403, body={"message": "limit reached", "error_code": 61})
    with make_client(rec) as crs, pytest.raises(QuotaExceededError) as caught:
        crs.shares.list()
    assert not isinstance(caught.value, RateLimitError)


def test_rate_limit_exposes_retry_after() -> None:
    rec = Recorder(status=429, body={"message": "slow down"}, headers={"Retry-After": "42"})
    with make_client(rec) as crs, pytest.raises(RateLimitError) as caught:
        crs.shares.list()
    assert caught.value.retry_after == 42


# -- paging ---------------------------------------------------------------------------


class Sequenced:
    """A transport that replays a queued sequence of responses."""

    def __init__(self, responses):
        self.requests: List[httpx.Request] = []
        self._responses = list(responses)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self._responses.pop(0)
        return httpx.Response(status, json=body)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def page(rows, page_no, total_pages, total):
    return {
        "shares": [{"short_code": c, "expired_at": None} for c in rows],
        "pagination": {
            "page": page_no,
            "limit": 2,
            "total": total,
            "total_pages": total_pages,
        },
    }


def test_a_page_carries_its_paging_figures() -> None:
    """A caller who has to guess whether more exists guesses wrong."""
    rec = Sequenced([(200, page(["a1", "a2"], 1, 3, 5))])
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        rows = crs.shares.list(limit=2)

    assert [r.short_code for r in rows] == ["a1", "a2"]
    assert (rows.page, rows.total, rows.total_pages) == (1, 5, 3)
    assert rows.has_more


def test_iter_all_does_not_stop_on_a_short_middle_page() -> None:
    """The bug in every hand-rolled version of this loop.

    A server may return a page shorter than the limit in the MIDDLE of a result set. Stopping
    on the first short page silently truncates, and the caller sees a list that looks whole.
    """
    rec = Sequenced(
        [
            (200, page(["a1", "a2"], 1, 3, 5)),
            (200, page(["b1"], 2, 3, 5)),  # short, but not the last
            (200, page(["c1", "c2"], 3, 3, 5)),
        ]
    )
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        codes = [r.short_code for r in crs.shares.iter_all(limit=2)]

    assert codes == ["a1", "a2", "b1", "c1", "c2"]
    assert len(rec.requests) == 3


def test_a_summary_has_no_title_because_the_api_returns_none() -> None:
    # An attribute that is always None reads as a broken field rather than an absent one.
    rec = Recorder(status=200, body={"shares": [{"short_code": "a1"}]})
    with make_client(rec) as crs:
        rows = crs.shares.list()
    assert not hasattr(rows[0], "title")


# -- idempotency ----------------------------------------------------------------------


def test_a_replayed_key_with_different_ciphertext_is_named_for_what_it_is() -> None:
    """The failure a caller actually hits.

    Passing the same idempotency_key to two creates cannot work: each create draws a fresh
    content key, so the bodies differ and the API refuses. The error has to say that, because
    "409 conflict" sends people looking for a duplicate share that does not exist.
    """
    rec = Recorder(status=409, body={"message": "already used", "error_code": 105})
    with make_client(rec) as crs, pytest.raises(IdempotencyConflictError):
        crs.shares.create(
            title="t",
            fields=[{"key": "k", "value": "v", "type": "text"}],
            idempotency_key="fixed",
        )


def test_a_supplied_content_key_fixes_the_link_but_not_the_body() -> None:
    """The distinction a live run had to teach.

    A fixed content key gives both calls the same link and the same access token — but the
    ciphertext still differs, because the salt and IV are fresh every time and must be. So a
    caller-supplied idempotency key is still not replayable, and no argument makes it one.
    """
    rec = Recorder()
    key = bytes(range(32))
    with make_client(rec) as crs:
        crs.shares.create(
            title="t",
            fields=[{"key": "k", "value": "v", "type": "text"}],
            idempotency_key="fixed",
            content_key=key,
        )
        crs.shares.create(
            title="t",
            fields=[{"key": "k", "value": "v", "type": "text"}],
            idempotency_key="fixed",
            content_key=key,
        )

    first, second = (json.loads(r.read()) for r in rec.requests)
    assert first["access_token"] == second["access_token"]
    assert first["data"] != second["data"], "a repeated IV would be the real bug here"
    for body in (first, second):
        assert crypto.decrypt_content(key, body["data"]) == [
            {"key": "k", "value": "v", "type": "text"}
        ]


# -- transport retries ----------------------------------------------------------------


def test_a_dropped_connection_is_retried_with_the_same_idempotency_key() -> None:
    """The case the mandatory header exists for.

    The retry must repeat the byte-identical request, or the server sees a new body under a
    used key and refuses — turning a recoverable blip into a hard failure.
    """
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(201, json={"short_code": "xy12"})

    # A configured origin, so the one /v1/capabilities question an unconfigured client asks
    # after its first create (Gitea #412) does not join the attempts counted here.
    with CredenShare(
        CREDENTIAL,
        transport=httpx.MockTransport(handler),
        max_retries=2,
        link_origin="https://crs.sh",
    ) as crs:
        share = crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "text"}])

    assert share.short_code == "xy12"
    assert len(seen) == 2
    assert seen[0].headers["idempotency-key"] == seen[1].headers["idempotency-key"]
    assert seen[0].read() == seen[1].read()


def test_an_http_500_is_not_retried() -> None:
    """It may have committed, and this client cannot tell.

    Retrying it would risk a second copy of a credential in the world under a caller who
    believes one was created.
    """
    rec = Recorder(status=500, body={"message": "boom"})
    with make_client(rec) as crs, pytest.raises(ApiError):
        crs.shares.create(title="t", fields=[{"key": "k", "value": "v", "type": "text"}])
    assert len(rec.requests) == 1


def test_retries_are_bounded_and_surface_as_unavailable() -> None:
    attempts: List[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("down", request=request)

    with (
        CredenShare(CREDENTIAL, transport=httpx.MockTransport(handler), max_retries=1) as crs,
        pytest.raises(ServiceUnavailableError),
    ):
        crs.shares.list()

    assert len(attempts) == 2


# -- the generic escape hatch ---------------------------------------------------------


def test_the_escape_hatch_generates_an_idempotency_key_on_a_non_get() -> None:
    """The API requires the header on every non-GET, and refuses the call without it.

    A caller reaching `call()` for an endpoint this SDK does not model yet should not have to
    know that, and should not get a 400 for leaving out a header whose only job is to protect
    a retry this client performs on their behalf.
    """
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.call("POST", "/some/future/endpoint", json={"a": 1})

    assert rec.requests[0].headers.get("idempotency-key")


def test_the_escape_hatch_never_overwrites_a_supplied_key() -> None:
    """Overwriting it would break the one thing the header is for.

    A caller who can reproduce their own key on retry has done exactly the right thing;
    replacing it means the API sees a value they cannot repeat.
    """
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.call("POST", "/some/future/endpoint", headers={"Idempotency-Key": "deploy-42"})

    assert rec.requests[0].headers.get_list("idempotency-key") == ["deploy-42"]


def test_a_lowercase_spelling_still_counts_as_supplied() -> None:
    """HTTP header names are case-insensitive, and a membership test on a dict is not.

    Checking `"Idempotency-Key" in headers` would miss this and send two - after which the
    API sees a key the caller cannot reproduce, which is the failure the header exists to
    prevent.
    """
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.call("PUT", "/some/future/endpoint", headers={"idempotency-key": "deploy-42"})

    assert rec.requests[0].headers.get_list("idempotency-key") == ["deploy-42"]


def test_the_escape_hatch_adds_nothing_to_a_get() -> None:
    """A GET creates nothing, so a key would only pollute the API's 24-hour retention."""
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.call("GET", "/some/future/endpoint")

    assert "idempotency-key" not in rec.requests[0].headers


def test_one_generated_key_is_reused_across_retries() -> None:
    """Generated before the loop, not inside it.

    A fresh key per attempt is precisely how a dropped connection turns into two copies of
    one secret - the case the mandatory header exists to rule out.
    """
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(200, json={})

    with CredenShare(CREDENTIAL, transport=httpx.MockTransport(handler), max_retries=2) as crs:
        crs.call("POST", "/some/future/endpoint", json={"a": 1})

    assert len(seen) == 2
    assert seen[0].headers["idempotency-key"] == seen[1].headers["idempotency-key"]


def test_a_delete_carries_no_generated_key() -> None:
    """POST, PUT and PATCH only. A DELETE gets nothing.

    `DELETE /shares/{code}` shipped at 0.1.4 without this header, and the release notes say
    the shares surface did not change. The backend consults the header on creates, so on a
    delete it is inert - it would be a wire change to a published surface that buys nothing.
    The endpoint is already idempotent by construction: a repeat is a 404, and there is no
    second copy of anything for a key to prevent.
    """
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.shares.expire("a1")

    assert rec.requests[0].method == "DELETE"
    assert "idempotency-key" not in rec.requests[0].headers


def test_a_caller_who_keys_a_delete_still_has_it_forwarded() -> None:
    """Narrowing what is GENERATED does not filter what was SUPPLIED.

    A caller who has a reason to key a DELETE - their own dedupe ledger, a replayed job -
    passes one and it goes out verbatim. This client never strips a header it was handed.
    """
    rec = Recorder(status=200, body={})
    with make_client(rec) as crs:
        crs.call("DELETE", "/some/future/endpoint", headers={"Idempotency-Key": "sweep-7"})

    assert rec.requests[0].method == "DELETE"
    assert rec.requests[0].headers.get_list("idempotency-key") == ["sweep-7"]


def test_a_patch_and_a_put_do_get_a_generated_key() -> None:
    """The other two methods that can create. Narrowing to POST alone would drop them."""
    for method in ("POST", "PUT", "PATCH"):
        rec = Recorder(status=200, body={})
        with make_client(rec) as crs:
            crs.call(method, "/some/future/endpoint", json={"a": 1})
        assert rec.requests[0].headers.get("idempotency-key"), f"{method} carried no key"


def test_neither_a_head_nor_an_options_gets_a_generated_key() -> None:
    """Non-GET is not the test. Only POST, PUT and PATCH can create anything."""
    for method in ("DELETE", "HEAD", "OPTIONS"):
        rec = Recorder(status=200, body={})
        with make_client(rec) as crs:
            crs.call(method, "/some/future/endpoint")
        assert "idempotency-key" not in rec.requests[0].headers, f"{method} carried a key"


def test_the_escape_hatch_maps_errors_like_a_modelled_call() -> None:
    """An escape hatch that dropped the error mapping would be a reason to reach past this
    client entirely, which is worse than not having one."""
    rec = Recorder(status=403, body={"message": "limit reached", "error_code": 61})
    with make_client(rec) as crs, pytest.raises(QuotaExceededError):
        crs.call("POST", "/some/future/endpoint", json={"a": 1})
