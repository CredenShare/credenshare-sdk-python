"""The /v1 additions of Gitea #404.

The access log, capabilities, the expired lists and notify_on.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
import pytest

from credenshare import FIELD_TYPES, NOTIFY_ON_EVENTS, UNLIMITED, CredenShare
from credenshare.errors import ApiError, InvalidArgumentError, NotFoundError, PermissionError_

CREDENTIAL = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue"
FIELD = {"key": "k", "value": "v", "type": "text"}

Reply = Tuple[int, Any, Dict[str, str]]


class Replay:
    """A transport that records requests and replays a queue (the last reply repeats)."""

    def __init__(self, *replies: Reply) -> None:
        self.requests: List[httpx.Request] = []
        self._replies = list(replies)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body, headers = (
            self._replies[0] if len(self._replies) == 1 else self._replies.pop(0)
        )
        if body is None:
            return httpx.Response(status, headers=headers)
        return httpx.Response(status, json=body, headers=headers)

    def client(self) -> CredenShare:
        return CredenShare(
            CREDENTIAL, transport=httpx.MockTransport(self.handler), link_origin="https://crs.sh"
        )


def access_log_body(next_cursor: Optional[str]) -> Dict[str, Any]:
    return {
        "short_code": "AbC123",
        "entries": [
            {
                "accessed_at": "2026-10-25T18:00:00Z",
                "accessed_ip": "203.0.113.7",
                "platform": "macOS",
                "user_agent": "Mozilla/5.0",
                "failed_passcode": False,
                "signed_in": True,
            },
            {
                "accessed_at": "2026-10-25T17:00:00Z",
                "accessed_ip": "198.51.100.2",
                "platform": "Linux",
                "user_agent": None,
                "failed_passcode": True,
                "signed_in": False,
            },
        ],
        "next_cursor": next_cursor,
        "retention_days": 90,
        "effective_from": "2026-07-27T18:00:00Z",
        "effective_to": "2026-10-25T18:00:00Z",
    }


# ── the access log ───────────────────────────────────────────────────────────────────


def test_the_access_log_reads_a_page_its_window_and_its_etag() -> None:
    rec = Replay((200, access_log_body("c1"), {"ETag": 'W/"abc"'}))
    est = timezone(timedelta(hours=-5))
    with rec.client() as crs:
        page = crs.shares.access_log(
            "AbC123",
            limit=10,
            cursor="prev",
            from_=datetime(2026, 10, 1, tzinfo=timezone.utc),
            to=datetime(2026, 10, 31, 23, 59, 59, tzinfo=est),
        )
    assert page.short_code == "AbC123"
    first, second = page.entries
    assert (first.accessed_ip, first.user_agent, first.signed_in, first.failed_passcode) == (
        "203.0.113.7",
        "Mozilla/5.0",
        True,
        False,
    )
    # A null user agent stays None rather than becoming a string a caller would match on.
    assert second.user_agent is None and second.failed_passcode and not second.signed_in
    assert page.next_cursor == "c1" and page.has_more
    assert page.retention_days == 90
    assert (page.effective_from, page.effective_to) == (
        "2026-07-27T18:00:00Z",
        "2026-10-25T18:00:00Z",
    )
    assert page.etag == 'W/"abc"' and not page.not_modified

    sent = rec.requests[0]
    assert sent.url.path == "/v1/shares/AbC123/access-log"
    # Times go out in UTC, RFC 3339, whatever zone the datetime carried.
    assert dict(sent.url.params) == {
        "limit": "10",
        "cursor": "prev",
        "from": "2026-10-01T00:00:00Z",
        "to": "2026-11-01T04:59:59Z",
    }
    assert "if-none-match" not in sent.headers and "idempotency-key" not in sent.headers


def test_an_unbounded_read_sends_no_query_and_ends_on_a_null_cursor() -> None:
    rec = Replay((200, access_log_body(None), {}))
    with rec.client() as crs:
        page = crs.shares.access_log("a/b")
    assert page.next_cursor is None and not page.has_more
    assert rec.requests[0].url.raw_path == b"/v1/shares/a%2Fb/access-log"


def test_an_unchanged_page_is_not_modified_rather_than_an_error() -> None:
    rec = Replay((304, None, {"ETag": 'W/"abc"'}))
    with rec.client() as crs:
        page = crs.shares.access_log("AbC123", if_none_match='W/"abc"')
    assert page.not_modified and page.etag == 'W/"abc"'
    assert page.entries == () and page.short_code == "AbC123"
    assert rec.requests[0].headers["if-none-match"] == 'W/"abc"'


@pytest.mark.parametrize(
    "status, error", [(403, PermissionError_), (404, NotFoundError), (400, ApiError)]
)
def test_refusals_map_to_their_errors(status: int, error: type) -> None:
    rec = Replay((status, {"message": "no", "error_code": 1}, {}))
    with rec.client() as crs, pytest.raises(error):
        crs.shares.access_log("AbC123")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 101},
        {"limit": 0},
        {"limit": True},
        {"from_": "2026-10-02T00:00:00Z", "to": "2026-10-01T00:00:00Z"},
        {"from_": datetime(2026, 10, 1)},  # naive: which zone did it mean?
    ],
)
def test_options_are_checked_before_any_request(kwargs: Dict[str, Any]) -> None:
    rec = Replay((200, access_log_body(None), {}))
    with rec.client() as crs, pytest.raises(InvalidArgumentError):
        crs.shares.access_log("AbC123", **kwargs)
    assert rec.requests == []


def test_the_walk_follows_every_cursor_and_never_revalidates() -> None:
    rec = Replay(
        (200, access_log_body("c1"), {}),
        (200, access_log_body("c2"), {}),
        (200, access_log_body(None), {}),
    )
    with rec.client() as crs:
        seen = list(crs.shares.iter_access_log("AbC123", limit=2))
    assert len(seen) == 6 and len(rec.requests) == 3
    assert [r.url.params.get("cursor") for r in rec.requests] == [None, "c1", "c2"]
    for sent in rec.requests:
        assert "if-none-match" not in sent.headers
        assert sent.url.params["limit"] == "2"


def test_the_walk_refuses_a_cursor_that_does_not_move() -> None:
    rec = Replay((200, access_log_body("same"), {}))
    with rec.client() as crs, pytest.raises(ApiError):
        list(crs.shares.iter_access_log("AbC123"))
    assert len(rec.requests) == 2


# ── the expired lists ────────────────────────────────────────────────────────────────

PAGE = {
    "shares": [{"short_code": "old1", "expired_at": "2026-10-20T00:00:00Z"}],
    "requests": [{"short_code": "req1", "expired_at": "2026-10-20T00:00:00Z"}],
    "pagination": {"page": 1, "limit": 25, "total": 1, "total_pages": 1},
}


def test_the_old_calls_send_what_they_always_have() -> None:
    rec = Replay((200, PAGE, {}))
    with rec.client() as crs:
        crs.shares.list()
        crs.requests.list()
    assert all("status" not in r.url.params for r in rec.requests)


def test_the_expired_half_is_asked_for_in_lists_and_walks() -> None:
    rec = Replay((200, PAGE, {}))
    with rec.client() as crs:
        assert crs.shares.list(status="expired")[0].short_code == "old1"
        crs.requests.list(status="expired")
        list(crs.shares.iter_all(status="expired"))
        list(crs.requests.iter_all(status="active"))
    assert [r.url.params["status"] for r in rec.requests] == [
        "expired",
        "expired",
        "expired",
        "active",
    ]


def test_an_unknown_status_is_refused_before_any_request() -> None:
    rec = Replay((200, PAGE, {}))
    with rec.client() as crs:
        for call in (
            lambda: crs.shares.list(status="archived"),
            lambda: crs.requests.list(status="Expired"),
            lambda: crs.shares.iter_all(status=""),
        ):
            with pytest.raises(InvalidArgumentError):
                call()
    assert rec.requests == []


# ── capabilities ─────────────────────────────────────────────────────────────────────


def capabilities_body(org: Optional[str], policy: Any) -> Dict[str, Any]:
    return {
        "api_version": "1",
        "key": {
            "key_id": "abc123",
            "scopes": ["shares:write", "audit:read"],
            "custody_level": 1,
            "organization_id": org,
            "rate_limit_rpm": 100,
        },
        "plan": {"code": "business", "name": "Business"},
        "limits": {
            "max_shares": -1,
            "remaining_shares": -1,
            "max_fields": 20,
            "max_days_access_logs": 90,
            "max_api_keys": 10,
            "max_webhooks": 5,
        },
        "features": {"secure_requests": True, "zero_knowledge": False},
        "sharing_policy": policy,
        "field_types": list(FIELD_TYPES),
        "notify_on_events": ["viewed", "denied", "expired", "deleted"],
    }


def test_capabilities_for_a_personal_key() -> None:
    rec = Replay((200, capabilities_body(None, None), {"ETag": 'W/"cap"'}))
    with rec.client() as crs:
        caps = crs.capabilities.get()
    assert caps.api_version == "1"
    assert caps.key.key_id == "abc123" and caps.key.scopes == ("shares:write", "audit:read")
    assert caps.key.custody_level == 1 and caps.key.organization_id is None
    assert caps.key.rate_limit_rpm == 100
    assert (caps.plan.code, caps.plan.name) == ("business", "Business")
    assert caps.limits.max_shares == UNLIMITED and caps.limits.max_days_access_logs == 90
    assert caps.features == {"secure_requests": True, "zero_knowledge": False}
    assert caps.sharing_policy is None
    # The API publishes the lists this SDK carries; they must agree.
    assert caps.field_types == tuple(FIELD_TYPES)
    assert caps.notify_on_events == NOTIFY_ON_EVENTS
    assert caps.etag == 'W/"cap"' and not caps.not_modified
    assert rec.requests[0].url.path == "/v1/capabilities"


def test_capabilities_for_a_team_key_carry_its_policy() -> None:
    rec = Replay((200, capabilities_body("org-1", {"require_passcode": True}), {}))
    with rec.client() as crs:
        caps = crs.capabilities.get()
    assert caps.key.organization_id == "org-1"
    assert caps.sharing_policy == {"require_passcode": True}


def test_unchanged_capabilities_are_not_modified() -> None:
    rec = Replay((304, None, {"ETag": 'W/"cap"'}))
    with rec.client() as crs:
        caps = crs.capabilities.get(if_none_match='W/"cap"')
    assert caps.not_modified and caps.etag == 'W/"cap"'
    assert rec.requests[0].headers["if-none-match"] == 'W/"cap"'


def test_a_304_still_fails_a_read_that_did_not_ask_for_one() -> None:
    """Only the conditional reads accept it; elsewhere an empty answer would read as real."""
    rec = Replay((304, None, {}))
    with rec.client() as crs:
        with pytest.raises(ApiError):
            crs.stats.get()
        with pytest.raises(ApiError):
            crs.call("GET", "/capabilities")


# ── notify_on ────────────────────────────────────────────────────────────────────────


def test_notify_on_is_sent_when_set_and_absent_otherwise() -> None:
    rec = Replay((201, {"short_code": "abc"}, {}))
    with rec.client() as crs:
        crs.shares.create(title="t", fields=[FIELD], notify_on=["viewed", "denied"])
        crs.shares.create(title="t", fields=[FIELD])
        crs.shares.create(title="t", fields=[FIELD], notify_on=[])
    bodies = [json.loads(r.read()) for r in rec.requests]
    assert bodies[0]["notify_on"] == ["viewed", "denied"]
    assert "notify_on" not in bodies[1] and "notify_on" not in bodies[2]


@pytest.mark.parametrize(
    "events",
    [
        ["opened"],
        ["viewed", "viewed"],
        ["Viewed"],
        ["viewed", "denied", "expired", "deleted", "viewed"],
        "viewed",
    ],
)
def test_notify_on_is_checked_as_the_api_checks_it(events: Any) -> None:
    rec = Replay((201, {"short_code": "abc"}, {}))
    with rec.client() as crs, pytest.raises(InvalidArgumentError):
        crs.shares.create(title="t", fields=[FIELD], notify_on=events)
    assert rec.requests == []
