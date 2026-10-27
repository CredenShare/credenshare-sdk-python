"""Links on a team's custom domain (Gitea #412).

The origin comes from configuration, else from /v1/capabilities once per client, else the
default.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import httpx
import pytest

from credenshare import CredenShare
from credenshare.client import DEFAULT_LINK_ORIGIN

CREDENTIAL = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue"
FIELD = {"key": "k", "value": "v", "type": "text"}
Reply = Tuple[int, Any]


def created(code: str) -> Reply:
    return (201, {"short_code": code})


def capabilities(link_origin: Any) -> Reply:
    return (200, {"api_version": "1", "key": {"key_id": "abc123"}, "link_origin": link_origin})


class Queue:
    """A transport that records requests and replays a queue (the last reply repeats)."""

    def __init__(self, *replies: Reply) -> None:
        self.requests: List[httpx.Request] = []
        self._replies = list(replies)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self._replies[0] if len(self._replies) == 1 else self._replies.pop(0)
        return httpx.Response(status, json=body)

    @property
    def capability_calls(self) -> int:
        return sum(r.url.path.endswith("/capabilities") for r in self.requests)

    def client(self, **kwargs: Any) -> CredenShare:
        return CredenShare(
            CREDENTIAL, transport=httpx.MockTransport(self.handler), max_retries=0, **kwargs
        )


def test_a_team_keys_links_are_on_its_custom_domain_asked_once() -> None:
    rec = Queue(
        created("abc123"), capabilities("https://cd-test.credenshare.io"), created("def456")
    )
    with rec.client() as crs:
        first = crs.shares.create(title="t", fields=[FIELD])
        second = crs.shares.create(title="t", fields=[FIELD])
        for share in (first, second):
            assert share.link.startswith(f"https://cd-test.credenshare.io/{share.short_code}#1")
        assert rec.capability_calls == 1
        # The link helpers agree with what the creates returned.
        assert crs.link_for(first.short_code, first.content_key) == first.link
        assert crs.link_origin() == "https://cd-test.credenshare.io"
    assert rec.capability_calls == 1


def test_a_configured_origin_wins_and_nothing_is_asked() -> None:
    rec = Queue(created("abc123"))
    with rec.client(link_origin="https://links.example.com/") as crs:
        share = crs.shares.create(title="t", fields=[FIELD])
    assert share.link.startswith("https://links.example.com/abc123#")
    assert len(rec.requests) == 1 and rec.capability_calls == 0


@pytest.mark.parametrize(
    "answer",
    [
        capabilities(None),
        (200, {"api_version": "1"}),
        (403, {"message": "no", "error_code": 78}),
        (500, {"message": "boom"}),
        capabilities("https://cd.example.com/evil"),
        capabilities("http://cd.example.com"),
        capabilities("https://user@cd.example.com"),
        capabilities("https://cd.example.com?x=1"),
        capabilities(42),
    ],
    ids=[
        "null",
        "absent",
        "refusal",
        "server-error",
        "a-path",
        "plain-http",
        "credentials",
        "a-query",
        "not-a-string",
    ],
)
def test_no_team_origin_or_a_failed_answer_gives_the_default(answer: Reply) -> None:
    rec = Queue(created("abc123"), answer, created("def456"))
    with rec.client() as crs:
        for _ in range(2):
            share = crs.shares.create(title="t", fields=[FIELD])
            assert share.link.startswith(f"{DEFAULT_LINK_ORIGIN}/"), share.link
    # The answer is kept, a "none" or a failure included: one question per client.
    assert rec.capability_calls == 1


def test_a_secure_requests_links_are_on_the_team_domain_too() -> None:
    rec = Queue((201, {"short_code": "rq01"}), capabilities("https://cd-test.credenshare.io"))
    with rec.client() as crs:
        req = crs.requests.create(title="t", fields=[{"item": "Password", "type": "password"}])
    assert req.collect_link == "https://cd-test.credenshare.io/r/rq01"
    assert req.access_link.startswith("https://cd-test.credenshare.io/r/rq01#1")


def test_the_capabilities_type_carries_the_origin() -> None:
    results: Dict[str, Any] = {}
    for name, origin in (("team", "https://cd-test.credenshare.io"), ("personal", None)):
        with Queue(capabilities(origin)).client() as crs:
            results[name] = crs.capabilities.get().link_origin
    assert results == {"team": "https://cd-test.credenshare.io", "personal": None}
