"""Secure requests, submissions and stats, against a stub transport.

A request inverts a share: the SDK mints the keypair, publishes the public half, and keeps
the private seed. So the properties worth testing are the mirror image of the share ones —
the seed never reaching the wire, a submission that opens with the seed the caller was
handed, and the two encodings on this one feature not being fed to each other.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import inspect
import json
import pickle
import pprint
from typing import Any, Dict, List, Optional

import httpx
import pytest

from credenshare import crypto
from credenshare.client import CredenShare, _Seed
from credenshare.crypto import decrypt_submission
from credenshare.errors import (
    ApiError,
    InvalidFieldError,
    MalformedKeyError,
    NotFoundError,
    RequestSeedTransmittedError,
    WireFormatError,
)

CREDENTIAL = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue"

FIELDS = [{"item": "Staging database password", "type": "password"}]


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


def make_client(rec: Recorder) -> CredenShare:
    # A configured origin, so the one /v1/capabilities question an unconfigured client asks
    # after its first create (Gitea #412) does not join the requests these tests read back.
    return CredenShare(CREDENTIAL, transport=rec.transport, link_origin="https://crs.sh")


def everything_sent(request: httpx.Request) -> str:
    """The whole request as one string: body, headers and URL."""
    return bytes(request.read()).decode() + json.dumps(dict(request.headers)) + str(request.url)


# ── create ───────────────────────────────────────────────────────────────────────────


def test_create_returns_the_seed_and_sends_only_the_public_half() -> None:
    """THE property of a secure request.

    The seed is the entire ability to read submissions. It is generated here, returned to the
    caller, and must not appear anywhere in the request — in any encoding. If it reaches the
    server the feature is not end-to-end encrypted at all, and nothing about the response
    would look wrong.
    """
    rec = Recorder(body={"short_code": "rq01", "expired_at": None})
    with make_client(rec) as crs:
        req = crs.requests.create(title="Onboarding credentials", fields=FIELDS)

    assert len(req.seed) == 32

    sent = everything_sent(rec.requests[0])
    for spelling in (
        req.seed.hex(),
        base64.b64encode(req.seed).decode(),
        base64.b64encode(req.seed).decode().rstrip("="),
        base64.urlsafe_b64encode(req.seed).decode(),
        base64.urlsafe_b64encode(req.seed).decode().rstrip("="),
    ):
        assert spelling not in sent, "the seed reached the wire"

    body = json.loads(rec.requests[0].read())
    assert body["public_key"] == crypto.keypair_from_seed(req.seed).public_key_b64url


def test_the_public_key_is_an_unpadded_base64url_sec1_point() -> None:
    """87 characters, decoding to 65 bytes starting 0x04. The spec's own field check."""
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS)

    public_key = json.loads(rec.requests[0].read())["public_key"]
    assert len(public_key) == 87
    assert "=" not in public_key
    raw = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
    assert len(raw) == 65
    assert raw[0] == 0x04
    assert req.public_key == public_key


def test_the_request_repr_withholds_the_seed() -> None:
    # The seed IS the private key; printing a SecureRequest should not spill it into a log.
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS)
    assert req.seed.hex() not in repr(req)
    assert "rq01" in repr(req)


def test_a_supplied_seed_is_used_verbatim() -> None:
    """The custody-derived case.

    A runner that derives its keypair from its credential must be able to recreate the same
    keypair on any machine with nothing stored — otherwise it can collect submissions it
    cannot read.
    """
    seed = crypto.custody_keypair("custodysecretvalue").seed
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS, seed=seed)

    assert req.seed == seed
    assert req.public_key == crypto.custody_keypair("custodysecretvalue").public_key_b64url


def test_a_seed_of_the_wrong_length_is_refused_before_any_request() -> None:
    """A typed SDK error, not the bare ValueError a crypto primitive raises two frames down.

    The same pre-check, producing the same class of error, in all four SDKs.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(MalformedKeyError, match="32 bytes"):
        crs.requests.create(title="t", fields=FIELDS, seed=b"too short")
    assert rec.requests == [], "nothing should have been sent"


def test_create_always_sends_an_idempotency_key() -> None:
    """A duplicate collect link is not inert - a person can fill it in."""
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=FIELDS)
    assert rec.requests[0].headers.get("idempotency-key")


def test_a_supplied_idempotency_key_is_the_one_sent() -> None:
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=FIELDS, idempotency_key="deploy-42")
    assert rec.requests[0].headers["idempotency-key"] == "deploy-42"


def test_the_same_seed_and_key_produce_a_byte_identical_body() -> None:
    """Unlike a share, a request create IS reproducible.

    Nothing in the body is randomised once the seed is fixed — there is no salt and no IV,
    because the create carries no ciphertext. So a caller-supplied idempotency key genuinely
    deduplicates here, which is the opposite of the share case and worth knowing.
    """
    seed = bytes(range(32))
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=FIELDS, seed=seed, idempotency_key="fixed")
        crs.requests.create(title="t", fields=FIELDS, seed=seed, idempotency_key="fixed")

    first, second = (r.read() for r in rec.requests)
    assert first == second


def test_a_field_using_key_instead_of_item_is_refused_before_any_request() -> None:
    """The trap for anyone arriving from shares.create, where 'key' is exactly right.

    Here 'key' is ignored and the prompt renders with no text, while the create succeeds.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(InvalidFieldError, match="the member is 'item'"):
        crs.requests.create(
            title="t", fields=[{"key": "Staging database password", "type": "password"}]
        )
    assert rec.requests == [], "nothing should have been sent"


def test_a_request_with_no_fields_is_refused_before_any_request() -> None:
    """The API returns 201 and a working short code, and the link renders an error page.

    Nothing at the API level would ever have shown this, so the SDK is the place to make it
    loud.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(InvalidFieldError, match="at least one field"):
        crs.requests.create(title="t", fields=[])
    assert rec.requests == []


def test_a_blank_prompt_is_refused() -> None:
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(InvalidFieldError, match="empty 'item'"):
        crs.requests.create(title="t", fields=[{"item": "   "}])
    assert rec.requests == []


def test_unknown_field_members_are_forwarded_rather_than_rejected() -> None:
    """Forwarded so a member the API learns tomorrow works without an SDK release.

    NOT preserved, which the docstring used to claim: the API unmarshals a request field
    into `{item, type}` and discards the rest. A share's extras survive because they sit
    inside the ciphertext; a request's prompts are plaintext metadata and do not.
    """
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=[{"item": "Token", "hint": "from 1Password"}])
    assert json.loads(rec.requests[0].read())["fields"] == [
        {"item": "Token", "hint": "from 1Password"}
    ]


def test_a_request_passcode_is_transmitted_unlike_a_shares() -> None:
    """The asymmetry, and it is deliberate rather than a leak.

    A collect link's passcode gates a form the server renders for a stranger's browser, so
    the server has to evaluate it. A share's passcode is mixed into the content key and
    reaches us only as a one-way verifier. Anyone assuming the share behaviour here would be
    wrong, so this asserts what actually happens.
    """
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=FIELDS, passcode="hunter2")

    body = json.loads(rec.requests[0].read())
    assert body["passcode"] == "hunter2"
    assert "passcode_verifier" not in body


def test_the_optional_metadata_the_spec_allows_is_forwarded() -> None:
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(
            title="t",
            fields=FIELDS,
            description="fill this in before Friday",
            expired_at="2026-09-01T00:00:00Z",
            max_submission=3,
            access_counts_left=5,
            requires_login=True,
            requires_mfa=False,
            restricted_domain=["example.com"],
            ip_whitelist=["203.0.113.4"],
            organization_id="org-1",
        )

    body = json.loads(rec.requests[0].read())
    assert body["description"] == "fill this in before Friday"
    assert body["expired_at"] == "2026-09-01T00:00:00Z"
    assert body["max_submission"] == 3
    assert body["access_counts_left"] == 5
    assert body["requires_login"] is True
    assert body["requires_mfa"] is False
    assert body["restricted_domain"] == ["example.com"]
    assert body["ip_whitelist"] == ["203.0.113.4"]
    assert body["organization_id"] == "org-1"


def test_omitted_options_are_absent_rather_than_null() -> None:
    """A null expiry would defeat the server's 30-day default and create a link that never
    closes - and such a row is invisible to both the API list and the dashboard."""
    rec = Recorder()
    with make_client(rec) as crs:
        crs.requests.create(title="t", fields=FIELDS)
    assert set(json.loads(rec.requests[0].read())) == {"title", "public_key", "fields"}


def test_a_public_key_we_did_not_send_is_an_error_not_a_result() -> None:
    """Otherwise the caller is handed a seed that cannot open a single submission.

    Only reachable on an Idempotency-Key replay of a create made under another seed. The
    alternative is silence until somebody first tries to read a submission.
    """
    rec = Recorder(body={"short_code": "rq01", "public_key": "AAAA"})
    with make_client(rec) as crs, pytest.raises(ApiError, match="different public key"):
        crs.requests.create(title="t", fields=FIELDS)


# ── the seed boundary ────────────────────────────────────────────────────────────────


FIXED_SEED = bytes(range(32))


def seed_spellings(seed: bytes) -> List[str]:
    """Every encoding somebody hand-rolling one would reach for."""
    return [
        seed.hex(),
        seed.hex().upper(),
        base64.b64encode(seed).decode(),
        base64.b64encode(seed).decode().rstrip("="),
        base64.urlsafe_b64encode(seed).decode(),
        base64.urlsafe_b64encode(seed).decode().rstrip("="),
    ]


def test_a_seed_smuggled_into_the_body_is_refused_rather_than_sent() -> None:
    """The boundary assertion, not the field list.

    The guarantee is "the seed is never transmitted", and a code review is not what enforces
    it: the SERIALIZED body is scanned, so a seed that reached it through a title, a
    description or an unknown field member is caught too. A later edit that adds a member
    carrying the seed fails here instead of in production.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(RequestSeedTransmittedError):
        crs.requests.create(
            title=base64.urlsafe_b64encode(FIXED_SEED).decode().rstrip("="),
            fields=FIELDS,
            seed=FIXED_SEED,
        )
    assert rec.requests == [], "nothing should have been sent"


def test_a_seed_in_an_unknown_field_member_is_refused() -> None:
    """The route the field list would not have covered: `fields` is forwarded verbatim."""
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(RequestSeedTransmittedError):
        crs.requests.create(
            title="t",
            fields=[{"item": "Token", "hint": FIXED_SEED.hex()}],
            seed=FIXED_SEED,
        )
    assert rec.requests == []


def test_a_seed_used_as_the_idempotency_key_is_refused() -> None:
    """A header is the wire too, and a body-only check watches the seed leave in one.

    Not a contrived input: `seed` and `idempotency_key` are adjacent arguments to this one
    method, and a caller who wants a deterministic key has a deterministic seed in hand.
    """
    rec = Recorder()
    with make_client(rec) as crs, pytest.raises(RequestSeedTransmittedError):
        crs.requests.create(
            title="t",
            fields=FIELDS,
            seed=FIXED_SEED,
            idempotency_key=base64.urlsafe_b64encode(FIXED_SEED).decode().rstrip("="),
        )
    assert rec.requests == []


def test_the_seed_is_withheld_from_every_serialization_python_reaches_for() -> None:
    """`__repr__` alone is not the guarantee.

    A Python developer serializes an object reflexively: `repr`, `str`, an f-string, a log
    line, `json.dumps`, `dataclasses.asdict`, `pprint`. Every one of those has to come back
    without the seed in it, or the seed lives in whatever collected the output. This test
    fails if any path renders it in any encoding.
    """
    rec = Recorder(body={"short_code": "rq01", "expired_at": None})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS, seed=FIXED_SEED)

    rendered = [
        repr(req),
        str(req),
        f"{req}",
        "{}".format(req),  # the reflex, not the style
        pprint.pformat(req),
        repr(dataclasses.asdict(req)),
        json.dumps(dataclasses.asdict(req), default=repr),
        repr(req.seed),
        str(req.seed),
        f"{req.seed}",
        pprint.pformat({"seed": req.seed}),
    ]
    for text in rendered:
        for spelling in seed_spellings(FIXED_SEED):
            assert spelling not in text, f"the seed appeared in {text!r}"
        assert repr(bytes(FIXED_SEED)) not in text, f"the raw bytes appeared in {text!r}"
        assert str(list(FIXED_SEED)) not in text, f"the byte list appeared in {text!r}"

    # And the access link is the seed in another spelling, so it is withheld from the same
    # paths — while remaining available to a caller who asks for it outright.
    assert "#" not in repr(req)
    assert "access_link" not in dataclasses.asdict(req)
    assert crypto.encode_fragment(FIXED_SEED) in req.access_link

    # asdict is the path worth naming separately. It deep-copies the field value, and the
    # redaction only survives if the COPY is still the redacting type — lose the subclass and
    # `repr(asdict(req))` prints all 32 bytes.
    assert type(dataclasses.asdict(req)["seed"]) is type(req.seed)
    assert repr(dataclasses.asdict(req)["seed"]) == "<32 bytes withheld>"

    # The seed itself is still the seed: usable, comparable, and storable on purpose.
    assert req.seed == FIXED_SEED
    assert len(req.seed) == crypto.SEED_LENGTH
    assert req.seed.hex() == FIXED_SEED.hex()
    assert crypto.keypair_from_seed(req.seed).public_key_b64url == req.public_key


# ── the links ────────────────────────────────────────────────────────────────────────


def test_a_created_request_carries_both_links() -> None:
    """The collect link is the one thing the feature exists to hand to a human, and it is not
    derivable from any API response — the SDK is the only place that knows the route."""
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS, seed=FIXED_SEED)

        assert req.collect_link == "https://crs.sh/r/rq01"
        assert req.collect_link == crs.collect_link_for("rq01")
        assert req.access_link == crs.access_link_for("rq01", FIXED_SEED)


def test_the_collect_link_is_keyless_and_the_access_link_is_the_secret() -> None:
    """Two links, and the difference is the whole point: one lets a stranger SUBMIT, the
    other lets its holder READ. Handing over the wrong one hands over every submission."""
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        req = crs.requests.create(title="t", fields=FIELDS, seed=FIXED_SEED)

    assert "#" not in req.collect_link
    for spelling in seed_spellings(FIXED_SEED):
        assert spelling not in req.collect_link

    assert req.access_link.startswith(req.collect_link + "#")
    assert base64.urlsafe_b64encode(FIXED_SEED).decode().rstrip("=") in req.access_link


def test_the_access_link_fragment_is_the_versioned_form_the_app_reads() -> None:
    """`"1" + base64url(seed)`, bare, with no `k=` prefix — byte for byte what the app's own
    encoder produces and what the other three SDKs return. Hand-assembly is exactly where a
    caller gets the version prefix wrong, which is why this is not left to the README."""
    rec = Recorder(body={"short_code": "rq01"})
    with make_client(rec) as crs:
        link = crs.access_link_for("rq01", FIXED_SEED)

    fragment = base64.urlsafe_b64encode(FIXED_SEED).decode().rstrip("=")
    assert link == f"https://crs.sh/r/rq01#1{fragment}"
    assert crypto.decode_fragment(link.split("#", 1)[1]) == FIXED_SEED


def test_the_link_origin_is_the_one_the_client_was_built_with() -> None:
    rec = Recorder(body={"short_code": "rq01"})
    with CredenShare(
        CREDENTIAL, transport=rec.transport, link_origin="https://links.example.com/"
    ) as crs:
        req = crs.requests.create(title="t", fields=FIELDS, seed=FIXED_SEED)

    assert req.collect_link == "https://links.example.com/r/rq01"
    assert req.access_link.startswith("https://links.example.com/r/rq01#1")


# ── reads ────────────────────────────────────────────────────────────────────────────


def test_get_returns_metadata_and_the_public_half() -> None:
    rec = Recorder(
        status=200,
        body={"short_code": "rq01", "expired_at": "2026-09-01T00:00:00Z", "public_key": "AAAA"},
    )
    with make_client(rec) as crs:
        row = crs.requests.get("rq01")

    assert (row.short_code, row.expired_at, row.public_key) == (
        "rq01",
        "2026-09-01T00:00:00Z",
        "AAAA",
    )
    assert rec.requests[0].url.path.endswith("/requests/rq01")


def test_an_expired_request_reports_its_short_code_and_nothing_else() -> None:
    """Not a 404: it is still your request. The API answers with the code alone."""
    rec = Recorder(status=200, body={"short_code": "rq01", "expired_at": None})
    with make_client(rec) as crs:
        row = crs.requests.get("rq01")
    assert row.expired_at is None
    assert row.public_key is None


def test_a_request_on_another_account_is_not_found() -> None:
    rec = Recorder(status=404, body={"message": "not found"})
    with make_client(rec) as crs, pytest.raises(NotFoundError):
        crs.requests.get("rq01")


def test_a_summary_has_no_title_because_the_api_returns_none() -> None:
    rec = Recorder(status=200, body={"requests": [{"short_code": "rq01"}]})
    with make_client(rec) as crs:
        rows = crs.requests.list()
    assert not hasattr(rows[0], "title")


def test_delete_reports_which_of_the_two_steps_happened() -> None:
    """Expire, then delete. A 200 alone would leave the caller inferring."""
    rec = Sequenced(
        [
            (200, {"short_code": "rq01", "outcome": "expired"}),
            (200, {"short_code": "rq01", "outcome": "deleted"}),
        ]
    )
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        first = crs.requests.delete("rq01")
        second = crs.requests.delete("rq01")

    assert first.outcome == "expired"
    assert second.outcome == "deleted"
    assert (first.short_code, second.short_code) == ("rq01", "rq01")
    assert [r.method for r in rec.requests] == ["DELETE", "DELETE"]


def test_a_deletion_carries_exactly_two_members() -> None:
    """`{short_code, outcome}` and nothing else, in all four SDKs.

    A third `deleted` boolean was proposed and refused: it is one bit derived from `outcome`,
    and a caller who reads the boolean stops seeing that `"expired"` is not a failed delete
    but the first half of one. This test is what stops it being re-added by convenience.
    """
    rec = Recorder(status=200, body={"short_code": "rq01", "outcome": "expired"})
    with make_client(rec) as crs:
        result = crs.requests.delete("rq01")

    assert [f.name for f in dataclasses.fields(result)] == ["short_code", "outcome"]
    assert not hasattr(result, "deleted")
    assert set(dataclasses.asdict(result)) == {"short_code", "outcome"}


# -- paging ---------------------------------------------------------------------------


def page(codes, page_no, total_pages, total):
    return {
        "requests": [{"short_code": c, "expired_at": None, "public_key": "AAAA"} for c in codes],
        "pagination": {"page": page_no, "limit": 2, "total": total, "total_pages": total_pages},
    }


def test_a_page_carries_its_paging_figures() -> None:
    rec = Sequenced([(200, page(["r1", "r2"], 1, 3, 5))])
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        rows = crs.requests.list(limit=2)

    assert [r.short_code for r in rows] == ["r1", "r2"]
    assert (rows.page, rows.total, rows.total_pages) == (1, 5, 3)
    assert rows.has_more
    assert "limit=2" in str(rec.requests[0].url)


def test_the_default_limit_is_the_servers_own_default() -> None:
    """25, not the 10 the published spec claims for this endpoint.

    The server applies 25 to every /v1 list when the parameter is absent, and caps it at 100.
    Sending 10 by default would make the same call return a different page here than in the
    other three SDKs, and correcting that after a registry publish is a breaking change.
    """
    rec = Sequenced([(200, page(["r1"], 1, 1, 1))])
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        crs.requests.list()

    assert "limit=25" in str(rec.requests[0].url)


def test_iter_all_does_not_stop_on_a_short_middle_page() -> None:
    """The same bug the shares walk had to be fixed for, now on the same shared walker."""
    rec = Sequenced(
        [
            (200, page(["r1", "r2"], 1, 3, 5)),
            (200, page(["s1"], 2, 3, 5)),  # short, but not the last
            (200, page(["t1", "t2"], 3, 3, 5)),
        ]
    )
    with CredenShare(CREDENTIAL, transport=rec.transport) as crs:
        codes = [r.short_code for r in crs.requests.iter_all(limit=2)]

    assert codes == ["r1", "r2", "s1", "t1", "t2"]
    assert len(rec.requests) == 3


def test_a_walk_refuses_when_the_api_echoes_the_wrong_page() -> None:
    """Progress becomes unobservable, so no termination condition can be trusted.

    The echoed page is checked only once there IS a next page to fetch, so this fixture has
    to claim more pages exist as well as answering with the wrong one.
    """
    rec = Sequenced([(200, page(["r1", "r2"], 7, 10, 20))])
    with (
        CredenShare(CREDENTIAL, transport=rec.transport) as crs,
        pytest.raises(ApiError, match="cannot be trusted to terminate"),
    ):
        list(crs.requests.iter_all(limit=2))


# -- submissions ----------------------------------------------------------------------


def seal(fields, seed) -> str:
    """Seal a submission the way a submitter's browser does.

    The payload is `JSON.stringify(fields)` wrapped to the request's public key, per section
    4 of the wire spec. Spelled out here rather than hidden behind a helper of its own,
    because what is being checked is that the SDK opens what the BROWSER produces.
    """
    plaintext = json.dumps(fields, separators=(",", ":")).encode("utf-8")
    return crypto.wrap_to_public_key(plaintext, crypto.keypair_from_seed(seed).public_key_raw)


def test_submissions_come_back_sealed_and_are_not_decrypted_on_the_way_through() -> None:
    """Returning the blob is the point. Decrypting here would mean the SDK held the seed."""
    seed = crypto.new_seed()
    fields = [{"key": "Staging database password", "value": "s3cr3t", "type": "password"}]
    blob = seal(fields, seed)

    rec = Recorder(
        status=200,
        body={
            "submissions": [
                {
                    "short_code": "sb01",
                    "created_at": "2026-09-01T10:00:00Z",
                    "data": blob,
                    "encryption_type": "e2ee-aes256-gcm",
                }
            ],
            "count": 1,
        },
    )
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")

    assert rec.requests[0].url.path.endswith("/requests/rq01/submissions")
    assert subs[0].data == blob
    assert "s3cr3t" not in subs[0].data
    assert subs[0].created_at == "2026-09-01T10:00:00Z"
    assert subs[0].encryption_type == "e2ee-aes256-gcm"
    assert subs.count == 1
    assert len(subs) == 1

    # And it opens with the seed the caller kept, by either route.
    assert decrypt_submission(subs[0].data, seed) == fields
    assert subs[0].decrypt(seed) == fields


def test_a_submission_repr_does_not_dump_the_blob() -> None:
    seed = crypto.new_seed()
    blob = seal([{"key": "k", "value": "v", "type": "text"}], seed)
    rec = Recorder(status=200, body={"submissions": [{"short_code": "sb01", "data": blob}]})
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")
    assert blob not in repr(subs[0])
    assert "sb01" in repr(subs[0])


def test_the_wrong_seed_does_not_open_a_submission() -> None:
    """One submitter can never read another's, and neither can a stranger's automation."""
    blob = seal([{"key": "k", "value": "v", "type": "text"}], crypto.new_seed())
    with pytest.raises(WireFormatError):
        decrypt_submission(blob, crypto.new_seed())


def test_the_seed_stays_a_redacting_type_through_every_copy_protocol() -> None:
    """The `dataclasses.asdict` guarantee rests on this, so it is asserted directly.

    `asdict` deep-copies each field value and hands back the copy. If `copy.deepcopy` were to
    return a plain `bytes` — which is what happens to a subclass whose reduce path is
    disturbed — the redaction would be lost in the single call it most has to survive, and
    nothing about `SecureRequest.__repr__` would notice.
    """
    seed = _Seed(FIXED_SEED)

    for label, produced in (
        ("copy", copy.copy(seed)),
        ("deepcopy", copy.deepcopy(seed)),
        ("pickle", pickle.loads(pickle.dumps(seed))),
    ):
        assert type(produced) is _Seed, label
        assert repr(produced) == "<32 bytes withheld>", label
        # Still the seed: a redaction that broke the value would be worse than the leak.
        assert bytes(produced) == bytes(FIXED_SEED), label
        assert produced == seed, label
        assert produced.hex() == FIXED_SEED.hex(), label


def test_decrypt_submission_takes_data_first_and_calls_it_data() -> None:
    """The settled signature is `(data, seed)` in all four SDKs, and the first parameter is
    named `data` after the API field it comes from.

    Asserted by KEYWORD, which is the only thing that pins the name: a positional call passes
    just as happily against a parameter called `blob`, which is what this SDK shipped before
    and what made a keyword call read differently here than in the other three.
    """
    fields = [{"key": "k", "value": "v", "type": "text"}]
    seed = crypto.new_seed()
    sealed = seal(fields, seed)

    assert decrypt_submission(data=sealed, seed=seed) == fields
    assert decrypt_submission(sealed, seed) == fields

    names = list(inspect.signature(decrypt_submission).parameters)
    assert names == ["data", "seed"], names


def test_a_submission_row_feeds_decrypt_submission_by_keyword() -> None:
    """`sub.data` into `data=` with no renaming on the way across one call - which is the
    reason the parameter carries the field's name rather than a description of it."""
    fields = [{"key": "Staging password", "value": "s3cr3t", "type": "password"}]
    seed = crypto.new_seed()
    rec = Recorder(
        status=200,
        body={"submissions": [{"short_code": "sb01", "data": seal(fields, seed)}]},
    )
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")

    assert decrypt_submission(data=subs[0].data, seed=seed) == fields


def test_the_blob_is_padded_standard_base64_not_base64url() -> None:
    """THE encoding trap on this feature.

    A request's public key travels as unpadded base64url; a submission's blob travels as
    padded standard base64. Both appear on the same feature, and feeding the wrong spelling
    in yields a blob that will not open rather than an error naming the mistake.
    """
    seed = crypto.new_seed()
    fields = [{"key": "k", "value": "v", "type": "text"}]
    blob = seal(fields, seed)

    assert decrypt_submission(blob, seed) == fields

    raw = base64.b64decode(blob, validate=True)
    as_base64url = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert as_base64url != blob
    with pytest.raises(WireFormatError):
        decrypt_submission(as_base64url, seed)


def test_withheld_legacy_submissions_are_counted_rather_than_hidden() -> None:
    """A pre-E2EE submission is plaintext server-side, and the API declines to hand it over.

    Reporting the count is what stops a reconciliation seeing fewer rows than the dashboard
    with no way to learn why.
    """
    rec = Recorder(
        status=200,
        body={"submissions": [], "count": 0, "skipped_not_end_to_end_encrypted": 2},
    )
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")

    assert list(subs) == []
    assert subs.skipped_not_end_to_end_encrypted == 2


def test_submissions_are_one_fetch_with_no_page_or_limit() -> None:
    """The deployed endpoint reads neither `page` nor `limit` and sends no `pagination`.

    So there is nothing to page: `submissions()` takes no paging arguments, sends none, and
    `iter_submissions()` makes exactly one call. A walk that inferred "another page exists"
    from a full one would re-request the identical rows until it hit MAX_PAGES and hand every
    sealed submission back thousands of times over — which is what the other shape of this
    method did before it was corrected.
    """
    rows = [{"short_code": f"sb{n}", "data": "AAAA"} for n in range(10)]
    rec = Recorder(status=200, body={"submissions": rows, "count": 10})
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")
        assert len(subs) == 10
        assert subs.count == 10

        walked = list(crs.requests.iter_submissions("rq01"))

    assert len(walked) == 10
    assert len(rec.requests) == 2, "one call each; the walk must not refetch"
    for request in rec.requests:
        assert request.url.query == b"", "no page and no limit are sent"


def test_a_submission_walk_stops_even_if_a_pagination_block_appears() -> None:
    """The termination guarantee does not depend on the server's cooperation.

    A response that claims nine more pages must not turn one call into ten: the endpoint
    ignores `page`, so every one of those ten would answer with the same rows. Stopping is
    the contract, and this fixture is the shape that would break a guessing walk.
    """
    rec = Recorder(
        status=200,
        body={
            "submissions": [{"short_code": "sb1", "data": "AAAA"}],
            "count": 1,
            "pagination": {"page": 1, "limit": 1, "total": 10, "total_pages": 10},
        },
    )
    with make_client(rec) as crs:
        codes = [sub.short_code for sub in crs.requests.iter_submissions("rq01")]

    assert codes == ["sb1"]
    assert len(rec.requests) == 1


def test_a_count_the_api_did_not_send_is_none_rather_than_a_guess() -> None:
    """`count` is the API's own figure. `len(subs)` is what was parsed. Both, so that a
    truncated response is visible instead of being smoothed over."""
    rec = Recorder(status=200, body={"submissions": [{"short_code": "sb1", "data": "AAAA"}]})
    with make_client(rec) as crs:
        subs = crs.requests.submissions("rq01")

    assert subs.count is None
    assert len(subs) == 1


# -- stats ----------------------------------------------------------------------------


def test_stats_parses_the_counts_and_the_series() -> None:
    rec = Recorder(
        status=200,
        body={
            "shares": {"active": 12, "expired": 3, "total_viewed": 40},
            "daily_views": [
                {"date": "2026-08-30", "count": 0},
                {"date": "2026-08-31", "count": 7},
            ],
        },
    )
    with make_client(rec) as crs:
        stats = crs.stats.get()

    assert (stats.shares.active, stats.shares.expired, stats.shares.total_viewed) == (12, 3, 40)
    assert [(d.date, d.count) for d in stats.daily_views] == [
        ("2026-08-30", 0),
        ("2026-08-31", 7),
    ]
    assert rec.requests[0].url.path.endswith("/stats")
    assert rec.requests[0].method == "GET"


def test_an_empty_series_is_a_series_and_not_a_missing_field() -> None:
    """daily_views is always present and may be empty. A caller forced to distinguish
    "no data" from "field absent" gets it wrong, so neither this nor the API makes them."""
    rec = Recorder(status=200, body={"shares": {}, "daily_views": []})
    with make_client(rec) as crs:
        stats = crs.stats.get()

    assert stats.daily_views == ()
    assert (stats.shares.active, stats.shares.expired, stats.shares.total_viewed) == (0, 0, 0)


def test_stats_errors_map_like_every_other_read() -> None:
    rec = Recorder(status=404, body={"message": "nope"})
    with make_client(rec) as crs, pytest.raises(NotFoundError):
        crs.stats.get()
