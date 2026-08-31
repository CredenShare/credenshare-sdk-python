"""Every error this SDK raises must be catchable the way the README says it is.

The README teaches ``except CredenShareError`` as the blanket, and ``except ApiError`` for
anything the API refused. Each case here was once outside one of those, which means a caller
following the documentation had a branch that silently caught nothing.
"""

from __future__ import annotations

import httpx
import pytest

import credenshare
from credenshare import crypto
from credenshare.client import ShareList, ShareSummary, _error_for
from credenshare.errors import ApiError, CredenShareError


class TestTheBlanketCatchIsGenuine:
    def test_field_validation_is_a_credenshare_error(self) -> None:
        """It was a bare ValueError, so the documented blanket missed the SDK's strictest check."""
        with pytest.raises(CredenShareError):
            crypto.validate_fields([{"label": "Password", "value": "x", "type": "text"}])

    def test_field_validation_is_still_a_value_error(self) -> None:
        """Anyone who already caught ValueError keeps working."""
        with pytest.raises(ValueError):
            crypto.validate_fields([{"label": "Password", "value": "x", "type": "text"}])

    def test_webhook_verification_failure_is_a_credenshare_error(self) -> None:
        assert issubclass(credenshare.WebhookVerificationError, CredenShareError)

    def test_webhook_error_is_reachable_from_both_documented_paths(self) -> None:
        assert credenshare.WebhookVerificationError is credenshare.webhooks.WebhookVerificationError


class TestDeliveryUnknownStaysInTheApiHierarchy:
    def test_it_is_an_api_error(self) -> None:
        """It replaced ServiceUnavailableError, which was one.

        A caller with `except ApiError` around a create would otherwise have stopped catching
        a case it caught before — a silent behaviour change on an error path.
        """
        assert issubclass(credenshare.DeliveryUnknownError, ApiError)

    def test_it_still_carries_attempts(self) -> None:
        error = credenshare.DeliveryUnknownError("gave up", attempts=3)
        assert error.attempts == 3
        assert isinstance(error, ApiError)


class TestTheIdempotencyCodesAreDistinguishable:
    @pytest.mark.parametrize("code", [105, 106])
    def test_both_arrive_as_idempotency_conflict(self, code: int) -> None:
        error = _error_for(httpx.Response(409, json={"message": "x", "error_code": code}))
        assert isinstance(error, credenshare.IdempotencyConflictError)
        assert error.code == code

    def test_the_remedies_are_told_apart_by_code(self) -> None:
        """105 means stop and fix the caller; 106 means wait and repeat the SAME request.

        Opposite remedies, so a caller has to be able to tell them apart. 106 used to fall
        through to a bare ApiError, which made the documented `err.code` check impossible.
        """
        conflict = _error_for(httpx.Response(409, json={"message": "x", "error_code": 105}))
        in_flight = _error_for(httpx.Response(409, json={"message": "x", "error_code": 106}))
        assert conflict.code != in_flight.code

    def test_an_unrelated_409_is_still_generic(self) -> None:
        error = _error_for(httpx.Response(409, json={"message": "x", "error_code": 999}))
        assert not isinstance(error, credenshare.IdempotencyConflictError)


class TestPaginationDoesNotTruncate:
    """A missing pagination block must not read as "no more pages".

    Node, Go and Rust all fall back. Python was the only one that answered False, so iter_all
    returned page one and reported a fraction of the account as all of it.
    """

    @staticmethod
    def _rows(n: int) -> list[ShareSummary]:
        return [ShareSummary(short_code=f"c{i}", expired_at=None) for i in range(n)]

    def test_a_full_page_with_no_figures_has_more(self) -> None:
        assert ShareList(self._rows(25), page=1, limit=25).has_more is True

    def test_a_short_page_with_no_figures_ends_the_walk(self) -> None:
        assert ShareList(self._rows(7), page=2, limit=25).has_more is False

    def test_total_is_used_when_total_pages_is_absent(self) -> None:
        assert ShareList(self._rows(25), page=1, limit=25, total=60).has_more is True
        assert ShareList(self._rows(25), page=1, limit=25, total=25).has_more is False

    def test_total_pages_still_wins(self) -> None:
        assert ShareList(self._rows(25), page=1, limit=25, total_pages=1).has_more is False
        assert ShareList(self._rows(25), page=1, limit=25, total_pages=3).has_more is True


class TestTheWalkTerminates:
    """`has_more` falling back to "a full page probably has a successor" is permanently true
    against a server that returns full pages and counts nothing. Bounding the walk is what
    stops the truncation fix from becoming a non-terminating request loop.
    """

    def test_a_constant_page_echo_is_refused(self) -> None:
        import httpx

        from credenshare import CredenShare

        def handler(request: httpx.Request) -> httpx.Response:
            # always answers page 1, whatever was asked for
            return httpx.Response(
                200,
                json={
                    "shares": [{"short_code": "a"}, {"short_code": "b"}],
                    "pagination": {"page": 1, "limit": 2, "total_pages": 9},
                },
            )

        client = CredenShare(
            credential="crs_sk_live_abc123.authsecretvalue",
            transport=httpx.MockTransport(handler),
        )
        seen = 0
        with pytest.raises(ApiError, match="page"):
            for _ in client.shares.iter_all(limit=2):
                seen += 1
                assert seen < 500, "iter_all is looping instead of raising"

    def test_max_pages_is_reachable_and_named(self) -> None:
        from credenshare.client import MAX_PAGES

        assert MAX_PAGES > 0


class TestArgumentConflictsAreNotFieldErrors:
    def test_custody_with_an_explicit_wrap_is_refused(self) -> None:
        """The raise site item 14 asked about, which had no test at all."""
        from credenshare import CredenShare, InvalidArgumentError

        client = CredenShare(credential="crs_sk_live_abc.authsecret.custodysecret")
        with pytest.raises(InvalidArgumentError, match="not both"):
            client.shares.create(
                title="t",
                fields=[{"key": "k", "value": "v", "type": "text"}],
                custody=True,
                item_key_wrap="whatever",
            )

    def test_it_is_catchable_as_both(self) -> None:
        from credenshare import InvalidArgumentError

        assert issubclass(InvalidArgumentError, CredenShareError)
        assert issubclass(InvalidArgumentError, ValueError)

    def test_a_field_problem_is_still_a_field_error(self) -> None:
        """The two must not be the same class - that was the whole point."""
        from credenshare import InvalidArgumentError, InvalidFieldError

        assert InvalidArgumentError is not InvalidFieldError
