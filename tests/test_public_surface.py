"""The package root, exercised exactly as the README tells a reader to use it.

Every other test module imports submodules directly (``from credenshare.client import ...``),
which is why three separate ImportError/AttributeError defects shipped in the documented
entry points while the suite stayed green. These tests import the way a user does.
"""

from __future__ import annotations

import credenshare


def test_the_readme_quickstart_import_resolves() -> None:
    """``from credenshare import CredenShare`` is the first line of the README."""
    from credenshare import CredenShare

    assert callable(CredenShare)


def test_the_client_value_types_are_importable_from_the_root() -> None:
    from credenshare import Credential, Share, ShareList, ShareSummary

    assert all(isinstance(t, type) for t in (Credential, Share, ShareList, ShareSummary))


def test_the_secure_request_and_stats_types_are_importable_from_the_root() -> None:
    """The three surfaces are `crs.shares`, `crs.requests` and `crs.stats`, and every value
    type they hand back has to be importable from where the client is."""
    from credenshare import (
        DailyView,
        RequestDeletion,
        RequestList,
        RequestSummary,
        SecureRequest,
        ShareCounts,
        Stats,
        Submission,
        SubmissionPage,
    )

    assert all(
        isinstance(t, type)
        for t in (
            SecureRequest,
            RequestSummary,
            RequestList,
            RequestDeletion,
            Submission,
            SubmissionPage,
            Stats,
            ShareCounts,
            DailyView,
        )
    )


def test_the_submissions_container_is_named_submissionpage() -> None:
    """`SubmissionPage` in all four SDKs. Python was the only one calling it `SubmissionList`.

    The old name is gone rather than aliased: 0.2.0 is unreleased, so nothing depends on it,
    and an alias would leave two names for one type in the very surface this rename was meant
    to make singular.
    """
    from credenshare import SubmissionPage

    assert isinstance(SubmissionPage, type)
    assert SubmissionPage.__name__ == "SubmissionPage"
    assert not hasattr(credenshare, "SubmissionList")
    assert "SubmissionList" not in credenshare.__all__
    assert "SubmissionPage" in credenshare.__all__

    # The name says page; the docstring has to keep saying it is not one, because a caller who
    # believes it is goes looking for the next page and writes a loop that cannot terminate.
    doc = SubmissionPage.__doc__ or ""
    assert "NOT a page" in doc
    assert "nothing to walk" in doc


def test_the_seed_length_constant_is_importable_and_agrees_with_a_seed() -> None:
    """A caller who stores or transports a seed checks its length, and the alternative is a
    magic 32 in their code. Exported under this name in all four SDKs."""
    from credenshare import SEED_LENGTH, new_seed

    assert SEED_LENGTH == 32
    assert len(new_seed()) == SEED_LENGTH


def test_the_readme_secure_request_flow_resolves_from_the_root() -> None:
    """`decrypt_submission` is the second half of the request example, and a reader who can
    import the client but not the decrypt call has a seed and no way to use it."""
    from credenshare import CredenShare, decrypt_submission, new_seed

    assert callable(decrypt_submission)
    assert len(new_seed()) == 32

    crs = CredenShare("crs_sk_live_abc123.authsecretvalue")
    try:
        assert hasattr(crs, "requests")
        assert hasattr(crs, "stats")
        assert callable(crs.call)
    finally:
        crs.close()


def test_webhooks_resolves_after_a_bare_import() -> None:
    """The README calls ``credenshare.webhooks.verify`` after ``import credenshare``."""
    assert callable(credenshare.webhooks.verify)
    assert credenshare.webhooks.SIGNATURE_HEADER == "X-CredenShare-Signature"


def test_every_error_the_sdk_raises_is_reachable_from_the_root() -> None:
    """An error a caller is told to catch must be importable from where they import the client."""
    from credenshare import errors

    missing = [name for name in errors.__all__ if not hasattr(credenshare, name)]
    assert not missing, f"errors not re-exported from the package root: {missing}"


def test_dunder_all_is_honest() -> None:
    """Everything __all__ advertises must actually resolve."""
    missing = [name for name in credenshare.__all__ if not hasattr(credenshare, name)]
    assert not missing, f"__all__ names that do not resolve: {missing}"
