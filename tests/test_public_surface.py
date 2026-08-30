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
