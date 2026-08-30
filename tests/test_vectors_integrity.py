"""The vendored fixture must not drift from the published one.

Nothing but the conformance vectors holds five independent implementations together — the
application and four SDKs, which share no code by design. If a vendored copy can be edited to
make a failing test pass, that guarantee is gone: the fixture stops being a contract and
becomes a mirror of whatever this SDK happens to do.

So the copy is pinned by digest here, and CI additionally re-fetches the published artifact
when it is configured to. The digest catches the local edit; the fetch catches the case where
the published spec moved and this SDK has not.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

# The digest is taken of the copy that ships inside the package — the one an installed
# wheel actually carries. Pinning a repository-only copy would leave the shipped fixture
# unpinned, which is the copy that matters.
from credenshare.conformance import VECTORS_PATH

#: SHA-256 of `src/credenshare/conformance/vectors.v1.json`.
#:
#: Updating this by hand is a deliberate act. If a conformance test fails, the fix is almost
#: never to re-pin this — it is to fix the implementation. Re-pin only when intentionally
#: adopting a newly published fixture, in a commit that says so and nothing else.
EXPECTED_SHA256 = "fa4011ffbd4f45e534117bbfeb82da65b9c851e92c256440c05c4fd4317da4d6"


def _digest() -> str:
    return hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()


@pytest.mark.skipif(
    EXPECTED_SHA256 == "REPLACED_BY_MAKE_PIN",
    reason="digest not pinned yet; run scripts/pin_vectors.py",
)
def test_the_vendored_fixture_has_not_been_edited() -> None:
    assert _digest() == EXPECTED_SHA256, (
        "the packaged vectors.v1.json does not match its pinned digest.\n"
        "If a conformance test was failing, fix the implementation rather than the fixture. "
        "Re-pin only to adopt a newly published fixture, deliberately."
    )


def test_the_fixture_is_well_formed_and_versioned() -> None:
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert data["version"] == 1
    # Every section this SDK implements must be present. A fixture that quietly lost a
    # section would turn a real conformance gap into a passing run.
    for section in (
        "hkdf",
        "fragment",
        "access_token",
        "passcode_verifier",
        "content",
        "seed_keypair",
        "custody_keypair",
        "ecdh_wrap",
    ):
        assert section in data, f"the fixture is missing the {section} vectors"


@pytest.mark.skipif(
    not os.environ.get("CREDENSHARE_VECTORS_URL"),
    reason="set CREDENSHARE_VECTORS_URL to check against the published fixture",
)
def test_the_vendored_fixture_matches_the_published_one() -> None:
    """The drift alarm CI runs.

    Byte-for-byte, not semantically: a whitespace-only difference still means the two files
    came from different generator runs, and that is worth knowing before it becomes a
    difference that matters.
    """
    import httpx

    published = httpx.get(os.environ["CREDENSHARE_VECTORS_URL"], timeout=30).content
    assert published == VECTORS_PATH.read_bytes(), (
        "the vendored fixture differs from the published one. The spec has moved; update "
        "src/credenshare/conformance/vectors.v1.json and re-pin its digest."
    )
