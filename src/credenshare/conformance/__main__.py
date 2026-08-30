"""Verify an installed copy of this SDK against the packaged conformance vectors.

    python -m credenshare.conformance          # summary
    python -m credenshare.conformance -v       # one line per vector

Exits non-zero on any failure, so it works as a deployment gate. Worth running in the
environment that will actually do the encrypting: a client that fails these produces content
nothing else can read, and that failure is otherwise invisible until somebody opens a link.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from . import VECTORS_PATH, load, run, say


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    verbose = "-v" in args or "--verbose" in args

    fixture = load()
    say("CredenShare conformance vectors v" + str(fixture["version"]))
    say("  " + str(VECTORS_PATH))
    say("")

    passed, failures = run(verbose=verbose)
    if verbose:
        say("")

    if not failures:
        say(f"{passed} passed. This installation conforms to the wire specification.")
        return 0

    for name, reason in failures:
        say("FAIL " + name)
        for line in reason.splitlines():
            say("     " + line)
    say("")
    say(f"{passed} passed, {len(failures)} FAILED")
    say(
        "This installation does not implement the wire specification correctly. Content it "
        "encrypts may be unreadable by every other client, including the web application."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
