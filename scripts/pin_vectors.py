"""Pin the vendored conformance fixture by digest.

Run after deliberately adopting a newly published fixture:

    python scripts/pin_vectors.py

It rewrites EXPECTED_SHA256 in tests/test_vectors_integrity.py. That is meant to be a
separate, obvious commit — the digest exists so that editing the fixture to make a failing
test pass is impossible to do quietly.
"""

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "src" / "credenshare" / "conformance" / "vectors.v1.json"
TEST = ROOT / "tests" / "test_vectors_integrity.py"

digest = hashlib.sha256(VECTORS.read_bytes()).hexdigest()
source = TEST.read_text(encoding="utf-8")
updated, count = re.subn(
    r'EXPECTED_SHA256 = "[^"]*"', f'EXPECTED_SHA256 = "{digest}"', source, count=1
)
if count != 1:
    sys.exit("could not find EXPECTED_SHA256 to update")

TEST.write_text(updated, encoding="utf-8", newline="\n")
print(f"pinned {VECTORS.relative_to(ROOT).as_posix()} at sha256:{digest}")
