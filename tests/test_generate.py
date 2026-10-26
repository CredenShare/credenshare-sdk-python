"""The local generator: the app's modes, its character sets, its strength figures, and draws
without modulo bias."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Any, Dict

import pytest

from credenshare import (
    PASSPHRASE_SEPARATORS,
    PASSWORD_SYMBOLS,
    generate_passphrase,
    generate_password,
    generate_pin,
    strength_of,
)
from credenshare.errors import InvalidArgumentError
from credenshare.generate import _WORDLIST, _passphrase_bits, _word_list

# The EFF publishes this digest's file; the generator must draw from exactly that list.
EFF_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"


def test_the_word_list_is_the_effs_byte_for_byte() -> None:
    assert hashlib.sha256(_WORDLIST.read_bytes()).hexdigest() == EFF_SHA256
    words = _word_list()
    assert len(words) == 7776 and words[0] == "abacus" and words[-1] == "zoom"


# The same table is asserted in all four SDKs, and matches the app and the CLI.
STRENGTH_TABLE = [
    ("password 20, all four sets (94)", 20 * math.log2(94), "131.0918", "Very Strong"),
    ("password 8, lowercase only (26)", 8 * math.log2(26), "37.6035", "Weak"),
    ("password 12, letters and numbers (62)", 12 * math.log2(62), "71.4504", "Strong"),
    ("password 10, numbers and symbols (42)", 10 * math.log2(42), "53.9232", "Fair"),
    ("passphrase 5 words", _passphrase_bits(7776, 5, False), "64.6241", "Strong"),
    ("passphrase 3 words", _passphrase_bits(7776, 3, False), "38.7744", "Weak"),
    ("passphrase 4 words with a digit", _passphrase_bits(7776, 4, True), "57.0212", "Fair"),
    ("passphrase 7 words", _passphrase_bits(7776, 7, False), "90.4737", "Very Strong"),
    ("pin 6", 6 * math.log2(10), "19.9316", "Weak"),
    ("pin 12", 12 * math.log2(10), "39.8631", "Weak"),
]


@pytest.mark.parametrize("name, bits, figure, label", STRENGTH_TABLE)
def test_strength_matches_the_app_and_the_other_sdks(
    name: str, bits: float, figure: str, label: str
) -> None:
    assert f"{bits:.4f}" == figure, name
    assert strength_of(bits) == label, name


def test_the_default_password_is_the_apps() -> None:
    g = generate_password()
    assert len(g.value) == 20 and g.strength == "Very Strong"
    assert math.isclose(g.bits, 20 * math.log2(94))
    pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + PASSWORD_SYMBOLS
    assert len(pool) == 94
    assert all(c in pool for c in g.value)


def test_password_options_shape_the_pool() -> None:
    g = generate_password(64, uppercase=False, symbols=False, exclude="0123abc")
    assert not any(c.isupper() or c in PASSWORD_SYMBOLS + "0123abc" for c in g.value)
    # 26 lower + 10 digits, less the 7 excluded.
    assert math.isclose(g.bits, 64 * math.log2(29))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"length": 7},
        {"length": 129},
        {"length": 12.5},
        {"uppercase": False, "lowercase": False, "numbers": False, "symbols": False},
        {"uppercase": False, "lowercase": False, "symbols": False, "exclude": "0123456789"},
    ],
)
def test_password_options_out_of_range_are_refused(kwargs: Dict[str, Any]) -> None:
    with pytest.raises(InvalidArgumentError):
        generate_password(**kwargs)


def test_the_default_passphrase_is_five_hyphenated_words() -> None:
    g = generate_passphrase()
    # Four EFF words carry a hyphen of their own (drop-down, felt-tip, t-shirt, yo-yo), so a
    # hyphenated passphrase can split into more than five parts, never fewer.
    assert len(g.value.split("-")) >= 5 and g.strength == "Strong"
    known = set(_word_list())
    assert all(w in known for w in generate_passphrase(12, separator="space").value.split(" "))


def test_passphrase_options() -> None:
    g = generate_passphrase(4, separator="space", capitalize=True, include_number=True)
    assert all(w[0].isupper() for w in g.value.split(" "))
    assert sum(c.isdigit() for c in g.value) == 1 and g.strength == "Fair"
    for name, sep in PASSPHRASE_SEPARATORS.items():
        value = generate_passphrase(3, separator=name).value
        if sep:
            assert len(value.split(sep)) >= 3, (name, value)


@pytest.mark.parametrize("kwargs", [{"words": 2}, {"words": 13}, {"separator": "comma"}])
def test_passphrase_options_out_of_range_are_refused(kwargs: Dict[str, Any]) -> None:
    with pytest.raises(InvalidArgumentError):
        generate_passphrase(**kwargs)


def test_pins() -> None:
    g = generate_pin()
    assert len(g.value) == 6 and g.value.isdigit() and g.strength == "Weak"
    for n in (3, 13, -2):
        with pytest.raises(InvalidArgumentError):
            generate_pin(n)


def test_draws_are_uniform() -> None:
    """A % reduction of random bytes would skew this. 60,000 digits: each should come up
    about 6,000 times, and 20% either way is far outside what chance produces at this size."""
    counts = Counter("".join(generate_pin(12).value for _ in range(5000)))
    for digit in "0123456789":
        assert 4800 < counts[digit] < 7200, (digit, counts[digit])


def test_a_generated_value_is_withheld_from_printing() -> None:
    g = generate_password()
    for rendered in (repr(g), str(g), f"{g}"):
        assert g.value not in rendered
    assert isinstance(g.value, str)
