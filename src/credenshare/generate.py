"""A local generator for passwords, passphrases and PINs (Gitea #404).

The app's three modes and the CLI's, with nothing sent anywhere: a generated secret never
leaves this process unless the caller sends it. Every draw goes through :func:`secrets.randbelow`,
which rejection-samples, so no character or word is favoured the way a ``%`` reduction of
random bytes favours some.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Tuple

from .errors import InvalidArgumentError

__all__ = [
    "PASSPHRASE_SEPARATORS",
    "PASSWORD_SYMBOLS",
    "Generated",
    "generate_passphrase",
    "generate_password",
    "generate_pin",
    "strength_of",
]

_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
_NUMBERS = "0123456789"

#: The symbols a password may draw from, the app's set.
PASSWORD_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?`\"~/\\'"

#: The separators by the names the app and the CLI use.
PASSPHRASE_SEPARATORS: Dict[str, str] = {
    "hyphen": "-",
    "space": " ",
    "period": ".",
    "underscore": "_",
    "none": "",
}

_WORDLIST = Path(__file__).with_name("eff_large_wordlist.txt")


@dataclass(frozen=True)
class Generated:
    """A generated secret with its strength.

    ``repr`` withholds the value, so printing or logging one does not print the secret. The
    value is still there, by name.
    """

    value: str = field(repr=False)
    #: The entropy of what the options generate, not of this one value.
    bits: float
    #: :func:`strength_of` ``bits``: Weak, Fair, Strong or Very Strong.
    strength: str

    def __str__(self) -> str:
        return f"Generated({self.strength}, {round(self.bits)} bits, value withheld)"


def strength_of(bits: float) -> str:
    """The app generator's label for a number of bits."""
    if bits < 40:
        return "Weak"
    if bits < 60:
        return "Fair"
    if bits < 80:
        return "Strong"
    return "Very Strong"


def _generated(value: str, bits: float) -> Generated:
    return Generated(value=value, bits=bits, strength=strength_of(bits))


def _whole(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgumentError(f"{name} is a whole number, got {value!r}")
    return value


def generate_password(
    length: int = 20,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude: str = "",
) -> Generated:
    """A password drawn uniformly from the chosen characters. The defaults are the app's.

    ``length`` is 8 to 128. ``exclude`` lists characters to leave out, such as ``"0Ol1"`` for
    a password read aloud.
    """
    n = _whole(length, "length")
    if not 8 <= n <= 128:
        raise InvalidArgumentError(f"a password is 8 to 128 characters, got {n}")
    pool = "".join(
        chars
        for on, chars in (
            (uppercase, _UPPERCASE),
            (lowercase, _LOWERCASE),
            (numbers, _NUMBERS),
            (symbols, PASSWORD_SYMBOLS),
        )
        if on
    )
    chars = [c for c in pool if c not in exclude]
    if not chars:
        raise InvalidArgumentError("those options leave no characters to choose from")
    value = "".join(chars[secrets.randbelow(len(chars))] for _ in range(n))
    return _generated(value, n * math.log2(len(chars)))


@lru_cache(maxsize=1)
def _word_list() -> Tuple[str, ...]:
    """The EFF long word list, 7,776 words, read once on first use.

    By the Electronic Frontier Foundation, licensed under CC BY 3.0 US; see NOTICE. The file
    is the EFF's byte for byte: dice numbers, a tab, the word.
    """
    lines = _WORDLIST.read_text(encoding="utf-8").strip().split("\n")
    return tuple(line.strip().split("\t")[1] for line in lines if "\t" in line)


def _passphrase_bits(list_size: int, n: int, with_number: bool) -> float:
    """Each word is log2 of the list; the digit adds log2(10) and its position log2(words)."""
    bits = n * math.log2(list_size)
    if with_number:
        bits += math.log2(10) + math.log2(n)
    return bits


def generate_passphrase(
    words: int = 5,
    *,
    separator: str = "hyphen",
    capitalize: bool = False,
    include_number: bool = False,
) -> Generated:
    """A passphrase drawn uniformly from the EFF long word list (12.9 bits a word).

    ``words`` is 3 to 12. ``separator`` is ``"hyphen"``, ``"space"``, ``"period"``,
    ``"underscore"`` or ``"none"``. ``capitalize`` upper-cases each word's first letter, which
    changes the look and not the strength: every word gets one, so it is not random.
    ``include_number`` appends one random digit to one random word.
    """
    n = _whole(words, "words")
    if not 3 <= n <= 12:
        raise InvalidArgumentError(f"a passphrase is 3 to 12 words, got {n}")
    if separator not in PASSPHRASE_SEPARATORS:
        raise InvalidArgumentError(
            f"separator is hyphen, space, period, underscore or none, not {separator!r}"
        )
    word_list = _word_list()
    picked = [word_list[secrets.randbelow(len(word_list))] for _ in range(n)]
    if capitalize:
        picked = [w[:1].upper() + w[1:] for w in picked]
    if include_number:
        where = secrets.randbelow(n)
        picked[where] += str(secrets.randbelow(10))
    return _generated(
        PASSPHRASE_SEPARATORS[separator].join(picked),
        _passphrase_bits(len(word_list), n, include_number),
    )


def generate_pin(length: int = 6) -> Generated:
    """A PIN of ``length`` digits, 4 to 12."""
    n = _whole(length, "length")
    if not 4 <= n <= 12:
        raise InvalidArgumentError(f"a PIN is 4 to 12 digits, got {n}")
    return _generated("".join(_NUMBERS[secrets.randbelow(10)] for _ in range(n)), n * math.log2(10))
