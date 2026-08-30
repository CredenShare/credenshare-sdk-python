"""What this client refuses.

Each case here is something that was once accepted. They share a shape: the wrong input did
not raise, it produced a plausible-looking result that failed somewhere far away — or, worse,
did not fail at all.
"""

from __future__ import annotations

import pytest

from credenshare import crypto
from credenshare.client import Credential
from credenshare.errors import MalformedKeyError
from credenshare.webhooks import WebhookVerificationError, _parse


class TestTheKeyFragment:
    def test_a_fragment_with_characters_outside_the_alphabet_is_refused(self) -> None:
        """Without validation these are discarded and the fragment yields a 32-byte key.

        The failure then surfaces as a decryption error on content that is perfectly fine,
        pointing every investigation at the wrong place.
        """
        mangled = "1" + "A" * 20 + "!!!*" + "A" * 23
        with pytest.raises(MalformedKeyError):
            crypto.decode_fragment(mangled)

    def test_a_well_formed_fragment_still_decodes(self) -> None:
        key = crypto.new_content_key()
        assert crypto.decode_fragment(crypto.encode_fragment(key)) == key

    def test_the_urlsafe_alphabet_is_accepted(self) -> None:
        """- and _ are the point of base64url; validation must not reject them."""
        for _ in range(200):
            key = crypto.new_content_key()
            fragment = crypto.encode_fragment(key)
            assert crypto.decode_fragment(fragment) == key


class TestTheWebhookTimestamp:
    @pytest.mark.parametrize(
        "value",
        [
            " 1735689600",  # surrounding whitespace
            "+1735689600",  # leading plus
            "1_735_689_600",  # python's underscore separators
            "\u0661\u0667\u0663",  # arabic-indic digits
        ],
    )
    def test_non_canonical_spellings_are_refused(self, value: str) -> None:
        """int() accepts all of these. Go, Node and Rust accept none of them.

        A header this client verified and the other three rejected would be a divergence
        that only ever appears in production, on one language.
        """
        with pytest.raises(WebhookVerificationError):
            _parse(f"t={value},v1=abc")

    def test_the_canonical_spelling_is_accepted(self) -> None:
        timestamp, signatures = _parse("t=1735689600,v1=abc")
        assert timestamp == 1735689600
        assert signatures == ["abc"]

    def test_a_negative_timestamp_is_still_a_unix_time(self) -> None:
        timestamp, _ = _parse("t=-1,v1=abc")
        assert timestamp == -1


class TestCustody:
    def test_the_wrap_round_trips_with_the_custody_key(self) -> None:
        credential = Credential.parse("crs_sk_live_abc.authsecret.custodysecret")
        assert credential.custody_secret is not None
        keypair = crypto.custody_keypair(credential.custody_secret)

        content_key = crypto.new_content_key()
        wrap = crypto.wrap_to_public_key(content_key, keypair.public_key_raw)

        assert crypto.unwrap_with_seed(wrap, keypair.seed) == content_key

    def test_the_wrap_does_not_carry_the_custody_secret(self) -> None:
        """The wrap goes to the server. The secret it derives from must not."""
        secret = "custodysecret"
        keypair = crypto.custody_keypair(secret)
        wrap = crypto.wrap_to_public_key(crypto.new_content_key(), keypair.public_key_raw)
        assert secret.encode() not in wrap.encode()
