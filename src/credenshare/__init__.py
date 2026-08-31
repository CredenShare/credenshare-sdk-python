"""CredenShare SDK — end-to-end encrypted secret sharing.

Encryption happens here, on your machine. The content key never reaches CredenShare, which
is what makes "we cannot read your data" a property of the system rather than a promise.

    from credenshare import CredenShare

    crs = CredenShare(credential="crs_sk_live_...")
    share = crs.shares.create(
        title="Staging deploy credentials",
        fields=[{"key": "Password", "value": "s3cr3t", "type": "password"}],
    )
    print(share.link)   # contains the key in its fragment - treat it as the secret

The implementation follows the published wire specification, and its correctness is defined
by `conformance/vectors.v1.json` rather than by this code.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

from . import webhooks
from .client import (
    CredenShare,
    Credential,
    Share,
    ShareList,
    ShareSummary,
)
from .crypto import (
    FIELD_TYPES,
    SeedKeypair,
    access_token,
    custody_keypair,
    decode_fragment,
    decrypt_content,
    encode_fragment,
    encrypt_content,
    keypair_from_seed,
    new_content_key,
    passcode_verifier,
    unwrap_with_seed,
    wrap_to_public_key,
)
from .errors import (
    ApiError,
    AuthenticationError,
    CredenShareError,
    CredentialFormatError,
    CustodySecretMissingError,
    CustodySecretTransmittedError,
    DeliveryUnknownError,
    IdempotencyConflictError,
    InvalidArgumentError,
    InvalidFieldError,
    MalformedKeyError,
    MissingKeyError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
    ServiceUnavailableError,
    WireFormatError,
)
from .webhooks import WebhookVerificationError

#: Read from the installed distribution rather than written here, because a second copy of the
#: version is a second thing to forget. It said "0.1.0" while 0.1.3 was on PyPI, and nothing
#: noticed: the release guard compared the TAG to pyproject.toml and never to this.
try:
    __version__ = _installed_version("credenshare")
except PackageNotFoundError:  # a checkout with no installed distribution
    __version__ = "0.0.0+source"

__all__ = [
    "__version__",
    "CredenShare",
    "Credential",
    "Share",
    "ShareList",
    "ShareSummary",
    "webhooks",
    "FIELD_TYPES",
    "SeedKeypair",
    "access_token",
    "custody_keypair",
    "decode_fragment",
    "decrypt_content",
    "encode_fragment",
    "encrypt_content",
    "keypair_from_seed",
    "new_content_key",
    "passcode_verifier",
    "unwrap_with_seed",
    "wrap_to_public_key",
    "ApiError",
    "AuthenticationError",
    "CredenShareError",
    "CredentialFormatError",
    "CustodySecretMissingError",
    "InvalidArgumentError",
    "InvalidFieldError",
    "WebhookVerificationError",
    "CustodySecretTransmittedError",
    "DeliveryUnknownError",
    "IdempotencyConflictError",
    "MalformedKeyError",
    "MissingKeyError",
    "NotFoundError",
    "PermissionError_",
    "QuotaExceededError",
    "RateLimitError",
    "ServiceUnavailableError",
    "WireFormatError",
]
