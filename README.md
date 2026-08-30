# CredenShare for Python

End-to-end encrypted secret sharing. **Encryption happens on your machine** — the content key
never reaches CredenShare, which is what makes "we cannot read your data" a property of the
system rather than a promise.

```bash
pip install credenshare
```

```python
from credenshare import CredenShare

with CredenShare(credential="crs_sk_live_...") as crs:
    share = crs.shares.create(
        title="Staging deploy credentials",
        fields=[
            {"key": "Username", "value": "deploy-bot",   "type": "text"},
            {"key": "Password", "value": "correct horse", "type": "password"},
        ],
    )

print(share.link)
# https://crs.sh/aB3dEf12#1xK9...
```

**That link is the secret.** The key lives in its fragment, which browsers never transmit.
Anyone holding the link can read the content; we cannot, and cannot recover it for you.

---

## The field object

Each field is `{"key": ..., "value": ..., "type": ...}`.

`key` is the **visible label**, not an identifier. It is not `label`, `name` or `title` — the
recipient view reads `key` and ignores the others, so a share built with the wrong member
still encrypts, posts, decrypts and renders, with every field blank and nothing erroring
anywhere. This SDK refuses those spellings rather than letting the mistake through.

`type` is one of `text`, `password`, `date`, `multiline`, `markdown`, `source_code`, and
decides how the recipient sees it: `password` is masked behind a reveal, `source_code` is
highlighted, `markdown` is rendered.

## A passcode

```python
share = crs.shares.create(
    title="Production database",
    fields=[{"key": "Password", "value": "s3cr3t", "type": "password"}],
    passcode="hunter2",
)
```

The passcode is mixed into the key derivation and never sent. The server receives only a
one-way verifier, so it can check an attempt without gaining the ability to decrypt. Share the
link and the passcode over different channels — that is the point of having both.

## Expiry and view limits

```python
crs.shares.create(
    title="Temporary access",
    fields=[...],
    expired_at="2026-09-01T00:00:00Z",
    access_counts_left=3,      # readable three times
    timed_view=60,             # visible for 60s once opened
)
```

## Listing and expiring

```python
for row in crs.shares.list(limit=50):
    print(row.short_code, row.expired_at)

crs.shares.expire("aB3dEf12")   # irreversible
```

`list` and `get` return **metadata only** — never content, never a key. A short code
belonging to another account reports exactly as one that does not exist, so a credential
cannot be used to discover what other accounts hold.

There is deliberately **no method to read a share over the API**. The recipient path is
protected by proof-of-work and captcha gates that bearer auth skips, so exposing it to a
credential would be an enumeration bypass. Open the link in a browser.

---

## Verifying webhooks

```python
from credenshare.webhooks import verify, WebhookVerificationError

@app.post("/hooks/credenshare")
async def hook(request):
    try:
        verify(
            await request.body(),                          # the RAW bytes
            request.headers["X-CredenShare-Signature"],
            secrets=WEBHOOK_SECRET,
        )
    except WebhookVerificationError:
        return Response(status_code=400)
```

Two things people get wrong here, both of which this SDK tries to make hard:

**Verify the raw body.** Re-serialising parsed JSON changes the bytes — key order, spacing,
escapes — and the signature will not match. It is the most common reason a correct
integration appears broken.

**Pass both secrets while rotating.** For 24 hours after you rotate, deliveries carry both
signatures so you can roll your configuration without dropping anything:

```python
verify(body, header, secrets=[NEW_SECRET, OLD_SECRET])
```

`verify` returns `True` or raises. It never returns `False`, because a falsy result is too
easy to drop with `if verify(...)` and no `else` — which yields a receiver that accepts
everything and looks like it checks.

---

## API credentials

A credential looks like this:

```
crs_sk_live_<keyId>.<authSecret>.<custodySecret>
                                  └ never transmitted
```

The third part is optional and, when present, **stays on your machine**. It is a separate
secret precisely so the server cannot reconstruct your custody private key: the auth secret
goes over the wire on every request, so deriving custody from it would mean the server
*could* decrypt. Not that it would — that it could, which is what zero-knowledge removes.

This SDK builds the `Authorization` header from the parsed parts rather than by trimming the
string, so a third part cannot survive a formatting mistake and reach the wire. There is a
test asserting exactly that.

Any machine holding the credential derives the same custody keypair, so ephemeral runners
need no local state:

```python
crs.credential.custody_public_key()   # register this; only the public half leaves
```

---

## The wire specification

This SDK implements the CredenShare wire and crypto specification, which ships in this
repository as [`CRYPTO_WIRE_SPEC.md`](CRYPTO_WIRE_SPEC.md). **The specification is
normative — not this code**, and not any other implementation. Where they disagree, this
is the bug.

The application and the four SDKs share no code, deliberately: a package the production
application depended on would mean a compromised publish is a compromised application. The
cost is drift, and drift here does not produce a test failure — it produces content that can
never be decrypted.

`vectors.v1.json` is what holds the implementations together, and it ships **inside** the
package rather than beside it, so you can verify the exact artifact you installed:

```bash
python -m credenshare.conformance
```

That needs no test runner and no dev dependencies, and it exits non-zero on failure, so it
works as a deployment gate. Worth running in the environment that will actually do the
encrypting — a client that fails these produces content nothing else can read, and the
failure is otherwise invisible until somebody opens a link.

The vectors include cases that **decrypt and unwrap material produced by a different
implementation**. Passing them means this client can read what another one wrote, which is
interoperability rather than self-consistency.

## Errors

Types imply remedies, because several of these look identical on screen and have opposite
fixes:

| Error | Means | What helps |
| ----- | ----- | ---------- |
| `MissingKeyError` | a link arrived with no key | ask for the link again — something stripped it |
| `MalformedKeyError` | the key is present but unusable | the link is truncated; ask for it again |
| `WireFormatError` | wrong passcode, or altered content | check the passcode. The two are indistinguishable by design |
| `AuthenticationError` | credential unknown or revoked | mint a new one |
| `PermissionError_` | missing scope, or a plan without API access | check scopes, or upgrade |
| `QuotaExceededError` | the plan's share allowance is spent | waiting does not help — expire old shares or change plan |
| `RateLimitError` | too many requests | wait `err.retry_after` seconds |
| `ServiceUnavailableError` | entitlements could not be resolved | nothing was created; retry |
| `NotFoundError` | no such share, or not yours | a code from another account reads exactly like one that never existed |
| `IdempotencyConflictError` | the key was reused with a different body | expected when you reuse your own key — encryption is randomised, so the body always differs |
| `DeliveryUnknownError` | delivered, but no response was read | it may have committed. Repeat the identical request; a fresh key here is how one secret becomes two |
| `CustodySecretMissingError` | `custody=True` on a two-part credential | use a credential that carries the third part |
| `ApiError` | any other refusal | the base class — `err.status`, `err.code` and `err.request_id` carry the detail |

## Requirements

Python 3.9+, with two runtime dependencies: `cryptography` and `httpx`. A client whose entire
claim is that it encrypts correctly should not ask you to trust a long tail of transitive
packages.

## Licence

Apache-2.0. Open source is a requirement here, not a preference: if the client performing the
encryption is closed, the claim that we cannot read your data is unverifiable.
