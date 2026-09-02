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

## Secure requests

A share hands out a secret. A **secure request** collects one: you publish a public key, and
whoever fills the link in seals their answer to it in their own browser. One submitter can
never read another's, and neither can we.

```python
req = crs.requests.create(
    title="Onboarding credentials",
    fields=[{"item": "Staging database password", "type": "password"}],
)

save_somewhere(req.seed.hex())  # 32 bytes, never transmitted
print(req.collect_link)         # https://crs.sh/r/aB3dEf12 - hand this to a human
print(req.access_link)          # the same link + the seed in its fragment - keep this
```

**The seed is the whole point of that call.** It is generated on your machine, only the
public half is sent, and it is the only thing that can ever open a submission. Store it
before you do anything else with the result: a request whose seed was dropped keeps
collecting submissions that nobody — you, us, or a court order — can read.

Two links, and the difference matters. `collect_link` is **keyless**: holding it lets
somebody submit and never read, which is what makes it safe to paste into a ticket.
`access_link` carries the seed in its fragment, so it *is* the ability to read every
submission on any device with nothing stored — treat it as the secret itself. Both are also
available from a stored seed later, as `crs.collect_link_for(code)` and
`crs.access_link_for(code, seed)`.

`req.seed` is `bytes`, but it does not print itself: `print(req.seed)` and an f-string both
render `<32 bytes withheld>`, and so do `repr(req)`, `dataclasses.asdict(req)` and a log
line that interpolates either. Persisting it takes an explicit `req.seed.hex()`. The seed
reaching a log is the failure this SDK cannot undo for you, so the accidental paths are
closed and the deliberate one is one call.

Note the field member: a request's fields use **`item`** (the prompt you are asking for),
where a share's use `key`. Reaching for `key` here is silently accepted by the API and
renders a form field with no label, so this SDK refuses it. So is a request with **no**
fields, which the API creates happily and which renders as an error page for whoever you
send it to.

### Reading the submissions

```python
subs = crs.requests.submissions(req.short_code)

for sub in subs:
    fields = sub.decrypt(req.seed)          # or decrypt_submission(sub.data, req.seed)
    store(fields)   # [{"key": "Staging database password", "value": "...", ...}]

subs.count                                  # what the API said it returned
subs.skipped_not_end_to_end_encrypted       # what it declined to return, and why below
```

`submissions` returns the **sealed blobs**; decryption is a separate call that takes the
seed. That split is deliberate — the SDK never asks for the seed until you decide to read
something. Note what the example does *not* do: printing the decrypted fields writes the
credential a human just handed you into whatever collected stdout.

**One call, no paging.** This endpoint answers with every submission and a `count`, and it
reads neither `page` nor `limit` — so `submissions()` takes neither, and `iter_submissions()`
makes exactly one request and stops. All four SDKs behave this way.

**The two encodings on this one feature.** A request's `public_key` goes out as **unpadded
base64url**; a submission's `data` comes back as **padded standard base64**. Pass `sub.data`
to `decrypt_submission(data, seed)` (or `sub.decrypt(seed)`) exactly as it arrived —
`data` first and named `data`, after the API field it comes from, so
`decrypt_submission(data=sub.data, seed=req.seed)` reads the same in all four SDKs.
Re-encoding it — running it through a base64url encoder because the public key used one —
fails as a *wrong key* rather than as a wrong decoder, which is a long way from the mistake.

Submissions stored before their request had a public key are held server-side in a form the
API *could* decrypt, and it declines to hand them over rather than making a credential a way
to read plaintext. They are counted in `subs.skipped_not_end_to_end_encrypted`, so a
reconciliation against the dashboard can say why a page looks short.

### A reproducible keypair, for automation with no state

Pass your own seed when a runner needs to derive the same keypair on every machine:

```python
from credenshare import crypto

seed = crypto.custody_keypair(crs.credential.custody_secret).seed
req = crs.requests.create(title="Nightly collect", fields=[...], seed=seed)
```

The custody secret is the third part of your credential and never leaves the machine, so the
keypair is reproducible from the credential alone, anywhere, with nothing stored. Revoking
the key revokes the ability to read in the same motion.

### Listing, and the two-step delete

```python
for row in crs.requests.list(limit=50):     # limit defaults to 25, capped at 100
    print(row.short_code, row.expired_at, row.public_key)

result = crs.requests.delete("aB3dEf12")
result.outcome     # "expired" - new submissions stop, existing ones survive
crs.requests.delete("aB3dEf12").outcome   # "deleted" - irreversible
```

Deleting is two calls, not one, and the result says which happened. The second is
irreversible: the sealed submissions go with it, and we never held the seed that could have
opened them.

One asymmetry worth knowing: a request's `passcode` **is** transmitted. It gates a form the
server renders for a stranger's browser, so the server has to be able to evaluate it. A
share's passcode is mixed into the content key and reaches us only as a one-way verifier.
Do not reach for one expecting the other.

---

## Stats

```python
stats = crs.stats.get()
stats.shares.active, stats.shares.expired, stats.shares.total_viewed

for day in stats.daily_views:      # oldest first, zero-filled, may be empty
    print(day.date, day.count)
```

The per-member breakdown the dashboard shows is deliberately absent: a key scoped to read
statistics should not become a way to enumerate colleagues.

---

## Endpoints this SDK does not model

```python
body = crs.call("POST", "/some/new/endpoint", json={"a": 1})
```

Same transport, same retries, same error types. An `Idempotency-Key` is added on a **POST,
PUT or PATCH** when you have not supplied one — the methods that can create, which are the
ones the API consults it on. Never on a GET or a DELETE, where the backend does not read it
and a generated key would buy nothing. Your own key is never overwritten and is forwarded on
any method, `DELETE` included.

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

Versioning, and how a release is cut, is in [`VERSIONING.md`](VERSIONING.md).


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
| `CustodySecretTransmittedError` | the custody half was about to be sent | rotate the credential; it should never have left the machine |
| `RequestSeedTransmittedError` | a request seed was about to be sent | expire the request and create a new one under a new seed — do not retry |
| `InvalidFieldError` | a field is not `{key, value, type}` | `key` is the visible label — not `label`, `name` or `title`. Also a `ValueError` |
| `WebhookVerificationError` | a delivery did not verify | treat it as a forgery, not a transient error |
| `ApiError` | any other refusal | the base class — `err.status`, `err.code` and `err.request_id` carry the detail |

## Requirements

Python 3.9+, with two runtime dependencies: `cryptography` and `httpx`. A client whose entire
claim is that it encrypts correctly should not ask you to trust a long tail of transitive
packages.

## Licence

Apache-2.0. Open source is a requirement here, not a preference: if the client performing the
encryption is closed, the claim that we cannot read your data is unverifiable.
