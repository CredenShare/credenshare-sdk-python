# Changelog

## 0.2.0 — 2026-09-02

Secure requests, submissions and account stats. A **secure request** is the mirror image of a
share: you publish a public key, somebody else seals content to it in their own browser, and
the 32-byte seed that opens the result never leaves your machine. Additive — nothing on the
shares surface changed behaviour, and its default page size is still 25.

A minor rather than a patch because this is new public API, and 0.1.4 is already on PyPI.

### Added

- **`crs.requests`** — `create`, `list`, `iter_all`, `get`, `delete`, `submissions` and
  `iter_submissions`. `create` mints the keypair locally, sends only the public half, and
  returns the seed in `SecureRequest.seed`. `delete` returns a `RequestDeletion` of exactly
  two members, `{short_code, outcome}`, the settled shape in all four SDKs — no derived
  `deleted` boolean, because a caller who reads the boolean stops seeing that `"expired"` is
  not a failed delete but the first half of one.
- **`crs.stats`** — `Stats`, `ShareCounts` and `DailyView`. `daily_views` is zero-filled and
  always present, so a day with no views is a row with `count` 0 rather than a gap.
- **`crs.collect_link_for(code)` and `crs.access_link_for(code, seed)`**, plus
  `SecureRequest.collect_link` and `SecureRequest.access_link`. `/r/<code>` is not derivable
  from anything the API returns, and the access fragment is version-prefixed (`"1" +
  base64url(seed)`) — hand-assembly is where that prefix gets lost. The collect link is
  keyless on purpose: holding it lets somebody submit and never read.
- **`Submission.decrypt(seed)`**, beside `decrypt_submission(data, seed)`, so the seal and the
  key meet at one call site. The free function's first parameter is named `data` after the API
  field it comes from, so `decrypt_submission(data=sub.data, seed=req.seed)` reads identically
  in all four SDKs; a positional call cannot tell the difference, which is why it went
  unnoticed while the parameter was called `blob`.
- **`SubmissionPage`** is the name of the submissions container, matching Node, Go and Rust.
  It is still not a page and there is still nothing to walk — no cursor, no `has_more`, no
  next call — and the docstring says so outright, because a caller who trusts the name writes
  a loop that cannot terminate.
- **`SEED_LENGTH`**, exported so a caller storing a seed can check its length without a magic
  32. Named the same in all four SDKs.
- **`RequestSeedTransmittedError`**, raised locally when a seed would have been transmitted.

### Security

- **The seed cannot reach the wire by accident.** `create` scans the SERIALIZED body *and* the
  outgoing `Idempotency-Key` for the seed as unpadded base64url, unpadded standard base64 and
  hex, and refuses rather than sends. An assertion rather than a code review: a seed smuggled
  in through a title, a description or an unknown field member is caught too, and a later edit
  that adds a member carrying the seed fails there instead of in production. The
  idempotency-key half is not hypothetical — `seed` and `idempotency_key` are adjacent
  arguments to the same method.
- **The seed does not print itself.** `SecureRequest.seed` is `bytes` whose `__repr__` and
  `__str__` render `<32 bytes withheld>`, which closes the paths a `__repr__` on the request
  alone does not: `print(req.seed)`, an f-string, `logging.info("%s", seed)`, `pprint` and
  `dataclasses.asdict(req)`. Storing one takes an explicit `req.seed.hex()`. `access_link` is
  a computed property rather than a field for the same reason — a field would put the seed
  back into `asdict`. The `asdict` case is now pinned rather than incidental: that call
  deep-copies each field value and hands back the copy, so `_Seed` defines `__copy__` and
  `__deepcopy__` to guarantee the copy is still the redacting type. It was one before only
  because CPython happens to reconstruct a `bytes` subclass through `__reduce_ex__`, and
  losing the subclass would print all 32 bytes in the one call the redaction most has to
  survive.
- **`SeedKeypair` no longer prints its seed or its scalar.** The generated dataclass repr
  printed both, and the scalar *is* the private key — so a bare `print(keypair)`, a logger or
  a failed pytest assertion put one in the output. The public half identifies it instead.
- A wrong-length seed is now a typed `MalformedKeyError` before anything is derived, rather
  than a bare `ValueError` from inside a crypto primitive.

### Fixed

- **`requests.list` defaults to `limit=25`, not 10.** The server applies 25 to every `/v1`
  list when the parameter is absent and caps it at 100; the published spec says 10 for this
  endpoint and is wrong. Sending 10 would have made the same call return a different page here
  than in the other three SDKs — a breaking correction once published.
- **`requests.submissions` no longer pretends to page.** The endpoint reads neither `page` nor
  `limit` and answers with the whole set plus a `count`, so both parameters are gone and
  `iter_submissions` makes exactly one request and stops — even if a response arrives carrying
  a `pagination` block that claims more. A walk that guessed "another page exists" from a full
  one would re-request identical rows up to the page cap and hand every sealed submission back
  thousands of times.
- The API's own returned-row figure is `SubmissionPage.count` (was `reported_count`), the name
  the other three SDKs use, and it is `None` when the API did not send one rather than being
  silently filled in from the rows. `len(subs)` is what was parsed.
- `DailyView` (was `DailyViewCount`) — one row type, one name, in all four SDKs.
- **The generated `Idempotency-Key` covers POST, PUT and PATCH only, not every non-GET.**
  Filling it in on any non-GET put a header on `DELETE /shares/{code}` — a wire change to a
  surface published at 0.1.4, whose release notes state the shares surface did not change. The
  backend consults the header on creates, so on a delete it was inert: the endpoint is
  idempotent by construction, a repeat is a 404, and there was no second copy of anything for
  a key to prevent. The 0.1.4 delete bytes are reproduced exactly again. A key you supply
  yourself is still forwarded untouched on **every** method, `DELETE` included — the narrowing
  governs only what this client generates.

### Documentation

- The README states the base64 asymmetry that this feature turns on: a request's `public_key`
  travels as unpadded base64url and a submission's `data` comes back as padded standard
  base64. Re-encoding the blob fails as a *wrong key*, not as a wrong decoder.
- The request-field validator no longer claims unknown members are preserved. The API
  unmarshals a request field into `{item, type}` and discards the rest — unlike a share's
  fields, whose extras survive inside the ciphertext. They are forwarded rather than rejected,
  so a member the API learns tomorrow works without an SDK release; nothing should be *kept*
  in one.
- The submissions example stores the decrypted fields instead of printing them. The canonical
  snippet should not teach writing the credential a human just handed over into stdout.

## 0.1.4 — released 2026-08-30

The first version whose install instructions are the registry ones, because 0.1.3 is on the
registries. Also fixes a version string that had drifted.

### Fixed

- **The in-code version constant was stale.** It read `0.1.0` while `0.1.3` was published: the
  release guard compared the TAG to the manifest and never to this second copy. `__version__` now derives from the installed distribution, so it cannot drift again.

### Documentation

- The install line is the registry command rather than a git URL.


## 0.1.3 — released 2026-08-30

No code change from 0.1.2. Cut to exercise the publish path with no stored credential: the npm
`NPM_TOKEN` bootstrap secret is deleted and publication now runs on OIDC trusted publishing, so
nothing long-lived exists in any repository that could publish this package.


## 0.1.2 — released 2026-08-30

The first version published to a package registry. No code change from 0.1.1: the conformance
fixture is byte-identical and every client still reports 24/24. Cut so that the published
version's own release workflow carries the npm OIDC version floor, which is what allows npm
publishing to move off a token immediately afterwards.


## 0.1.1 — released 2026-08-30

`v0.1.0` was tagged before the release-facing files were corrected, so the artifact resolved at
that tag told consumers to install unpinned and its changelog denied its own release. This
version contains those corrections. Nothing about the cryptography or the wire format changed
between the two; the conformance fixture is byte-identical.

### Fixed

- **`iter_all` terminates.** The `has_more` fallback added in 0.1.0 removed a silent
  truncation and left an unbounded walk in its place: against a server that returns full pages
  and sends no counts, `iter_all` was measured yielding 30,001 rows over 301 requests and still
  going. It now refuses a server that echoes a page number other than the one requested, and
  stops at `MAX_PAGES`.
- **`InvalidArgumentError`** is raised for `create(custody=True, item_key_wrap=...)`, which is
  an argument conflict rather than a malformed field. 0.1.0 raised `InvalidFieldError`, whose
  docstring did not cover that call site. Both subclass `CredenShareError` and `ValueError`.

### Documentation

- The README install line names the tag, and the changelog no longer describes 0.1.0 as
  unreleased.

## 0.1.0 — released 2026-08-30

First release.

### Error hierarchy

Everything this SDK raises is now inside `CredenShareError`, and everything the API refused is
inside `ApiError`. Both were true of most errors and quietly false of several, which is the
worst shape for a documented catch-all to have: the branch exists, it looks right, and it
catches nothing.

- **`DeliveryUnknownError` is an `ApiError`.** It replaced `ServiceUnavailableError` on the
  read-timeout path, and that was one. Had it stayed outside, `except ApiError` around a
  create would have stopped catching a case it caught before, and the discovery would have
  been a production incident rather than a compile error.
- **`InvalidFieldError`** replaces the bare `ValueError` from `validate_fields` and from
  `create(custody=True, item_key_wrap=...)`. It subclasses `ValueError` as well, so existing
  handlers keep working. Node's twin is `InvalidFieldError` too.
- **`WebhookVerificationError` subclasses `CredenShareError`** and is exported from the
  package root as well as from `credenshare.webhooks`.

### Fixed

- **`ShareList.has_more` no longer answers `False` when the server omits the pagination
  block**, so `iter_all` no longer stops after page one and reports a fraction of an account
  as all of it. It falls back to `total`, then to whether the page came back full — matching
  Node, Go and Rust, which all did this already. Python was the only one that truncated.
- **Error code 106 (an identical request still in flight) is distinguishable.** It fell
  through to a bare `ApiError`, so the `err.code` discrimination the docs describe could not
  be performed. Both 105 and 106 arrive as `IdempotencyConflictError` now and `err.code` tells
  them apart — they have opposite remedies: 105 means stop and fix the caller, 106 means wait
  briefly and repeat the same request unchanged.
- `_unb64url` validates. `get()` and `expire()` percent-encode the short code. A read timeout
  reports `DeliveryUnknownError` rather than claiming nothing was created. The webhook
  timestamp is parsed canonically.

### Added

- `create(custody=True)`, plus `item_key_wrap` and `organization_id`. Without it every
  API-created share was custody `"none"` — the link was the only way back to the content.
- `webhooks.SIGNATURE_HEADER`, previously private and the only one of the four clients with no
  importable constant for it.

- End-to-end encrypted share creation, listing and expiry against the `/v1` API. Encryption
  happens locally; the content key never reaches CredenShare.
- Split API credentials (`crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]`). The custody
  part is derived from, and never transmitted — the bearer header is assembled from parsed
  parts rather than by trimming the string, so a formatting mistake cannot put it on the wire.
- Webhook signature verification, including the dual-signature rotation grace window and a
  symmetric replay-tolerance check.
- `python -m credenshare.conformance` verifies an installed copy against the wire
  specification's vectors, which ship inside the package.
- Field validation refuses `label`, `name` and `title` where the specification says `key`.
  The API accepts those silently and the recipient view renders every field blank, so the
  refusal is stricter than the wire contract on purpose.
