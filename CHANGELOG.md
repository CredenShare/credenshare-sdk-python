# Changelog

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
