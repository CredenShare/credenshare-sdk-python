# Changelog

## 0.1.0 — unreleased

First release.

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
