# Security Policy

maruhi is a diskless secrets manager: security is the product's core, and
reports are taken seriously.

## Reporting a vulnerability

Report privately through **GitHub Security Advisories** ("Report a
vulnerability" on this repository's Security tab). Do not open a public issue
for a suspected vulnerability.

Include: the affected component (CLI / server / web / protocol), a
reproduction or the reasoning that reaches the flaw, and which spec guarantee
it breaks (`docs/CRYPTO_SPEC.md` §14 enumerates the intended guarantees — a
breaking report can name the guarantee).

## Disclosure process

- **Acknowledgement**: reports are acknowledged on the advisory thread —
  the goal is an initial response within 7 days (the project is run by a
  solo maintainer, so a fix timeline can't be promised up front; progress
  is coordinated on the thread)
- **Coordinated disclosure**: a fix lands on `main`, then the advisory is
  published. A report whose fix needs a spec revision goes through the same
  human-review path as any spec change (see `docs/REVIEWING.md`)
- **Embargo**: please keep details private until the advisory is published
- **Credit**: reporters are credited on the published advisory unless they
  prefer to stay anonymous

## What is in scope

- The cryptographic protocol (chain verification, DEK wraps, statements —
  `docs/CRYPTO_SPEC.md`)
- The authorization surface (`docs/AUTH_SPEC.md` — existence concealment,
  session capability restriction, scope)
- The audit log and its tamper evidence (`docs/AUDIT_SPEC.md`)
- The published CLI and the hosted service
- `docs/THREAT_MODEL.md` lists the trust boundaries and the declared
  non-guarantees — a report inside a declared non-guarantee is still welcome
  as an FYI but is not a vulnerability

## For reviewers

`docs/REVIEWING.md` is the guide for external security reviewers: the trust
model, the invariants to attack, the spec-to-code map, and how to re-verify
the test vectors.

## Supported versions

The `main` branch and the latest released CLI version. Self-hosted
deployments are responsible for tracking releases.
