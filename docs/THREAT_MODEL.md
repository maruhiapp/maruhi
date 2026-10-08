# Threat model

The distilled, reader-oriented version of the threat model that lives inside
the specs. Where the wording differs, the specs govern:
`CRYPTO_SPEC.md` (§14 guarantees/non-guarantees), `AUTH_SPEC.md`,
`AUDIT_SPEC.md` (§6), `docs/REVIEWING.md` (the reviewer-facing map).

## Assets

- Variable values (the secrets) — plaintext exists only in memory, never on
  disk
- Epoch DEKs and the member/reserve keys that unwrap them
- Chain integrity — the membership log is the source of truth for "who may
  see what"
- Name ↔ ID correspondences and schema metadata (a swapped name is a
  secret-leak vector: `DB_URL` pointing to a staging value)

## Trust boundaries

1. **Client ↔ server**: the server is *not trusted* with plaintext or key
   material. Every byte it serves — ciphertexts, wraps, statements, the
   chain — is verified client-side (CRYPTO_SPEC §5.2 / §6.3). A malicious or
   compromised server degrades to availability attacks and detectable
   equivocation, not silent forgery.
2. **Server ↔ other members**: the server also verifies the chain on append
   (defense against rogue clients — the two-wheels model, §6.4).
3. **Web ↔ session**: the session cookie is the credential most exposed to
   XSS, so session principals get a positively-enumerated read-and-revoke-only
   API surface (AUTH_SPEC §4-3). Bulk value pulls and every key-material
   operation are terminal-only.
4. **Device ↔ person**: device keys are separate from the member's person
   key; `revoke_device` stops post-revocation epochs reaching that device
   (CRYPTO_SPEC §14.2-11).
5. **Operator ↔ members** (self-hosting): the operator sees ciphertexts and
   plaintext meta (existence, names, schema) but no DEKs or values.

## Principal attackers and the answers

| Attacker | Answer |
|---|---|
| Server forging values/names/DEKs | Signature verification + epoch-DEK commitments (§14.2-1..4): refused at verification; a colluding key-holder is bounded and attributable |
| Server forking or rolling back the chain | Evidentiary — two signed views at one coordinate are undeniable proof (§14.2-5); detection needs a floor or an out-of-band anchor (§14.3-3) |
| Removed/demoted member or leaked old key | Rotation obligation at removal/scope shrink + epoch consistency (§7, §14.2-3); rotation-needed detection finds the exposure window (AUDIT_SPEC §4.1) |
| Stolen device | `revoke_device` + scope recipient filtering (§14.2-11); its API tokens need separate revocation (SHOULD — client proposes it) |
| Session XSS | Capability restriction to a positive enumeration; no signature-capable operation exists for sessions (AUTH_SPEC §4-3) |
| Non-member probing | Existence concealment — uniform 404 (AUTH_SPEC §11-2) |
| Append-flood chain bloat | Acceptance-policy caps on entry/chain size (§6.4) |
| Post-hoc audit tampering | Cumulative hash notarized in checkpoints; position-monotonic cross-check (AUDIT_SPEC §6) |

## Declared non-guarantees (CRYPTO_SPEC §14.3)

- **Availability** — a malicious server can refuse or delay; not preventable
- **Already-read plaintext** — deletion and revocation stop distribution, they
  cannot un-read what was already fetched (§1 principle 5)
- **Chain freshness without an anchor** — a client with no floor and no
  out-of-band anchor can be shown a stale-but-valid chain
- **Falsehood at record time** — a server that never writes an audit row is
  undetectable; the audit log is server-managed data (AUDIT_SPEC §6)
- **Plaintext meta concealment** — names/existence/schema are visible to the
  server by design (open item)
- **Endpoint/compromise of an authorized client** — a member's key is
  legitimate by definition; mitigation is scope, rotation, and attribution

## Residual risks worth knowing

- Four-eyes quorum is only as strong as owner independence; a person holding
  ≥ required_approvals identities at enablement is outside its reach
  (§14.2-10), and permanent key loss below quorum locks the governed ops
- Checkpoint `values_digest` per-variable non-regression is not cross-checkable
  by chain verification (opaque digest — §6.4); colluding server + current
  member can lower the baseline — reduces to "has legitimate push anyway"
