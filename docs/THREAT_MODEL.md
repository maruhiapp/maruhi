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
   API surface (AUTH_SPEC §5). Bulk value pulls and every key-material
   operation are terminal-only.
4. **Device ↔ person**: device keys are separate from the member's person
   key; `revoke_device` stops post-revocation epochs reaching that device
   (CRYPTO_SPEC §14.2-11).
5. **Operator ↔ members**: by default the operator sees ciphertexts and
   plaintext meta (existence, names, schema) but no DEKs or values — no
   project's DEK is wrapped to the server by default (CRYPTO_SPEC §9).
   **Exception**: once a project owner runs `grant_server` (CRYPTO_SPEC §9 —
   GitHub Actions sync via workload leases §9.1, mirrors §9.2), the in-scope
   epoch DEKs are wrapped to the deployment's public key. Whoever runs the
   deployment holds the matching private key — on a self-host it lives in the
   operator's own Workers Secret — so from that point the operator *can*
   decrypt the granted environments. The disclosure is never silent: while
   the verified chain carries an active grant, every CLI command that opens
   the project states it (project ID, server-key fingerprint, granted
   environments — §9's constant display; the dashboard lists granted servers
   as reported by the server).

## Principal attackers and the answers

| Attacker | Answer |
|---|---|
| Server forging values/names/DEKs | Signature verification + epoch-DEK commitments (§14.2-1..4): refused at verification; a colluding key-holder is bounded and attributable |
| Server rolling back the chain | Evidentiary — two signed views at one coordinate are undeniable proof (§14.2-5); detection needs a floor or an out-of-band anchor (§14.3-3) |
| Server forking the chain per member | A split view is *not* guaranteed to be detected — head gossip's mutual cross-check can be beaten by the server's omission (§14.3-4); out-of-band agreement points narrow the residue |
| Removed/demoted member or leaked old key | Rotation obligation at removal/scope shrink + epoch consistency (§7, §14.2-3); rotation-needed detection finds the exposure window (AUDIT_SPEC §4.1) |
| Stolen device | `revoke_device` + scope recipient filtering (§14.2-11); its API tokens need separate revocation (SHOULD — client proposes it) |
| Session XSS | Capability restriction to a positive enumeration; no signature-capable operation exists for sessions (AUTH_SPEC §5) |
| Non-member probing | Existence concealment — uniform 404 (AUTH_SPEC §11-2) |
| Append-flood chain bloat | Acceptance-policy caps on entry/chain size (§6.4) |
| Post-hoc audit tampering | Cumulative hash notarized in checkpoints; position-monotonic cross-check (AUDIT_SPEC §6, §14.2-7) |

## Declared non-guarantees (CRYPTO_SPEC §14.3)

The spec's explicit list, all ten items — a finding that only restates one
is not a new vulnerability (a way to widen one is):

1. **Availability** — a malicious server can refuse responses, delete data,
   or selectively delay. Repair paths and warnings exist; prevention isn't
   possible.
2. **Plaintext correctness** — a legitimate writer's wrong (or mistaken)
   value can't be prevented: under E2EE the server can't verify values.
3. **First-sync freshness** — a client holding neither a local floor nor an
   out-of-band anchor can be shown an internally consistent *old* view (a
   shortened chain with that time's values/statements/manifests). A rolled
   back view makes a removed member look current.
4. **Split view** — distributing a different internally-consistent view per
   member is *not guaranteed to be detected*: head gossip adds
   detectability but the server can defeat it by selective omission.
5. **Collusion residue** — a key that once held member rights (removed
   member, demoted member, leaked old key) plus the server can inject
   attributed fake values/statements inside that membership interval. The
   forward direction (forging the next version after the real latest) is
   detected only for a floor-holding client via epoch rules; a floorless
   client reduces to item 3.
6. **Leakage / un-revocation** — a member can leak the DEKs and plaintexts
   they hold; cryptography can't un-read an already-read value.
7. **Declaration–value agreement** — agreement between declared
   `var_type`/description and the actual value is advisory only; a signature
   proves "the author declared this type", never that a value was replaced
   in time.
8. **Guardian recovery collusion** — a colluding guardian (one under
   `mode = any`, all under `all`) plus the ward's account authentication can
   restore the ward's reserve key. Out-of-band identity confirmation by the
   guardian is the only defense.
9. **Invite-link interception** — anyone who can read the channel the link
   is passed over can accept under their own key before the legitimate
   counterpart; the backing source and out-of-band confirmation close it.
   **An invite link is passed over a trusted person-to-person channel**
   (normative — AUTH_SPEC §15-3).
10. **Reserve-key exposure** — during a restore from total device loss the
    reserve key sits in the restoring device's memory; a compromised device
    at that moment exposes it. The recovery means is the post-restore
    `key reserve rotate`.

## Residual risks worth knowing

Beyond the §14.3 list (each cites its home section):

- **Audit falsehood at record time** — a server that writes fake rows, or
  never writes one, is undetectable; only notarized prefixes are
  tamper-evident (§14.2-7; the audit log is server-managed data —
  AUDIT_SPEC §6)
- **Plaintext meta** — existence, names and schema fields are visible to the
  server by design (§14.2-9, open item #3)
- **Revoked devices keep API tokens** — `revoke_device` leaves the device's
  tokens able to authenticate until expiry or targeted revocation; they
  read ciphertexts, plaintext meta and self-info but no post-revocation
  values (§14.2-11, AUTH_SPEC §6)
- **CLI login phishing** — the device-code shape is phishable
  (AUTH_SPEC §4-3)
- **Terminal gate bypass** — the value-display gate stops pipes, CI and
  known agents, but an unknown agent or a local process allocating a PTY
  passes (ADR-0016 decision 7); `maruhi run`'s output redaction is
  exact-match and misses transformed output (pf4-design §12)
- **The dashboard is a display, not a verifier** (ADR-0018) — its chain view
  folds the server's report without checking it; use
  `maruhi project verify` for a verified member set
- **Four-eyes quorum is only as strong as owner independence** — a person
  holding ≥ `required_approvals` identities at enablement is outside its
  reach (§14.2-10), and permanent key loss below quorum locks the governed
  ops
- **Checkpoint `values_digest` opacity** — per-variable non-regression is
  not cross-checkable by chain verification (§6.4); a colluding server +
  current member can lower the baseline — reduces to "has legitimate push
  anyway"
- **Open findings** from earlier reviews are tracked in
  [AUDIT_REVIEW_2026-09-26](AUDIT_REVIEW_2026-09-26.md) and
  [SECURITY_REVIEW_2026-08-14](SECURITY_REVIEW_2026-08-14.md)
