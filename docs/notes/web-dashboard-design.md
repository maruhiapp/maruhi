# Web dashboard screen design (W0 — within ADR-0018's frame)

Position: the origin W0 of Wave 3 W (ROADMAP Phase 2 / session-22 §1). This document settles
`apps/web` (hosted / self-hosted-bundled keyless web)'s **screen set, information architecture,
permission/visibility axes, API gap analysis, and implementation split** as the design document.
The norms (trust boundary, where issuance lives, display discipline) have ADR-0018 (incl.
revision 2) as their source of truth; this document is its screen catalog / implementation
reference. The rulings' course (options considered, rejection reasons) is in
docs/notes/session-39.md (rulings AM–AT).

Premises (decisions not revisited): ADR-0018 decisions 1–4 + revision 1 (don't ship the
decryptor, no screen sharing, ceremonies are TTY, UI contract settled ahead). `maruhi ui`
(stage 2) and the value-bearing UI (stage 3) are out of this document's scope.

## 1. Who sees these screens (persona × chain role × auth state)

| # | Persona | Auth state | Chain role | What they want from the web | Replaceable by CLI? |
|---|---|---|---|---|---|
| P1 | Visitor who came to learn about the product | Unauthenticated | none | Landing / docs navigation | No (web-specific) |
| P2 | Person who opened an invite link | Unauthenticated (incl. unregistered) | none (invited role undecided) | Guidance on "what to do next" | No (the link's landing point is the web origin) |
| P3 | Member (reader / member) | Session | reader / member | Browsing their project's current state (members, environments, variable names, rotation-needed, audit class 1) | Yes (TUI), but browser browsing may have its own demand (unmeasured) |
| P4 | Admin (admin / owner) | Session | admin / owner | Audit (incl. class 2), inventory and revocation of invites and tokens | Yes (`maruhi audit` / `invite` / `rotation`) |
| P5 | Stakeholder without the CLI (an audit-view-only interested party — the recipient of session-29 §4's "hand them a keyless admin screen") | Session | reader (invitable without involvement in value decryption) | Read-only audit / status browsing | No (the premise is that they don't install the CLI) |
| P6 | Agent / automation | Token / OIDC | any | — | Outside the web's scope (API / CLI / leases are the official path. Web sessions are human OAuth only) |

Observations:
- The only personas **only the web can satisfy** are P1, P2, P5. P1 and P2 are satisfied by
  unauthenticated static pages. P5 is satisfied by authenticated **reading** (there's no
  operation P5 should perform)
- P3 and P4's demand is met by the CLI / TUI (stage 1) and unmeasured even in dogfooding
  (ADR-0018 Rationale (3)). Where the web reliably adds value is "inventory and revocation"
  (listability suits the browser, and revocation moves toward reducing credentials so the XSS
  blast radius is small)
- Operations involving values, keys, or chain writes (push / invite acceptance / member add /
  grant_server / key generation / recovery) are out of scope from the start per ADR-0018
  decision 1

## 2. Comparison of shapes and the conclusion

Comparison of 3 shapes (the 3-round comparison and rejection reasons are in session-39 ruling
AM):

- **(a) Minimal static-guidance-page form**: unauthenticated static pages (S1, S2) only.
  Management and browsing all go to the CLI / `maruhi ui`. The operator's delivery surface is
  minimal, but P5 (stakeholders without the CLI) is structurally cut off, and the home for
  ROADMAP Phase 2's audit UI (W2) disappears
- **(b) Keyless admin screen (the full allowlist of ADR-0018 decision 1)**: includes invite-link
  issuance and token management. Issuance is credential generation (revision 1, item 5), and the
  invite link's out-of-band anchor (AUTH_SPEC §15-3's `h` / `s` / `if`) additionally requires the
  issuing client's **verified head and key FP** — keyless web has neither, so it would normalize
  anchor-less links
- **(c) Intermediate form (adopted)**: static pages + authenticated **reads** + **revocation
  mutations only**. The boundary principle = "**mutations on the web are limited to ones that
  reduce credentials / visibility (revocation, logout). No credential generation (invite
  issuance, token issuance), no warning dismissal (rotation dismiss), no chain writes**"
  (ADR-0018 revision 2)

The adopted form (c) can degenerate to (a) screen by screen (dropping any authenticated screen
doesn't break the others), preserving each stage's independent stoppability (ADR-0018's
character) at the screen level too.

## 3. Screen list and gap analysis

For each screen: target persona / implemented APIs it uses / missing APIs (**enumeration only —
not implemented in this PR**). Authorization is always server-side (§11-2's existence
concealment, §12-3's table, AUDIT_SPEC §6's visibility classes) as the source of truth; the web
just renders the results.

### S1. Landing (static, unauthenticated)

- Target: P1. Lineage of the current `HomePage`. No API needed. No gap

### S2. Invite guidance `/invite` (static, unauthenticated)

- Target: P2. **Fully static**: displays only guidance that acceptance happens in the CLI, and
  does **not interpret** the URL fragment (AUTH_SPEC §15-3 revision, ADR-0018 revision 2.
  History in session-39 ruling AR)
- **The invariant is enforced by configuration (session-39 §10 — round 4)**: `/invite` is
  delivered as an independent static HTML asset **outside** the SPA (the funstack bundle — which
  carries an inline bootstrap script), with a per-path CSP `script-src 'none'` placed in
  `_headers` (an extension of `write-headers.ts`). "No script touches `location`" becomes a
  checkable configuration rather than a convention
- No API needed. No gap

### S3. Login (web OAuth)

- Target: P3–P5. Implemented: `GET /auth/github/start` / `callback` (AUTH_SPEC §3), sessions
  (§5), `GET /auth/me`. No gap

### S4. Project list

- Target: P3–P5 (the starting point after login)
- Implemented APIs: **doesn't stand without one**. `/auth/me` returns only orgs; the source of
  truth for project membership is the chain-derived state inside each project DO (CRYPTO_SPEC
  §6.4), and no cross-cutting index exists
- **Missing API (resolved in W2a — rulings BI–BK of 2026-08-29, norm in AUTH_SPEC §11-5)**:
  "the list of projects where the caller is a chain-derived member" = `GET /projects`. The
  adopted shape is **a role-less D1 projection (`project_members` — a candidate index
  maintained at chain acceptance) + read-time membership confirmation against each project
  DO** (ruling BI-c — history including rejected options is in session-42.md). Org-mediated
  candidate enumeration was rejected (chain membership is org-independent — §9-2 — so it
  structurally drops invite-path cross-org members = P5's main use); projection-only was also
  rejected (ghost rows after expulsion don't self-heal). The response is only the caller's own
  membership (minimal form: `projectId` + chain-derived `role`), consistent with §11-2
  (existence concealment) — it takes no target specifier and out-of-scope is non-appearance.
  **Include this API in the session permission enumeration (AUTH_SPEC §5)** (S4 is a session
  screen — missing the enumeration means W2b 403s this screen. Fixed in session-39 §10. The
  `SESSION_ALLOWED_ENDPOINTS` addition is in the W2a implementation PR — implemented)
- Interim degradation: even without the list API, S5 onward works by manually entering a project
  ID (genesis hash = capability) (bookmark operation). W2 can ship before W2a (→ in the W2
  implementation, direct ID entry is promoted to a **formal auxiliary path** coexisting with the
  list — permanently supporting bookmark operation and direct access during list outages)

### S5. Project overview (members, environments, variable names, epochs)

- Target: P3–P5. Reads only
- Implemented APIs: chain fetch (§11 — members, role, grant_server, head declarations
  `attestations` included), environment list (§12-4), metadata-only pull (§12-7 — variable
  names, statements, manifest. Records no `var.read`, so browsing doesn't pollute the audit. A
  GET with no state needs no CSRF header)
- No gap. Display discipline: everything is a **server-declared display** (see §4). No chain
  verification is implemented — the member list, roles, FPs are displayed as "server
  declarations"

### S6. Audit viewer

- Target: P4 (incl. class 2), P3 / P5 (class 1 + own rows)
- Implemented APIs: `GET /projects/:id/audit/events` (row_id cursor, filters, visibility classes
  at the server authz stage — AUDIT_SPEC §7), `GET /projects/:id/audit/invites` (chain-role
  admin axis), `GET /auth/audit/events` (self axis)
- No gap. Display discipline: `seq` is included only in admin responses and may be displayed
  as-is (zero new information — ruling C1). However, **the web makes no completeness claims
  like gap checks or mirror matching** (the domain of `maruhi audit verify` / `reconcile`).
  Lists for below-admin use the wording "events visible at your role" and never hint at the
  count or existence of invisible classes (count non-disclosure — AUDIT_SPEC §7)

### S7. Rotation-needed flags

- Target: P3–P5 (class 1 — all members)
- Implemented API: `GET /projects/:id/rotation/flags` (derived view)
- No gap. **No dismissal** (warning removal — §2's boundary principle. Guide to CLI `maruhi
  rotation dismiss`). Display-name resolution is identifiers only + alongside the
  metadata-only pull's statement names (server-declared display)

### S8. Invite management (list, revoke)

- Target: P4 (chain role admin or above — AUTH_SPEC §15-2)
- Implemented APIs: `GET /projects/:id/invites` / `DELETE /projects/:id/invites/:id`
- No gap. **No issuance** (ADR-0018 revision 2 — missing anchor + capability generation.
  session-39 ruling AN). The screen statically carries issuance-procedure guidance (`maruhi
  invite create`)

### S9. Token management (list, revoke)

- Target: P3–P5 (own tokens only — a user-scoped resource)
- Implemented API: `POST /auth/token/revoke` is **revocation of the presented token itself,
  token-principal only** (for CLI logout) and can't be used from a session-principled web
- **Missing APIs** (designed in the AUTH_SPEC §6 revision — implemented in W3a [2026-08-30]):
  1. List `GET /auth/tokens` (id / name / token_prefix / scopes / created_at / last_used_at /
     expires_at. **Raw values and hashes are never returned**)
  2. Designated revocation `DELETE /auth/tokens/:tokenId` (session principal or `*` × admin
     token — same level as §13-2's key-material conditions. Non-matching gets a uniform 404)
- **No issuance or raw-value display** (the issuance path stays device flow only — ADR-0018
  revision 2, AUTH_SPEC §6 revision. The raw value's only place of existence is the terminal
  display at issuance time)
- Resolved alongside: the default TTL (SECURITY_REVIEW L-2 — included in the AUTH_SPEC §6
  revision. Implemented in W3a — the migration rule and explicit TTL are rulings CE / CF in
  session-44.md)

### S11. Device registry (read + revocation of bound tokens — 2026-09-21 DK K5 addition)

- Target: P3–P5 (own registry only — a user-axis resource. Independent route
  `/dashboard/devices`, same placement as S9 — ruling CP). The rulings' course is in
  docs/notes/dk-design.md §10 (K5-7–K5-10)
- Implemented APIs: `GET /auth/devices` (AUTH_SPEC §13-11 — inside the session permission
  enumeration) + S9's `GET /auth/tokens` / `DELETE /auth/tokens/:tokenId` (the tokenId match and
  the revocation path)
- **The registry is advisory** (the home for display names and token correspondence — never an
  input to verification or authorization). The device keys' source of truth is each project's
  chain, and S5's Members table emits `add_device` / `revoke_device` folds (device count, FP,
  cap) as "server declarations". S11's descriptive text says "as reported by the server; the
  chain is the source of truth — `maruhi device list` verifies it", and always places the
  full-length FP next to each display name (a display-level hedge against display-name spoofing)
- **What it doesn't carry**: registration / display-name updates / deletion / approval of
  addition requests (all are APIs session principals are denied, and also hit ADR-0018 revision
  2's chain-write and credential-generation bans). The chain's `revoke_device` isn't performed
  from the web either. What it does carry is the loss-time path = existing token revocation
  (S9's permitted mutation as-is — "Lost a device? `maruhi device revoke <fingerprint>` from
  another device, then revoke its API token here")
- No gap (the wire shortfall — `add_device` entries not carrying the FP — is absorbed by S5's
  fold side as a degraded form [not reported / unresolved], owner decision — dk-design.md §10
  K5-1)

### S10. (Optional, later) session list / revocation

- Target: P3–P5. Implemented API: `POST /auth/logout` (current session only)
- **Missing API**: list of own sessions and designated revocation. AUTH_SPEC §5 prescribes
  "immediately revocable via server-side deletion", but the API surface for list / designated
  revocation is undesigned. It's a revocation-family feature so it fits the boundary principle —
  designed as a §5 revision when demand appears (excluded from v1's screen set)

## 4. Display discipline (the keyless web's position on the TCB)

ADR-0018 revision 2's norm. Rationale and rejected options in session-39 rulings AP, AQ:

1. **Implement no verification, claim no "verified"**: don't put chain-verification or
   signature-verification code in the web bundle. The composition where operation-delivered JS
   draws its own "verified" badge makes the verifier and the data distributor the same trust
   domain — verification theater (same argument as ADR-0018 Context). All displays are "server
   declarations (as reported by the server)" and the UI copy says so
2. **Verification is the CLI's domain**: situations needing verified display (chain / audit
   matching) are guided to `maruhi project verify` / `maruhi audit verify` / `reconcile`
3. **Fingerprints (FP) are reference values, not matching material**: ceremonies (mutual
   confirmation) are TTY (ADR-0018 revision 1, item 2). FPs displayed on the web are reference
   values for matching against audit rows / chain displays; no wording readable as "match this
   screen's FP" is placed
4. **Visibility wording**: below-admin audit lists say "events visible at your role". Never hint
   at the existence or count of invisible classes (AUDIT_SPEC §7)
5. **English** (ADR-0017): all user-visible web copy is in English

## 5. Permission × screen visibility matrix

| Screen | Unauthenticated | reader | member | admin | owner |
|---|---|---|---|---|---|
| S1 landing / S2 invite guidance | ○ | ○ | ○ | ○ | ○ |
| S3 login | ○ | — | — | — | — |
| S4 project list | × | ○ | ○ | ○ | ○ |
| S5 project overview | × | ○ | ○ | ○ | ○ |
| S6 audit (class 1 + own rows) | × | ○ | ○ | ○ | ○ |
| S6 audit (class 2, seq) | × | × | × | ○ | ○ |
| S7 rotation-needed flags | × | ○ | ○ | ○ | ○ |
| S8 invite management (list, revoke) | × | × | × | ○ | ○ |
| S9 token management (own) | × | ○ | ○ | ○ | ○ |
| S11 device registry (own — read + bound-token revocation) | × | ○ | ○ | ○ | ○ |

- The source of truth is server authorization (§11-2 / §12-3 / AUDIT_SPEC §6). The table is UI
  differentiation, not defense. The boundary (§2's principle) is enforced in 2 layers:
  1. **Don't put the capability in the bundle** (the code paths for issuance, acceptance,
     dismiss, decryption don't live on the web — ADR-0018 decision 1's discipline). But this is
     **no boundary against same-origin XSS**: XSS isn't confined to the bundle's code paths and
     can call arbitrary APIs with the victim's session cookie (+ self-attachable `x-maruhi-csrf:
     1`) (PR #103 pullfrog review finding)
  2. **Server-side session-principal capability limits** (AUTH_SPEC §5 — restrict the APIs a
     session principal can call to the positive enumeration "reads + revocation family + auth
     family". Ruling AT, implementation = PR-W2b). The boundary principle only becomes enforced
     at this layer

## 6. XSS blast-radius evaluation (the adopted form (c)'s residual)

The web being TCB (CLAUDE.md) is unchanged even keyless. The evaluation's basis: XSS can issue
arbitrary `fetch` from the same origin, the session cookie rides along, and the CSRF header can
be self-attached — so "not placed on screens / the bundle" doesn't shrink the blast radius;
**only the set of APIs the server permits to session principals** does (reflecting a PR #103
pullfrog review finding — the initial draft lacked this distinction). Total-loss scenarios under
the adopted form:

- **Structurally impossible (independent of server implementation's current state)**: value /
  key decryption (no key exists in the browser), chain writes / value pushes / meta operations
  (require signatures by chain-derived sig keys; XSS can't produce a signature), maruhi token
  issuance (device flow requires presenting a GitHub access token — §4)
- **Denied by session capability limits (AUTH_SPEC §5 — ruling AT. Implementation = PR-W2b)**:
  invite issuance (generating a raw invite token = a bearer capability) and acceptance (binding
  the attacker's key's user_id — a surface short of FP mutual confirmation), rotation dismiss
  (removing class-1 warnings), recovery blob registration / retrieval (replacement =
  availability attack, retrieval = monitored), DEK-wrap deletion (§12-6's repair path — the only
  destructive family without a signature), value-bearing bulk pull (polluting the audit trail —
  further shrinking SECURITY_REVIEW L-1's residual). **Until W2b is implemented, these are
  currently reachable from an admin session's XSS** (the server currently treats session
  principals as full-power without scope checks — the current behavior of
  `ensureTokenScopeForProject` / `ensureKeyMaterialAccess`). The ordering constraint — W2b lands
  before W2 (the first session-bearing screens) — comes from here
- **What remains (the adopted form's accepted residual)**: viewing of metadata (project /
  environment / variable names, members, FPs, the visible portion of audit) via session riding,
  and abuse of the revocation family (revoking tokens / invites = recoverable DoS)
- Existing defenses stay: strict CSP (hash-allowlisting only the self-built bootstrap script),
  self-serving, `x-maruhi-csrf`, HttpOnly sessions

## 7. Implementation split plan (W1 onward — session-27 §14 format)

1. **PR-W1: statically reduced form** — web (add S2 `/invite` as **independent static HTML
   outside the SPA** + per-path CSP `script-src 'none'` [write-headers.ts extension] + S1
   cleanup + confirmation of `_headers` / CSP application). The implementation of AUTH_SPEC
   §15-3's revision (approved in this PR). No server / API changes. **Stopping here stands as
   form (a) (the minimal static-guidance form)**
2. **PR-W2a: project-list API** — server (`GET /projects`, a cross-cutting list of chain-derived
   membership. Adopted shape = role-less D1 projection [candidate index] + read-time DO
   confirmation — rulings in session-42.md BI–BK, norm in AUTH_SPEC §11-5) → api-schema (+
   addition to `SESSION_ALLOWED_ENDPOINTS`) → CLI (`maruhi project list` — as the same API's
   first consumer, verifying the server implementation first). No web changes
3. **PR-W2b: session-principal capability limits** — server (implementing AUTH_SPEC §5's
   positive enumeration: sessions get 403 on every endpoint outside "reads + revocation family +
   auth family". Includes check-order consistency with §11-2's existence concealment and
   acceptance-path fixture tests). api-schema changes only if ForbiddenError needs a declaration
   addition. No web changes. **Independent of W1 / W2a — can land anytime first** (no
   session-bearing screen exists on the web yet, so zero user impact). **Prerequisite of W2**:
   shrink the session's XSS blast radius per §6's evaluation before the first session-bearing
   screen ships. **Recommended as the W series' first implementation PR** (a pure defense
   strengthening with zero dependencies — no reason to wait — session-39 §10). The
   implementation form follows AUTH_SPEC §5's recommendation of baking declarations into the
   endpoint contract (the same single implementation point as §12-10 (1)), and W2a's
   project-list API (session-permitted — S4) is added on the declaration's permitted side
4. **PR-W2: read-only dashboard** — web (S3 login, S4 list, S5 overview, S6 audit, S7 flags.
   All consume implemented APIs + W2a's only). Implements the display discipline (§4).
   **Stopping here = a read-only dashboard** (covers P5's demand too). Delivery is a
   **same-origin single Worker** (maruhi-server bundles and serves the web assets — the shape
   independently required by 3 constraints: `__Host-` sessions, `connect-src 'self'`, the OAuth
   callback. Ruling and rejected options in session-43.md BM)
5. **PR-W3a: token-management API + TTL** — server (`GET /auth/tokens`, designated revocation,
   default TTL = implementing the AUTH_SPEC §6 revision) → api-schema → CLI (re-login guidance
   on expired 401 + `--token-ttl-days`). No web changes. **Implemented (2026-08-30 — rulings
   CE–CH in docs/notes/session-44.md)**. The migration rule adopts not the initial option
   (non-retroactive) but **re-anchoring existing non-expiring rows to "application time + 90
   days" + NULL fail-closed on the verification side** (non-retroactivity was rejected for
   permanently sheltering L-2 in existing rows — ruling CE). Unattended use on
   lease-non-supporting runtimes (§8 handoff) is resolved by explicit TTL at issuance
   (`expiresInDays` 1..365) (ruling CF)
6. **PR-W3b: revocation-family screens** — web (S8 invite management, S9 token management).
   Depends on W3a. **Implemented (2026-08-30 — rulings CN–CQ in docs/notes/session-45.md)**:
   S8 is ProjectScreen's 4th tab; S9 is the independent route `/dashboard/tokens` (ruling CP).
   Revocation is inline 2-step confirmation (ruling CO); expired and pre-migration null rows get
   an Expired server-declared display (ruling CQ). This completes the W series (adopted form
   (c))
- Dependencies: W1 is independent. W2 depends on W2a (can lead via interim manual ID entry — §3
  S4) and **W2b (required — the ordering constraint is §6)**. W3b depends on W3a. W2a / W2b /
  W3a are mutually independent and can run in parallel. All independent of `maruhi ui` (stage 2)
  and the theme MIT-ization (the web side consumes the theme as-is)
- Per-stage stoppability: W1 alone = form (a). W2b alone also stands as an independent defense
  strengthening. Through W2 = read-only. Through W3 = the adopted form (c) complete. The
  intermediate state after any stage stands independently

## 8. Out of scope / handoffs

- `maruhi ui` (stage 2) proper, concretization of the UI contract, theme MIT-ization (ADR-0018
  decision 4 — still a stage-2 prerequisite)
- Value-bearing UI (stage 3 ADR), shell selection (revision 1, item 3)
- S10 session-management API (an AUTH_SPEC §5 revision when demand appears)
- ~~**The collision between PAT unattended use on lease-non-supporting runtimes (GitLab CI /
  k8s etc. — AUTH_SPEC §14-1's supported issuer is v1 = GitHub Actions only) and the default
  TTL**: becomes a shape requiring re-login (human intervention) every 90 days. The treatment
  (allow explicit TTL at issuance [with a cap], or solve by expanding supported issuers) is a
  ruling at W3a implementation time. The option of reverting to a non-expiring default is not
  taken (reintroducing L-2 — the handoff from PR #103's pullfrog review finding)~~ **Resolved
  (2026-08-30, W3a ruling CF — session-44.md)**: adopted explicit TTL at issuance
  `expiresInDays` (1..365 — the cap is enforced by the wire Schema). Expanding supported issuers
  stays as a non-exclusive long-term path (an AUTH_SPEC §14 future extension). Not reverted to
  a non-expiring default
- ~~Cross-cutting search UX spanning audit UI visibility classes (advanced class-2 filters) is
  deferred to W2's implementation ruling (the API is already implemented and doesn't
  constrain)~~ **Resolved (2026-08-29, W2 ruling BQ — session-43.md)**: W2's audit UI is a
  filter-less single chronological list + `before` cursor, with no class-naming UI or advanced
  filters (exposing the class structure in the UI itself would hint at the invisible set). The
  `seq` column is response-adaptive (shown if present), not duplicating role pre-determination
  into the client. Advanced cross-cutting search stays the CLI's (`maruhi audit`) domain;
  re-rule if demand is measured
- Deploy to Cloudflare button verification and the docs site (G) are a separate task (ROADMAP)
- **Member-management UI (future item — record of the 2026-08-31 owner brain dump)**: for user
  convenience, there's demand for managing team members (addition, invites, approval, etc.) from
  web screens. Under E2EE, adding a member = wrapping the DEK to the new member's public key (a
  cryptographic operation), which the keyless web (ADR-0018 / AUTH_SPEC §5's capability limits)
  can't complete alone. Draft policy directions: ① The parts needing no key (viewing the member
  list, invite **revocation** — the existing lines of S5 / S8) can be expanded directly on the
  web. Invite **issuance** is not included here — ADR-0018 revision 2 decision 2 already
  explicitly excludes it from the web (the out-of-band anchor [§15-3's `h` / `s` / `if`]
  requires the issuer's verified chain state and key FP = issuance is precisely the
  key-requiring side + capability generation). Web issuance demand is met by ②'s two-sided
  handoff (filed on the web → issued on the CLI). ② The key-requiring parts can be realized via
  a two-sided handoff "**filed on the web → confirmed and executed on a key-holding CLI**" —
  reusing AUTH_SPEC §4's (2026-08-31 revision's CLI login handoff) flow rows, single-use
  tickets, and polling parts in the reverse direction, gaining the screens' convenience without
  giving the web keys. ③ If the session capability line moves (§5 / §15-2 / ADR-0018), it's
  filed as an independent ruling (not a §4 revision). Start timing undecided — this item is a
  record only
