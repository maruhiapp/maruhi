# Session 39 notes (W0: Web dashboard screen design + re-ruling ADR-0018 revision 1's item 5)

Date: 2026-08-28. Target: W0, the starting point of Wave 3's W (screen design — ROADMAP
Phase 2 / session-22 §1) + a re-ruling of ADR-0018 revision 1's item 5 handoff (the
boundary of token issuance and raw-value display). No implementation — only design, rulings,
and drafting of ADR-0018 revision 2 / the AUTH_SPEC revision. The ruling process follows the
goal's instruction: "multiple candidates → superior-alternative search → 3 rounds of
comparison → autonomous selection". Ruling codes continue from session-38 (AF–AL): AM onward.

Deliverables: docs/notes/web-dashboard-design.md (the W0 design document — the screen set,
gap analysis, implementation split W1 onward), ADR-0018 revision 2, AUTH_SPEC 0.13-draft
(§6 / §15-3), and this note. Approval = PR review (merge constitutes owner approval).

## 1. Ruling AM: the overall shape of the keyless Web (static minimal / the whole allowlist / middle ground)

### Round 1

- **Option AM-a: static guidance pages only, minimal** (management also goes to `maruhi ui`.
  The comparison target ADR-0018 Consequences required) — minimizes the operator's serving
  surface and zeroes the authenticated surface's XSS blast radius. However, the persona
  analysis (design document §1) structurally cuts off P5 (stakeholders who will not install
  the CLI — the recipients of session-29 §4's "hand them a keyless management screen"), and
  the home of ROADMAP Phase 2's audit UI (W2) also disappears. `maruhi ui` is local to each
  person and does not reach "people who won't install the CLI" — (a) converts P5's need into
  "make them install the CLI", which is an over-demand of keys and ceremonies on someone for
  whom a reader role + read screens suffice
- **Option AM-b: a keyless management screen (the whole of decision 1's allowlist)** —
  including invitation-link issuance and token management (with issuance). Both issuance
  operations are credential generation (revision 1's item-5 point), and invitation issuance
  additionally carries the anchor-loss problem (ruling AN). A conflation of "no decryption
  needed" with "low risk" remains
- **Option AM-c: the middle form — static + authenticated reads + revocation-family
  mutations only** — excludes issuance and limits mutations to "the direction that reduces
  credentials / visibility"

### Round 2 (superior-alternative search)

- Whether AM-c's boundary can be promoted from an ad-hoc screen list to a **principle**: "the
  only mutations placed on the Web are revocation and logout (they reduce credentials).
  Credential generation (invitation issuance, token issuance), warning dismissal (rotation
  dismiss), and chain writes are never placed". Where rotation dismiss falls is the litmus
  test of this principle — dismiss needs no decryption and generates no credential, but it is
  **a governance operation that erases a class-1 warning for every member** (AUDIT_SPEC §3.3),
  and would give XSS a surface for silencing warnings. Stating the principle as "only the
  reducing direction" drops dismiss naturally onto the CLI side — no exception list is needed,
  and the judgment for future screen additions becomes unique. Adopted
- **Option AM-d: (c) + relaxing the write family to "allowed with a confirmation"** —
  dismissed: the confirmation UI is drawn by the same bundle (self-confirmation, the same
  shape as the UI-contract signing-oracle problem — session-30 §1). The presence of a
  confirmation is not a boundary

### Round 3 (re-inspection)

- Re-evaluating the XSS blast radius (design document §6): (c)'s worst case = metadata
  viewing + revocation DoS (recoverable). **Correction (PR #103 pullfrog review finding)**:
  the original draft wrote "issuance and dismiss are structurally impossible", but that was
  wrong — omitting them from the bundle is not a boundary against same-origin XSS (XSS can
  issue arbitrary fetches with the session + our own CSRF header); what is structurally
  impossible is only operations requiring decryption / signing of values and keys (chain
  writes, push, meta operations) and maruhi-token issuance (the device flow demands a GitHub
  token). Invitation issuance / acceptance, dismiss, recovery blobs, DEK deletion, and
  value-bearing pulls are all **currently permitted to a session principal** by the server.
  Making this evaluation hold requires server-side session-capability restriction → ruling AT
  builds it into the design
- Degenerability: (c) can degenerate screen-by-screen into (a) (stopping after W1 alone is
  (a) itself — design document §7). ADR-0018's "each stage can be stopped independently" is
  preserved at the screen level
- Reversibility of choosing not to take (a): if demand for authenticated screens (P3–P5) is
  not measured, stopping W2 onward returns to (a). The reverse ((a) to (c)) involves closing
  API gaps and is expensive — when in doubt, stand on the degenerable side

**Choice: option AM-c** (with the boundary principle). Fixed in ADR-0018 revision 2, item 1.

## 2. Ruling AN: excluding invitation-link issuance from the Web (revising decision 1's allowlist)

### Round 1

- **Option AN-a: issuance on the Web too (anchorless links)** — dismissed: an invitation
  link's fragment (AUTH_SPEC §15-3) carries the out-of-band anchors `h` / `s` (the issuer's
  verified head) and the mutual-confirmation material `if` (the issuer's key FP). The keyless
  Web holds neither verified chain state nor keys and cannot embed these. Making anchorless
  links the normal path would normalize second-class links that lack detection material for
  rollback / fork distribution to new members (floor-less first sync = CRYPTO_SPEC
  §14.3-3's dominant residual) (§6.3 out-of-band anchor (a)), and the accepting CLI would
  gain a branch that accepts the omission without warning (a regression of fail-closed)
- **Option AN-b: Web issuance + embedding the server-declared head in the fragment** —
  dismissed: an anchor's meaning is "a verified value not routed through the server"; the
  moment a server-declared value is embedded it dies as a detection mechanism (a malicious
  server declaring an old head gets the anchor to ratify it — poisoning)
- **Option AN-c: issuance only via the CLI / `maruhi ui`. The Web goes as far as listing /
  revocation** — issuance is also the generation of an invite token (a bearer capability) and
  aligns with the same "generates no credentials" side as the token boundary (ruling AO)

### Round 2 (superior-alternative search)

- **Option AN-d: AN-c + statically placing issuance guidance (`maruhi invite create`) on the
  Web's invitation-management screen** — fills the navigation gap ("there is no issue button")
  with guidance. Zero added code paths. Adopted as AN-c's superior alternative

### Round 3 (re-inspection)

- Confirmed that listing / revocation stay as-is: invitation listing and revocation
  (AUTH_SPEC §15-2 — admin) are inventory-taking and credential reduction, fitting AM's
  boundary principle. Revision 1 already established "listing and revocation stay" on the
  token side, and the invitation side aligns the same way
- Because ADR-0018 decision 1's allowlist explicitly includes "invitation-link issuance",
  this is a **revision of a decision** — presented as ADR revision 2 (not relitigating; it is
  the invitation version of the "re-ruling credential generation" opened by revision 1's item
  5. The anchor loss is a new fact unremarked at revision 1's time)

**Choice: option AN-c + AN-d**. ADR-0018 revision 2, item 2.

## 3. Ruling AO: the token boundary (resolving revision 1's item 5) + handling L-2

### Round 1

- **Option AO-a: an issuance UI on the Web (the raw value shown once in the issuance
  response)** — dismissed: today a token defaults to all-project admin, no expiry (AUTH_SPEC
  §6 / SECURITY_REVIEW L-2). XSS would make "issue itself a high-authority token and carry it
  out" one step — even if the keyless Web protects values, an attacker with a credential-
  generation surface reaches the values via CLI / API (routing around the boundary). The raw
  value entering the DOM is also revision 1's item-4 (extension contamination) surface
- **Option AO-b: Web is listing / revocation only. Issuance stays on the device flow
  (terminal) only** — the issuance API is **not added at all** (the current sole issuance
  path = device flow is kept), so the attack-surface increment is zero. The raw value's only
  place of existence stays fixed at "one display on the terminal at issuance"
- **Option AO-c: issuance on `maruhi ui` + a DOM raw-value display** — dismissed: even on
  localhost, a browser extension's content script can touch the DOM (session-30 §2 — LNA does
  not apply to extensions). Extensions cannot touch a terminal's issuance display — that
  difference vanishes the moment the raw value enters the DOM (the same composition as
  session-29 §7-2)

### Round 2 (superior-alternative search)

- **Option AO-d: AO-b + also codify the terminal-only rule of the raw value for `maruhi
  ui`** — ahead of the stage-2 design, fix in the ADR "the token raw value never enters ui's
  DOM (issuance and display are terminal)". Revision 1's item 5 explicitly required this as
  ruling material, and not deciding it here passes the same undecided item into stage-2
  design. Adopted
- **Option AO-e: create the issuance API and allow issuance from ui under a per-operation
  contract (revision 1's item 1)** — dismissed (this time): demand is unmeasured (dogfooding
  runs on the device flow). If it becomes necessary, the stage-2 UI-contract design can add
  it as a ceremony-style operation — "ui requests issuance; the raw value is displayed on the
  key-holding process's terminal" (AO-d does not block that — it only fixes the discipline of
  never entering the DOM)

### Round 3 (re-inspection)

- **Handling L-2 (no expiry)**: SECURITY_REVIEW's handoff reads "together with the token-
  management UI design and the spec revision" — this ruling is that point in time. Once a
  listing UI is designed, there is no option of leaving a "no expiry" column it lists as the
  spec's default. The AUTH_SPEC §6 revision includes **a default TTL (draft value 90 days) +
  renewal on re-login (same-name rotation)**. Retroactive application to existing tokens is
  delegated to the implementation PR's (W3a) migration rules (the spec sets the default for
  new issuance). **Correction (PR #103 pullfrog review finding)**: the original draft's
  "unattended workloads like CI use leases, so a TTL does not collide with unattended
  operation" was an overclaim — the only lease-capable issuer in v1 is GitHub Actions
  (§14-1), and GitLab CI / k8s / cron etc. can only use PATs, needing human intervention every
  90 days. The limitation is stated in §6, and the handling (an explicit TTL designation
  [with a cap] or extending issuers — never returning to a no-expiry default) is handed off
  to W3a
- Confirming the missing APIs: the current `POST /auth/token/revoke` **revokes the presented
  token itself and is token-principal-only** (for CLI logout — handlers-auth.ts), unusable
  from a session-principal Web. A listing API (returns no raw values or hashes) + targeted
  revocation (session principal or `*` × admin tokens — the same level as §13-2's
  key-material condition) are designed in the §6 revision (implementation is W3a). No rename
  API is built (re-issuing under the same name = rotation suffices; it adds no extra write
  surface)
- Confirming the authority level of targeted revocation: revocation is in the credential-
  reducing direction, but "revoking another token" from a scoped token could be an
  availability attack (stealing the CI token to delete work tokens), so it sits at the same
  "session or `*` × admin" as §13-2

**Choice: option AO-b + AO-d + handling L-2 in the same §6 revision**. ADR-0018 revision 2,
item 3; the AUTH_SPEC §6 revision.

## 4. Ruling AP: whether chain verification is needed on the keyless Web, and the display discipline

### Round 1

- **Option AP-a: put verification code (@maruhi/crypto's verify subset) in the Web bundle and
  show "verified"** — signature verification is possible with public data only, so it is
  technically feasible. Dismissed: the verifier (the Web's JS) and the data distributor (the
  server) live on **the same operator-served domain**, and a malicious or compromised
  operator can fake the data and the badge together — by the same argument as ADR-0018
  Context's "the structure in which the distributor can be malicious does not disappear", the
  badge becomes merely a performance of verification. On top of that, bundling crypto code
  grows the supply chain and the audit surface (even verification alone makes it "a Web that
  contains crypto", complicating decision 1's check "contains no decryption / wrap code
  paths" into checking "a crypto subset with only decryption excluded")
- **Option AP-b: do not implement verification; label every display as "server-declared"** —
  the displays state the Web's trust position (same domain as the server) as it is

### Round 2 (superior-alternative search)

- **Option AP-c: AP-b + guide situations needing a verified display toward the CLI**
  (`maruhi project verify` / `audit verify` / `reconcile`) — does not deny that verification
  demand exists; routes it to where verification means something (the user's machine, a
  signature-verified chain). Adopted
- **Option AP-d: server-declared display + another-channel verification (eyeballing against a
  digest the CLI prints)** — dismissed: adding an eyeball-comparison ceremony to the Web runs
  backward against revision 1's item 2 (ceremonies are TTY). If it is going to be compared,
  just look at it in the CLI from the start

### Round 3 (re-inspection)

- Added an FP-display discipline: a key FP shown on the Web is a **reference value** for
  cross-checking against audit / chain displays, not comparison material for mutual
  confirmation (a ceremony) — wording readable as "compare against this screen" is banned
  (a ceremony's integrity depends on "the displayed word = the word the key-holding process
  computed", which the Web cannot guarantee — an application of revision 1's item 2)
- Confirmed no exception for self-hosting (operator = oneself): the bundle is identical, and a
  "verified display when self-hosted" branch would be a behavior split from hosted + the same
  banned shape as decision 1's "a form merely hidden behind a flag"
- Consistency with the CLI's TCB discipline: the CLI trusts a name only through a verified
  statement (AUTH_SPEC §12-2). The Web displays the same data labeled "unverified" — not a
  **relaxation** of discipline but honestly writing the verifier's absence into the display

**Choice: option AP-b + AP-c (+ the FP discipline)**. ADR-0018 revision 2, item 4; design
document §4.

## 5. Ruling AQ: the audit UI's visibility classes and showing the admin-only `seq`

### Round 1

- **Option AQ-a: implement visibility-class filtering on the Web side too** — dismissed: the
  source of truth for visibility is the server's authorization stage (AUDIT_SPEC §7 — class 2
  behaves as if it does not exist below admin). A client-side second implementation only adds
  divergence risk (the inverse pattern of hidden-only shapes: the Web has no need to hide what
  the server returned)
- **Option AQ-b: render the API response as-is. Show `seq` on admin responses** — `seq` was
  made admin-response-only by the C1 ruling (the division of labor with row_id — AUDIT_SPEC
  §7), so showing it to an admin reveals zero new information. `maruhi audit reconcile`'s
  reports speak in seq, so it is useful for matching reconciliation results against the
  screen
- **Option AQ-c: do not show `seq` on the Web** — dismissed: it removes the reconciliation
  cross-check for no gain (admins can see seq via API / CLI anyway)

### Round 2 (superior-alternative search)

- **Option AQ-d: AQ-b + codify the non-assertion of completeness** — the Web does **not**
  perform gap checks, mirror cross-checks, or cumulative-hash comparisons, and does not show
  completeness displays like "no gaps" (verification is the CLI's verify / reconcile — the
  same line as ruling AP). seq is emitted only as a column of raw data. Adopted
- A wording discipline for below-admin: the list heading reads "events visible at your role",
  never hinting at the count or existence of invisible classes (maintaining count non-leakage
  — AUDIT_SPEC §7 — at the display layer)

### Round 3 (re-inspection)

- Confirmed that consuming the audit API under a Web session produces no CSRF / audit
  pollution: reads write no audit rows (var.read is ciphertext distribution only —
  AUDIT_SPEC §3.3). Metadata-only pull is also unrecorded. Web browsing does not contaminate
  forensics
- The self axis (`GET /auth/audit/events` — S6's self view) is outside the class concept
  (one's own rows are always visible), so no discipline addition is needed

**Choice: option AQ-b + AQ-d**. Design document §3 S6 · §4.

## 6. Ruling AR: a static guidance page for someone who opens an invitation link (AUTH_SPEC §15-3 revision)

### Round 1

- **Option AR-a: a dynamic page that interprets the fragment and displays role (`r`) etc.** —
  dismissed: (1) interpretation code is the entrance to drifting toward a "Web acceptance
  screen" (a shrunken replay of §15-3's old sentence "the Web dashboard will interpret the
  same format when implemented"). (2) The invite token (a bearer capability) lands in our
  own code's script context — it remains true that any script on the page can read
  location.hash, but if our code never touches it, the path of leaking via a compromise or
  bug in our code disappears. (3) The information (role) worth showing a pre-acceptance party
  is displayed by the accepting client (CLI) inside the ceremony — a page display is a
  duplicate outside the ceremony and makes precedence ambiguous on mismatch
- **Option AR-b: purely static guidance (no fragment interpretation)** — static text: "this
  link is accepted with the maruhi CLI: `maruhi invite accept '<this page's URL>'`". Guidance
  that passes the link's URL straight into a command can be written location-independent

### Round 2 (superior-alternative search)

- **Option AR-c: AR-b + an installation path for those without the CLI (a link to docs)** —
  only adds a static link. It fills the actual next step for P2 (unregistered, no CLI).
  Adopted
- **Option AR-d: making "does not interpret the fragment" checkable (fixing the no-JS page
  via CSP / the build)** — after consideration, sent to W1's implementation-time check list
  (a page structure with no script tag at all is already proven by spike-a's static serving.
  The spec text carries only the "does not interpret" norm; the checking means is
  implementation's territory)

### Round 3 (re-inspection)

- The link's fragment format is unchanged (the goal's constraint — §15-3's format provisions
  stay). The revision replaces only the last sentence (the Web-interpretation notice) — the
  minimal diff
- Confirmed unchanged: the accepting client's interpretation and anchor-pinning rules
  (§15-3's existing provisions)
- This executes ADR-0018 Consequences' "AUTH_SPEC §15-3 is a revision candidate" — not a new
  decision but the confirmation of a pre-announced revision

**Choice: option AR-b + AR-c**. AUTH_SPEC §15-3 revision; ADR-0018 revision 2, item 5.

## 7. Ruling AS: the permanent home of the W0 design document

### Round 1

- **Option AS-a: include it in this session note (session-39)** — dismissed: the screen
  catalog, gap analysis, and implementation split are a living document that each of the W1–W3
  implementation sessions references and updates; burying it under a session number hurts
  discoverability (a "precedent of format" reference like session-27 §14 is fine, but a
  catalog's permanent home is not)
- **Option AS-b: an independent topic note (docs/notes/web-dashboard-design.md)** — the
  precedent of `device-key-sealing.md` / `cli-parser-alternatives.md` (topic notes not owned
  by a session number). The division of labor: norms are fixed in the ADR / specs; catalogs
  and analyses live in a note
- **Option AS-c: absorb into ADR-0018** — dismissed: an ADR records decisions; the granularity
  of a screen catalog, API gaps, and matrices is excessive (it would break the ADR's
  readability). A form needing an ADR revision every time the catalog moves under W1
  implementation is too costly

### Round 2 (superior-alternative search)

- **Option AS-d: make it a spec under docs/ root (WEB_SPEC.md)** — dismissed: docs/ root is
  the place of "single source of truth"-class normative documents (CRYPTO / AUTH /
  AUDIT_SPEC). Screen design is a design document that changes as implementation proceeds;
  giving it spec status (the heavy revise → approve → implement procedure) would stall
  follow-through. Fixing only the normative parts (boundaries, display discipline) in
  ADR-0018 revision 2 is enough

### Round 3 (re-inspection)

- Confirmed the reference chain: ADR-0018 revision 2 (norms) → web-dashboard-design.md
  (catalog, analysis, split) → session-39 (the history, rejection reasons). A pointer from
  ROADMAP's W row to the design document is added, making the reading order for
  implementation sessions unique
- The future `maruhi ui` (stage 2) design document can reuse the same form (independent topic
  note + ADR revision) — format consistency

**Choice: option AS-b**.

## 8. Ruling AT: capability restriction for session principals (resolving the PR #103 pullfrog review finding)

pullfrog's first review (review 5052658273) pointed out the wrong premise of ruling AM's
worst-case evaluation (§1 round 3's correction) and the implementation-side facts —
`ensureTokenScopeForProject` lets session principals through, `ensureKeyMaterialAccess`
always permits sessions, and invitation issuance and rotation dismiss are reachable from a
session on chain role alone. On verification it was judged legitimate (code confirmed). A
ruling on the mechanism that actually enforces the boundary principle (ruling AM) is added.

### Round 1

- **Option AT-a: only write it down as a documented residual (no server change)** —
  dismissed: ADR-0018 revision 2's boundary principle would become an unenforced "do not
  place it in the UI" declaration, unable to bear the weight of merge = norm confirmation. It
  also runs against the spirit of "forms that merely hide are banned" (decision 1) — a bundle
  omission is only the superior alternative of hiding in the UI; the location of the
  capability (the set the server permits to sessions) is unchanged
- **Option AT-b: on the server, restrict what a session principal may call to an affirmative
  enumeration (allowlist)** — a session cookie is the credential most exposed to XSS; permit
  only the APIs the Web's screen set needs (reads + revocation family + the auth family) and
  reject everything else with 403. Affirmative enumeration rather than a deny-list is the
  same shape as ADR-0016 (the fail-open → fail-closed reversal) — adding a new endpoint
  defaults to "not for sessions"
- **Option AT-c: separate the Web to a different origin and restrict via CORS** — dismissed:
  neither CORS nor a header allowlist has power against same-origin XSS (the restrictions
  work only cross-origin). It only doubles the serving surface to 2 origins and does not
  touch the layer in question (the set the server permits to sessions)

### Round 2 (superior-alternative search)

- **Option AT-d: AT-b + explicitly include signature-required operations (chain appends,
  push, meta operations) in the refusal** — these were never satisfiable by keyless XSS via
  signature verification, but including them in the explicit refusal keeps the defense from
  depending on signature verification's implementation detail (and future verification
  changes). Under an affirmative enumeration they fall in naturally (not enumerated =
  rejected). Adopted
- **Option AT-e: give sessions variable scopes (the same scopes column as tokens)** —
  dismissed: only a single fixed profile (the Web's screen set) is needed, and making it
  variable creates a new design problem on the issuance surface (who chooses the scope). If
  ever needed, it can be extended on top of AT-b's enumeration

### Round 3 (re-inspection)

- Confirmed no legitimate session consumers exist: for every restricted target (invitation
  issuance · **acceptance** · rotation dismiss · recovery-blob registration/fetch · DEK
  deletion · value-bearing bulk pull), there is no legitimate path from adopted form (c)'s
  Web screens. Acceptance lost its legitimate path via the §15-3 revision (the static
  guidance page — no Web acceptance screen is built) — the surface where session XSS + a
  leaked invitation link binds an attacker's key to the victim's user_id (the same shape as
  the surface §15-2 closed for scoped tokens) can be closed before FP mutual confirmation.
  Excluding value-bearing pull eliminates the very surface where SECURITY_REVIEW L-1
  (audit-trail contamination of session pulls) occurs
- No impact on the CLI / `maruhi ui` (both are token-principal). The existing Web has no
  session-bearing screens, so user impact is zero — it can land anytime independent of W1 /
  W2a, and it is made **a precondition of W2 (the first session-bearing screens)** (the
  ordering constraint is design document §6 · §7)
- Consistency of judgment order: the 403's position must be consistent with §11-2 (existence
  concealment) · §12-3 (judgment order) — in the implementation PR (W2b), follow §14-3's
  precedent (positioned after the authorization stage) and impose a pinning test. The spec
  prescribes only the norm "a session principal is rejected"
- Location: AUTH_SPEC §5 (the session chapter) prescribes the capability restriction, and
  §13-2 · §15-2's authorization tables are followed up in the same change to remove sessions
  (so a standalone read of a table cannot mislead)

**Choice: option AT-b + AT-d**. AUTH_SPEC §5 addition + §13-2 / §15-2 follow-up; ADR-0018
revision 2, item 1's enforcement mechanism made explicit; design document §6 / §7 (PR-W2b).

## 9. Summary of deliverables and handoffs

- **ADR-0018 revision 2**: (1) the Web's shape = static + reads + revocation family only
  (the mutation boundary principle — **enforced by server-side session capability
  restriction**: ruling AT), (2) excluding invitation issuance from the Web (anchor loss +
  capability generation), (3) token issuance and raw values are terminal-only (resolving
  item 5. `maruhi ui`'s DOM also never shows them) + L-2 resolved in the same §6 revision,
  (4) the display discipline (no verification · server-declared labels · FPs are reference
  values), (5) the static guidance page for invitation links, (6) a pointer to the design
  document
- **AUTH_SPEC 0.13-draft**: §5 (session-principal capability restriction — affirmative
  enumeration. Ruling AT), §6 (the design of the listing / targeted-revocation APIs [target =
  self only · 404 for non-applicable] / issuance = device flow stays / the raw value's
  terminal-only rule / default TTL 90 days = L-2 resolved — unattended use on lease-
  incapable runtimes is a W3a handoff), §13-2 / §15-2 (follow-up removing sessions from the
  authorization tables), §15-3 (the static guidance page — no fragment interpretation)
- **Design document** (docs/notes/web-dashboard-design.md): personas · screens S1–S10 · gap
  analysis (the project-list API / token listing and targeted-revocation APIs — enumeration
  only, no implementation) · the visibility matrix · the XSS blast radius · the
  implementation split W1–W3b
- **Handoffs**: (1) W2a's project-list API makes the D1-projection vs fan-out design ruling
  at the head of the implementation PR (coexistence with §11-2 is a hard requirement).
  (2) Retroactive application / migration rules of the TTL to existing tokens and the
  handling of PAT unattended use on lease-incapable runtimes (GitLab CI / k8s etc.) (explicit
  TTL designation [with a cap] or extending issuers — never returning to a no-expiry
  default) are ruled in W3a. (3) W2b (session capability restriction) 403's consistency with
  §11-2 / §12-3 judgment order gets a pinning test in the implementation PR. (4) The
  session listing / revocation API (S10) is an AUTH_SPEC §5 revision when demand appears.
  (5) `maruhi ui` (stage 2)'s UI-contract concretization and theme MIT-licensing stay
  unstarted (ADR-0018 decision 4's preconditions are unchanged)

## 10. Round 4 (re-inspection at the owner's direction — 2026-08-28)

One additional round under the owner's instruction "look at what was decided once more and
think whether a better option exists". Taking the previous lesson (ruling AT — a spec-
document-based re-inspection walked past the implementation's current behavior), the
inspection procedure included **cross-checking api-schema's complete endpoint catalog against
§5's permission enumeration item by item**. Conclusion: the core rulings (AM–AT) are not
overturned. One defect fix + three checkability strengthenings were applied, and three
fundamental alternatives were considered and rejected.

### 10-1. Defect fix: the W2a project-list API was missing from §5's permission enumeration

- Found by the complete cross-check. S4 (the project list) is a session screen, but §5's read
  enumeration did not include the listing API designed in W2a — under the fail-closed default
  (not enumerated = rejected), implementing W2b as written would have made **S4 a 403**. It
  is a self-made instance of the same "trap of reading a table / enumeration standalone" that
  pullfrog pointed out on §15-2's list/revoke row, and my round 3 walked past it
- Fix: add "project list (designed in W2a — the caller's own memberships only)" to §5's read
  enumeration, and write "a new API opened to sessions is added to this enumeration in the
  same revision" as the fail-closed default's proviso. Cross-references were also added to
  design document S4 / §7 W2b

### 10-2. Strengthening: enforcing `/invite`'s invariant by construction (making ruling AR checkable)

- Implementation confirmation: the current web carries funstack's inline bootstrap script in
  index.html, and the CSP is its hash permission (`write-headers.ts`). Making `/invite` a
  page of the SPA would keep "static, no script" at convention level
- Adoption: `/invite` is served as **an independent static HTML asset outside the SPA**, and
  a per-path CSP **`script-src 'none'`** is placed in `_headers` (convention → a checkable
  construction. Written into AUTH_SPEC §15-3; implementation is W1). Round 3's AR-d
  (the checking means is implementation's territory) was promoted to the normative side once
  the implementation form was confirmed

### 10-3. Strengthening: W2b's implementation form and priority

- Implementation form: appended to §5 a recommendation that session rejection be **baked into
  the endpoint contract as a declaration (a single implementation point)** rather than a
  manual per-handler check — the same shape as §12-10 (1)'s strict acceptance (AST-annotation
  baking + a pinning test), structurally eliminating the room to forget it
- Priority: appended to design document §7 a recommendation to **run W2b ahead as the W
  series' first implementation PR** (a pure defensive strengthening with zero dependencies
  and zero user impact; there is no reason to wait)
- Along with it, added a cross-reference to §12-7's value-bearing-pull CSRF section: "§5
  rejects this path itself to sessions. The CSRF requirement is not removed — it is earlier
  defense plus insurance against future loosening" (the remaining one place of the
  standalone-reading trap)

### 10-4. Fundamental alternatives considered and rejected

- **A Web-only BFF (a separate API surface `/web/*`)** — dismissed: against same-origin XSS,
  "the set callable with a session" is the whole boundary even under a BFF, and the defense
  level is identical to §5's affirmative enumeration. It only adds a new API surface +
  handler duplication (§5 dominates)
- **The zero-revocation form (c′) (make the Web read-only; revocation also goes to the
  CLI)** — dismissed: the XSS residual shrinks only by the "revocation DoS (recoverable)"
  share, while it loses **the incident-response emergency path of "immediately revoking a
  leaked token or invitation from any browser"**. A credential-reducing operation is one an
  attacker gains nothing by performing, and the value of keeping it outweighs (a re-
  confirmation of AM's boundary principle)
- **Adding session rejection to AUDIT_SPEC §7 (dismiss)** — judged unnecessary: §3.3's
  recording rule was already "chain role admin or above × token scope admin", and a session,
  which carries no scope, **on a strict reading fails the condition from the start** (the
  current implementation's session pass-through is the deviation from spec). W2b is in the
  direction of catching up to AUDIT_SPEC's wording, so a duplicate norm is not added
- Maintained as confirmed: TTL 90 days (draft value — adjustable in review), re-rejecting
  session variable scopes (AT-e), leaving auditHead outside the enumeration (no Web consumer
  — not enumerated = rejected suffices), S10 outside v1
