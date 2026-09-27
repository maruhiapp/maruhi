# Session 48: gap 9 — the ruling record on the CLI-login scaling path (the web-flow handoff)

Date: 2026-08-31. Purpose: ruling on hosted-design.md §8 gap 9 (the CLI-login scaling path — an open-beta release condition) and session-47 §11's handoff (positioning BYO App). Format: **a dialogue ruling with the owner present** (unlike the previous sessions' "autonomous choice → post-approval", this proceeded: stage 1 = stop at fact-checking → stage 2 = present the option comparison → the owner picks the direction → a final zero-based exploration confirms convergence. This PR's merge constitutes formal approval). The ruling symbols continue session-47's (…DE) numbering, starting at **DF**. Deliverable mapping: AUTH_SPEC 0.17-draft (a full §4 revision + follow-ups in §3 / §6 / §13-2 / §15-2) / AUDIT_SPEC vocabulary follow-up / hosted-design.md additions (§2-2, §3-4, §8 gap 9, §9 H1b) / ROADMAP (H1b added) / this ruling record. **No implementation is included** (implementation stage = H1b).

---

## 1. Primary-source verification (2026-08-31 — the ruling's inputs)

Re-verified against GitHub's official docs (Rate limits for OAuth apps / Authorizing OAuth apps / Rate limits for GitHub Apps). Since H0's numbers were copied over rather than taken as given, every number was rechecked:

- **Device-flow user-code entry = 50/hour (per App)**: confirmed (the original text: "there is a rate limit of 50 submissions per hour per application"). The problem framing is correct — this throttles the whole hosted deployment's CLI logins to 50 per hour
- **OAuth token requests = 2,000/hour (per App, secondary)**: confirmed. Web flow's code exchange and device flow's polling share the same budget. The secondary rate limit is "subject to change without notice", has no remaining-quota observation API, and continued excess "may result in the banning of your integration"
- **Client-credential requests = 5,000/hour (15,000 for a GHE Cloud org-owned App)**: confirmed (check-token's attribution is a reasonable inference from the auth scheme〔Basic = client_id:client_secret〕 — there is no per-item explicit text)
- **Token issuance = 10/hour/user, 10 per (user, app, scope) tuple**: per-user, so it does not throttle the hosted deployment
- **Correction to the H0 table (reflected in hosted-design.md §3-4)**: web login's `/user` / `/user/emails` are called with **the user's token** and count against that user's own 5,000/hour. Consumption of the shared App budget is 1 token request per login only (the H0 table's "+ 5,000/hour" was wrong)
- **Web flow's code → token exchange requires client_secret** (device flow alone is exempt): a CLI-only web flow is structurally impossible, and a handoff is always server-mediated — this confirmation overturned the previous session's estimate (the direct-loopback option) and narrowed the design space to "choosing the delivery method of a server-mediated handoff"
- OAuth Apps officially support multiple callback URLs and loopback redirects (any port) (the 2026-08-03 spec change restricted wildcards). However under the server-mediated form, the GitHub-side callback stays the single conventional one, so this fact's main use evaporated
- **Migrating to a GitHub App does not move the login throttle**: the 2,000/hour token-request secondary is shared by "GitHub Apps and OAuth apps", and the 50/hour device-flow code entry also does not change with App type → hosted-design.md §3-4 escalation (b) effectively drops out as an answer to this problem (the throttle does not move a millimeter against the migration's cost〔a large project〕)

## 2. Ruling DF: a server-mediated web-flow handoff (polling delivery) + full removal of device flow + making the CLI provider-agnostic

**Adopted** (spec = a full AUTH_SPEC §4 revision; implementation = H1b): the CLI creates a pending login on the maruhi server (`POST /auth/cli/start` — flowId / flowToken〔256-bit, only its hash stored〕/ userCode / verificationUrl), the user completes §3's web OAuth in a browser and explicitly approves by matching the userCode on a script-free approval page on the maruhi origin, and the CLI receives the maruhi PAT by polling the server (`POST /auth/cli/poll`) (single-use CAS; the raw value is never stored in the DB). The approval credential is a single-use, short-lived approval ticket — **an existing Web session cannot approve**. Settled as a 3-point set:

1. **Delivery is polling** (CLI → maruhi server. GitHub consumption is 1 token request per login only)
2. **Device flow is fully removed** (not kept alongside. Owner confirmation 2026-08-31: "delete it if there is no reason to keep it" — every reason to keep it was exhausted: SSH / CI / agent environments are covered by polling + manually opening the URL, an equivalent degraded form to device flow; GHES was never supported since the server pins github.com; old-CLI compatibility carries no obligation pre-publication)
3. **The CLI does not know the provider** (owner requirement 2026-08-31: "build it on the premise that providers other than GitHub may be integrated": no provider-specific fields on the wire, verificationUrl is opaque, and a future IdP addition〔§7〕completes entirely inside the browser leg)

Rationale: (1) the throttle moves 50/hour → 2,000/hour, a 40× increase (scale sense: steady re-logins under a 90-day TTL support tens of thousands of users, and even a sign-up spike means 2,000 account approvals per hour — realistic growth does not touch the ceiling; a scale that does touch it is one where billing, BYO, and negotiating an increase with GitHub all stand). (2) Every consumption point now goes through the server — **an observation point and a control point are gained** (secondary has no remaining-quota API, so self-counting is the only observation — added to the H3 tripwires). (3) Net reduction of the attack surface — audience verification (check-token), token-format pre-checks (old L-3), and the unauthenticated outbound relay are all eliminated. (4) The residual H0 explicitly accepted (§2-2 (a)(b) — the refusal path / adversarial consumption being unblockable via direct github.com) shrinks drastically (disabling Enable Device Flow removes the 50/hour surface altogether). (5) If implemented before H5, the published CLI carries only the handoff and no breaking change ever occurs.

**The cost (explicit)**: the approval surface moves from github.com to the maruhi origin (Web = TCB). Mitigations: a script-free approval page (the same discipline as §15-3's invite landing page, `script-src 'none'`), the explicit act of matching the userCode (the same friction level as the old device flow's code entry), mandatory fresh OAuth (no session as an approval credential — keeping it outside §5's allowed enumeration). The phishing residual (the shape where an attacker starts a flow and has the victim open the URL) is the same shape as RFC 8628's device-code phishing and **not a worsening**.

**Rejected options**:

- **Delivery = loopback by default (302 to a temporary listener on 127.0.0.1)**: the strongest form, structurally closing the phishing residual by binding browser and CLI to the same machine — but it does not work under SSH / containers / agent environments, and a degraded path (= polling) is needed anyway → two delivery mechanisms to implement, test, and document from day one. Polling alone is minimal with identical behavior in every environment. **Reserved as a wire-nonbreaking additive extension** (AUTH_SPEC §4-3)
- **Delivery = pasting a one-time code**: the user hand-pastes a code shown in the browser into the CLI. Manual friction equal to the old device flow with thin switching gains, and the code passes through the clipboard and terminal history. Inferior to polling
- **Approval via an existing Web session**: would add approval — effectively a PAT-issuing mutation — to session capabilities, colliding head-on with AUTH_SPEC §5's capability limits and ADR-0018 revision 2 (issuance is terminal-only). Session theft / Web XSS would escalate into CLI-login approval
- **Keeping device flow alongside (automatic fallback / an explicit flag)**: every affirmative reason is exhausted, per point 2. Coexistence would preserve the bring-your-own-token verification attack surface, muddy the monitoring semantics of the 50/hour budget, and permanently maintain a "which path did they come in on" branch
- **Lowering re-login frequency via automatic token refresh**: guts the intent of the 90-day default TTL (forcing periodic re-authentication — W3a ruling CE / resolving L-2). The frequency problem is already solved by 2,000/hour; no reason to add a refresh mechanism
- **Bringing your own GitHub PAT**: removes the shared App budget, but audience verification becomes impossible in principle (a PAT is not issued for an App, so "a credential intended for maruhi" cannot be verified, and a victim's PAT leaked elsewhere works verbatim for impersonation). The UX is also the worst (manual PAT creation). Teaching users the habit of "paste a PAT" itself contradicts the product philosophy of a secrets manager
- **Identity proof by SSH-key signing** (matching against the public key list on github.com): a non-standard protocol (violates CLAUDE.md's ban on inventing protocols), key possession ≠ account control, and the exact opposite of provider-agnosticism
- **Switching to passkeys / email magic links**: would take on new hazardous material and supply chains — an account-recovery flow and an email-sending foundation (gap 8) — before demand is observed. Email-as-identifier also collides with AUTH_SPEC §2's discipline. Premature per ADR-0009's re-judgment discipline (once demand is established)
- **Migrating to a GitHub App**: confirmed numerically in §1 that the throttle does not move
- **Multi-App sharding / GHE Cloud org ownership**: the H0 rejections stand (numbers re-verified in §1 — GHE changes neither the 50 code entries nor the 2,000 token requests)
- **Doing nothing (waiting for invite-only-beta measurements — H0's default path)**: compared as an equal product judgment and rejected. (1) The "publicly known × invite-only" window that H5 inevitably produces (session-47 §10) can be removed structurally before publication, (2) removing device flow after publication is a breaking change (pre-publication is cheapest), (3) what measurement teaches is "when we hit the ceiling" — "that a ceiling exists" is already known; little is gained by waiting

## 3. Ruling DG: deferring BYO App (tenant-brought OAuth App)

**Deferred** (not rejected — the response to session-47 §11's handoff): BYO does not solve gap 9 (the free individual tier stays on the shared App = the open-beta ceiling does not move). Moreover, after ruling DF the shared-budget squeeze itself recedes, and BYO's main motive shifts from "separating a big tenant's budget" to "org administrators' bulk-management needs (approval, revocation)" — which belongs to enterprise SSO (the AUTH_SPEC §7 / ADR-0009 WorkOS insertion point) and **merges into ADR-0009's next re-judgment point (paid-plan design or observed SSO demand)**. Reasons not to pre-implement: (1) it creates a new custody class — holding tenants' client_secrets (today's secrets are just the one deployment secret), and (2) a funnel to resolve "which tenant's App" before login (an org hint) is needed — complexity running opposite to the CLI's provider-agnosticism (ruling DF point 3).

## 4. Record of the zero-based exploration (convergence confirmation — owner-requested, 2026-08-31)

After stage 2's 3-option comparison and before adoption, the whole design space was re-enumerated across 5 families (an upward-compatibility / silver-bullet search):

1. **Direct CLI ↔ GitHub family**: device flow (50/hour), CLI-direct web flow (impossible — client_secret), bring-your-own GitHub PAT (no audience verification), SSH-key signing (non-standard) — all dead
2. **Server-mediated family**: the adopted family. In-family variants (loopback, paste, SSE vs polling, QR display) are all delivery choices; polling is minimal and identical in every environment. The others can be added later as additive extensions
3. **Eliminating-CLI-login family**: issuing a bootstrap token from the Web (violates ADR-0018) and token refresh (reintroducing L-2) are rejected. **Credential delegation from an existing device** (a logged-in device approves a new device's key) has a future as device-addition UX but cannot eliminate first login, so it is not a gap-9 answer — recorded only as an unexplored idea
4. **Provider-change family**: passkeys and magic links (rejected above). Multi-provider support's future cost is already minimized by ruling DF's point-3 "build"
5. **Moving-the-constraint family**: BYO (ruling DG), GHE, sharding, negotiating an increase with GitHub (an operational lever, not design — at a scale that needs it, billing already stands)

Conclusion: no upward-compatible option. Converged on "option 3 (polling delivery) + full device-flow removal + provider-agnostic".

## 4b. Supplementary ruling DH: making start record-free + restricting CLI login to existing accounts (owner-adopted 2026-08-31)

After the 8 review round-trips on PR #115 (the supplementary record in §5), a second-stage
zero-based exploration at the owner's request ("loop until no better ideas come out") identified the
**common root** of the symptomatic fixes stacked up across the rounds:
"for a party that has paid no cost and shown no intent, the server creates state
(a pending row at unauthenticated start) and performs irreversible processing (get-or-create at
callback, invite-code consumption)". The owner adopted the 2 options that cut the root (A + H —
reflected in the spec within this revision PR).

- **A (record-free start)**: `POST /auth/cli/start` stores nothing on the server and returns a signed
  self-contained flow credential (flowToken = a random value + flowId + expiry + HMAC-SHA-256; domain-
  separated from vsig — AUTH_SPEC §4-2) plus a vsig-signed verificationUrl. A flow row is born only
  "the moment an existing-account holder completes OAuth".
  **What disappears**: the unauthenticated pool's capacity, the eviction-style cap, the protection CAS,
  the eviction alert (most of the mechanisms stacked in review rounds 2–4). **The cost**: a new
  component — the flow-signing key (a server-side HMAC key — auto-generated on first use and stored in D1;
  the self-host procedure does not grow). A record-free pending flow becomes the only credential not
  backed by the DB, but it is not a session (15 minutes; permits nothing on its own)
- **H (existing accounts only)**: CLI login creates no account. The only entry point for sign-up is
  §3's Web login, where H1's signupPolicy gate and invite-code acceptance also exclusively live.
  An identity with no account gets a "sign-up guidance page" (script-free) in response, and
  nothing irreversible happens. **What disappears**: the "a single-use invite code burns on a
  first-come wrong account" branch that §4-3 had forwarded to H1 (the forwarding itself dissolves), the
  "opening a link and completing OAuth creates a maruhi account" property, and the intermediate state of
  the user_id-binding CAS (the row is already bound when born).
  **The cost**: a first-time user's browser detours once into sign-up (existing users' flow is
  unchanged). The first exploration's finding B (deferring consumption/creation to approval time) is
  subsumed by H and no longer needed
- **Options re-verified and rejected inside the exploration loop**: making loopback delivery the default
  (breaks the cases where browser and CLI are on different machines — SSH, remote development; the
  future-extension reservation stays) / approval via an existing Web session (XSS → escalation into
  token issuance — the DF-time rejection re-confirmed) / pasting a Web-issued code into the CLI
  (the already-rejected delivery form re-confirmed) / fully stateless flow rows (single-use delivery
  needs at least one CAS-able state) / moving storage to KV / DO (weakens CAS, only adds
  complexity) / abolishing userCode or auto-approving (the last line of defense against phishing) /
  choosing issuance parameters on the approval-page side (erases the meaning of CLI flags)
- **Spec-level details (for implementers)**: the flowToken MAC **must include flowId in the signed
  material** (not deleting the old §4-2 "(flowId, flowToken) pair-match" check but **relocating** it —
  since start is unauthenticated and free, anyone can hold a legitimate flowToken, so without the
  binding, recombination of "someone else's flowId + one's own flowToken" would steal another's PAT.
  Settled in PR #115 round 9 〔the same finding by pullfrog / Bugbot / the Security agent〕). The issuance parameters
  (tokenName / scopes / expiresInDays) are carried by the vsig-covered verificationUrl
  (needed for the approval page's display and the row creation. flowToken stays off the browser channel).
  The sign-up guidance page's resume funnel is the **verificationUrl** (the callback response itself is
  single-use and cannot be reloaded — same round, Bugbot finding). First-time generation of the
  flow-signing key is idempotent (first-wins + read-back — same round, nitpick). consumed / denied rows
  are kept until flowToken expiry + slack (deleting them earlier makes poll misread "no row = pending"
  and wait forever). The total-volume discipline for rows (opportunistic deletion + a cap — draft value
  1,000, excess = a uniform error + an H3 alert) moves to the creation point (callback) — since filling
  it costs "an existing account × a completed OAuth", eviction is no longer needed and a plain refusal
  suffices

## 5. Handoffs

- **Implementation = H1b** (hosted-design.md §9 addition, ROADMAP): independent of H1 and can run in parallel; **a prerequisite of H5 (going public)**. The coexistence grace window for the old endpoint (server deployed ahead + old CLI) is the implementation PR's call
- H1's CLI fail-fast and invite-code pre-validation are re-based onto the post-§4-revision form (hosted-design.md §2-2 addition — whether an independent pre-validation endpoint is still needed is re-judged in the H1 implementation PR) **(re-updated by §4b ruling DH: code acceptance/validation lives only on the Web sign-up side〔§3〕; the CLI side shrinks to the signupPolicy check + guidance — §2-2 re-amended)**
- The H3 tripwires gain "self-counted token requests" and "the login-flow rows' ~~eviction・~~creation cap reached" (hosted-design.md §3-4 addition — secondary has no remaining-quota observation API, so self-counting is the only observation. Under §4b ruling DH the eviction mechanism disappeared and the alert target is only the creation-point cap). The check-token watch disappears
- The approval page's friction shape (showing the userCode for matching + an approval click vs entering a code) is settled in the implementation PR — the spec requires "an explicit action + the matching wording + **a display of what is granted (tokenName, scopes, expiry)**" and does not bind the form (the input-method difference produces no essential defensive difference against the phishing residual — the attacker can hand the victim a complete code. Meanwhile, showing what is granted is an improvement the old device flow lacked — a gain from owning the approval surface — originating in the PR #115 pullfrog review)

**Spec supplements originating in the PR #115 review (2026-08-31 — 3 clarifications within ruling DF's scope)**: (1) the approval page displays, in addition to the userCode, what is granted (tokenName, requested scopes, expiry) (above). (2) The browser leg is only §3's stages 1–3 and issues no session (CLI login carries no Web-login side effects — least capability). (3) Bounding the flow rows — opportunistic deletion of expired rows (bundled into start's batch) + a deployment-wide concurrent-pending cap (draft value 1,000). Round 2 (a follow-up review of 8dfefdd) added 2 more: (4) the pending cap is **eviction-style**, not a 429 (deleting the oldest pending — an unauthenticated single pool under a 429 shape enables sticky occupation = a cross-tenant availability lever. Eviction occurrences produce an H3 alert; the residual is noted in §4-3; the cap is self-host adjustable). (5) The tokenName character-set constraint (rejecting control / bidi characters at acceptance — §6; protection shared across display surfaces) and inert rendering on the approval page (mitigating approval-text impersonation — the residual is in §4-3). Round 3 (a follow-up review of abda759) added 2 more: (6) **narrowing the eviction set + a protection CAS** — the callback records "browser-leg arrival" via CAS before any irreversible side effect (account creation, H1's invite-code consumption), and protected rows leave the eviction set (the eviction window cannot extend past the point where side effects are decided. Only when every row is protected does it 429 — protection requires a completed OAuth per row, so it cannot be filled cheaply). Round 4 (a follow-up review of d4856bf, pullfrog + Bugbot) fixed the callback's processing order as (i) settling the OAuth completion → (ii) the protection CAS → (iii) get-or-create → (iv) the approval page (protecting before the code exchange would let a state-self-supplying non-browser call get protection for free and break the occupation brake — resolving pullfrog's state-oracle and unspecified-branch findings). Round 5 (a follow-up review of 7cec846) added 2 points: a **binding CAS** of the get-or-create result's user_id onto the flow row (a repeat arrival by a different identity gets a uniform error without rotating the ticket — blocking the first-come-approver's ticket-revocation attack and flow hijacking〔binding a different account to the CLI〕: Bugbot finding. H1 checks the mismatch before invite-code consumption), and noting "only the last-opened page can approve" as a §4-3 cost (pullfrog finding). Round 6 (a follow-up review of 0b81d41) made flowId's unguessability (draft value 128-bit — if enumerable it becomes the starting point of binding-first-arrival and protection-stuffing) a requirement in §4-1 (1), and added the dead-end branch of a different user_id arriving first (binding is monotonic, no release) to §4-3's residuals. Round 7 (a follow-up review of 4551224) noted in §4-3 that the dead-end branch's recovery path **does not hold under H1's invite regime** (the first arrival is NULL → no mismatch check exists at binding, and the single-use code is consumed on the wrong-account side) — whether it is handled operationally〔reissuing the invite〕or by moving the consumption point〔reservation at start + settlement at poll — interferes with the bounding rules〕is **referred to the H1 side's ruling** (not decided in this PR). Round 8 (a follow-up review of b90cf3c — resolving a re-raised nitpick and leftovers from round 1) added 2 points: pinning poll's issuance order to "the approved → consumed CAS **gates** issuance (only the winner is issued; losers get a uniform refusal. A post-CAS issuance failure ends as consumed = fail-closed leaving no half-delivery)" (flowToken is a bearer and concurrent polls are expected), and adding the "all rows protected → start returns 429" branch to §4-3's residual enumeration (it takes cap-count OAuth-completed flows = cannot be sustained cheaply, recovers naturally via TTL, H3 alert). Invite-code consumption is the price of account creation; later re-logins need no code — what a flow expiry loses is only the PAT delivery. (7) The tokenName character constraint's implementation owner = **H1b** (noting the tightening of the existing Schema and non-retroactivity). None of these change the adopted skeleton (server-mediated, polling, single-use CAS).
**(Overwritten by §4b supplementary ruling DH — 2026-08-31)**: the round records above are kept as-is for history, but of them (3) bounding, (4) the eviction-style cap, (6) the protection CAS and narrowing the eviction set, round 5's binding CAS (intermediate state), round 7's referral to H1, and round 8's "all-rows-protected 429" residual were **replaced premise-and-all or resolved** by ruling DH (record-free start + existing-accounts-only). Still valid after DH: (1) displaying what is granted, (2) no session issuance, (5) the tokenName protection, the callback's "OAuth completion first" ordering principle, the ticket discipline (the latest single ticket, not rotated by another identity), flowId entropy, and poll's CAS gate.
- Loopback delivery stays an additive reservation (AUTH_SPEC §4-3; adding a delivery hint to start keeps the wire non-breaking)
- `docs/SELF_HOSTING.md` follow-ups (the Enable Device Flow step, the `/auth/device/exchange` row in the WAF table, the `device_flow_disabled` troubleshooting entry) belong to the H1b implementation PR (the verified-runbook discipline — do not write a step that has no implementation)
- The authMethod vocabulary `cli_handoff` is a draft value (AUDIT_SPEC §3.1 followed up. Final naming is H1b's)
- Hosted operations: after the H1b implementation, disable "Enable Device Flow" on the OAuth App (closing the old 50/hour surface to adversarial consumption — a hosted-design.md §3-4 addition)
- Cross-device credential delegation (§4 family 3) remains recorded as an untouched idea for future device-addition UX
