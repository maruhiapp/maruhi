# ADR-0009: Auth is a direct GitHub OAuth implementation — WorkOS not adopted (with a re-decision point)

**Context**: WorkOS adoption was considered for future enterprise needs and free-user growth.
**Decision**: Core auth is a direct implementation of GitHub OAuth (web + device flow. In the 2026-08-31 full revision of AUTH_SPEC §4 the device flow was abolished — CLI login was also unified into the server-mediated web-flow handoff: session-48 ruling DF. This ADR's decision [direct implementation, no framework] is unchanged). No framework such as Better Auth either. However, the six items in AUTH_SPEC (internal user_id primary key, email verification + no auto-linking, first-class orgs, DB-backed sessions, maruhi-issued tokens, idempotent get-or-create) keep future IdP additions possible without downtime.
**Rationale**: For the self-hosted edition, zero external dependencies is the product value, so a direct GitHub implementation is mandatory. Because of the single-codebase strategy, WorkOS would be a pure addition, not a reduction. The in-house scope is a few hundred lines of OAuth client + session + token, containing no dangerous goods (passwords etc.). Better Auth collides with the E2EE-led user-model design over schema ownership.
**Consequences**: Re-decision point: the work-start date of the hosted edition. Writing no provider information into the membership chain is the most important irreversible constraint (CRYPTO_SPEC §6.1). **(→ The re-decision was carried out at 2026-08-30 H0 — below)**

---

## Re-decision (2026-08-30 — H0: arrival of the hosted work-start date)

Because Revision 1 of ADR-0014 (moving the hosted cloud edition earlier) brought the re-decision point in Consequences due, the re-decision was carried out (ruling DE — docs/notes/session-47.md).

**Verdict: v1 continues with the direct GitHub OAuth implementation. WorkOS remains not adopted.**

1. **All of the original Rationale still stands**: self-hosted = no external dependencies (WorkOS is a pure addition under the single codebase); the implemented scope is as small as originally estimated and contains no dangerous goods; the AUTH_SPEC §7 insertion point (the six items) is maintained in the current spec even after the W series and S0 (the §2 data model and §9 separation are unchanged)
2. **The hosted beta's target audience (the persona in hosted-design.md §1) is developers who have GitHub; there is no actual demand for enterprise SSO yet**. SSO is a feature for "once demand is measured on a paid plan"; introducing it before needs are observed is deferred for the same reason as ADR-0011 (minimizing unstable and external dependencies)
3. **Newly confirmed facts (2026-08-30 primary sources — hosted-design.md §3-4) do not change the decision**: the hosted CLI login is rate-limited by GitHub device flow's shared cap of 50 code entries / hour / App. Adding WorkOS cannot solve it (the cap remains unless CLI auth is taken off the GitHub device flow, and if it is taken off, the answer is an in-house path such as the web-flow handoff — same §3-4 (a) — not adding an IdP service). Rather, the fact that "auth-surface changes are confined to one place in our own implementation" makes implementing mitigation cheap (addendum 2026-08-31: that mitigation = the web-flow handoff, adopted by session-48 ruling DF, which revised AUTH_SPEC §4. The BYO App topic was merged by ruling DG into this ADR's next re-decision point [paid-plan design or observed SSO demand])
4. **Next re-decision point**: whichever comes first — paid-plan (GA) design, or observed actual demand for enterprise SSO (a concrete customer request). Maintaining the insertion point (AUTH_SPEC §7) remains an acceptance criterion for any revision.
