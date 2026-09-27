# Session 30 memo (re-evaluating ADR-0018 and comparing GUI shells — the background of revision 1)

Date: 2026-08-18 (after ADR-0018 = PR #82 merged, same day). Format: a continuation of the
implementation-free design dialogue. Scope: a flat re-evaluation of ADR-0018 → comparing the 3 GUI shell
options (localhost / IWA / signed desktop) → the revision-1 ruling
(settle the UI contract first, pin ceremonies to the TTY, defer shell selection).
The deliverables are ADR-0018 revision 1 and this note only.

## 1. Key points of the re-evaluation (the core stands; 3 framing corrections)

ADR-0018's core (no decryption / wrap capability on the hosted Web / no sharing the owner's screen /
deferring the valued GUI / CLI and TUI first) survived re-evaluation.
The corrections are 3:

1. **"Value-free" ≠ "low-risk"**: even with a value-free `maruhi ui`, the structure in which the
   UI asks the key-holding process to perform operations leaves a surface where a compromised UI
   (extensions, XSS) uses the CLI as a **signing oracle** (invite acceptance and `member add`
   involve signatures). Mitigations: narrow per-operation APIs + pinning ceremonies to the TTY (→ revision 1)
2. **A TTY is not human authentication**: any local process that can create a PTY passes.
   The accurate framing is "a fail-closed misuse guard that stops typical agent / pipe misoutputs"
   (a clarification of ADR-0016, not a change)
3. **CLI distribution does not eliminate operator trust either**: the operator distributes
   both the binaries and the npm bundle (ADR-0015). What disappears is the dependence on "web
   delivery updatable on every page open"; the accurate phrasing is a move to "explicitly installed,
   explicitly updated artifacts". Strengthening checksum signing and provenance is separate (the ADR-0015 line)

Handoff (unruled — a W0 discussion point): decision 1's allowlist includes **API token
management**, but issuing an additional token is credential generation, and
"decryption-free" is not "low-privilege" (tokens today are all-project
admin and non-expiring by default — AUTH_SPEC §6 / SECURITY_REVIEW L-2). Whether issuing and
displaying raw values belongs on the Web is re-ruled in W0, including the option of narrowing to
"holds no credentials either".

## 2. Comparing the 3 GUI shells (with fact-checking)

Premise: the owner expects GUI demand to arrive with high probability. The comparison assumes
a full GUI that handles values.

### localhost UI (open 127.0.0.1 in a browser)

- The lightest implementation. The key / crypto / keychain boundary stays the existing CLI's
- **The screen assets ship bundled inside the CLI binary** — the difference from "operator-served
  per-visit web delivery" holds here too (a correction: the initial comparison had undervalued this point)
- Two pressure points: **browser-extension injection** (LNA's restrictions do not apply to
  extensions; an extension with host permission can inject a content script into localhost pages)
  and **the existence of a TCP listener** (other local processes, DNS
  rebinding, and the full set of CSRF countermeasures are needed — the authentication requirements of ADR-0018 decision 2)
- Verdict: the path for dogfooding and prototyping. Do not fix it up front as the
  production valued GUI

### IWA (Isolated Web Apps)

- The model fits: a signed Web Bundle, a fixed origin derived from the public key
  (`isolated-app://`), isolation from ordinary browser extensions, version pinning and
  update management
- Why not adopted (for now): **Google's allowlist regime** (from Chrome 143, an
  early adopter program assuming partner contact; there is no distribution path for
  general developers. Developer Mode is for testing), Chrome-only, and no natural path to the
  OS keychain (putting keys in IndexedDB returns to the shape ADR-0018 avoided)
- Re-evaluate once general distribution becomes possible

### Signed desktop (Tauri + CLI sidecar)

- **The current front-runner for a valued GUI**: no extensions, no TCP listener
  (IPC is in-process), the UI is pinned to a signed artifact, and the OS keychain is
  used by the sidecar CLI as-is. Tauri officially supports bundling external binaries (sidecar) and
  updater signing (mandatory, cannot be disabled)
- Costs (the largest dependency addition this repository would take): the Rust toolchain —
  outside the existing quality gate (oxlint / tsc / vitest / fallow / ImportLint);
  the WebView runtime's supply chain (Windows = WebView2 updates externally via
  Microsoft / Linux = the distro's WebKitGTK lags — only your own JS is "pinned by signature");
  operating the updater's private key (losing it = cannot ship updates to existing users);
  code-signing, notarization, and installer QA across 3 OSes
- If started, the natural point is after macOS notarization (ROADMAP — the signing infrastructure overlaps) is done

### The core of the comparison (ruling material)

- **The signing-oracle problem is common to localhost and desktop** (the structure where the UI
  asks the key-holding process to operate is identical). The mitigation is the same: narrow
  per-operation APIs + pinning ceremonies to the TTY. Therefore the real difference between the two shrinks
  to 2 points — "extensions" and "TCP" — and shrinks further when value-free
- The integrity of the ceremony (the 12 fingerprint words) depends on "the displayed words = the words the
  key-holding process computed". Since the UI layer could substitute the display under any shell,
  **keeping ceremonies on the terminal** is the shell-independent defense

## 3. Ruling (revision 1)

Do not choose the shell now; **fix the contract**:

1. Fix the contract between the UI and the key-holding process (per-operation APIs; no generic
   sign/wrap; never hand values or key material to the UI layer) up front as a stage-2 prerequisite.
   Write the front-end as a client of this contract and keep the shell replaceable
2. Ceremonies stay on the TTY even when a GUI exists (stage 2's "large display of the 12
   fingerprint words" is withdrawn)
3. Shell selection is deferred to the stage-3 (valued GUI) ruling. Dogfooding uses
   localhost; the valued front-runner is signed desktop; IWA is re-evaluated once generally
   distributable. Add the shell comparison as a mandatory topic of the stage-3 ADR

Rationale: keep a form where each stage can stop (the ADR-0018 pattern). Shell selection depends on
unfixed facts — "demand for values in a GUI", "IWA distribution opening up", "macOS notarization
done" — and nothing is gained by deciding now. The contract and where ceremonies live are the
shell-invariant parts; fixing them first means the front-end is implemented once.

## 4. References

- ADR-0018 (the object of this revision) / ADR-0015 (CLI distribution and notarization) /
  ADR-0016 (the TTY primary boundary; ceremonies' scope)
- docs/notes/session-29.md (the background of ADR-0018 itself)
- AUTH_SPEC §6 (API tokens) / SECURITY_REVIEW_2026-08-14 L-2
  (non-expiring tokens) — the basis of §1's handoff
- IWA: developer.chrome.com/docs/iwa/ (introduction / allowlist /
  connect-to-extensions / version-management. The allowlist runs from Chrome 143,
  behind the early adopter program)
- Tauri: v2.tauri.app (develop/sidecar / plugin/updater — updater signing is
  mandatory and cannot be disabled)
- LNA (Local Network Access): does not apply to extensions (WICG
  local-network-access — an extension with host permission can make local requests)
