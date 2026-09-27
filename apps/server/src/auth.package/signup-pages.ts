// Guidance pages for signup control (AUTH_SPEC §3).
//
// The delivery discipline is identical to cli-pages.ts (the §15-3 invite
// landing page's mold): no scripts, self-hosted CSS only (the shared `page()`
// frame), CSP `script-src 'none'`. The response point is handlers-auth.ts
// (the delivery header shares handlers-auth-cli.ts's htmlResponse). All
// wording is English (ADR-0017).
//
// All three pages are written in the same 3 stages ("landing wording on
// denial"):
//   1. What happened (h1 + one sentence)
//   2. What did not happen — **"No account was created" is stated on the
//      outcome row** (visualizing fail-closed — AUTH_SPEC §3; the wording
//      matches the implementation that creates no rows)
//   3. What can be done next (h2 "What you can do" + bullet list)
// - invite-invalid does not differentiate invalid / expired / consumed (the
//   same uniformity as §15's 410; with a 256-bit single-use code the
//   enumeration-oracle concern is thin to begin with, and differentiating
//   buys no UX)
// - No waitlist-collection surface is built (hosted-design.md §2-2 — the
//   guidance goes as far as contacting the operators)

import { page } from "./cli-pages.ts";

const NO_ACCOUNT_CREATED = `        <p class="outcome">No account was created.</p>`;

/** Denial page for signupPolicy = closed (§3 — ends after the OAuth round trip, creating no rows). */
export function renderSignupClosedPage(): string {
  return page(
    "maruhi — sign-ups closed",
    `        <h1>Sign-ups are closed</h1>
        <p>This maruhi server is not accepting new accounts right now.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>
            If you already have an account under a different GitHub identity, sign in with that
            one.
          </li>
          <li>Otherwise, contact the operator of this server about getting access.</li>
        </ul>`,
  );
}

/** Denial page for signupPolicy = invite with no code presented (§3). */
export function renderSignupInviteRequiredPage(): string {
  return page(
    "maruhi — invite required",
    `        <h1>Sign-ups are invite-only</h1>
        <p>This maruhi server requires a sign-up invite code to create an account.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>
            If you received an invite, open the sign-up link that came with it &mdash; the link
            carries your code.
          </li>
          <li>To request an invite, contact the operator of this server.</li>
          <li>
            If you already have an account under a different GitHub identity, sign in with that
            one.
          </li>
        </ul>`,
  );
}

/**
 * Page for an invalid signup invite code (§3 — used both when start's
 * pre-verification fails and when the callback's consumption CAS loses.
 * Does not differentiate unknown / expired / consumed).
 */
export function renderSignupInviteInvalidPage(): string {
  return page(
    "maruhi — invite code can't be used",
    `        <h1>This sign-up invite code can&#39;t be used</h1>
        <p>The code is invalid, has expired, or was already used.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>Ask the operator of this server for a new sign-up invite code.</li>
          <li>
            If sign-ups are open on this server, you can also
            <a href="/auth/github/start">sign up without a code</a>.
          </li>
        </ul>`,
  );
}
