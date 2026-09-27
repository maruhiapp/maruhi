// Server-rendered pages for CLI login (AUTH_SPEC §4-1 (4)).
//
// The delivery discipline is identical to the §15-3 invite landing page:
// **no scripts** (form POST only) and CSP `script-src 'none'`. Styles are
// self-hosted external CSS only (`style-src 'self'` — no hash allowance for
// inline style / <style>): /theme.css (an unconverted bundle of
// apps/web/theme/maruhi.css = the brand's canonical artifact. ADR-0013 —
// no colors or hex values are written here) + /pages.css
// (apps/web/public/pages.css — the frame, spacing, and confirmation-code
// presentation shared with /invite). The logo is a self-hosted SVG
// (`img-src 'self'`). Both are served by the same Worker as apps/web build
// output (the assets in apps/server/wrangler.jsonc — bundled for
// self-hosting too). All wording is English (ADR-0017). The ruling is in
// docs/notes/web-design-pass.md §5 (DP4).
//
// - tokenName is rendered **inert** as unauthenticated input (HTML escaping
//   + visual separation from the approval wording via <code>; no
//   formatting/markup interpretation — §4-1 (4) (iv). The character-class
//   constraint at acceptance is §6's job)
// - Error pages are uniform (§4-2 — flow state and denial reasons are not
//   differentiated)
// - flowToken never appears on any page (§4-1 (1))

import type { TokenScope } from "@maruhi/core";

/** Escapes HTML text / attribute values (the implementation point of inert rendering). */
function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * The self-hosted assets the pages reference (build output of
 * apps/web/public / theme). Reachability in real delivery is pinned by
 * apps/web/test/e2e.test.ts (combined configuration).
 */
const PAGE_STYLESHEETS = ["/theme.css", "/pages.css"] as const;
const PAGE_LOGO = "/logo-inverted.svg";

/**
 * The CSP shared by all pages (duplicated across the meta tag and the
 * delivery header — same rationale as invite.html; the header-side
 * application point is htmlResponse in handlers-auth-cli.ts).
 * style-src / img-src allow self-hosting only, and form-action allows only
 * the approval form's POST target (the same origin). script-src stays
 * 'none'.
 */
const CLI_PAGE_CSP =
  "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'";

/**
 * The CSP for the delivery header. `frame-ancestors 'none'` is the approval
 * page's clickjacking defense (default-src does **not** fall back to this
 * directive, so without it any origin could iframe the page).
 * frame-ancestors is ineffective in a meta tag (ignored per spec), so as
 * with invite.html / write-headers.ts it is carried only on the header
 * side. Non-approval pages (done / denied / error / signup guidance) pass
 * through the same htmlResponse, so it is attached consistently.
 */
export const CLI_PAGE_CSP_HEADER = `${CLI_PAGE_CSP}; frame-ancestors 'none'`;

/**
 * The common frame for scriptless pages (shared with signup-pages.ts — the
 * same delivery discipline). The structure matches invite.html: a brand
 * header (not a heading) → main; the page's title is the body-side h1.
 * `data-astryx-theme="maruhi"` is present because /theme.css tokens are
 * defined under `@scope ([data-astryx-theme="maruhi"])` (the same mark as
 * the dashboard root). `meta color-scheme` is for dark rendering before
 * the CSS arrives.
 */
export function page(title: string, body: string): string {
  const stylesheets = PAGE_STYLESHEETS.map(
    (href) => `    <link rel="stylesheet" href="${href}" />`,
  ).join("\n");
  return `<!doctype html>
<html lang="en" data-astryx-theme="maruhi">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${CLI_PAGE_CSP}" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="color-scheme" content="light dark" />
    <meta name="robots" content="noindex" />
    <title>${escapeHtml(title)}</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
${stylesheets}
  </head>
  <body>
    <div class="page">
      <header class="brand">
        <img src="${PAGE_LOGO}" alt="" width="28" height="28" />
        <span>maruhi</span>
      </header>
      <main>
${body}
      </main>
    </div>
  </body>
</html>
`;
}

/**
 * The uniform error page (§4-2). vsig failure, expiry, re-arrival under a
 * different account, terminal state, cap reached, ticket mismatch — all get
 * the same wording (no oracle into flow state).
 */
export function renderCliErrorPage(): string {
  return page(
    "maruhi — CLI sign-in error",
    `        <h1>This sign-in link can&#39;t be used</h1>
        <p>The link is invalid, has expired, or was already used.</p>
        <p class="outcome">No token was issued.</p>
        <p>Return to your terminal and run <code>maruhi login</code> again to start over.</p>`,
  );
}

/**
 * The signup guidance page (§4-1 (4) (ii) — ruling DH: CLI login creates
 * no account). It carries only the route to Web login (signup's only entry
 * point) and a flow-resume link (verificationUrl). Zero side effects.
 *
 * `signupPolicy` (AUTH_SPEC §3) makes the first paragraph's wording follow:
 * under invite control, guiding to a plain signup link would only lead to
 * an invite-required denial page ("following guidance wording" in
 * hosted-design.md §2-2). A display-only branch; the acceptance source of
 * truth stays the server gate (§3).
 *
 * The composition is the same 3-stage as the denial page (signup-pages.ts):
 * what happened → what did not happen (the outcome row) → what can be done
 * next.
 */
export function renderSignupGuidancePage(
  origin: string,
  verificationUrl: string,
  signupPolicy: "open" | "invite" | "closed",
): string {
  const signupUrl = `${origin}/auth/github/start`;
  const signupStep =
    signupPolicy === "invite"
      ? `Sign-ups on this server are invite-only. Open the sign-up link that came with your
            sign-up invite code (the link carries the code) with this GitHub account. If you
            don&#39;t have an invite, contact the operator of this server.`
      : signupPolicy === "closed"
        ? `Sign-ups on this server are currently closed. Contact the operator of this server
            about getting an account.`
        : `<a href="${escapeHtml(signupUrl)}">Sign up in the browser</a> with this GitHub account.`;
  return page(
    "maruhi — sign up first",
    `        <h1>No maruhi account yet</h1>
        <p>
          The GitHub account you just signed in with is not linked to a maruhi account, and CLI
          sign-in only works for existing accounts.
        </p>
        <p class="outcome">Nothing has been created or changed by opening this page.</p>
        <h2>What to do next</h2>
        <ol>
          <li>${signupStep}</li>
          <li>
            Then <a href="${escapeHtml(verificationUrl)}">resume the CLI sign-in</a> (or open the
            verification link shown in your terminal again).
          </li>
        </ol>`,
  );
}

/** Input to the approval page (§4-1 (4) (iv) — shows the verified identity and the grants). */
interface ApprovalPageInput {
  readonly userCode: string;
  /** Display name of the verified identity (GitHub login; visualizes mix-ups). */
  readonly identityLabel: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly flowId: string;
  /** Single-use, short-lived approval ticket (the raw value is embedded only in this page). */
  readonly ticket: string;
}

function scopeLine(scope: TokenScope): string {
  const project =
    scope.project === "*" ? "all projects" : `project <code>${escapeHtml(scope.project)}</code>`;
  return `<li>${escapeHtml(scope.permission)} access to ${project}</li>`;
}

/**
 * The approval page (§4-1 (4) (iv)): userCode + which account is approving
 * + the grants of the PAT this approval issues (tokenName rendered inert).
 * Only explicit approve / deny actions (form POST). The confirmation code
 * is the page's largest element (comparison is the last defense against
 * phishing — §4-3).
 */
export function renderApprovalPage(input: ApprovalPageInput): string {
  return page(
    "maruhi — approve CLI sign-in",
    `        <h1>Approve CLI sign-in?</h1>
        <p>A command-line sign-in is asking for an access token for your maruhi account.</p>
        <p class="code-panel">
          <span class="code-label">Confirmation code</span>
          <code class="user-code">${escapeHtml(input.userCode)}</code>
        </p>
        <p>
          <strong>Approve only if this code matches the one shown in your terminal.</strong>
          If the codes differ, or you did not start a CLI sign-in, choose Deny.
        </p>
        <h2>What will be granted</h2>
        <dl class="grants">
          <dt>Signing in as</dt>
          <dd><strong>${escapeHtml(input.identityLabel)}</strong></dd>
          <dt>Token name</dt>
          <dd>
            <code>${escapeHtml(input.tokenName)}</code>
            <small>Chosen by the requester, shown verbatim.</small>
          </dd>
          <dt>Access</dt>
          <dd>
            <ul>
${input.scopes.map((scope) => `              ${scopeLine(scope)}`).join("\n")}
            </ul>
          </dd>
          <dt>Expires</dt>
          <dd>${String(input.expiresInDays)} days after issuance</dd>
        </dl>
        <form method="post" action="/auth/cli/approve" class="actions">
          <input type="hidden" name="flowId" value="${escapeHtml(input.flowId)}" />
          <input type="hidden" name="ticket" value="${escapeHtml(input.ticket)}" />
          <button type="submit" name="decision" value="approve" class="button button-primary">Approve</button>
          <button type="submit" name="decision" value="deny" class="button button-secondary">Deny</button>
        </form>`,
  );
}

/** Approval-complete page (the poll side receives the PAT — the token never appears in the browser). */
export function renderApprovedPage(userCode: string): string {
  return page(
    "maruhi — CLI sign-in approved",
    `        <h1>Sign-in approved</h1>
        <p>
          You approved the CLI sign-in with code <code>${escapeHtml(userCode)}</code>.
          Return to your terminal &mdash; it will finish signing in shortly.
        </p>
        <p>You can close this page.</p>`,
  );
}

/** Denial-complete page (acceptance of an explicit denial — the flow can no longer be approved). */
export function renderDeniedPage(): string {
  return page(
    "maruhi — CLI sign-in denied",
    `        <h1>Sign-in denied</h1>
        <p>The CLI sign-in was denied.</p>
        <p class="outcome">No token was issued.</p>
        <p>If this was you, you can close this page and run <code>maruhi login</code> again.</p>`,
  );
}
