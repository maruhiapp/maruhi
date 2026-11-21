import type { TokenScope } from "@maruhi/core";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const PAGE_STYLESHEETS = ["/theme.css", "/pages.css"] as const;
const PAGE_LOGO = "/logo-inverted.svg";

const CLI_PAGE_CSP =
  "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'";

export const CLI_PAGE_CSP_HEADER = `${CLI_PAGE_CSP}; frame-ancestors 'none'`;

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

export function renderCliErrorPage(): string {
  return page(
    "maruhi — CLI sign-in error",
    `        <h1>This sign-in link can&#39;t be used</h1>
        <p>The link is invalid, has expired, or was already used.</p>
        <p class="outcome">No token was issued.</p>
        <p>Return to your terminal and run <code>maruhi login</code> again to start over.</p>`,
  );
}

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

interface ApprovalPageInput {
  readonly userCode: string;
  readonly identityLabel: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly flowId: string;
  readonly ticket: string;
}

function scopeLine(scope: TokenScope): string {
  const project =
    scope.project === "*" ? "all projects" : `project <code>${escapeHtml(scope.project)}</code>`;
  return `<li>${escapeHtml(scope.permission)} access to ${project}</li>`;
}

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

export function renderDeniedPage(): string {
  return page(
    "maruhi — CLI sign-in denied",
    `        <h1>Sign-in denied</h1>
        <p>The CLI sign-in was denied.</p>
        <p class="outcome">No token was issued.</p>
        <p>If this was you, you can close this page and run <code>maruhi login</code> again.</p>`,
  );
}
