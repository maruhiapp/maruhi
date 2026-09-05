// CLI ログインのサーバー描画ページ(AUTH_SPEC §4-1 (4))。
//
// 配信規律は §15-3 の招待着地ページと同一: **スクリプトなし**(フォーム POST
// のみ)・CSP `script-src 'none'`。スタイルは自己配信の外部 CSS のみ
// (`style-src 'self'` — インライン style / <style> のハッシュ許可は使わない):
// /theme.css(apps/web/theme/maruhi.css の無変換同梱 = ブランドの正の生成物。
// ADR-0013 — ここに色や hex を書かない)+ /pages.css(apps/web/public/pages.css —
// /invite と共有する枠・余白・確認コードの見せ方)。ロゴは自己配信 SVG
// (`img-src 'self'`)。どちらも apps/web のビルド出力として同じ Worker から配信
// される(apps/server/wrangler.jsonc の assets — セルフホストでも同梱)。文言は
// すべて英語(ADR-0017)。裁定は docs/notes/web-design-pass.md §5(DP4)。
//
// - tokenName は未認証入力として**不活性描画**する(HTML エスケープ +
//   <code> による承認文言との視覚的分離。書式・マークアップの解釈なし —
//   §4-1 (4) (iv)。受理時の文字種制約は §6 が担う)
// - エラーページは一様(§4-2 — フロー状態・拒否理由を出し分けない)
// - flowToken はいかなるページにも現れない(§4-1 (1))

import type { TokenScope } from "@maruhi/core";

/** HTML テキスト / 属性値のエスケープ(不活性描画の実装点)。 */
function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * ページが参照する自己配信アセット(apps/web/public / theme のビルド出力)。
 * 実配信での到達性は apps/web/test/e2e.test.ts が固定する(combined 構成)。
 */
const PAGE_STYLESHEETS = ["/theme.css", "/pages.css"] as const;
const PAGE_LOGO = "/logo-inverted.svg";

/**
 * ページ共通の CSP(meta タグと配信ヘッダーで二重化する — invite.html と同じ
 * 論拠。ヘッダー側の適用点は handlers-auth-cli.ts の htmlResponse)。
 * style-src / img-src は自己配信のみ、form-action は承認フォームの POST 先
 * (自オリジン)のみ許す。script-src は 'none' のまま。
 */
const CLI_PAGE_CSP =
  "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'";

/**
 * 配信ヘッダー用の CSP。`frame-ancestors 'none'` は承認ページのクリック
 * ジャッキング防御(default-src はこのディレクティブにフォールバック
 * **しない**ため、明示しないと任意オリジンから iframe 可能になる)。
 * frame-ancestors は meta タグでは無効(仕様上無視される)ため、invite.html /
 * write-headers.ts と同じくヘッダー側にのみ載せる。承認ページ以外(完了・
 * 拒否・エラー・サインアップ案内)も同じ htmlResponse を通るので一貫して付く。
 */
export const CLI_PAGE_CSP_HEADER = `${CLI_PAGE_CSP}; frame-ancestors 'none'`;

/**
 * スクリプトなしページの共通枠(signup-pages.ts と共用 — 同一の配信規律)。
 * 構造は invite.html と同じ: ブランドヘッダー(見出しではない)→ main。ページの
 * 題は body 側の h1。`data-astryx-theme="maruhi"` は /theme.css のトークンが
 * `@scope ([data-astryx-theme="maruhi"])` 配下で定義されるため(ダッシュボードの
 * ルートと同じ印)。`meta color-scheme` は CSS 到着前のダーク描画のため。
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
 * 一様エラーページ(§4-2)。vsig 失敗・期限切れ・別アカウント再到達・終端状態・
 * 上限到達・チケット不一致 — すべて同一の文言(フロー状態のオラクルを作らない)。
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
 * サインアップ案内ページ(§4-1 (4) (ii) — 裁定 DH: CLI ログインはアカウントを
 * 作らない)。載せるのは Web ログイン(サインアップの唯一の入口)への導線と
 * フロー再開リンク(verificationUrl)のみ。副作用ゼロ。
 *
 * `signupPolicy`(AUTH_SPEC §3 — 2026-09-01 H1)で 1 段目の文言を追随させる:
 * invite 制下でプレーンなサインアップリンクを案内すると invite-required の
 * 拒否ページへ誘導するだけになる(hosted-design.md §2-2 の「案内文言の追随」)。
 * 表示のみの分岐であり、受理の正はサーバーゲート(§3)のまま。
 *
 * 構成は拒否ページ(signup-pages.ts)と同じ 3 段: 何が起きたか → 何が起きて
 * いないか(outcome 行)→ 次にできること。
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

/** 承認ページの入力(§4-1 (4) (iv) — 表示は認証済みアイデンティティと付与内容)。 */
interface ApprovalPageInput {
  readonly userCode: string;
  /** 認証済みアイデンティティの表示名(GitHub login。取り違えの可視化)。 */
  readonly identityLabel: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly flowId: string;
  /** 単回・短命の承認チケット(生値はこのページにのみ埋まる)。 */
  readonly ticket: string;
}

function scopeLine(scope: TokenScope): string {
  const project =
    scope.project === "*" ? "all projects" : `project <code>${escapeHtml(scope.project)}</code>`;
  return `<li>${escapeHtml(scope.permission)} access to ${project}</li>`;
}

/**
 * 承認ページ(§4-1 (4) (iv)): userCode + どのアカウントとして承認するか +
 * この承認が発行する PAT の付与内容(tokenName は不活性描画)。承認 / 拒否の
 * 明示操作のみ(フォーム POST)。確認コードはページ最大の要素(照合が
 * フィッシングの最後の防衛 — §4-3)。
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

/** 承認完了ページ(poll 側が PAT を受け取る — ブラウザにトークンは出ない)。 */
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

/** 拒否完了ページ(明示拒否の受理 — フローは以後承認不能)。 */
export function renderDeniedPage(): string {
  return page(
    "maruhi — CLI sign-in denied",
    `        <h1>Sign-in denied</h1>
        <p>The CLI sign-in was denied.</p>
        <p class="outcome">No token was issued.</p>
        <p>If this was you, you can close this page and run <code>maruhi login</code> again.</p>`,
  );
}
