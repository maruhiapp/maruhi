// CLI ログインのサーバー描画ページ(AUTH_SPEC §4-1 (4))。
//
// 配信規律は §15-3 の招待着地ページと同一: **スクリプトなし**(フォーム POST
// のみ)・CSP `script-src 'none'`。スタイルシートも持たない(素の UA 描画 —
// インライン style を CSP で許す例外を増やさない)。文言はすべて英語
// (ADR-0017)。
//
// - tokenName は未認証入力として**不活性描画**する(HTML エスケープ +
//   <code> による承認文言との視覚的分離。書式・マークアップの解釈なし —
//   §4-1 (4) (iv)。受理時の文字種制約は §6 が担う)
// - エラーページは一様(§4-2 — フロー状態・拒否理由を出し分けない)
// - flowToken はいかなるページにも現れない(§4-1 (1))

import type { TokenScope } from "@maruhi/core";

/** HTML テキスト / 属性値のエスケープ(不活性描画の実装点)。 */
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * ページ共通の CSP(meta タグと配信ヘッダーで二重化する — invite.html と同じ
 * 論拠。ヘッダー側の適用点は handlers-auth-cli.ts の htmlResponse)。
 * form-action は承認フォームの POST 先(自オリジン)のみ許す。
 */
export const CLI_PAGE_CSP =
  "default-src 'none'; script-src 'none'; style-src 'none'; base-uri 'none'; form-action 'self'";

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${CLI_PAGE_CSP}" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex" />
    <title>${escapeHtml(title)}</title>
  </head>
  <body>
    <main>
      <h1>&#12953; maruhi</h1>
${body}
    </main>
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
    `      <h2>This sign-in link can&#39;t be used</h2>
      <p>The link is invalid, has expired, or was already used.</p>
      <p>Return to your terminal and run <code>maruhi login</code> again to start over.</p>`,
  );
}

/**
 * サインアップ案内ページ(§4-1 (4) (ii) — 裁定 DH: CLI ログインはアカウントを
 * 作らない)。載せるのは Web ログイン(サインアップの唯一の入口)への導線と
 * フロー再開リンク(verificationUrl)のみ。副作用ゼロ。
 */
export function renderSignupGuidancePage(origin: string, verificationUrl: string): string {
  const signupUrl = `${origin}/auth/github/start`;
  return page(
    "maruhi — sign up first",
    `      <h2>No maruhi account yet</h2>
      <p>
        This GitHub identity is not linked to a maruhi account. CLI sign-in only works for
        existing accounts.
      </p>
      <ol>
        <li><a href="${escapeHtml(signupUrl)}">Sign up in the browser</a> with this GitHub account.</li>
        <li>
          Then <a href="${escapeHtml(verificationUrl)}">resume the CLI sign-in</a> (or open the
          verification link shown in your terminal again).
        </li>
      </ol>
      <p>Nothing has been created or changed by opening this page.</p>`,
  );
}

/** 承認ページの入力(§4-1 (4) (iv) — 表示は認証済みアイデンティティと付与内容)。 */
export interface ApprovalPageInput {
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
  const project = scope.project === "*" ? "all projects" : `project <code>${escapeHtml(scope.project)}</code>`;
  return `<li>${escapeHtml(scope.permission)} access to ${project}</li>`;
}

/**
 * 承認ページ(§4-1 (4) (iv)): userCode + どのアカウントとして承認するか +
 * この承認が発行する PAT の付与内容(tokenName は不活性描画)。承認 / 拒否の
 * 明示操作のみ(フォーム POST)。
 */
export function renderApprovalPage(input: ApprovalPageInput): string {
  return page(
    "maruhi — approve CLI sign-in",
    `      <h2>Approve CLI sign-in?</h2>
      <p>A command-line sign-in is asking for an access token.</p>
      <p>
        Confirmation code: <strong><code>${escapeHtml(input.userCode)}</code></strong>
      </p>
      <p>
        <strong>Approve only if this code matches the one shown in your terminal.</strong>
        If the codes differ, or you did not start a CLI sign-in, choose Deny.
      </p>
      <h3>What will be granted</h3>
      <ul>
        <li>Signing in as: <strong>${escapeHtml(input.identityLabel)}</strong></li>
        <li>Token name (chosen by the requester, shown verbatim): <code>${escapeHtml(input.tokenName)}</code></li>
${input.scopes.map((scope) => `        ${scopeLine(scope)}`).join("\n")}
        <li>Expires ${String(input.expiresInDays)} days after issuance</li>
      </ul>
      <form method="post" action="/auth/cli/approve">
        <input type="hidden" name="flowId" value="${escapeHtml(input.flowId)}" />
        <input type="hidden" name="ticket" value="${escapeHtml(input.ticket)}" />
        <button type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
      </form>`,
  );
}

/** 承認完了ページ(poll 側が PAT を受け取る — ブラウザにトークンは出ない)。 */
export function renderApprovedPage(userCode: string): string {
  return page(
    "maruhi — CLI sign-in approved",
    `      <h2>Sign-in approved</h2>
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
    `      <h2>Sign-in denied</h2>
      <p>The CLI sign-in was denied. No token was issued.</p>
      <p>If this was you, you can close this page and run <code>maruhi login</code> again.</p>`,
  );
}
