// サインアップ制御の案内ページ(AUTH_SPEC §3 — 2026-09-01 H1)。
//
// 配信規律は cli-pages.ts と同一(§15-3 の招待着地ページの型): スクリプトなし・
// スタイルなし・CSP `script-src 'none'`。応答点は handlers-auth.ts(配信ヘッダーは
// handlers-auth-cli.ts の htmlResponse を共用)。文言はすべて英語(ADR-0017)。
//
// - 拒否ページはどれも「アカウントは作られていない」を明示する(fail-closed の
//   可視化 — AUTH_SPEC §3。行を作らない実装と文言を一致させる)
// - invite-invalid は無効・失効・消費済みを出し分けない(§15 の 410 と同じ一様さ。
//   256-bit 単回コードなので列挙オラクルの懸念自体は薄いが、区別して得る UX もない)
// - waitlist の収集面は作らない(hosted-design.md §2-2 — 案内は運営への連絡まで)

import { page } from "./cli-pages.ts";

/** signupPolicy = closed の拒否ページ(§3 — OAuth 完走後・行を作らず終了)。 */
export function renderSignupClosedPage(): string {
  return page(
    "maruhi — sign-ups closed",
    `      <h2>Sign-ups are closed</h2>
      <p>
        This maruhi server is not accepting new accounts right now, so no account was
        created.
      </p>
      <p>
        If you already have an account under a different identity, sign in with that one.
        Otherwise, contact the operator of this server about getting access.
      </p>`,
  );
}

/** signupPolicy = invite でコード未提示の拒否ページ(§3)。 */
export function renderSignupInviteRequiredPage(): string {
  return page(
    "maruhi — invite required",
    `      <h2>Sign-ups are invite-only</h2>
      <p>
        This maruhi server requires a sign-up invite code to create an account, so no
        account was created.
      </p>
      <p>
        If you received an invite, open the sign-up link that came with it &mdash; the link
        carries your code. To request an invite, contact the operator of this server.
      </p>`,
  );
}

/**
 * 無効なサインアップ招待コードのページ(§3 — start の事前検証と callback の
 * 消費 CAS 敗北の両方で使う。不明・失効・消費済みを出し分けない)。
 */
export function renderSignupInviteInvalidPage(): string {
  return page(
    "maruhi — invite code can't be used",
    `      <h2>This sign-up invite code can&#39;t be used</h2>
      <p>The code is invalid, has expired, or was already used. No account was created.</p>
      <p>
        Ask the operator of this server for a new sign-up invite code. If sign-ups are open
        on this server, you can also <a href="/auth/github/start">sign up without a code</a>.
      </p>`,
  );
}
