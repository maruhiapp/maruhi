// サインアップ制御の案内ページ(AUTH_SPEC §3 — 2026-09-01 H1)。
//
// 配信規律は cli-pages.ts と同一(§15-3 の招待着地ページの型): スクリプトなし・
// 自己配信 CSS のみ(共通枠 `page()`)・CSP `script-src 'none'`。応答点は
// handlers-auth.ts(配信ヘッダーは handlers-auth-cli.ts の htmlResponse を共用)。
// 文言はすべて英語(ADR-0017)。
//
// 3 枚とも同じ 3 段で書く(ROADMAP H6「拒否時の着地文言」— DP4 で整えた):
//   1. 何が起きたか(h1 + 1 文)
//   2. 何が起きていないか — **「アカウントは作られていない」を outcome 行で明示**
//      (fail-closed の可視化 — AUTH_SPEC §3。行を作らない実装と文言を一致させる)
//   3. 次にできること(h2 "What you can do" + 箇条書き)
// - invite-invalid は無効・失効・消費済みを出し分けない(§15 の 410 と同じ一様さ。
//   256-bit 単回コードなので列挙オラクルの懸念自体は薄いが、区別して得る UX もない)
// - waitlist の収集面は作らない(hosted-design.md §2-2 — 案内は運営への連絡まで)

import { page } from "./cli-pages.ts";

const NO_ACCOUNT_CREATED = `        <p class="outcome">No account was created.</p>`;

/** signupPolicy = closed の拒否ページ(§3 — OAuth 完走後・行を作らず終了)。 */
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

/** signupPolicy = invite でコード未提示の拒否ページ(§3)。 */
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
 * 無効なサインアップ招待コードのページ(§3 — start の事前検証と callback の
 * 消費 CAS 敗北の両方で使う。不明・失効・消費済みを出し分けない)。
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
