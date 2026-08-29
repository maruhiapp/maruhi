// サインイン後の /dashboard 復帰マーカー(裁定 BU — docs/notes/session-43.md §10)。
//
// OAuth callback は `${origin}/`(S1 ランディング)へ固定リダイレクトする(API
// 挙動 — 本 PR で不変)。ダッシュボードの Sign in クリック時に sessionStorage へ
// ワンショットのマーカーを置き、S1 側がマーカーを消費したときだけ `/auth/me` を
// 1 回確認して /dashboard へ戻す。マーカーなしの S1(P1 訪問者)は API を一切
// 呼ばない(BP 第 3 周で棄却した「S1 での常時 /auth/me 照会」を避けたまま、
// 受容していた「余分な 1 ホップ」を解消する)。
//
// sessionStorage はタブ単位・OAuth 往復はタブ内遷移なので届く。storage 不可の
// 環境(プライベートモード等)では例外を型付きの「マーカーなし」へ写して
// 現行導線(静的リンク)に劣化する(握り潰しではなく分類 — api.ts と同じ規律)。

const RESUME_MARKER_KEY = "maruhi-resume-dashboard";

/** Sign in クリック時に呼ぶ: 完了後に /dashboard へ戻る意図を記録する。 */
export function markResumeToDashboard(): void {
  try {
    window.sessionStorage.setItem(RESUME_MARKER_KEY, "1");
  } catch {
    // storage 不可 = マーカーなしとして現行導線(ランディング着地)に劣化する
  }
}

/** S1 側で 1 回だけ消費する: マーカーがあれば消して true。 */
export function consumeResumeToDashboard(): boolean {
  try {
    const marked = window.sessionStorage.getItem(RESUME_MARKER_KEY) !== null;
    if (marked) window.sessionStorage.removeItem(RESUME_MARKER_KEY);
    return marked;
  } catch {
    return false;
  }
}
