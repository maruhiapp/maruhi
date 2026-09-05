// セッション失効の通知経路(DP3 改訂 11 — PR #148 pullfrog 指摘)。
//
// シェル(DashboardLayout)は遷移をまたいで 1 回だけマウントされ、`GET /auth/me` も
// 1 回しか呼ばない。そのため画面のフェッチが途中で 401 を返しても、シェルは自力では
// 「サインイン済み」から戻れない。画面側の FailureNotice が 401 を描くときにここを通じて
// 親へ知らせ、シェルはその場でサインイン画面へ切り替える(再読込は要らない)。
// 最初の 401 に反応するだけで、遷移ごとの /auth/me 再確認(1 往復)は増やさない。
import { createContext, useContext, useEffect } from "react";

/** 親シェルが提供する「セッションが失効した」の受け口。シェルの外では undefined。 */
export const SessionExpiredContext = createContext<(() => void) | undefined>(undefined);

/** `expired`(= 画面のフェッチが 401)のとき親シェルへ通知する。 */
export function useReportSessionExpired(expired: boolean): void {
  const report = useContext(SessionExpiredContext);
  useEffect(() => {
    if (expired) report?.();
  }, [expired, report]);
}
