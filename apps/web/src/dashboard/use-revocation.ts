"use client";

// 失効操作(DELETE)の行単位の状態機械(裁定 CO — docs/notes/session-45.md)。
// S8(招待)と S9(トークン)で共用する。
//
// - 武装(armed)は常に 1 行のみ(別行の武装・Cancel で解除)
// - 確認で DELETE(CSRF ヘッダーは api 層が一律付与 — AUTH_SPEC §11-4)
// - 成否によらず完了後に一覧を再取得する(楽観更新でクライアント推測の状態を
//   描かない — 表示規律 §4 と同じ側。410 / 404 は他所で状態が動いた印でもある)
// - 状態は一覧リソースの再取得をまたいで生存させる(呼び出し側は一覧の外 —
//   画面レベル — で本フックを持つ): 再取得中のアンマウントで失敗表示が
//   消えない
import { useCallback, useRef, useState } from "react";

import { apiDelete, type ApiFailure } from "./api.ts";

/** 失効操作の画面状態(武装・実行中・直近の失敗)。 */
export interface RevocationState {
  readonly armedId: string | undefined;
  readonly pendingId: string | undefined;
  readonly failure: ApiFailure | undefined;
}

const IDLE: RevocationState = { armedId: undefined, pendingId: undefined, failure: undefined };

/** 2 段階失効の状態と操作(revokePath は id → DELETE パスのビルダー)。 */
export function useRevocation(
  revokePath: (id: string) => string,
  reload: () => void,
): {
  revocation: RevocationState;
  arm: (id: string | undefined) => void;
  confirm: (id: string) => void;
} {
  const [revocation, setRevocation] = useState<RevocationState>(IDLE);
  // in-flight ガード(PR #109 Bugbot 指摘): DELETE の実行中は arm / confirm を
  // 受け付けない — 後着の完了が別行の武装状態を上書きし、失敗の帰属が別の
  // 失効に見える競合を塞ぐ。UI 側も pendingId を見て他行の Revoke を無効化する
  // (RevokeControl の isLocked)— ガードは見えないボタンでなく効かないボタンを
  // 作らないための二層目
  const pendingRef = useRef(false);
  const arm = useCallback((id: string | undefined) => {
    if (pendingRef.current) return;
    setRevocation({ armedId: id, pendingId: undefined, failure: undefined });
  }, []);
  const confirm = useCallback(
    (id: string) => {
      if (pendingRef.current) return;
      pendingRef.current = true;
      setRevocation({ armedId: id, pendingId: id, failure: undefined });
      void apiDelete(revokePath(id)).then((result) => {
        pendingRef.current = false;
        setRevocation({
          armedId: undefined,
          pendingId: undefined,
          failure: result.kind === "ok" ? undefined : result,
        });
        reload();
      });
    },
    [revokePath, reload],
  );
  return { revocation, arm, confirm };
}
