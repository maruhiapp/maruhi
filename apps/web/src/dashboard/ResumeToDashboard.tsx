"use client";

// S1 に置く不可視の復帰島(裁定 BU): サインイン往復のマーカーがあるときだけ
// `/auth/me` を 1 回確認し、セッションが立っていれば /dashboard へ戻す。
// マーカーがなければ何もしない(P1 訪問者のランディングは API 呼び出しゼロの
// まま)。セッションが立っていなければ(OAuth 中断・失敗)マーカーだけ消えて
// ランディングに留まる — 断定的なエラー表示は置かない(サーバー申告の範囲外)。
import { type ReactNode, useEffect } from "react";

import { apiGet } from "./api.ts";
import { consumeResumeToDashboard } from "./resume.ts";
import { navigateTo } from "./shared.tsx";
import type { Me } from "./types.ts";

export function ResumeToDashboard(): ReactNode {
  useEffect(() => {
    if (!consumeResumeToDashboard()) return;
    void apiGet<Me>("/auth/me").then((result) => {
      if (result.kind === "ok") navigateTo("/dashboard");
    });
  }, []);
  return null;
}
