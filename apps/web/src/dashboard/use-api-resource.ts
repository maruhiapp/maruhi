"use client";

// 単発 GET リソースの 3 状態フック(W2 で ProjectScreen 内に置いていたものを
// W3b で S9 と共用するため独立モジュール化 — 挙動は不変)。
import { useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, type ApiResult } from "./api.ts";

/** useApiResource の画面状態。 */
export type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "failed"; failure: ApiFailure }
  | { kind: "ok"; value: T };

/**
 * 単発 GET の 3 状態(loading / failure / value)を持つ小さなフック。
 * path 変更・再読込で古い in-flight 応答は捨てる(effect のクリーンアップで
 * stale マーク — 後着の旧プロジェクト応答が新しい画面を上書きしない。
 * PR #107 Bugbot 指摘の修正)。
 */
export function useApiResource<T>(path: string): {
  state: ResourceState<T>;
  reload: () => void;
} {
  const [state, setState] = useState<ResourceState<T>>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let stale = false;
    setState({ kind: "loading" });
    void apiGet<T>(path).then((result: ApiResult<T>) => {
      if (stale) return;
      setState(
        result.kind === "ok"
          ? { kind: "ok", value: result.value }
          : { kind: "failed", failure: result },
      );
    });
    return () => {
      stale = true;
    };
  }, [path, attempt]);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  return { state, reload };
}
