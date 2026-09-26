"use client";

// 単発 GET リソースの 3 状態フック(複数画面で共用)。
import { useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, type ApiResult } from "./api.ts";

/**
 * useApiResource の画面状態。ok の `refreshing` は、同じ path の再読込(reload)中で
 * 直前の値を描き続けていることを示す(値は再取得の完了で置き換わる)。
 */
export type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "failed"; failure: ApiFailure }
  | { kind: "ok"; value: T; refreshing: boolean };

/** 取得済みの値がどの path のものか(path 変更時に前の値を持ち越さないため)。 */
export interface Loaded<T> {
  readonly path: string;
  readonly state: ResourceState<T>;
}

/**
 * 同じ path の再読込中は直前の値を残す(表を LoadingRow に差し替えるとフォーカス中の
 * 行の要素が消えて body へ落ちる)。path が変わった・直前が失敗/読込中なら loading。
 */
export function reloadingState<T>(current: Loaded<T>, path: string): ResourceState<T> {
  return current.path === path && current.state.kind === "ok"
    ? { ...current.state, refreshing: true }
    : { kind: "loading" };
}

/**
 * 単発 GET の 3 状態(loading / failure / value)を持つ小さなフック。
 * path 変更・再読込で古い in-flight 応答は捨てる(effect のクリーンアップで
 * stale マーク — 後着の旧プロジェクト応答が新しい画面を上書きしない)。
 * 同じ path の再読込(reload)中は直前の値を `refreshing: true` で描き続ける。
 */
export function useApiResource<T>(path: string): {
  state: ResourceState<T>;
  reload: () => void;
} {
  const [loaded, setLoaded] = useState<Loaded<T>>({ path, state: { kind: "loading" } });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let stale = false;
    setLoaded((current) => ({ path, state: reloadingState(current, path) }));
    void apiGet<T>(path).then((result: ApiResult<T>) => {
      if (stale) return;
      setLoaded({
        path,
        state:
          result.kind === "ok"
            ? { kind: "ok", value: result.value, refreshing: false }
            : { kind: "failed", failure: result },
      });
    });
    return () => {
      stale = true;
    };
  }, [path, attempt]);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  // path が変わった直後(effect 前の 1 描画)に前の path の値を見せない
  const state: ResourceState<T> = loaded.path === path ? loaded.state : { kind: "loading" };
  return { state, reload };
}
