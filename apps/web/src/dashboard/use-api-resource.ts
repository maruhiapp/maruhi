"use client";

import { useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, type ApiResult } from "./api.ts";

export type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "failed"; failure: ApiFailure }
  | { kind: "ok"; value: T; refreshing: boolean };

export interface Loaded<T> {
  readonly path: string;
  readonly state: ResourceState<T>;
}

export function reloadingState<T>(current: Loaded<T>, path: string): ResourceState<T> {
  return current.path === path && current.state.kind === "ok"
    ? { ...current.state, refreshing: true }
    : { kind: "loading" };
}

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
  const state: ResourceState<T> = loaded.path === path ? loaded.state : { kind: "loading" };
  return { state, reload };
}
