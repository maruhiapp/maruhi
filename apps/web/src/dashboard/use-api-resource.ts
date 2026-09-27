"use client";

// The three-state hook for a one-shot GET resource (shared across screens).
import { useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, type ApiResult } from "./api.ts";

/**
 * The screen state of useApiResource. `refreshing` on ok means a reload
 * of the same path is in flight while the previous value keeps being
 * rendered (the value is replaced when the re-fetch completes).
 */
export type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "failed"; failure: ApiFailure }
  | { kind: "ok"; value: T; refreshing: boolean };

/** Which path the fetched value belongs to (so a path change never carries the previous value over). */
export interface Loaded<T> {
  readonly path: string;
  readonly state: ResourceState<T>;
}

/**
 * During a reload of the same path the previous value stays (swapping
 * the table for a LoadingRow would drop the focused row's element and
 * focus would fall to body). If the path changed or the last state was
 * failed/loading, it is loading.
 */
export function reloadingState<T>(current: Loaded<T>, path: string): ResourceState<T> {
  return current.path === path && current.state.kind === "ok"
    ? { ...current.state, refreshing: true }
    : { kind: "loading" };
}

/**
 * A small hook holding the three states of a one-shot GET
 * (loading / failure / value). A path change or reload discards a stale
 * in-flight response (marked stale in the effect's cleanup — a
 * late-arriving response for an old project never overwrites the newer
 * screen).
 * During a reload of the same path the previous value keeps rendering
 * with `refreshing: true`.
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
  // Never show the previous path's value right after a path change (the
  // one render before the effect)
  const state: ResourceState<T> = loaded.path === path ? loaded.state : { kind: "loading" };
  return { state, reload };
}
