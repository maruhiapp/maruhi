"use client";

// The invisible return island placed on S1 (ruling BU): only when the
// sign-in round-trip marker exists does it check `/auth/me` once and,
// if a session is up, return to /dashboard.
// Without the marker it does nothing (a P1 visitor's landing stays at
// zero API calls). If no session is up (OAuth aborted / failed) only
// the marker disappears and the page stays on the landing — no
// assertive error display (outside what the server reports).
import { type ReactNode, useEffect } from "react";

import { apiGet } from "./api.ts";
import { apiPaths } from "./endpoints.ts";
import { consumeResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
import { navigateTo } from "./shared.tsx";
import type { Me } from "./types.ts";

export function ResumeToDashboard(): ReactNode {
  useEffect(() => {
    if (!consumeResumeToDashboard()) return;
    void apiGet<Me>(apiPaths.me()).then((result) => {
      if (result.kind === "ok") navigateTo(spaPaths.dashboard());
    });
  }, []);
  return null;
}
