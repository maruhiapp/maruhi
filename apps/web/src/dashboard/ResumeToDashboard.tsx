"use client";

import { type ReactNode, useEffect } from "react";

import { apiGet } from "./api.ts";
import { apiPaths } from "./endpoints.ts";
import { navigateTo } from "./navigation.ts";
import { consumeResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
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
