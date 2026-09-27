"use client";

import { Theme } from "@astryxdesign/core";
import type React from "react";

// The prebuilt theme object (`astryx theme build` output).
// It injects no CSS at runtime, so it is compatible with the strict
// style-src 'self' CSP.
import { maruhiTheme } from "../../theme/maruhi.js";

export function Providers({ children }: { children: React.ReactNode }) {
  return <Theme theme={maruhiTheme}>{children}</Theme>;
}
