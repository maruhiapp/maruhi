"use client";

import { Theme } from "@astryxdesign/core";
import type React from "react";

import { maruhiTheme } from "../../theme/maruhi.js";

export function Providers({ children }: { children: React.ReactNode }) {
  return <Theme theme={maruhiTheme}>{children}</Theme>;
}
