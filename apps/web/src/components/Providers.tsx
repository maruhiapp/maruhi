"use client";

import { Theme } from "@astryxdesign/core";
import type React from "react";

// プリビルド版テーマオブジェクト(astryx theme build の生成物)。
// ランタイム CSS 注入をしないため、style-src 'self' の厳格 CSP と両立する。
import { maruhiTheme } from "../../theme/maruhi.js";

export function Providers({ children }: { children: React.ReactNode }) {
  return <Theme theme={maruhiTheme}>{children}</Theme>;
}
