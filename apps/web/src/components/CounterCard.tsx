"use client";

// クライアントコンポーネント("use client" 境界の検証対象)。
// Astryx コンポーネント + xstyle(stylex.create + typed tokens)の検証を兼ねる。
// xstyle は StyleX コンパイラ(@astryxdesign/build/vite)を要求する。
// コンパイラ未設定時に無警告で無スタイルになることを e2e テストで再現する。
import { Button } from "@astryxdesign/core/Button";
import { spacingVars } from "@astryxdesign/core/theme/tokens.stylex";
import * as stylex from "@stylexjs/stylex";
import { useState } from "react";

const overrides = stylex.create({
  counterButton: {
    marginTop: spacingVars["--spacing-5"],
  },
});

export function CounterCard() {
  const [count, setCount] = useState(0);
  return (
    <Button
      label={`count: ${count}`}
      variant="primary"
      onClick={() => setCount((c) => c + 1)}
      xstyle={overrides.counterButton}
      data-testid="counter-button"
    />
  );
}
