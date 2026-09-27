"use client";

// Client component (the target of the "use client" boundary check).
// Also verifies Astryx components + xstyle (stylex.create + typed
// tokens). xstyle requires the StyleX compiler (@astryxdesign/build/vite).
// The e2e test reproduces that an unconfigured compiler silently renders
// with no styles.
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
