import { createRequire } from "node:module";

import type { ViteUserConfig } from "vite-plus/test/config";

type ResolveAlias = NonNullable<NonNullable<ViteUserConfig["resolve"]>["alias"]>;

// Shared resolve.alias for the configs that run a Cloudflare pool
// (the root vitest.config.ts, apps/server's, and packages/crypto's
// workerd config). The pool's in-workerd entry imports "vitest/worker"
// and "vitest/runtime" by bare specifier, and resolves them through
// the vite instance of the run's root config. This repo installs no
// standalone vitest at the root (the test runner is vite-plus's
// bundled copy), so those specifiers do not resolve on their own —
// point them at the runner's own copy, resolved through vite-plus,
// whose dependency it is, keeping the pool and the runner on a single
// vitest module instance.
const vitePlusRequire = createRequire(
  createRequire(import.meta.url).resolve("vite-plus/package.json"),
);

// The annotation matters: inferred from the literal, the array's type
// makes defineConfig's UserConfig comparison exceed the checker's
// stack depth (TS2321) in the configs that use it.
export const vitestPoolAliases: ResolveAlias = [
  { find: /^vitest\/worker$/, replacement: vitePlusRequire.resolve("vitest/worker") },
  { find: /^vitest\/runtime$/, replacement: vitePlusRequire.resolve("vitest/runtime") },
];
