import { createRequire } from "node:module";

import type { ViteUserConfig } from "vite-plus/test/config";

type ResolveAlias = NonNullable<NonNullable<ViteUserConfig["resolve"]>["alias"]>;

const vitePlusRequire = createRequire(
  createRequire(import.meta.url).resolve("vite-plus/package.json"),
);

export const vitestPoolAliases: ResolveAlias = [
  { find: /^vitest\/worker$/, replacement: vitePlusRequire.resolve("vitest/worker") },
  { find: /^vitest\/runtime$/, replacement: vitePlusRequire.resolve("vitest/runtime") },
];
