// Derives release.yml's smoke matrix from TARGETS (shared.ts is the single
// source of truth). Output is a one-line JSON for GITHUB_OUTPUT:
// [{ target, runner, bin }]

import { TARGETS } from "./shared.ts";

console.log(JSON.stringify(TARGETS.map((t) => ({ target: t.name, runner: t.runner, bin: t.bin }))));
