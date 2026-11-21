import { TARGETS } from "./shared.ts";

console.log(JSON.stringify(TARGETS.map((t) => ({ target: t.name, runner: t.runner, bin: t.bin }))));
