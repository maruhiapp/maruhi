// release.yml の smoke matrix を TARGETS(shared.ts = 単一の出所)から導出する。
// 出力は GITHUB_OUTPUT に入れる 1 行 JSON: [{ target, runner, bin }]

import { TARGETS } from "./shared.ts";

console.log(JSON.stringify(TARGETS.map((t) => ({ target: t.name, runner: t.runner, bin: t.bin }))));
