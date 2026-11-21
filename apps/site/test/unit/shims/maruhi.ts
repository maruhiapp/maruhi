import { spawnSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";

const argv = process.argv.slice(2);
const log = process.env["RECIPE_TEST_LOG"];
const valuesFile = process.env["RECIPE_TEST_VALUES"];
if (log === undefined || valuesFile === undefined) {
  console.error("maruhi shim: RECIPE_TEST_LOG and RECIPE_TEST_VALUES are required");
  process.exit(2);
}
if (argv[0] !== "run") {
  console.error(`maruhi shim: only \`run\` is supported (got ${JSON.stringify(argv)})`);
  process.exit(2);
}
const flags: Record<string, string> = {};
let i = 1;
while (i < argv.length && argv[i] !== "--") {
  const flag = argv[i];
  const value = argv[i + 1];
  if (!flag?.startsWith("--") || value === undefined) {
    console.error(`maruhi shim: unexpected argument ${JSON.stringify(flag)}`);
    process.exit(2);
  }
  flags[flag] = value;
  i += 2;
}
if (argv[i] !== "--") {
  console.error("maruhi shim: `--` is required");
  process.exit(2);
}
const command = argv.slice(i + 1);
appendFileSync(log, JSON.stringify({ tool: "maruhi", flags, command }) + "\n");
const values = JSON.parse(readFileSync(valuesFile, "utf8")) as Record<string, string>;
const [executable, ...args] = command;
if (executable === undefined) {
  console.error("maruhi shim: a command is required after `--`");
  process.exit(2);
}
const traced = process.env["RECIPE_TEST_XTRACE"] !== undefined && executable === "sh";
const child = spawnSync(executable, traced ? ["-x", ...args] : args, {
  env: { ...process.env, ...values },
  stdio: "inherit",
});
process.exit(child.status ?? 1);
