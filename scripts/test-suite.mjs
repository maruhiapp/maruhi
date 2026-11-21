import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT_CONFIG = join(ROOT, "vitest.config.ts");

const SUITES = ["app-unit", "cli", "packages", "server"];

function suiteFor(relPath) {
  if (/^packages\/[^/]+\//.test(relPath)) return "packages";
  if (relPath.startsWith("apps/cli/")) return "cli";
  if (relPath.startsWith("apps/server/")) return "server";
  if (/^apps\/[^/]+\/vitest\.unit\.config\.ts$/.test(relPath)) return "app-unit";
  throw new Error(
    `vitest project config "${relPath}" matches no test-suite rule — ` +
      `teach scripts/test-suite.mjs which suite it belongs to`,
  );
}

function projectSpecifiers() {
  const src = readFileSync(ROOT_CONFIG, "utf8");
  const m = src.match(/\bprojects\s*:\s*\[/);
  if (!m || m.index === undefined) {
    throw new Error(`no projects: array found in ${ROOT_CONFIG}`);
  }
  const start = m.index + m[0].length;
  const end = src.indexOf("]", start);
  if (end === -1) {
    throw new Error(`unterminated projects: array in ${ROOT_CONFIG}`);
  }
  const block = src.slice(start, end);
  const strings = [];
  const rest = block
    .replace(/\/\/[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(["'`])([^"'`\n]*)\1/g, (_q, _open, s) => {
      strings.push(s);
      return "";
    });
  if (!/^[\s,]*$/.test(rest)) {
    throw new Error(
      `projects: in ${ROOT_CONFIG} must be plain string literals ` +
        `(found: ${rest.trim().slice(0, 80)})`,
    );
  }
  return strings;
}

function expandSpecifier(spec) {
  if (/[*?[{]/.test(spec)) {
    const matches = [...new Bun.Glob(spec).scanSync({ cwd: ROOT })].toSorted();
    if (matches.length === 0) {
      throw new Error(`projects: glob "${spec}" matched no files`);
    }
    return matches;
  }
  if (!existsSync(join(ROOT, spec))) {
    throw new Error(`projects: entry "${spec}" does not exist on disk`);
  }
  return [spec];
}

function projectName(relPath) {
  const src = readFileSync(join(ROOT, relPath), "utf8");
  const testIdx = src.search(/\btest\s*:/);
  if (testIdx === -1) {
    throw new Error(`no test: block in ${relPath}`);
  }
  const m = src.slice(testIdx).match(/\bname\s*:\s*(["'`])([^"'`\n]+)\1/);
  if (!m) {
    throw new Error(`no literal test.name in ${relPath}`);
  }
  if (m[2].includes("${")) {
    throw new Error(`interpolated test.name in ${relPath}`);
  }
  return m[2];
}

function partition() {
  const suites = Object.fromEntries(SUITES.map((s) => [s, []]));
  for (const spec of projectSpecifiers()) {
    for (const relPath of expandSpecifier(spec)) {
      suites[suiteFor(relPath)].push(projectName(relPath));
    }
  }
  for (const [suite, members] of Object.entries(suites)) {
    suites[suite] = members.toSorted();
  }
  return suites;
}

const [command, ...args] = process.argv.slice(2);

switch (command) {
  case "list": {
    process.stdout.write(`${JSON.stringify(partition(), null, 2)}\n`);
    break;
  }
  case "probe": {
    const [relPath] = args;
    if (!relPath) {
      process.stderr.write("usage: test-suite.mjs probe <repo-relative path>\n");
      process.exit(1);
    }
    try {
      process.stdout.write(`${suiteFor(relPath)}\n`);
    } catch (e) {
      process.stderr.write(`${e.message}\n`);
      process.exit(1);
    }
    break;
  }
  case "run": {
    const [suite, ...extra] = args;
    if (!SUITES.includes(suite)) {
      process.stderr.write(
        `unknown suite "${suite ?? ""}" — expected one of: ${SUITES.join(", ")}\n`,
      );
      process.exit(1);
    }
    const names = partition()[suite];
    const passthrough = extra[0] === "--" ? extra.slice(1) : extra;
    const projects = names.flatMap((n) => ["--project", n]);
    const result = spawnSync(
      join(ROOT, "node_modules/.bin/vp"),
      ["test", "run", ...projects, ...passthrough],
      {
        cwd: ROOT,
        stdio: "inherit",
      },
    );
    process.exit(result.status ?? 1);
    break;
  }
  default: {
    process.stderr.write(
      "usage: test-suite.mjs list | run <suite> [-- vitest args] | probe <path>\n",
    );
    process.exit(command ? 1 : 0);
  }
}
