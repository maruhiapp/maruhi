// Effect-aware type diagnostics (@effect/tsgo) over every program that uses
// Effect. The generic floating-promise rules cannot see a dropped Effect
// (an Effect value is not a thenable), so the Effect language service's
// own correctness rules guard that class of bug instead.
//
//   bun scripts/effect-diagnostics.mjs
//
// One rule configuration for every program (passed as --lspconfig, so no
// tsconfig carries it): the correctness rules fail the run, the
// unstable-API notice is off (effect v4's http modules are marked
// unstable and the repo pins effect exactly), and --strict makes any
// remaining warning fail too. Messages (style suggestions) never fail.
// The web bundle and packages/crypto are Effect-free by contract (CLAUDE.md
// "Effect fence"), so they are not checked here.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const PROJECTS = [
  "apps/server/tsconfig.json",
  "apps/server/scripts/tsconfig.json",
  "apps/cli/tsconfig.json",
  "packages/core/tsconfig.json",
  "packages/api-schema/tsconfig.json",
];

// The correctness preset minus anyUnknownInErrorContext, which is off by
// default and flags deliberate `unknown` error channels (test helpers, the
// CLI's API client seam)
const CORRECTNESS = [
  "classSelfMismatch",
  "duplicatePackage",
  "effectFnImplicitAny",
  "experimentalApiUsage",
  "floatingEffect",
  "floatingEffectInVitest",
  "genericEffectServices",
  "missingEffectContext",
  "missingEffectError",
  "missingLayerContext",
  "missingReturnYieldStar",
  "missingStarInYieldEffectGen",
  "nonObjectEffectServiceType",
  "obsoleteMatchImport",
  "obsoleteSchemaImport",
  "outdatedApi",
  "overriddenSchemaConstructor",
  "promiseInEffectSuccess",
  "schemaLiteralNonFinite",
  "schemaOpaqueInstanceMember",
  "unsafeEffectTypeAssertion",
];

const lspConfig = JSON.stringify({
  diagnosticSeverity: {
    ...Object.fromEntries(CORRECTNESS.map((rule) => [rule, "error"])),
    unstableApiUsage: "off",
  },
});

const format = process.env["GITHUB_ACTIONS"] === "true" ? "github-actions" : "text";

function check(project) {
  return new Promise((resolve) => {
    const child = spawn(
      "bunx",
      [
        "effect-tsgo",
        "diagnostics",
        "--project",
        `${ROOT}${project}`,
        "--strict",
        "--severity",
        "error,warning",
        "--format",
        format,
        "--lspconfig",
        lspConfig,
      ],
      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("close", (code) => resolve({ project, code, output }));
  });
}

const results = await Promise.all(PROJECTS.map(check));
let failed = false;
for (const { project, code, output } of results) {
  if (code === 0) {
    console.log(`effect-diagnostics: ${project} clean`);
  } else {
    failed = true;
    console.error(`effect-diagnostics: ${project} failed (exit ${code})`);
    process.stderr.write(output);
  }
}
process.exit(failed ? 1 : 0);
