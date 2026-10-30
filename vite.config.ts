import { correctness, presets } from "@effect/tsgo/oxlint-presets";
import { defineConfig } from "vite-plus";

// The repository's lint configuration (oxlint, driven by vite-plus). It
// replaces the two .oxlintrc.json files (root + apps/web) that nested
// oxlint configs used to provide: vite-plus reads the lint block of the
// workspace root's vite.config.ts only, and every glob below is written
// from the repository root.
//
// The Effect diagnostics gate lives here too. Its rules are the
// effecttsgo correctness preset shipped by @effect/tsgo (the package is
// a dependency only as the supplier of this preset and of the patched
// tsgolint / oxlint artifacts — the root package.json `prepare` script
// re-applies `effect-tsgo patch --oxlint` on every install; it is not
// used as an editor language server). Severities match the standalone
// gate this replaces (scripts/effect-diagnostics.mjs): every correctness
// rule at error, except unstableApiUsage (off: effect v4's http modules
// are marked unstable and the repo pins effect exactly),
// schemaClassMissingBrand (off: CLAUDE.md brands a type only where it
// carries an invariant), and anyUnknownInErrorContext (excluded: it
// flags deliberate `unknown` error channels — test helpers, the CLI's
// API client seam).
// Enabling the effecttsgo plugin also switches some of its rules on by
// category, so every rule the package ships is pinned explicitly: the
// correctness set at error, everything else off.
const effectTsgoRules: Record<string, string> = {};
for (const preset of Object.values(presets)) {
  for (const rule of Object.keys(preset.rules ?? {})) {
    effectTsgoRules[rule] = "off";
  }
}
for (const rule of Object.keys(correctness.rules ?? {})) {
  effectTsgoRules[rule] = "error";
}
effectTsgoRules["effecttsgo/any-unknown-in-error-context"] = "off";
effectTsgoRules["effecttsgo/schema-class-missing-brand"] = "off";
effectTsgoRules["effecttsgo/unstable-api-usage"] = "off";

export default defineConfig({
  // The formatter configuration, formerly .oxfmtrc.json: import sorting
  // is part of the format, and prose / generated files stay unformatted.
  fmt: {
    sortImports: true,
    ignorePatterns: [
      "**/*.md",
      "bun.lock",
      "fallow-baselines",
      ".agents",
      ".claude",
      ".deepsec",
      "apps/cli/test/golden",
    ],
  },
  lint: {
    jsPlugins: [{ name: "eslint-js", specifier: "oxlint-plugin-eslint" }],
    plugins: ["effecttsgo"],
    categories: {
      correctness: "error",
      suspicious: "error",
    },
    // Type-aware rules (oxlint-tsgolint). The categories above already
    // pull in the type-aware correctness / suspicious rules; the ones
    // listed "off" below had findings when type-aware linting was
    // introduced and are enabled one by one as their findings are fixed
    // (consistent-return and the two type-assertion rules flag Effect
    // idioms / tsgolint is not deterministic on
    // no-unnecessary-type-assertion). The "error" list names rules
    // outside those categories that the tree already satisfies.
    // Effect values are not thenables, so dropped Effects are guarded
    // by the effecttsgo rules above, not by no-floating-promises.
    // typeCheck makes `vp check` run the full typecheck as well.
    options: { typeAware: true, typeCheck: true },
    rules: {
      "typescript/await-thenable": "error",
      "typescript/no-array-delete": "error",
      "typescript/no-floating-promises": "error",
      "typescript/no-for-in-array": "error",
      "typescript/no-implied-eval": "error",
      "typescript/no-meaningless-void-operator": "error",
      "typescript/no-misused-promises": "error",
      "typescript/no-unsafe-enum-comparison": "error",
      "typescript/no-unsafe-unary-minus": "error",
      "typescript/restrict-plus-operands": "error",
      "typescript/consistent-return": "off",
      "typescript/no-base-to-string": "off",
      "typescript/no-duplicate-type-constituents": "off",
      "typescript/no-misused-spread": "off",
      "typescript/no-redundant-type-constituents": "off",
      "typescript/no-unnecessary-boolean-literal-compare": "off",
      "typescript/no-unnecessary-template-expression": "off",
      "typescript/no-unnecessary-type-arguments": "off",
      "typescript/no-unnecessary-type-assertion": "off",
      "typescript/no-unnecessary-type-conversion": "off",
      "typescript/no-unnecessary-type-parameters": "off",
      "typescript/no-unsafe-type-assertion": "off",
      "typescript/require-array-sort-compare": "off",
      "typescript/restrict-template-expressions": "off",
      "typescript/unbound-method": "off",
      ...effectTsgoRules,
    },
    ignorePatterns: [
      "fallow-baselines",
      ".agents",
      ".claude",
      ".deepsec",
      // astryx theme build artifacts (from apps/web/.oxlintrc.json)
      "apps/web/theme/maruhi.js",
      "apps/web/theme/*.d.ts",
      "apps/web/dist",
    ],
    overrides: [
      {
        // Promoted to correctness by oxlint 1.85. Moving helper
        // functions out of tests is a large-scale migration and whether
        // a capture exists varies per call site. Keep the locality.
        files: ["**/test/**", "**/*.test.ts"],
        rules: { "unicorn/consistent-function-scoping": "off" },
      },
      {
        // Outbound HTTP goes through one client
        // (packages/core/src/egress.ts): effect's own clients add trace
        // headers (traceparent / b3) to every request, which the "say
        // nothing" principle rules out. Tests may build plain clients
        // for their local stub servers. This override does not reach
        // apps/web/src, and the web needs no copy: the bundle tripwires
        // in apps/web/test/unit/endpoints.test.ts refuse a value import
        // of effect, @effect/* or @maruhi/core (static or dynamic), and
        // any @maruhi/crypto specifier, in every source file there.
        // (With the former nested configs the root `apps/*/src/**` glob
        // never matched web files; the enumeration below preserves
        // exactly that reach.)
        files: ["apps/cli/src/**", "apps/server/src/**", "apps/site/src/**", "packages/*/src/**"],
        rules: {
          "no-restricted-imports": [
            "error",
            {
              paths: [
                {
                  name: "effect/http",
                  importNames: ["FetchHttpClient"],
                  message:
                    "Build outbound HTTP clients only with egressHttpClientLayer from @maruhi/core (packages/core/src/egress.ts)",
                },
                {
                  name: "@effect/platform-bun/BunHttpClient",
                  message:
                    "Build outbound HTTP clients only with egressHttpClientLayer from @maruhi/core (packages/core/src/egress.ts)",
                },
                {
                  name: "@maruhi/core",
                  importNames: [
                    "UserIdSchema",
                    "ProviderUserIdSchema",
                    "KeyFingerprintHexSchema",
                    "OrgIdSchema",
                    "ProjectIdSchema",
                    "EnvironmentIdSchema",
                    "VariableIdSchema",
                    "decodeUserId",
                    "decodeProviderUserId",
                    "decodeKeyFingerprintHex",
                    "decodeOrgId",
                    "decodeProjectId",
                    "decodeEnvironmentId",
                    "decodeVariableId",
                    "environmentIdSchemaWithMessage",
                  ],
                  message:
                    "UserId / ProviderUserId / KeyFingerprintHex / OrgId / ProjectId / EnvironmentId / VariableId are minted only at a trust boundary (packages/core/src/identity.ts and packages/core/src/project.ts / auth.ts): a wire schema in packages/api-schema, a branded Drizzle column, a fingerprint computed from keys (userKeyFingerprintHex / serverKeyFingerprintHex), a generated id, or one of the hand-written mint sites listed in vite.config.ts. Read the value from where it was already minted (the verified chain state, a decoded field, a branded column) instead",
                },
                {
                  name: "@maruhi/crypto/test-support",
                  message:
                    "Test support only: its testUserId / testKeyFingerprintHex are unchecked casts for test data. Shipped code mints a brand only through the mints in packages/core/src/identity.ts",
                },
              ],
            },
          ],
        },
      },
      {
        // The one place allowed to wrap effect's fetch client
        files: ["packages/core/src/egress.ts"],
        rules: { "no-restricted-imports": "off" },
      },
      {
        // The identity mint sites (packages/core/src/identity.ts,
        // project.ts, auth.ts): the wire schemas and decode* mints may
        // be imported only at trust boundaries — api-schema's wire
        // definitions, the CLI's flag / config / record parsers, the
        // server's row mapping (Drizzle columns and the data store's
        // branded reads), handler decoding, generation, and the provider
        // API's subject. The `is*` guards are NOT restricted: every
        // exported one (isProjectId / isEnvironmentId / isVariableId /
        // isKeyFingerprintHex) is a non-narrowing format check, and a
        // guard that cannot mint needs no boundary. The actual mint next
        // to them (decode* / a schema) is what this list pins. The
        // egress and test-support bans above are restated because an
        // override replaces the rule's options
        files: [
          "packages/api-schema/src/**",
          "apps/cli/src/commands/flags.ts",
          "apps/cli/src/ci.package/command.ts",
          "apps/cli/src/commands/device.ts",
          "apps/cli/src/env.package/command.ts",
          "apps/cli/src/commands/rotation.ts",
          "apps/cli/src/server.package/command.ts",
          "apps/cli/src/commands/pull-run.ts",
          "apps/cli/src/keychain.ts",
          "apps/cli/src/context.ts",
          "apps/cli/src/anchor.ts",
          "apps/cli/src/audit.package/audit-list.ts",
          "apps/cli/src/audit.package/command.ts",
          "apps/cli/src/config-schema.ts",
          "apps/cli/src/device-revoke.ts",
          "apps/cli/src/floor-log.ts",
          "apps/cli/src/floor-log-decode.ts",
          "apps/cli/src/floor.ts",
          "apps/cli/src/invite-link.ts",
          "apps/cli/src/json-record.ts",
          "apps/cli/src/mcp.ts",
          "apps/cli/src/meta-statement.ts",
          "apps/cli/src/own-devices.ts",
          "apps/cli/src/pins.ts",
          "apps/cli/src/proxy.package/command.ts",
          "apps/cli/src/proxy.package/proxy-accept.ts",
          "apps/cli/src/scope.ts",
          "apps/cli/src/sync.package/command.ts",
          "apps/server/src/ids.ts",
          "apps/server/src/auth.package/github.ts",
          "apps/server/src/restore-worker.ts",
          "apps/server/src/data/data-plane.ts",
          "apps/server/src/data/data-store-attestation-queries.ts",
          "apps/server/src/data/data-store-environment-queries.ts",
          "apps/server/src/data/data-store-proposal-queries.ts",
          "apps/server/src/data/data-store-rows.ts",
          "apps/server/src/data/data-store-variable-queries.ts",
          "apps/server/src/data/data-store-version-queries.ts",
          "apps/server/src/data/data-store-wrap-queries.ts",
          "apps/server/src/data/data-store-write-ops.ts",
          "apps/server/src/db.package/invites.ts",
          "apps/server/src/audit-store-query.ts",
          "apps/server/src/audit-store-rotation-read.ts",
          "apps/server/src/audit-store-rows.ts",
          "apps/server/src/handlers/handlers-membership.ts",
          "apps/server/src/handlers/handlers-rotation.ts",
          "apps/server/src/import-check.ts",
          "apps/server/src/ops/ops-backup.ts",
        ],
        rules: {
          "no-restricted-imports": [
            "error",
            {
              paths: [
                {
                  name: "effect/http",
                  importNames: ["FetchHttpClient"],
                  message:
                    "Build outbound HTTP clients only with egressHttpClientLayer from @maruhi/core (packages/core/src/egress.ts)",
                },
                {
                  name: "@effect/platform-bun/BunHttpClient",
                  message:
                    "Build outbound HTTP clients only with egressHttpClientLayer from @maruhi/core (packages/core/src/egress.ts)",
                },
                {
                  name: "@maruhi/crypto/test-support",
                  message:
                    "Test support only: its testUserId / testKeyFingerprintHex are unchecked casts for test data. Shipped code mints a brand only through the mints in packages/core/src/identity.ts",
                },
              ],
            },
          ],
        },
      },
      {
        // Effect fence (CLAUDE.md "Architecture"): packages/crypto is
        // one of the two trusted leaves and is Effect-free by contract,
        // so it imports nothing from effect — values, types, subpaths
        // and re-exports alike. The other leaf (the web bundle,
        // apps/web/src) is held by the value-import tripwire in
        // apps/web/test/unit/endpoints.test.ts (rulings BR / CD); types
        // stay allowed there because they are erased from the bundle,
        // while crypto has no reason to see Effect types at all (core
        // and api-schema build on crypto, not the other way round).
        // This override replaces the outbound-HTTP one above for these
        // files; that ban is subsumed here
        files: ["packages/crypto/**"],
        rules: {
          "no-restricted-imports": [
            "error",
            {
              patterns: [
                {
                  group: ["effect", "effect/**", "@effect/**"],
                  message:
                    "packages/crypto is Effect-free by contract (the Effect fence in CLAUDE.md). Keep Effect in core / api-schema / the apps and pass plain values into crypto",
                },
              ],
            },
          ],
        },
      },
      {
        // Vocabulary since the device-key separation (DK K7-5 / K7-13).
        // User-facing text (strings and templates) says "device key" /
        // "reserve key"; "master key" remains only in persisted names
        // (`master::` / `MasterKeys` — K4-12) and in comments. The help
        // golden and docs are pinned by
        // apps/site/test/unit/cli-vocabulary.test.ts, and runtime text
        // is pinned by this rule
        files: ["apps/cli/src/**/*.ts"],
        rules: {
          "eslint-js/no-restricted-syntax": [
            "error",
            {
              selector: "Literal[value=/master[ -]key|master private key/i]",
              message:
                'User-facing text must not say "master key". This device\'s key is "device key"; the ledger\'s key is "reserve key" (DK K7-5)',
            },
            {
              selector: "TemplateElement[value.raw=/master[ -]key|master private key/i]",
              message:
                'User-facing text must not say "master key". This device\'s key is "device key"; the ledger\'s key is "reserve key" (DK K7-5)',
            },
          ],
        },
      },
      {
        // HttpApi response envelopes are named (DK K9-4 / K9-5 / K9-7).
        // Do not write an inline `Schema.Struct` as the `success` value
        // in the options of `HttpApiEndpoint.*(…)` — wrapped forms
        // (`.annotate` / `.pipe` / `Schema.Array(...)`) are also caught
        // by descendant combination. Excluded: `payload` / `params` /
        // `error` Structs, `HttpApiSchema.NoContent`, and a field
        // literally named `success` on a data Schema. Endpoints are
        // defined only in this package (apps only reference the types)
        files: ["packages/api-schema/src/**/*.ts"],
        rules: {
          "eslint-js/no-restricted-syntax": [
            "error",
            {
              selector:
                "CallExpression[callee.object.name='HttpApiEndpoint'] > ObjectExpression > Property:matches([key.name='success'], [key.value='success']) CallExpression[callee.object.name='Schema'][callee.property.name='Struct']",
              message:
                "Do not write an inline Schema.Struct into success. Place a named export const after the row's type (list = row stem + List, read = resource + Result, create = resource + verb + Result) and export it from index.ts so Web / CLI can take the derived type (DK K9-4)",
            },
          ],
        },
      },
      {
        // Astryx styling discipline (ADR-0013, B2 operation; from
        // apps/web/.oxlintrc.json). Details: the styling-discipline
        // section of CLAUDE.md. The stylex plugin validates xstyle
        // values (ESLint plugins work via oxlint's jsPlugins)
        files: ["apps/web/**/*.{js,jsx,ts,tsx,mjs,cjs,mts,cts}"],
        jsPlugins: [{ name: "stylex", specifier: "@stylexjs/eslint-plugin" }],
        rules: {
          "stylex/valid-styles": "error",
          "eslint-js/no-restricted-syntax": [
            "error",
            {
              selector: "JSXAttribute[name.name='className']",
              message:
                "className is forbidden. Use Astryx xstyle (stylex.create + typed tokens) or defineTheme (see the styling discipline in CLAUDE.md)",
            },
            {
              selector: "JSXAttribute[name.name='style']",
              message:
                "Inline style is forbidden. Use Astryx xstyle (stylex.create + typed tokens) or defineTheme (see the styling discipline in CLAUDE.md)",
            },
            {
              selector: "CallExpression[callee.object.name='stylex'][callee.property.name='props']",
              message:
                "stylex.props on raw DOM is only allowed inside apps/web/src/ui.package/. App code uses Astryx components + xstyle",
            },
          ],
        },
      },
      {
        // src/ui.package is where new visual patterns live, so the
        // styling restrictions are lifted there, and in no other
        // ui.package directory
        files: ["apps/web/src/ui.package/**"],
        rules: {
          "eslint-js/no-restricted-syntax": "off",
        },
      },
    ],
  },
});
