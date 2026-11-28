import { correctness, presets } from "@effect/tsgo/oxlint-presets";
import { defineConfig } from "vite-plus";

// See ADR-0028.
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
effectTsgoRules["effecttsgo/prefer-schema-over-json"] = "off";
effectTsgoRules["effecttsgo/schema-class-missing-brand"] = "off";
effectTsgoRules["effecttsgo/unstable-api-usage"] = "off";
effectTsgoRules["effecttsgo/flat-map-map-to-zip-with"] = "off";
effectTsgoRules["effecttsgo/promise-all-in-effect"] = "error";
effectTsgoRules["effecttsgo/promise-race-in-effect"] = "error";

export default defineConfig({
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
    plugins: ["effecttsgo" as never],
    categories: {
      correctness: "error",
      suspicious: "error",
    },
    options: { typeAware: true, typeCheck: true, denyWarnings: true },
    rules: {
      "typescript/await-thenable": "off",
      "typescript/no-array-delete": "off",
      "typescript/no-floating-promises": "off",
      "typescript/no-for-in-array": "off",
      "typescript/no-implied-eval": "off",
      "typescript/no-meaningless-void-operator": "off",
      "typescript/no-misused-promises": "off",
      "typescript/no-unsafe-enum-comparison": "off",
      "typescript/no-unsafe-unary-minus": "off",
      "typescript/restrict-plus-operands": "off",
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
        files: ["**/test/**", "**/*.test.ts"],
        rules: { "unicorn/consistent-function-scoping": "off" },
      },
      {
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
        files: ["packages/core/src/egress.ts"],
        rules: { "no-restricted-imports": "off" },
      },
      {
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
          "apps/server/src/data.package/data-plane.ts",
          "apps/server/src/data.package/data-store-rows.ts",
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
        files: ["apps/web/src/ui.package/**"],
        rules: {
          "eslint-js/no-restricted-syntax": "off",
        },
      },
    ],
  },
});
