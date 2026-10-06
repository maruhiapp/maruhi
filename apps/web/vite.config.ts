import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// Protect the publicDir's untransformed copies from layer-split's HTML
// injection. Kept in step with the targets whose byte equality
// write-headers.ts checks (pages.css is the self-hosted stylesheet shared
// by /invite and the server-served ceremony pages).
const PUBLIC_PASSTHROUGH = ["invite.html", "pages.css"] as const;

// FunStack splits Vite environments into rsc / client / ssr. ssr emits
// JS only and no CSS. @astryxdesign/build 0.6.2's astryx-build-layer-split
// hard-errors when StyleX rules exist but no target CSS does, so it is
// applied only to environments that emit CSS. In addition, client's
// writeBundle(linkOrphanStylesheets) injects the SPA CSS as <link> into
// the publicDir-copied HTML, so the checked assets are written back. The
// stylexOptions key keeps the legacy mode
// (prebuilt CSS consumption; no src alias).
//
// This is a local patch on a vendor plugin (awaiting the upstream fix of
// ADR-0013 option ⑤). AstryxVitePluginOptions 0.6.2 has neither an
// environment scope nor a publicDir exclusion (re-verified against
// 0.5.2). If the target plugin is not found or its shape changed, fail
// loudly rather than silently passing through: so that the next upgrade
// cannot silently undo one half of the workaround and bring back the ssr
// hard error / pollute invite.html.
const LAYER_SPLIT_PLUGIN = "astryx-build-layer-split";

function adaptAstryxLayerSplit(plugins: Plugin[]): Plugin[] {
  const target = plugins.find((plugin) => plugin.name === LAYER_SPLIT_PLUGIN);
  if (target === undefined) {
    throw new Error(
      `${LAYER_SPLIT_PLUGIN} not found in astryxStylex(): @astryxdesign/build changed shape; ` +
        "re-check adaptAstryxLayerSplit before upgrading",
    );
  }
  if (typeof target.writeBundle !== "function") {
    throw new Error(
      `${LAYER_SPLIT_PLUGIN}.writeBundle is not a plain function: @astryxdesign/build changed shape; ` +
        "re-check adaptAstryxLayerSplit before upgrading",
    );
  }
  const write = target.writeBundle as (
    this: unknown,
    ...hookArgs: unknown[]
  ) => void | Promise<void>;
  return plugins.map((plugin) => {
    if (plugin !== target) return plugin;
    const adapted: Plugin = {
      ...plugin,
      applyToEnvironment(environment) {
        return environment.name !== "ssr";
      },
      writeBundle(outputOptions, bundle) {
        const outDir =
          outputOptions.dir ??
          (outputOptions.file === undefined ? undefined : dirname(outputOptions.file));
        const snapshots =
          outDir === undefined
            ? []
            : PUBLIC_PASSTHROUGH.flatMap((name) => {
                const filePath = join(outDir, name);
                return existsSync(filePath) ? [{ filePath, content: readFileSync(filePath) }] : [];
              });
        return Promise.resolve(write.call(this, outputOptions, bundle)).then(() => {
          for (const snap of snapshots) writeFileSync(snap.filePath, snap.content);
        });
      },
    };
    return adapted;
  });
}

// The StyleX compiler is always on. A build without it loses all styles
// at runtime silently (the e2e is the effective defense), so there is
// no switch to remove the compiler.
const stylexPlugins = adaptAstryxLayerSplit(
  astryxStylex({
    stylexOptions: {
      dev: process.env["NODE_ENV"] === "development",
      runtimeInjection: false,
      treeshakeCompensation: true,
      unstable_moduleResolution: {
        type: "commonJS",
        rootDir: import.meta.dirname,
      },
    },
  }),
);

export default defineConfig({
  plugins: [
    ...stylexPlugins,
    funstackStatic({
      root: "./src/Root.tsx",
      app: "./src/App.tsx",
    }),
    react(),
  ],
});
