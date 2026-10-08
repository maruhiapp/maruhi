import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// Protect the publicDir's untransformed copies from layer-split's HTML
// handling. Kept in step with the targets whose byte equality
// write-headers.ts checks (pages.css is the self-hosted stylesheet shared
// by /invite and the server-served ceremony pages).
const PUBLIC_PASSTHROUGH = ["invite.html", "pages.css"] as const;

// FunStack splits Vite environments into rsc / client / ssr. ssr emits
// JS only and no CSS. @astryxdesign/build 0.6.6's astryx-build-layer-split
// hard-errors when StyleX rules exist but no target CSS does, so it is
// applied only to environments that emit CSS.
//
// In addition, client's writeBundle branches on whether any HTML file is
// already under the output directory. With none, it rewrites the StyleX
// block of the SPA CSS in place into the cascade layers (the branch we
// need). With some, it moves the layers into a separate
// astryx-stylex-<hash>.css and links that only from the HTML present at
// that moment (linkStylesheetsForEveryPage). FunStack writes the SPA HTML
// after every environment has built, so the only HTML present then is the
// publicDir copy (invite.html): the SPA would never link the layers, and
// the product layer would be lost while invite.html got a <link>. So the
// passthrough files are taken out of the output directory while the
// plugin runs and written back afterwards (also restoring their bytes),
// and a stray astryx-stylex-*.css fails the build. The stylexOptions key
// keeps the legacy mode (prebuilt CSS consumption; no src alias).
//
// This is a local patch on a vendor plugin (awaiting the upstream fix of
// ADR-0013 option ⑤). AstryxVitePluginOptions 0.6.6 has neither an
// environment scope nor a publicDir exclusion (re-verified at the 0.6.2 →
// 0.6.6 upgrade). If the target plugin is not found or its shape changed,
// fail loudly rather than silently passing through: so that the next
// upgrade cannot silently undo one part of the workaround and bring back
// the ssr hard error / pollute invite.html / drop the product layer.
const LAYER_SPLIT_PLUGIN = "astryx-build-layer-split";
const SPLIT_STYLESHEET = /^astryx-stylex-.*\.css$/;

function outputDir(options: {
  dir?: string | undefined;
  file?: string | undefined;
}): string | undefined {
  return options.dir ?? (options.file === undefined ? undefined : dirname(options.file));
}

/** Take the passthrough files out of outDir; the returned function writes them back. */
function parkPassthrough(outDir: string | undefined): () => void {
  if (outDir === undefined) return () => {};
  const parked = PUBLIC_PASSTHROUGH.map((name) => join(outDir, name))
    .filter((filePath) => existsSync(filePath))
    .map((filePath) => ({ filePath, content: readFileSync(filePath) }));
  for (const file of parked) rmSync(file.filePath);
  return () => {
    for (const file of parked) writeFileSync(file.filePath, file.content);
  };
}

/** Fail the build if the plugin took the separate-stylesheet branch. */
function assertNoSplitStylesheet(outDir: string | undefined): void {
  if (outDir === undefined) return;
  const stray = readdirSync(outDir, { recursive: true, encoding: "utf8" }).filter((path) =>
    SPLIT_STYLESHEET.test(basename(path)),
  );
  if (stray.length > 0) {
    throw new Error(
      `${LAYER_SPLIT_PLUGIN} wrote ${stray.join(", ")} instead of rewriting the SPA CSS in place: ` +
        "the SPA HTML would not link it; re-check adaptAstryxLayerSplit",
    );
  }
}

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
        const outDir = outputDir(outputOptions);
        const restore = parkPassthrough(outDir);
        return Promise.resolve()
          .then(() => write.call(this, outputOptions, bundle))
          .finally(restore)
          .then(() => assertNoSplitStylesheet(outDir));
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
