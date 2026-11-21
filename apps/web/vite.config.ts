import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const PUBLIC_PASSTHROUGH = ["invite.html", "pages.css"] as const;

const LAYER_SPLIT_PLUGIN = "astryx-build-layer-split";
const SPLIT_STYLESHEET = /^astryx-stylex-.*\.css$/;

function outputDir(options: {
  dir?: string | undefined;
  file?: string | undefined;
}): string | undefined {
  return options.dir ?? (options.file === undefined ? undefined : dirname(options.file));
}

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
