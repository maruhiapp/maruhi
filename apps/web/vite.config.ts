import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// publicDir の無変換コピーを layer-split の HTML 注入から守る。
// write-headers.ts がバイト等価を検査する対象と揃える。
const PUBLIC_PASSTHROUGH = ["invite.html", "invite.css"] as const;

// FunStack は Vite 環境を rsc / client / ssr に分ける。ssr は JS のみで
// CSS を出さない。@astryxdesign/build 0.5.2 の astryx-build-layer-split は
// StyleX 規則があるのに対象 CSS が無いと hard error するため、CSS を出す
// 環境だけに適用する。加えて client の writeBundle が publicDir コピーの
// HTML へ SPA CSS を <link> 注入するので、検査対象アセットは書き戻す。
// stylexOptions キーの legacy モードは維持する
// (docs/notes/spike-a.md — プリビルド CSS 消費。src alias は使わない)。
function adaptAstryxLayerSplit(plugins: Plugin[]): Plugin[] {
  return plugins.map((plugin) => {
    if (plugin.name !== "astryx-build-layer-split") return plugin;
    const originalWrite = plugin.writeBundle;
    if (typeof originalWrite !== "function") return plugin;
    const write = originalWrite as (this: unknown, ...hookArgs: unknown[]) => void | Promise<void>;
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

// StyleX コンパイラは常時有効。未設定ビルドはランタイムで全損する
// (検証記録: docs/notes/spike-a.md — e2e が実効的な防御)ため、
// コンパイラを外すスイッチは置かない。
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
