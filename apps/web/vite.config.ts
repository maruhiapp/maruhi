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
// 環境だけに適用する。加えて client の writeBundle(linkOrphanStylesheets)が
// publicDir コピーの HTML へ SPA CSS を <link> 注入するので、検査対象アセットは
// 書き戻す。stylexOptions キーの legacy モードは維持する
// (docs/notes/spike-a.md — プリビルド CSS 消費。src alias は使わない)。
//
// これは vendor プラグインへの局所パッチ(ADR-0013 ⑤ の upstream 解決待ち)。
// 0.5.2 の AstryxVitePluginOptions には環境スコープも publicDir 除外も無い。
// 対象プラグインが見つからない・形が変わった場合は黙って素通しせず落とす:
// 片方の回避だけ外れて ssr が hard error に戻る / invite.html が汚れる、を
// 次のアップグレードで無言に起こさないため。
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
