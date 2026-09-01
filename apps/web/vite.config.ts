import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// FunStack は Vite 環境を rsc / client / ssr に分ける。ssr は JS のみで
// CSS を出さない。@astryxdesign/build 0.5.2 の astryx-build-layer-split は
// StyleX 規則があるのに対象 CSS が無いと hard error するため、CSS を出す
// 環境だけに適用する。stylexOptions キーの legacy モードは維持する
// (docs/notes/spike-a.md — プリビルド CSS 消費。src alias は使わない)。
function skipLayerSplitOnSsr(plugins: Plugin[]): Plugin[] {
  return plugins.map((plugin) => {
    if (plugin.name !== "astryx-build-layer-split") return plugin;
    return {
      ...plugin,
      applyToEnvironment(environment) {
        return environment.name !== "ssr";
      },
    };
  });
}

// StyleX コンパイラは常時有効。未設定ビルドはランタイムで全損する
// (検証記録: docs/notes/spike-a.md — e2e が実効的な防御)ため、
// コンパイラを外すスイッチは置かない。
const stylexPlugins = skipLayerSplitOnSsr(
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
