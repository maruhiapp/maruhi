import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// StyleX コンパイラは常時有効。未設定ビルドはランタイムで全損する
// (検証記録: docs/notes/spike-a.md — e2e が実効的な防御)ため、
// コンパイラを外すスイッチは置かない。
const stylexPlugins = astryxStylex({
  stylexOptions: {
    dev: process.env["NODE_ENV"] === "development",
    runtimeInjection: false,
    treeshakeCompensation: true,
    unstable_moduleResolution: {
      type: "commonJS",
      rootDir: import.meta.dirname,
    },
  },
});

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
