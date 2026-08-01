import { astryxStylex } from "@astryxdesign/build/vite";
import funstackStatic from "@funstack/static";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// SPIKE_NO_STYLEX=1 で StyleX コンパイラを外したビルドを作れる
// (xstyle 用 stylex.create がコンパイラ未設定だと無警告で無スタイル描画になる罠の再現用)。
const stylexPlugins =
  process.env["SPIKE_NO_STYLEX"] === "1"
    ? []
    : astryxStylex({
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
