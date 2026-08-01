// maruhi ブランドテーマ(ADR-0013: ブランド定義の唯一の置き場所)。
// スパイク A では「defineTheme → astryx theme build で静的 CSS 化 → CSP 下で配信」を検証する。
// (<Theme> のランタイム注入はインライン <style> を挿入するため、style-src 'self' と両立しない)
import { defineTheme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral";

export const maruhiTheme = defineTheme({
  name: "maruhi",
  extends: neutralTheme,
  color: {
    // ㊙ 印の朱色をアクセントに(スパイク用の仮ブランド。生 hex はテーマ定義のみに置ける)
    accent: "#C73E3A",
    neutralStyle: "warm",
  },
});

export default maruhiTheme;
