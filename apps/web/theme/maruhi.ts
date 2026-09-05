// maruhi ブランドテーマ(ADR-0013: ブランド定義の唯一の置き場所)。
// 配信は `astryx theme build` で静的 CSS 化したもの(<Theme> のランタイム注入はインライン
// <style> を挿入するため、style-src 'self' と両立しない — docs/notes/spike-a.md)。
//
// 色の裁定は docs/notes/web-design-pass.md §1-1 / §1-2 と §3「DP1 実装時の裁定録」(A・B)。
// ここに現れる生 hex は「朱」の 2 値 + on-accent の 2 値のみで、他はすべて HCT 導出に任せる。
import { defineTheme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral";

// 朱(vermilion)— ㊙ 印の赤。SVG ロゴ(apps/web/public/logo*.svg・favicon)の fill と同値。
// HCT: hue 44 / chroma 76 / tone 44。danger(--color-error = crimson、hue 28)と色相で 16° 離す。
// light 側の値がブランドの正(単色ロゴはこの色で描く)。
const VERMILION_LIGHT = "#C1330B";
// dark 側は同じ色相・同じ彩度で tone 63 に上げたもの(dark body 上で 6.6:1、popover 上で 4.6:1)。
// Astryx の seed 導出は dark accent を tone 80 の pastel(彩度 ≈ 31)に固定するため、
// 「彩度を落とさない」(§1-1)を満たすには tokens での明示が必要(裁定 A)。
const VERMILION_DARK = "#FF693C";
// on-accent。light は白(5.6:1)。dark は warm neutral の tone 10(= 導出される dark surface と
// 同値。6.0:1)— seed 導出の PD[20](#780000)は 4.1:1 で AA に届かないため明示する。
const ON_VERMILION_LIGHT = "#FFFFFF";
const ON_VERMILION_DARK = "#241915";

export const maruhiTheme = defineTheme({
  name: "maruhi",
  extends: neutralTheme,
  color: {
    // seed タプル: neutral(warm)の色相・--color-on-accent 以外の導出パレットを朱の色相で揃える
    accent: [VERMILION_LIGHT, VERMILION_DARK],
    neutralStyle: "warm",
  },
  tokens: {
    // 導出値(light tone 40 / dark tone 80)を朱の確定値で置き換える。
    // --color-accent-muted / --color-text-accent / --color-icon-accent は var(--color-accent)
    // 参照で生成されるため追随する。--color-on-accent だけは seed から焼き込まれるので同期して上書きする
    "--color-accent": [VERMILION_LIGHT, VERMILION_DARK],
    "--color-on-accent": [ON_VERMILION_LIGHT, ON_VERMILION_DARK],
  },
  components: {
    // Section(ページの節)の既定 variant に面の色を与える(DP3 改訂 8 — 裁定 S)。
    // neutral テーマでは section の面が surface と同値で、本文領域(surface)の上に置くと
    // 見えない。Astryx の surface 階層(body → surface → card)に従い、body 側へ半分寄せた
    // 色で「線を引かない薄いパネル」にする。表の行は Section の縁まで伸びる(Astryx の
    // 整列モデル)ので、節に収まって見える。値はトークン参照のみ(生 hex を増やさない)
    section: {
      "variant:section": {
        backgroundColor:
          "color-mix(in oklab, var(--color-background-body) 55%, var(--color-background-surface))",
      },
    },
  },
});

export default maruhiTheme;
