# web-design-pass — DP 系列(デザインパス)の裁定

Status: 2026-09-03 起草・所有者裁定済み(DP1 / DP2 の前提)。ROADMAP.md「DP 系列」の設計文書。
DP1〜DP5 の各 PR はこの文書を正として実装し、変更があればまずここを改訂する。

前提規律(変えない):

- **ADR-0013**: 見た目の変更は ① defineTheme(トークン・variant)→ ② Astryx コンポーネントの `xstyle` →
  ③ `ui.package` での合成 → ④ `ui.package` での自作 → ⑤ upstream、の順。`swizzle` 禁止・`className` /
  インライン `style` 禁止・生 hex はテーマ定義のみ
- **ADR-0018**: Web は鍵・平文を持たない(読み取り + 失効系のみ)。値・鍵操作は CLI
- **TCB 規則(CLAUDE.md)**: ダッシュボードのオリジン(`my.maruhi.app`)にサードパーティスクリプト・CDN・
  外部フォント・アナリティクスを一切載せない。厳格 CSP
- **「言わざる」**: クライアント → 外部への送信を持たない。LP にも適用する(§5)

## 1. 所有者裁定(2026-09-03)

| # | 論点 | 裁定 |
|---|---|---|
| 1 | ロゴ・配色 | **㊙ をロゴにする**。ただし絵文字ではなく**自前の SVG**(円 + 「秘」。字形は OFL の CJK フォント〔Noto Sans CJK / Source Han〕からパス化)。**accent のカラーコードは SVG の赤に一致**させ、絵文字ベンダーの色には合わせない(我々の SVG が正・絵文字は近似)。赤の**彩度は落とさない**(Hanko の濃い赤の実例)。方向は**朱(vermilion — 橙寄りの赤)**で、danger(クリムゾン系)と色相で離す。テキスト文脈(CLI 出力・README 見出し)では絵文字 ㊙ を使い続ける |
| 2 | ダーク | **システム追従・両モード**(`defineTheme` の `[light, dark]` タプル = CSS `light-dark()`)。手動トグルは持たない(状態の保存先を増やさない)。デザインは**ダークから起こす**。独自カスタマイズは最小(accent seed・neutral `warm`)で **Astryx 既定に寄せる**。細部の色調整は後から `tokens` 上書きで行える |
| 3 | フォント | **ダッシュボード(`my.maruhi.app` — TCB)は Astryx 既定(システムフォント)**: body / heading = `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, …`、code = `"SF Mono", Monaco, Consolas, monospace`。Web フォントは読み込まない(ゼロバイト)。等幅の自己配信(0/O・1/l 判別)は **DP3 / DP4 の実機確認で問題があれば足す**。確認コードの可読性はフォントでなく**文字集合**(紛らわしい文字の除外)で担保する — DP4 で既存の生成規則を確認。**LP / docs(apex — TCB ではない)は自己配信の可変フォント 2 書体を使う(2026-09-03 追記)**: 見出し・本文 = **Archivo**(SIL OFL・ウェイト 100〜900・幅 62〜125% — 極太 / 幅広の見出しはこの幅軸で作る)、コード = **Martian Mono**(SIL OFL・可変)。参考 = bun.com が同じ 2 書体を自己配信している(フォントの選択は意匠の模倣にならない)。woff2・`font-display: swap`・italic は不要なら落とす。外部 CDN は使わない(§1-5)。**OFL の配布義務(著作権表示 + ライセンス全文の同梱。両書体は Reserved Font Name 未宣言なのでサブセット版も元の名で可)は §4 に記載**。書体の見え方はロゴ SVG と並べて DP2 で確認し、合わなければ Geist / Inter へ差し替え可 |
| 4 | LP と docs の配置 | **LP は apex `maruhi.app` に独立の静的サイトとして配信**(製品オリジン `my.maruhi.app` と分離 = TCB 分離)。**docs は `maruhi.app/docs`**(同じ静的サイト内のパス。SEO の集約・1 デプロイ・URL 1 つ)。`maruhi.dev` は取得済みのまま **`maruhi.app` へ 301**(防御的保持)。LP / docs は**独立の wrangler 設定**で立て、後日 O9(Alchemy v2 化)で宣言に包める形にする |
| 5 | アナリティクス | **入れない**。訴求点にする(「このサイトにトラッカーはありません」)。訪問数は **Cloudflare Web Analytics のサーバー側集計**(スクリプト注入なし・Cookie なし・zone レベルの HTTP 集計)のみ。waitlist 等のフォームも Workers に POST するだけで第三者 SaaS を挟まない |
| 6 | O9 との順序 | **O9(Alchemy v2 化)は DP の後**。DP はベータのゲート・O9 は任意。DP2 で LP / docs を独立 wrangler 設定に切っておけば移行量は同じ |

## 2. トーンの方向(参考サイト — 寄せすぎない)

所有者が挙げた参考: [WorkOS](https://workos.com/)(エンタープライズ感)、[Resend](https://resend.com/)(伸びている
開発者向け製品)、[Phase](https://phase.dev/)・[Shelve](https://www.shelve.cloud/)(競合 — セキュリティ重視の印象)。
**無理に寄せず、Astryx のコンポーネントで仕上げる**ことを優先する。共通して読み取れる要素:

- ダーク基調。neutral はほぼモノクロで、**アクセントは 1 色**をごく限定的に使う(ボタン・リンク・強調 1 か所)
- **コード / ターミナルが主役**: ヒーローにインストールコマンドや CLI の出力を置き、UI のスクリーンショットより
  「打つコマンドと返る結果」で製品を説明する。maruhi は「Everything happens in the CLI」なのでこの型が合う
- 余白が多く、装飾(グラデーション・イラスト)は控えめ。エンタープライズ感は**装飾の少なさと情報の整列**で出す
- セキュリティの訴求は「怖がらせる」でなく「仕組みを淡々と書く」(E2EE・ゼロ知識・オープンソース・自己ホスト可)

maruhi 固有の差別化: 朱の ㊙ 印(競合は青〜紫〜緑系)、「diskless」「言わざる(テレメトリゼロ)」、
セルフホスト一発(`wrangler deploy`)、ゼロ知識の運営。

## 3. DP1 ブランド基盤 — 成果物

- `apps/web/theme/maruhi.ts`: accent seed を朱の確定値へ(HCT で light / dark を導出 — Astryx の accent 生成に任せ、
  必要なら `[light, dark]` タプルで dark 側の明度だけ上げる)。neutral `warm` 維持。typography / radius は既定
- ロゴ SVG(`apps/web/public/` 系の静的アセット + LP 用): ㊙ の円と「秘」。単色版(accent)と反転版。favicon
  (SVG + PNG フォールバック)・OG 画像(1200×630、ダーク地に ㊙ + `maruhi`)
- danger と accent のコントラスト確認(失効・削除ボタンは Astryx の danger variant で形としても区別)
- 生 hex はテーマ定義と SVG にのみ存在する(ADR-0013)

### DP1 実装時の裁定録(2026-09-03)

各裁定点は「案を 3 つ以上列挙 → 上位互換 / 銀の弾丸を探索 → 新案が尽きるまで反復 → 選定」の
ループで決めた。判断基準は ADR-0013 の検討順で浅い層に収まること・TCB 規則と依存最小・生成物が
少ない・後戻りが安いこと。数値は Astryx 0.5.2 の HCT 実装(`@astryxdesign/core/src/theme/hct.ts` —
実体は CIELAB LCh。以下「HCT」)と `contrast.ts` で算出した。

**前提の訂正(実装で判明した事実)**: `defineTheme` の `color.accent` は `--color-accent` を
`light-dark(P[40], P[80])` に**トーン固定**で導出する(`expandColorScale.ts`)。`[light, dark]`
タプルは各スキームのパレットの**色相・彩度**を差し替えるだけで、dark 側は常にトーン 80(pastel、
彩度 ≈ 31)になる。§3 冒頭の「タプルで dark 側の明度だけ上げる」は成立しないため、朱の確定値は
`tokens` で明示する(裁定 A)。**明示する理由は彩度そのものではない**(所有者 2026-09-03: 「彩度を
落とさない」は絶対条件ではなく、pastel でおかしくなければ可): (1) 導出される dark accent `#FFB3A8` は
neutralTheme の dark error `#FFC6C1` と ΔE76 = 10.5・相互コントラスト 1.15:1 で、リンクと
エラー文言が同じ色に見える(§1-1「danger と色相で離す」が dark で崩れる)。(2) ブランドの赤 `#C1330B`
から ΔE76 = 58 離れ、同じ画面に置く ㊙ ロゴと accent が別の色に見える(明示値 `#FF693C` は ΔE76 = 19)。
Astryx 自身の既定 dark accent(`#2694FE`)もトーン 60 前後で、トーン 80 は汎用ジェネレータの選択に
すぎない。比較画像は PR #146 に添付。

**A. accent と SVG の赤の一致方法** — 列挙: (i) seed のみ置き SVG は導出値に従う / (ii) `tokens` で
`--color-accent` を固定し `--color-on-accent` を手で同期 / (iii) 導出結果が狙いになるよう seed を逆算 /
(iv) seed タプル + `tokens` の併用(上位互換) / (v) accent を導出に任せ SVG を `currentColor` 化して
「一致」の問題そのものを消す(銀の弾丸候補)。**選定 = (iv)**: `color.accent: [朱L, 朱D]` で warm neutral
の色相と導出パレットを朱に揃えたうえ、`tokens` で `--color-accent` と `--color-on-accent` の 2 トークン
だけを確定値で上書きする。SVG の赤 = light 側の `--color-accent`(`#C1330B`)で、生成 CSS にそのまま
現れる(e2e の「生成 CSS と一致」契約はそのまま通る)。棄却: (i) は dark が pastel になり §1-1 違反。
(iii) は light のトーン 40 固定は逆算できるが dark のトーン 80 は逆算不能。(ii) 単独は neutral の
色相が seed 由来のままになる(併用で解消)。(v) は favicon / OG が固定色を要するため「一致」を消せない
(モノクロ版 `logo-mono.svg` として部分採用 — `currentColor` はインライン `<svg>` / CSS mask で文脈の
文字色を継承する用途。`<img>` で参照すると黒で描かれる)。`--color-on-accent` の上書きは、seed から焼き込まれる
dark 側 `P[20]`(`#780000`)が朱 D 上で 4.1:1 と AA に届かないため必要(明示値 `#241915` = warm
neutral トーン 10 = 導出 dark surface と同値。6.0:1)。

**B. 朱の具体値と danger の分離** — 候補は色相で振り(トーンは light 44 / dark 63 に固定して比較。
light 44 は warm body `#FFEDE7` 上でリンク文字として 4.9:1 を確保する上限、dark 63 は popover
`#3A2E29` 上で 4.6:1 を確保しつつ彩度 76 を保てる値):

| # | 案 | light | HCT | dark | HCT | Δhue vs `--color-error`(H28) | L: on body / on surface / white on accent | D: on body / on surface / on-accent on accent |
|---|---|---|---|---|---|---|---|---|
| B0 | 現状維持(`#C73E3A` seed → 導出) | `#B22A2B` | H32 C63 T40 | `#FFB3A8` | H33 C31 T80 | 3.8° | 5.7 / 6.3 / 6.4 | 11.0 / 10.0 / 10.0 |
| B1 | 顔料の朱(vermilion pigment 系) | `#C92621` | H36 C76 T44 | `#FF6551` | H36 C71 T63 | 7.8° | 4.9 / 5.4 / 5.6 | 6.5 / 5.9 / 5.9 |
| **B2** | **朱(橙寄り)— 採用** | **`#C1330B`** | H44 C76 T44 | **`#FF693C`** | H44 C76 T63 | **15.8°** | 4.9 / 5.5 / 5.6 | 6.6 / 6.0 / 6.0 |
| B3 | 朱(JIS 朱色寄り) | `#BA3E00` | H49 C73 T44 | `#F77027` | H52 C78 T63 | 21.0° | 4.9 / 5.4 / 5.6 | 6.6 / 6.0 / 6.0 |
| B4 | 銀朱 / 朱肉系 | `#CF1033` | H27 C76 T44 | `#FF6366` | H27 C67 T63 | 1.0° | 4.9 / 5.4 / 5.6 | 6.5 / 5.9 / 5.9 |

**選定 = B2**。danger(`--color-error` = `#A50C25` / `#FFC6C1`、neutralTheme 由来の crimson)と色相で
16° 離れ(ΔE76 = 24 light / 59 dark)、かつ「赤」と読める範囲に留まる。B3 は JIS の朱色に近いが橙に
寄りすぎて「赤い印」の印象が弱い。B1 は分離が 8° で不足。B4 は danger と同色相(棄却)。B0 は dark が
pastel(§1-1 違反)かつ分離 4°。**朱の最終 hex は所有者確認が要る唯一の点** — PR 上で B1 / B3 への
差し替えを指示できる(`theme/maruhi.ts` の 2 定数 + SVG の fill + 再生成)。

**C. 「秘」字形のパス化の道具** — 列挙: (i) Python fontTools を /tmp で一回性実行 / (ii) opentype.js 等を
devDependency / (iii) フォントの SVG テーブル・手作業抽出 / (iv) `<text>` + フォント埋め込み(パス化しない)
/ (v) 絵文字フォントの ㊙ グリフを抽出。**選定 = (i)**。成果物は SVG のみで、道具はリポジトリに残さない
(依存最小・供給網を増やさない)。手順は再現可能な形で記す: `NotoSansCJKjp-Bold.otf`(notofonts/noto-cjk
v2.004)の U+79D8 を `fontTools` の `SVGPathPen` + `TransformPen`(y 反転)でパス化し、1000×1000 の
viewBox に配置(下の E)。棄却: (ii) は一回の抽出のために devDependency を増やす。(iii) は Noto CJK に
SVG テーブルがなく手作業は再現性が無い。(iv) はフォント配信 = Web フォント追加(§1-3 違反)。(v) は
絵文字グリフの色・ライセンス依存(§1-1 の趣旨に反する)。フォントは Noto Sans CJK JP(OFL 1.1、
© 2014-2021 Adobe)を採用(Source Han Sans と同一原図。Noto の方が配布形態が単純)。

**D. favicon / OG の形式と生成** — 形式: favicon = `favicon.svg`(反転版 = 朱の円盤に白抜き) + PNG
32 / 192 + `apple-touch-icon.png` 180(iOS は透過を黒で埋めるため dark body 色の不透明地)。OG =
`og.png` 1200×630(dark body `#1B0D07` 地に ㊙ + `maruhi`。ワードマークも同フォントの Latin グリフを
パス化し、ラスタが環境のフォントに依存しない)。ラスタライズの列挙: (i) resvg / sharp を devDependency /
(ii) ImageMagick 等を一回性 / (iii) **既存 devDependency の Playwright Chromium で SVG をスクリーンショット**
(上位互換: 新規依存ゼロ・e2e と同じレンダラ)/ (iv) PNG を作らず SVG のみ(iOS・OG スクレイパーが
SVG 非対応なので不可)。**選定 = (iii)**、一回性スクリプトで実行し PNG のみコミット。`<head>` には
`description`・`icon`(svg / png)・`apple-touch-icon`・`og:*`・`twitter:card=summary_large_image` を
追加(英語 — ADR-0017)。**OG の絶対 URL**: 列挙 = 静的に hosted origin を書く / 相対 URL(スクレイパー
が解決しないものがある — 不可)/ ビルド時環境変数 / Worker がリクエスト時に書き換える(静的シェルの
原則に反する)。**選定 = ビルド時環境変数 `MARUHI_WEB_ORIGIN`、既定 `https://my.maruhi.app`**
(`Root.tsx` はビルド時 RSC なので `process.env` を読める。セルフホストは deploy URL を指定 —
SELF_HOSTING.md に 1 行)。CSP は変更なし(すべて自己配信、`img-src 'self'` の範囲内)。

**E. 円と字形のプロポーション** — 列挙(1000 単位): (a) ㊙ グリフ忠実(リング 40・字形 66%)/ (b) 印章風
(リング 64・字形 60〜62%)/ (c) favicon 最適(リング 80・字形 64%)/ (d) リング無しの字形単体 /
(e) 反転版は字形を大きく(リングが無い分)— 上位互換として (b)+(e) の併用。ウェイトは Bold と Black を
16 / 24 / 32 / 64 / 160 px で比較。**選定 = Bold・輪郭版はリング 64(直径の 6.7%)・字形 62%、反転版
(favicon)は字形 66%**。Black は 32 px 以下で画線が潰れて塊になり、Bold は 32 px で「秘」が判読できる。
16 px では何を選んでも判読不能なので、favicon は「朱の丸」として認識されることを優先し反転版を使う。
(a) は 16〜24 px でリングが消える。(c) は 160 px 以上で窮屈。(d) は ㊙ の同一性を失う。

**成果物と検証の再現**: `apps/web/theme/maruhi.ts`(生 hex は朱 2 値 + on-accent 2 値のみ)→
`bun run --filter @maruhi/web theme:build && bunx oxfmt apps/web/theme`(生成物は oxfmt 済みで
コミットする — 差分ゼロの確認もこの順)。SVG 4 点 + PNG 4 点は `apps/web/public/`。OFL 全文と著作権表示は
`apps/web/public/fonts/OFL-NotoSansCJK.txt`(配信物からも読める。DP2 の Archivo / Martian Mono も同じ
ディレクトリに置く — §4)。各 SVG の先頭コメントに由来を記す。

## 4. DP2 LP + docs — 構成

- 新パッケージ(`apps/site` 案。既存の `apps/docs` スタブを吸収してもよい): **Blume**(ADR-0008 で決定済み — Astro
  ベース)の静的出力で LP と docs を 1 サイトにする。LP を Blume の外(素の Astro 等)で作る必要が実際に出た場合は
  ADR-0008 の改訂として提起する(蒸し返さない)。LP = `/`、
  docs = `/docs/*`。**独立の `wrangler.jsonc`**(Workers Static Assets・custom domain `maruhi.app`)。
  製品 Worker(`maruhi-server-hosted`)とは別デプロイ
- **スタイリング(2026-09-03 所有者裁定 — Astryx はダッシュボード、LP は Blume)**: 3 層のみ。(1) **Blume の theme
  tokens**(色・角丸・フォント)に Astryx `defineTheme` と同じ値(朱 accent・warm neutral・Archivo / Martian Mono)
  を入れて docs と LP の両方に効かせる — 二重管理を避けるなら `apps/web/theme/maruhi.ts` から CSS 変数を書き出す
  生成スクリプト(DP1 で判断)。(2) **LP のカスタムページは Astro コンポーネントの scoped `<style>`(素の CSS)**。値は
  CSS 変数を参照し、生 hex・マジックナンバーを書かない(ADR-0013 の精神を LP にも適用)。**CSP との関係(訂正)**: Astro の
  `build.inlineStylesheets` 既定 `'auto'` は 4 kB 未満のスタイルを HTML の `<style>` にインライン化するため、そのままだと
  `style-src 'unsafe-inline'`(またはハッシュ列挙)が要る。LP は `build.inlineStylesheets: 'never'` で外部 CSS に固定し、
  `style-src 'self'` を保つ(Blume が Astro 設定を露出するかは DP2 の確認項目 — 露出しなければ component overrides /
  eject の判断材料に加える)。(3) docs は Blume 既定(component overrides は必要時のみ)。**入れないもの**: Tailwind
  (依存増・トークン二重化)、StyleX(静的サイトにコンパイラ不要)、Astryx の React 部品(原則不使用 — 必要なら React
  islands で個別に)。増える依存は `blume` 本体のみ。**留保**: theme tokens でフォント差し替え・ヘッダー / フッター・
  カスタムページの自由度がどこまで届くかは Blume を実際に入れて `node_modules/blume/docs` を読んで確定する(DP2 の
  最初の作業)。届かない部分は component overrides か、LP のみ `blume eject` 相当の自由度を取るかをそこで決める
- `maruhi.dev` → `maruhi.app` の 301(ゾーンのリダイレクトルール。Worker は置かない)
- 「最初の 5 分」(ADR-0014 改訂 1)へ導く構成: 価値提案(1 画面)→ インストール(コマンド)→ `maruhi login` →
  招待制の案内 / waitlist → セルフホストへの導線(SELF_HOSTING.md)
- LP の CSP は TCB ほど厳格でなくてよいが、**外部スクリプト・外部フォント・トラッカーは置かない**(§1-5)。
  埋め込み(動画等)が要る場合は自己配信
- フォント(§1-3): Archivo(見出し・本文)+ Martian Mono(コード)を `/fonts/` から自己配信(可変 woff2・Latin
  サブセット・`font-display: swap`)。docs(Blume)も同じ 2 書体を共有。**Bun の印象の要素分解**: 極太 / 幅広の見出し
  (Archivo の幅軸)・黒地・コードブロックが本文と同格・マスコット — マスコットの役は ㊙ ロゴが担う
- **OFL 1.1 の配布義務**(DP2 の実装で落とさない): (a) 配信物と並べて各書体の著作権表示と OFL 全文を同梱する
  (`/fonts/OFL-Archivo.txt` / `/fonts/OFL-MartianMono.txt` 等 — 配布物からユーザーが読める場所。リポジトリの
  `LICENSE` 一式にも追記)。(b) サブセット化・可変軸の間引きは OFL の Modified Version に当たるが、**両書体とも
  Reserved Font Name を宣言していない**(上流 `OFL.txt` の著作権行に "with Reserved Font Name" の句なし —
  Omnibus-Type/Archivo・evilmartians/mono、2026-09-03 確認)ため、**改変版でも元のファミリ名(`Archivo` /
  `Martian Mono`)を名乗れる**。よって Latin サブセット(≈ 半減)を既定にし、改名は不要。同梱する OFL 全文は
  上流のものをそのまま置く(改変の有無で義務は変わらない)
- 現 `apps/web/src/pages/HomePage.tsx`(スパイク骨格)は、LP が apex に立った時点で `my.maruhi.app/` を
  `/dashboard` へのリダイレクト(または最小の案内)に置き換える。e2e の機構検証フック(built-at / counter /
  about)は別の検証ページへ移すか、テストの前提を改める(削除で e2e を壊さない)
- hosted-design.md §7 L1 の改訂: 「`maruhi.dev` = docs」→「docs = `maruhi.app/docs`、`maruhi.dev` は 301」

### DP2 実装時の裁定録(2026-09-03)

各裁定点は DP1 と同じループ(案を 3 つ以上列挙 → 上位互換 / 銀の弾丸を探索 → 新案が尽きるまで生成規則を
変えて反復 → 選定)で決めた。判断基準は §4 の 3 層に収まる・「言わざる」と依存最小に整合・生成物が少ない・
O9(Alchemy v2 化)で後から包みやすい・後戻りが安いこと。

**Blume の確認結果(留保の解消 — Blume 1.5.3、`node_modules/blume/docs` と `blume --help`、仮導入ビルドで実測)**:
(1) **theme tokens の到達範囲**: `theme.accent` / `background` は `{ light, dark }` の 2 値、`theme.css`(プロジェクト
ルート)で `--blume-background / foreground / muted / muted-foreground / border / accent / accent-foreground / action /
code-background / radius / font-*` を `:root` と `:root[data-theme="dark"]` に上書きでき、docs と LP の両方に効く。
(2) **フォント**: `theme.fonts` の 3 ロール(display / body / mono)はローカル woff2 の `variants`(可変レンジ `"100..900"`
可)を受け、Astro Fonts API が `/_astro/fonts/<hash>.woff2` に自己配信する。**既定は Inter / IBM Plex Mono を Google
Fonts からビルド時に取得**し、スキーマの default のため無効化できない = ローカル指定が「言わざる」の必須条件(取得は
ビルド時のみで、配信物からの外部通信ではないが、ビルドの外部依存を作らない)。`<Font>` は `@font-face` を **必ず
インライン `<style>` で出す**(D の前提)。(3) **Astro 設定の露出**: `build.inlineStylesheets` は直接露出しないが、
`integrations` が透過するので統合の `astro:config:setup` → `updateConfig` で 'never' に固定できる(実測で効く)。
(4) **カスタムページ**: `pages/*.astro` を同一ルートにマウントし、`PageLayout`(ヘッダー + テーマ + フォント、サイドバー
なし)で LP の自由度は十分。`blume:data` から config / navigation / fontCssVars を読む。`basePath: "/docs"` で docs を
`/docs/*` に載せ、ルートはカスタムページが持つ(公式サポート。Docusaurus の `routeBasePath` 相当)。(5) **component
overrides / eject**: `components.ts` の `layout` スロット(Header / Footer / Logo …)と `blume eject` がある。DP2 では
どちらも不要。(6) **外部通信**: 検索 = Orama(ブラウザ内、索引 `/blume-search.json`)、`llms.txt` / raw Markdown /
Copy as Markdown / WebMCP(ページ内登録のみ)/ OG カード(Takumi、ビルド時ローカル描画)/ sitemap / robots は外部通信
なし。**analytics は opt-in で無宣言なら何も注入しない**(Vercel / PostHog / 任意 script は宣言時のみ)。Ask AI / MCP
サーバーは server 出力が要る opt-in(既定 off)。**Open in chat** は ChatGPT / Claude / v0 / Cursor 等へのナビゲーション
リンク(ユーザー操作時のみ・自動送信なし)。「Give feedback」は GitHub issue の事前入力リンク。`@vercel/analytics` は
Blume のバンドルに含まれるが `window.va` 不在で no-op(実測: LP / docs の全リクエストが同一オリジン)。(7) **ランタイム**:
Blume は Node 22.12+ を要求するが `bunx --bun blume build` で Bun 上でも完走する(実測。CI の Node 版に依存しないため
これを採る)。**Bun の印象の要素分解に対する答え**: 極太 / 幅広の見出しは Archivo の `font-stretch: 112%` + weight 800、
黒地はシステム追従の dark、コードブロックは本文と同格(LP のヒーローはターミナル)、マスコットの役は ㊙ ロゴ。

**A. パッケージの配置と名前** — 列挙: (i) `apps/site` 新設 + `apps/docs` スタブ削除 / (ii) `apps/docs` を LP 込みで拡張 /
(iii) LP と docs を別パッケージ / (iv) `apps/web` に Astro を同居 / (v) パッケージを作らずリポジトリ直下に Blume を置く。
**選定 = (i)** `@maruhi/site`(FSL-1.1-MIT = リポジトリ既定)。名前は「apex サイト = LP + docs」を表し、`apps/docs` の
名では LP が異物になる。品質ゲート: `typecheck` は `blume.config.ts` / `scripts` / `test` / `theme`(`.astro` / `.mdx` は
tsc の対象外 — Blume の `blume check` は任意)、oxfmt / oxlint は TS のみ対象で `.astro` は無視、ImportLint は TS 相対
import(`../web/theme` は参照しない — B)、fallow は entry(`blume.config.ts` / `scripts/*.ts` / unit test)と ignore
(`public/**` / `.blume/**`)を宣言。ルート vitest projects に `apps/site/vitest.unit.config.ts` を追加。棄却: (iii) は
テーマ・検索・OG の共有を失い 2 デプロイになる。(iv) は TCB に Blume の依存木(≈ 850 パッケージ)を入れる。(v) は
ワークスペースの規約から外れる。

**B. テーマトークンの共有** — 列挙: (i) `apps/web/theme/maruhi.ts` から CSS 変数を書き出す生成スクリプト / (ii) 値を手で複製
し差分検査で漂流検知 / (iii) `packages/brand` に定数を置き両者が import / (iv) `apps/web/theme/brand.ts` に定数を分離し site が
相対 import / (v) site の config が `maruhi.ts` を直接 import(Astryx の `defineTheme` を評価) / (vi) **生成物 `maruhi.css` を
入力にする生成スクリプト**(上位互換: 朱 2 値だけでなく HCT 導出の warm neutral〔body / surface / popover / text / border〕も
同じ経路で取れ、web 側のソースに触れない)。**選定 = (vi)**: `apps/site/scripts/theme.ts` が `maruhi.css` の `light-dark(#…, #…)`
宣言を抽出し、`theme.css`(Blume tokens)/ `theme/tokens.ts`(config が読む定数)/ `public/logo-dark.svg`(fill を dark accent
へ)/ 複製資産(favicon / logo / og / apple-touch-icon)を書き出す。生成物はコミットし、`test/unit/theme.test.ts` が
「再生成 = コミット済み」を検査(DP1 の「生成 CSS と一致」契約と同型)。site 側の手書き hex はゼロ(unit test が検査)。
棄却: (i)(v) は site に `@astryxdesign/core` の評価を持ち込む。(ii) は二重管理。(iii)(iv) は web の theme を触り、
neutral の導出値は `maruhi.css` にしか無いので結局 CSS を読む。Blume の `--blume-muted` ← Astryx `surface`、
`--blume-code-background` ← `popover`(dark で本文より明るい面)、`--blume-radius` ← `--radius-element` と写像した。

**C. フォントの取得・サブセット化・配信** — 列挙: (i) 上流リポジトリの可変 TTF / woff2 をそのまま置く / (ii) `pyftsubset` で
Latin サブセット化(一回性 /tmp)/ (iii) サブセット化ツールを devDependency / (iv) **Fontsource の variable パッケージ
(`@fontsource-variable/archivo` / `martian-mono` 5.3.0、Google Fonts と同じ原本を Latin 等のサブセットに分割済みの woff2 +
OFL 全文)から一回性に取り出す**(銀の弾丸: サブセット化の道具そのものが不要)/ (v) Blume の `theme.fonts` に Google
provider を指定(ビルド時に Google から取得 — 「言わざる」の趣旨とビルドの外部依存で不可)。**選定 = (iv)**: `archivo-latin-
wdth-normal.woff2`(90 KB — 幅軸 62〜125% + 太さ 100〜900。見出しの幅広に幅軸が要る)と `martian-mono-latin-wght-normal.woff2`
(24 KB — 太さ 100〜800。コードに幅軸は不要)。italic は落とす(§1-3)。`unicode-range` は Latin 1 ファイルずつなので不要
(Astro Fonts API の `@font-face` は `font-display: swap` と fallback metrics を付ける)。置き場は `apps/site/public/fonts/`
(OFL 全文 `OFL-Archivo.txt` / `OFL-MartianMono.txt` と同じディレクトリ = 配布単位。LP のフッターからリンク)。**Astro Fonts
API は原本を `/_astro/fonts/<hash>.woff2` に複製して参照する**ため配信物にフォントが 2 経路載る(計 ≈ 113 KB の重複)—
`/fonts/` の可読 URL + ライセンス同居と、ハッシュ付き最適化配信の両方を取る代償として受容。両書体とも上流の OFL に
Reserved Font Name の句が無いことを Fontsource の LICENSE(上流のコピー)で再確認(改名不要)。README のライセンス表に
1 行追加。棄却: (i) は 3 スクリプト込みで数百 KB。(ii)(iii) は道具が増える(Fontsource が同じ結果を配っている)。

**D. LP の作り方と CSP** — 列挙: (i) PageLayout のカスタムページ + scoped `<style>` / (ii) RootLayout(docs の chrome 付き)/
(iii) `layout.Layout` スロットで shell を自作 / (iv) `blume eject` / (v) LP のみ素の Astro(ADR-0008 改訂)。**選定 = (i)**。
CSP の実測と対処: (a) Astro の `inlineStylesheets` 'auto' → 統合で **'never'**(medium-zoom 等の小 CSS が外部化された)。
(b) Blume chrome の **inline `<script>` 6 本**(テーマ初期化・ヘッダー操作・ナビ・ClientRouter のスタイル読み込み等。内容は
Blume のバージョンで決定的)→ 配信物から収集した **SHA-256 ハッシュで許可**(`apps/web/scripts/write-headers.ts` の方式)。
(c) Astro Fonts の **`@font-face` `<style>` 2 本**(無効化不能 — 上の確認 (2))→ 同様にハッシュ。(d) テーマトグルが JS で挿す
遷移抑制 `<style>` → 固定文字列の実在を確認してハッシュ。(e) **Shiki のトークン `style` 属性**(`--shiki-light/dark`)と chrome
の一部(サイドバーの `padding-inline-start`、CardGroup の `--blume-cols`)= `style-src-attr` はハッシュで許可できない →
列挙: `style-src-attr 'unsafe-inline'` / `'unsafe-hashes'` + 全属性値の列挙 / ハイライト無効(Blume に無い)/ **ビルド後に
属性値をクラス `.sa-<hash>` へ写像した 1 本の CSS に外部化**(Shiki 公式 `transformerStyleToClass` と同じ手法を配信物に適用
— Blume はトランスフォーマを露出しない)。**選定 = 外部化**(`scripts/postbuild.ts` 第 1 段。HTML に `style` 属性が 1 つも
残らないことをビルドで検査、e2e が docs で `[style]` = 0 とトークン着色の維持を検証)。結果の CSP: `default-src 'none';
script-src 'self' 'sha256-…'×6; style-src 'self' 'sha256-…'×3; img-src 'self' data:; font-src 'self'; connect-src 'self';
manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` — **`'unsafe-inline'` は script にも style
にも無い**。§4 の「`style-src 'self'` を保つ」は「'self' + 決定的な内容のハッシュ」の形で満たす(TCB の `apps/web` と同じ
解釈)。あわせて `postbuild.ts` が配信物の src / href の外部参照ゼロ(href は自リポジトリの GitHub と製品オリジンのみ許可)
とインラインイベントハンドラ無しを機械検査し、Blume が出す `_headers`(.md / .txt の charset・トップの Link)を保持して
`/*` に CSP / nosniff / `Referrer-Policy: no-referrer` / HSTS(apex 単独)を追記する。棄却: (ii) は LP にサイドバーが要らない。
(iii)(iv) は Blume 既定を捨てて上流追随を失う。(v) は ADR-0008 の改訂が要り、Blume で足りることが実測で分かった。

**E. wrangler 設定の形** — 列挙: (i) 独立 `apps/site/wrangler.jsonc`(assets のみ・`main` なし)/ (ii) `apps/server/wrangler.jsonc`
に名前付き環境 `site` を足す / (iii) Cloudflare Pages / (iv) 製品 Worker に `/docs` を同梱。**選定 = (i)**: `name: maruhi-site`、
`routes: [{ pattern: "maruhi.app", custom_domain: true }]`、`workers_dev: false`、`preview_urls: false`、`assets.directory: ./dist`、
`html_handling: "drop-trailing-slash"`(Blume の内部リンク・canonical・sitemap は末尾スラッシュ無しで、出力は `x/index.html`。
`/docs/x/` は 308 で `/docs/x` へ)、`not_found_handling: "404-page"`(Blume の `404.html` — chrome 付き)。環境変数なし・設定
1 本で O9 の宣言化に包みやすい。CI は `wrangler deploy --dry-run` で妥当性を検査(製品 Worker の 8b と同型)。preview は
ローカル `wrangler dev`(`bun run --filter @maruhi/site preview`)のみ — apex 以外の origin を作らない。棄却: (ii) は環境継承の
規則で製品側の設定を汚す。(iii) は Pages が Workers 収束の方針で新規採用しない。(iv) は TCB に LP を同居させる(§1-4 違反)。

**F. `my.maruhi.app/` と e2e フックの移し先** — 列挙: (i) `_redirects` で `/` → `/dashboard` 302 / (ii) 最小の案内ページ / (iii) 据え置き
/ (iv) 案内ページ + 機構検証フックを `/about`(「このデプロイについて」= 診断ページ)へ移す(上位互換: サインイン往復の
`ResumeToDashboard`〔裁定 BU〕を壊さず、フックに運用上の意味〔ビルド時刻・クライアント動作確認〕を与える)。**選定 = (iv)**:
`HomePage` = SVG ロゴ(`/logo.svg`、絵文字 ㊙ を置換)+ 「Open the dashboard」+ `maruhi.app` への導線 + 「About this
deployment」。`AboutPage` = 説明 + Diagnostics(`built-at`・`CounterCard`)。e2e は hydrate 検証を `/about` へ、`/` の待機を
`home-heading` へ変更(SPA / MPA 劣化・API 呼び出しゼロ・マーカー復帰の検証はそのまま。全 25 件通過)。棄却: (i) は静的
シェルの `_redirects` だと OAuth 往復後の着地(`/`)が変わり、認証フローの検証が DP2 の範囲を超える。(iii) は LP の重複。

**G. LP の情報構成の粒度** — 列挙: (i) 1 ページに全部 / (ii) インストール / セルフホストをサブページに / (iii) LP は 1 画面 + 全部
docs へ。**選定 = (i)**(1 ページ・6 節: ヒーロー〔ターミナル〕→ How it works〔4 枚〕→ 1. Install〔README と同じ pre-release
手順〕→ 2. Sign in〔`config set server` + `login`、鍵生成の儀式を正直に〕→ 3. Get access〔招待制の現状。waitlist の置き場 =
`#access` の `data-waitlist-placeholder`、H6 で差し替え〕→ Or run it yourself〔`/docs/self-hosting`〕→ フッター〔GitHub /
Docs / License / 「No analytics, no trackers」/ フォントの OFL リンク〕)。docs の初期コンテンツは 3 ページ(index / getting-
started / self-hosting)で、仕様書・SELF_HOSTING.md への導線を置く(書き下ろしは最小 — 後続は `blume-update-docs`)。
棄却: (ii) は内容が薄い段階で階層を増やす。(iii) は「最初の 5 分」の導線が LP で完結しない。

**H. Blume の機能の取捨** — on(外部通信なし・既定): 検索(Orama ローカル)/ `llms.txt` / raw Markdown / Copy as Markdown /
WebMCP(ページ内登録のみ)/ OG カード(ローカル描画。palette は生成トークン、LP は DP1 の `og.png`)/ sitemap / robots /
JSON-LD / agent-readability.json / テーマトグル(docs は Blume 既定 — §1-2 の「手動トグルを持たない」はダッシュボードの裁定)/
banner(private preview の案内、dismiss は localStorage)/ Edit on GitHub・Give feedback(GitHub へのリンク)。**off**:
`ai.openInChat`(第三者 AI へのリンク — 「言わざる」の趣旨。Copy as Markdown が残る)/ RSS(blog 無し)/ analytics(無宣言)/
Ask AI・MCP サーバー(既定 off。server 出力が要る)/ `lastModified`(既定 off。浅い clone で崩れる)。**off にできない外部
通信は無い**(実測: LP / docs / テーマトグル / 検索 / クライアント遷移の全経路で外部オリジンへの要求ゼロ・CSP 違反ゼロ)。

**新たに出た裁定点**: (L) **`bun audit` の推移依存**: Blume の依存木に image-size@2.0.2(修正版なし)と
@vercel/routing-utils の path-to-regexp@6.1.0(厳密ピン)が含まれ CI の監査が落ちる。列挙: 名前単位の `overrides`
(router の ^8 系まで巻き込む)/ 監査ステップの除外 / advisory ID 単位の `--ignore`(採用 — ビルド時のみ動く
メンテナ側ツールチェーンで配信物に載らず、実行経路も無い。根拠は ci.yml のコメント。Blume 更新で消える見込み)。
(I) **ダークモードのロゴ**: `logo.image` の `{ light, dark }` 形で `<img>` 2 枚を出し分ける。dark 用 SVG は
原本の fill を dark accent(`#FF693C`)へ差し替えた生成物(B の生成スクリプト — 手書き hex ゼロ)。currentColor 版
(`logo-mono.svg`)だと印が文字色になり「朱の印」でなくなるため不採用。(J) **Blume の実行ランタイム**: `bunx --bun blume`(Bun)。
Node 22.12+ の要求は Bun 上の実測完走で代替し、CI に Node のセットアップを足さない。(K) **配信物の重複フォント**(C)。

**検証(2026-09-03)**: `bun run check` 7 段通過(site は fmt / lint / typecheck / ImportLint / fallow / unit test に乗る)。web e2e
25 件通過(F 後)。site e2e 11 件通過 — 全リクエスト同一オリジン・CSP 違反ゼロ(LP / docs / トグル / 検索 / クライアント遷移)・
Archivo / Martian Mono の適用・light / dark の accent と body が `tokens.ts` と一致・`/docs` 到達・末尾スラッシュ正規化・404。
スクリーンショット(light / dark / mobile)は PR 本文。人間タスク = hosted-ops.md §7 O10(初回デプロイ)/ O11(`maruhi.dev`
301)/ O12(訪問数はサーバー側集計のみ)。


**G 改訂 1(2026-09-04、所有者レビュー後)**: 所有者の評価「デザインは悪くないが構成が微妙で魅力が伝わらない」を受け、
競合 LP(Phase / Infisical / Doppler / Shelve / Keyway)を実読して差分を整理した。共通項: 全社が AI エージェント対応を前面に出す。
Phase は E2EE を掲げるが Console 側で復号し `.env` エクスポートを持つ。Keyway は「エージェントが `.env` を読める」を
ヒーローに置き、サーバー側 AES。Infisical / Doppler はコンプライアンス・規模・統合数で語る。maruhi の差分は「復号器が
MIT の CLI 一つで、サーバー・ダッシュボード・運営者のいずれも平文を持てない」「`.env` 書き出し機能が存在しない」
「自分の CF アカウントへ `wrangler deploy` 一発」「エージェントには `maruhi schema` の契約だけ渡し、値表示は fail-closed」
「非保証(CRYPTO_SPEC §14.3)を自分から書く」の 5 点に集約される(「No telemetry」は Phase も明記しており独自性として
は押さない)。列挙した構成: **(A)** 信頼境界を軸(「誰が平文を読めるか」の表を最初に置く)/ (B) ディスクレスを軸
(`maruhi run` の実演から入る)/ (C) セルフホストを軸(`wrangler deploy` から入る)。**選定 = (A)**(所有者裁定)。
(B) は「diskless run がある」だけでは差別化にならない(ADR-0014)。(C) は Infisical と同じ土俵で語ることになる。
ヒーローコピーは所有者の「短くインパクト重視」の指示で **「Secrets only you can read. / Not even us.」**(2 行目を accent 色)。
新構成(1 ページ・7 節): Hero〔`push` → `run` のターミナル〕→ Who can read your secrets〔CLI / run プロセス = yes、server /
dashboard / operator / AI agent = no の表〕→ Nothing to leak from disk〔`printenv | wc -c` と `ls .env*` の実演〕→ Agents get
the contract, not the values〔`maruhi schema` の実出力 + 値表示拒否メッセージ〕→ Your Cloudflare account. One deploy.〔3 コマンド〕
→ What we don't promise〔§14.3 から 4 点〕→ Get started〔install / sign in / Access(`#access`、waitlist placeholder は据え置き)〕。
ADR-0014 の柵: 「最も安全」と言わない、機能数で争わない、競合名を LP に出さない、ターミナル出力は CLI の実文字列
(`Pushed … (version=1, epoch=1)` / `Confirmation code:` / agent gate の拒否文 / `schema` の表)を使う。`THREAT_MODEL.md` は
未執筆(H5)なので非保証のリンク先は CRYPTO_SPEC §14.3。検証: site e2e 11 件(h1 の断言を新コピーに更新)・`blume validate
--strict`・fmt / lint / tsc 通過。文言の推敲は初回デプロイ後に続ける(§4 の「構造は今、コピーは後」)。

**G 改訂 2(2026-09-04、所有者レビュー 2 回目)**: 改訂 1 に対する所有者の指摘 = (a) 競合は LP にコマンドを並べていないのでは、
脅威や「なぜ E2EE / なぜディスクレス」を書いているのでは (b) 文章が多すぎて読むのがしんどい、イラストを入れて読みやすく
(c) Why が 2 つだけだと「競合でいい」となる — maruhi に自然につながる Why の連鎖にする (d) Cursor / Copilot / Claude Code は
競合ではないので名前を出してよい。競合 LP の再実測(コマンド数 / 脅威説明): Keyway 4 / あり(「AI エージェントが .env を読む」
→「ディスクに無ければ読めない」の因果が最も明快)、Infisical 2 / あり(sprawl・長寿命資格情報・エージェントは資格情報を
持てない)、Doppler 0 / あり(侵害統計)、1Password dev 0 / あり、Phase 3 / **なし**(機能列挙のみ — maruhi に最も近い E2EE 競合が
「なぜ」を語っていない = 空いている席)、Shelve 1 / ほぼなし。改訂 1 の maruhi はターミナル 5 個で 6 社中最多だった。
**選定 = 「Why の連鎖」構成**: 5 つの問いを順に潰すと maruhi の設計にしか着地しない並び —
01 Who reads your files?(エディタとエージェントは全ファイルを文脈として読む → 秘密はファイルにできない → `maruhi run`)
→ 02 Then where do they live?(サーバー。多くはサーバー / コンソールが復号できる → 出る前に暗号化)→ 03 Who holds the key?
(復号器が小さくなければ E2EE は意味を持たない。復号するダッシュボードは XSS 一発、export .env は 01 を無に戻す → 復号器は
MIT の CLI 一つ、ダッシュボードは鍵を持たない、`.env` writer は存在しない)→ 04 How does the agent still work?(名前・型・
設定済みかだけ要る → `maruhi schema`、値表示は fail-closed)→ 05 Who runs the server?(暗号文にも運営者はいる → 自分の
CF アカウントへ `wrangler deploy`、またはこちら。どちらもテレメトリなし)→ 締め「残るのは you と you が選んで走らせた
プロセス」。01 だけなら Keyway / Doppler、02 まで なら Phase、03 以降で maruhi のみ、という設計(指摘 c への答え)。
各問いは「問い → 事実 1〜2 文 → So: 答え(左罫 accent)」+ 図で、図はインライン SVG の線画(線 = muted、鍵と `.env` だけ
accent。style 属性は使わず class で色付け — CSP の style-src-attr を増やさない)。03 の図は「誰が平文を読めるか」の
タイル(改訂 1 の表を圧縮)。コマンドは hero の push → run と 04 の schema の 2 箇所に減らし、install / sign-in / self-host
の手順は docs(getting-started / self-hosting)へ委ねる。ターミナルは `pre-wrap` で折り返し(狭い列・モバイルで横スクロール
させない)。棄却: 脅威を文章だけで語る案(指摘 b に反する)/ 図を画像ファイルにする案(テーマ追従できず、`img-src` の
配信物が増える)/ 表を残す案(タイルで同じ情報を短く出せる)。検証: site e2e 11 件・`blume validate --strict`・postbuild
(外部参照ゼロ、style 属性の外部化は 9 件で変化なし)・fmt / lint。

## 5. DP3〜DP5 の入口(詳細は各 PR で)

- DP3(ダッシュボード): アプリシェル・空状態 / ローディング / エラーの統一(`FailureNotice` 13 か所)・監査ビューアの
  可読性(web-dashboard-design.md §4 の表示規律を保つ)・レスポンシブ・a11y。**xstyle の同じ上書きが 2〜3 回出たら
  人間に提案してから `ui.package` へ**
- DP4(儀式ページ): CLI 承認ページ(確認コードの視認性 = フィッシングガードの UX)・サインアップ案内 / 拒否時の着地・
  `/invite`。CSP `script-src 'none'` のまま自己配信 CSS でブランド統一。確認コードの文字集合を確認
- DP5(CLI): 出力の一貫性(TTY 規律)・`login` の期限と案内・繰り返し Note の抑制・英語校正・`--help` 整合

## 6. スコープ外

- 手動ダークトグル・**ダッシュボード(TCB)側の** Web フォント自己配信(必要になったら再訪 — §1-2 / §1-3)
- `maruhi ui`(ADR-0018 第 2 段)・値あり UI(第 3 段)
- 課金ページ・ステータスページ(H4 / GA)
