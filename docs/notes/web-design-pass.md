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

**G 改訂 2 補遺 — イラストのタッチ(2026-09-04、所有者裁定)**: 同一題材(02「鍵を持つ端末 → 暗号文 → 鍵のないサーバー」)を
7 案で描いて比較した — A 細線(改訂 2 初版)/ B 太線ピクトグラム / C フラット面 2 トーン / D アイソメトリック / E ブループリント
(方眼 + 寸法線)/ F ASCII 罫線 / G 印章(㊙ の朱印)。評価軸 = §2 のトーン適合・小サイズ可読性・light / dark・5 枚以上を揃える
コスト・競合との被り。**選定 = B + G の差し色**: 物体は 3px 丸端の前景色の線 + code 背景色の面(ロゴ ㊙ と同じ線の重さで
モバイルでも読める。線幅 1 種・面 1 種・accent 1 種なので揃えやすい)、accent は各図で「鍵を持つもの」1 点だけ(01 `.env`、
02 鍵、03 CLI タイルの ㊙ 印 = `/logo.svg` / `/logo-dark.svg` を `<img>` で再利用し CJK フォントに依存しない、04 守られた値、
05 deploy)。棄却: A(見出しの Archivo に負けて存在感が薄い・SaaS 線画に見える)/ C(Keyway / Linear 系と同じ棚)/
D(Cloudflare / Doppler の意匠と重なり、5 枚を同じ角度・光で揃えるコストが最大)/ E は docs のアーキテクチャ図に留保 /
F は 404 ページ等 1 箇所の遊びに留保(読み上げ・折り返しに弱い)。比較ページは所有者向け artifact(非公開)。

## 5. DP3〜DP5 の入口(詳細は各 PR で)

- DP3(ダッシュボード): アプリシェル・空状態 / ローディング / エラーの統一(`FailureNotice` 13 か所)・監査ビューアの
  可読性(web-dashboard-design.md §4 の表示規律を保つ)・レスポンシブ・a11y。**xstyle の同じ上書きが 2〜3 回出たら
  人間に提案してから `ui.package` へ**
- DP4(儀式ページ): CLI 承認ページ(確認コードの視認性 = フィッシングガードの UX)・サインアップ案内 / 拒否時の着地・
  `/invite`。CSP `script-src 'none'` のまま自己配信 CSS でブランド統一。確認コードの文字集合を確認
- DP5(CLI): 出力の一貫性(TTY 規律)・`login` の期限と案内・繰り返し Note の抑制・英語校正・`--help` 整合

### DP3 実装時の裁定録(2026-09-04)

各裁定点は DP1 / DP2 と同じループ(案を 3 つ以上列挙 → 上位互換 / 銀の弾丸を探索 → 新案が尽きるまで
反復 → 選定)で決めた。判断基準は ADR-0013 の検討順で浅い層に収まる・Astryx 既定に寄せる(§1-2)・
表示規律(web-dashboard-design.md §4)を 1 つも崩さない・配信物にプレビュー用コードを混ぜない・
後戻りが安いこと。実測は `apps/web/test/screenshots.ts`(裁定 F)と一回性の axe-core / キーボード
走査スクリプト(裁定 E)で行った。

**前提の訂正(実装で判明した事実)**: (1) Astryx の `Table` は自前の横スクロール枠(`role="group"` の
scroll wrapper、`tabindex=0`)を持ち、Layout の padding ぶん左右へ bleed する。W 系列のモバイル幅で表が
「切れて見えた」のは枠が視覚的なスクロールバーを出さないためで、構造的には読める。よって表の横スクロール
枠を自作する案(初版の `TableFrame`)は不要で、DP3 の初期実装から取り除いた。(2) `Text` の `wordBreak` は
maxLines 無しでも適用されるが、空白を含まない 64 hex の識別子は flex 項目の min-content を押し広げるため
それだけでは折れない(`overflow-wrap: anywhere` + `min-width: 0` が要る — 裁定 H の `HexText`)。
(3) 内部 user_id は ULID(26 文字 — AUTH_SPEC §9)で、モバイル幅の圧縮バーには「Signed in as + ULID +
Sign out + トグル」が収まらない(裁定 A の狭幅規則)。(4) `useMediaQuery` は SSR 互換のため初回描画で
必ず false を返す — 認証済み画面の本文はフェッチ後に描かれるため、Table → List の切替が見えることはない。

**A. アプリシェルの構成と配置** — 列挙: (i) 画面ごとの ad-hoc ヘッダー(現状: /dashboard だけに
ユーザー表示と Sign out、サブ画面は「← Dashboard」リンクのみ)/ (ii) `AppShell` + `TopNav`(ロゴ・3 到達点・
ユーザー・Sign out)を認証済み全画面に / (iii) `AppShell` + `SideNav` / (iv) `Layout` の header スロットだけを
各画面に / (v) **`DashboardShell`(上位互換)**: (ii) に加えて**セッション状態(`GET /auth/me`)をシェルが
1 か所で持ち**、401 は全画面で同じサインインカード、ok のときだけ本文を描く(旧 `DashboardScreen` の S3 を
シェルへ移す)。パンくずは親階層だけを渡し現在地は見出しから補う。表示規律の但し書き(`ServerReportedNote`)
はページ末尾にシェルが 1 回置く。**選定 = (v)**。棄却: (i) はサブ画面からログアウトできず、ユーザー表示も
無い。(iii) は到達点が 3 つで SideNav の要件(グループ化・増える見込み)を満たさず、Astryx の layout docs も
「浅く安定した nav は TopNav」。(iv) はランドマーク(skip link / main / nav)とモバイルのドロワーを自作する
ことになる。**付随の裁定**: (a) 本文は me の確認後に描く(1 往復の直列化を受容 — 401 のとき本文が一瞬
描かれてから消える形と、子リソースの 401 分岐が並走する形を避ける)。(b) `height="auto"` + `variant="section"`
— 既定の `elevated` は本文の高さで面が終わり(auto)か、main の内部スクロール(fill)になる。HP5 のモバイル
閲覧は文書スクロール(アドレスバーの収縮・端までの慣性)が自然なので auto を採り、面の段差を出さない
section にした(Astryx 既定からの唯一の逸脱で、視覚トークンは触っていない)。(c) 狭い幅(AppShell `md` =
768px 以下)ではユーザー表示を到達点と一緒にドロワー側(`startContent`)へ移し、バーには Sign out だけを
残す。(d) e2e は認証済み画面のテストがすべて `/auth/me` をモックする形に追随(`routeSession`)。

**B. 空状態 / ローディング / エラーの統一** — 列挙: (i) 現状維持(空 = `EmptyState` と素の `Text` が混在、
失敗 = `FailureNotice`、読込 = `LoadingRow`)/ (ii) 空を全部 `EmptyState` に揃えるだけ / (iii) 3 状態を 1 つの
`ResourceView` に畳む(`useApiResource` 以外の状態 — ページング追記・失効の失敗・シェルの認証 — を覆えず、
2 つの規律が並ぶ)/ (iv) `FailureNotice` に placement 引数を足す(API を増やす割に見た目は同じ)/ (v)
**`FailureNotice` の API(failure / onRetry / subject)は変えず、置き方の規律を 2 種に固定し、空状態だけ新部品
`EmptyNotice` に揃える(上位互換)**。**選定 = (v)**。規律: (a) **置換** = リソース本体の代わりに描き、再取得
手段があれば `onRetry`。(b) **追記** = 描けた本体の下に足す(Load more の失敗・失効の失敗)。行から再操作できる
失敗は `onRetry` を渡さない。13 か所(旧 DashboardScreen のセッション失敗表示はシェルへ移動 — 数は不変)= 置換 9 / 追記 4 で、各呼び出しにコメントで印を付けた。
`EmptyNotice` は見出し + 「as reported by the server」の規定文言で、件数を出さない(§4-4)。`LoadingRow` は
Spinner の `role="status"` に見える文言と同じ label を渡す。**付随**: 概要タブはチェーン取得を先頭リソースに
して環境一覧をその後に読む(一様 404 / 403 で同じ Banner が節ごとに並ぶ形を避ける — 1 往復の直列化を受容)。
棄却: (ii) は失敗と読込の規律が文書化されないまま残る。(iii)(iv) は上記。

**C. 監査ビューアの可読性** — 列挙: (i) 現状(5 列。actor = `user · key FP · token id` を 1 文字列、details も
` · ` 連結)/ (ii) セルを**ラベル付きの断片**に分解(actor = 主体 1 行 + `key` / `token` の断片、details =
`target` / `env` / `var` / `epoch` / `v` / `chain seq` の対、`var.read` の件数要約は別行)/ (iii) Table を
`List`(1 イベント = 1 項目)に置き換える(デスクトップの列走査を失う)/ (iv) 列幅の調整のみ / (v) **(ii) +
狭い幅だけ (iii) に切り替える(上位互換 — 裁定 D)**。**選定 = (v)**。表示規律の確認: 項目・順序・文言は
変えず(seq は応答適応のまま・「Events visible to your role」の規定文言・`Server time (UTC)`・FP は参照値の
ままラベル `key` を付けただけで「照合せよ」と読める文言は無い)、件数表示も加えていない。棄却: (i) は
FP と target が同じ塊で読めない。(iii) 単独は列走査を失う。(iv) は根本(1 文字列)が変わらない。

**D. レスポンシブ方針** — 列挙: (i) 何もしない(Astryx の scroll wrapper に任せる)/ (ii) 全表を狭い幅で
List 化 / (iii) 監査一覧だけ List 化、他の表は Astryx の横スクロール枠に任せる / (iv) CSS で `td` をブロック化する
古典手法(Table の ARIA 構造を壊す。StyleX で Astryx 内部を上書きすることになる)/ (v) ブレークポイント
定数を 1 つに固定して (iii)。**選定 = (v)**: `NARROW_VIEWPORT_QUERY = "(max-width: 768px)"`(AppShell の
`md` と同じ式 — ナビのドロワー化と本文の表示形切替が同じ幅で起きる)を `shared.tsx` に 1 定義。HP5 の主用途
(監査を読む)だけ List 形にし、S5 / S8 / S9 の表は横スクロール(枠は `tabindex=0` でキーボードでも
スクロールできる)。識別子は `HexText` で任意位置折り返し(見出し直下の project ID・chain head・member id・
key FP・token prefix)。棄却: (ii) は失効の 2 段階ボタンや Token を項目内に組み直す量に対して得るものが
少ない。(iv) は上記。

**E. a11y 監査の方法と直す範囲** — 列挙: (i) コードの目視のみ / (ii) `@axe-core/playwright` を devDependency
に追加 / (iii) Playwright の ARIA スナップショット + 手動のキーボード走査 / (iv) React Doctor + `astryx doctor`
のみ / (v) **axe-core を一回性(scratchpad の `page.evaluate` — CDP 経由なので CSP の対象外)で注入し、
(iii)(iv) と合わせる(依存を増やさない上位互換)**。**選定 = (v)**。範囲: wcag2a / 2aa / 21a / 21aa +
best-practice を S4 / S5 / S6(admin・reader・本人軸)/ S8 / S9 × light / dark / mobile の 18 態で実行。
**所見と処置**: (a) `empty-table-header`(minor)— 失効列と変数名列の空見出し → `Actions` / `Variables` を
付けた。(b) `color-contrast`(serious)— `SegmentedControl` の非選択ラベルが dark で 4.26:1(12px、AA は
4.5)→ 監査軸の切替を `ToggleButtonGroup`(single)に置換して解消(Astryx 内部色なので上流候補として
PR に記載。テーマの色値は触らない — DP1 で確定)。(c) 見出し階層: ページ h1 はシェル(サインイン前は
カードの「Sign in」が h1)、節は h2(旧 h3 を昇格)、空状態の見出しは h3。(d) ランドマーク: AppShell の
skip link → `nav[Dashboard]` → main、パンくずは `nav[Breadcrumb]`、モバイルのドロワーは `dialog[Navigation]`
で Escape で閉じて焦点がトグルへ戻る。(e) フォーカス可視: light / dark とも accent 2px の outline(TextInput
は枠線色 + 内側リング)。(f) タブは矢印で焦点移動・Enter で選択(手動活性化)。**直さなかったもの**:
`TopNavHeading` のロゴリンクの焦点リングは 1px の固定色(Astryx 内部)— 実測では両モードで視認できる
ため据え置き(上流候補に含める)。

**F. 認証が要る画面の目視確認とスクリーンショット** — 列挙: (i) scratchpad のみのスクリプト(再現不能)/
(ii) **`apps/web/test/screenshots.ts` をコミット**(e2e と同じ `page.route` モック。フィクスチャは
`test/fixtures.ts` へ切り出して e2e と共用)/ (iii) 配信物にプレビュー用ルート + モックデータ(禁止)/
(iv) 実 OAuth でログイン(GitHub App の設定が要り、本セッションでは不能)/ (v) (ii) + 結果を所有者向けの
非公開ページ(Claude の Artifact)に light / dark / mobile と変更前後で並べる(DP2 と同じ)。**選定 = (v)**。
手順は `screenshots.ts` 先頭に記載(`build` → `preview`(port 8788)→ `screenshots`。出力は
`apps/web/screenshots/` — .gitignore 済み)。11 画面 × 3 態 = 33 枚、CSP 違反があれば失敗する。

**G. PR の分割** — 列挙: (i) 1 本 / (ii) DP3a(シェル + 状態統一)/ DP3b(監査可読性 + レスポンシブ + a11y)/
(iii) 3 本以上。**選定 = (i)**: シェルがブレークポイント(D)・ランドマークと見出し階層(E)・状態の統一(B)の
土台で、分けると DP3a だけでは a11y と e2e の追随が中途半端になる。差分は web の 12 ファイル + 文書で
レビュー可能な量(コミットは関心ごとに分けた)。

**H. xstyle の繰り返し** — DP3 で出た xstyle は **1 種類のみ**: 識別子の任意位置折り返し(`overflowWrap:
anywhere` + `wordBreak: break-all` + `minWidth: 0`)。列挙: (i) 各画面で `stylex.create` を書く(3 回以上の
重複になる)/ (ii) `shared.tsx` に 1 定義 + `HexText` 部品(定義は 1 か所で、使用箇所は 12)/ (iii) `ui.package`
を新設して置く(③)/ (iv) `defineTheme` の Text variant(①)。**選定 = (ii)** — 定義の重複は作らず、昇格は
人間の判断に委ねる(CLAUDE.md「逆流させない」)。**昇格候補(PR に列挙)**: `HexText` を ui.package の
部品または Text の variant(`code-breakable` 等)へ。他に繰り返しはない(既存の tabpanel の `display: none`
上書きは W 系列のまま 1 か所)。

**新たに出た裁定点**: (I) **軸切替の部品**: SegmentedControl → ToggleButtonGroup(E-(b))。e2e の指し方は
`radio` → `button[pressed=false]`。(J) **ロゴの色**: シェルのロゴは `public/logo.svg`(light の朱で固定)でなく
インライン SVG 部品 `MaruhiMark`(`public/logo-mono.svg` と同じパス)を `Icon color="accent"` で描き、
light / dark の `--color-accent` を継承する(DP1 裁定 A の (v)「currentColor 化」の部分採用)。パスデータの
二重管理は SVG 側を正としてコメントで結ぶ。(K) **サインイン前のページ見出し**: シェルは me が取れるまで
ページ見出しを出さず、サインインカードの「Sign in」が h1 になる(「API tokens」の下にサインインカード、
という形を避ける)。(L) **プロジェクト見出しの短縮形**: h1 は `Project ab…ab`(先頭・末尾 8 桁)、全文は
直下に `HexText`(`data-testid="project-id"` は据え置き)。

**A 改訂 1(2026-09-04、所有者レビュー後 — サイドバー型 + Astryx テンプレート起点)**: 所有者の指示
「レイアウトはサイドバー型に(SaaS の主流で、自分も使いやすい)」「Astryx のテンプレートをもっと積極的に
使う(ログインもサイドバーもテンプレートにある)」を受け、TopNav 案(A-(v))を **SideNav 案(A-(iii))に
差し替えた**。所有者の裁定であり、A の「到達点 3 つは TopNav の範囲」という棄却理由は「使い慣れた形」に
劣後する。形はテンプレートをそのまま起点にする(`astryx template shell-side-nav` / `AppShellSideNavOnly` /
`SideNavWithHeaderMenu` / `login` / `table-page` / `LayoutHeaderWithActions`): (a) **フレーム** = AppShell +
`SideNav`(`collapsible`。ヘッダー = `SideNavHeading` + `NavIcon`〔accent の円盤に on-accent の ㊙ = favicon と
同じ反転版〕、本文 = `SideNavSection` の到達点 3 つ〔Folder / Key / ClipboardDocumentList〕、プロジェクト画面
では Projects の子項目に現在のプロジェクト〔短縮 ID〕が選択状態で並ぶ、フッター = `SideNavSection`
"Account"〔ユーザー id → Account audit、Sign out〕— `shell-side-nav` のフッター構成)。モバイル幅では
AppShell が SideNav をドロワーへ移す(A-(c) の「ユーザー表示をドロワーへ」は SideNav では自然に成立するので
`useMediaQuery` の分岐を廃止)。(b) **ページ** = `Layout`(fill)の header スロットにパンくず + h1 + 説明
(`LayoutHeader hasDivider`)、content スロットに本文 + `ServerReportedNote`。main の内部スクロール
(`table-page` の形。A-(b) の「文書スクロール」は撤回 — テンプレートの既定に寄せる)。(c) **サインイン** =
`login` テンプレートの形(Center + ロゴ + Card〔h1 "Sign in"・説明・primary の "Sign in with GitHub"〕)。
資格情報の入力欄は無い(GitHub OAuth のみ)ので Button に `href` を渡してリンクとして描く。サインアウト直後は
Card 内に info Banner。(d) **アイコン**: テンプレートは `@heroicons/react` を使うか SVG をインラインで持つ。
依存を増やさない方針で後者を採り、heroicons(MIT)の outline 5 つを `icons.tsx` に写した。列挙した他案:
SideNav + TopNav の併用(スイート向け — 到達点が薄く 2 本目が余る)/ `LayoutPanelNavigation`(Layout の
start パネルにナビ — AppShell のドロワーとスキップリンクを失う)/ `Shell Nav`(コマンドパレット付き —
検索対象が無い)。棄却。e2e は不変(`signed-in-user` / `sign-out` / `login-card` / `sign-in-link` の testid は
SideNavItem / Card / Button が透過する)。axe 18 態で違反 0、キーボード走査で SideNav の全項目・折りたたみ
ボタン・ドロワー(Escape で閉じて焦点がトグルへ戻る)を確認。E の「直さなかったもの」に挙げた
`TopNavHeading` の焦点リングは TopNav を使わなくなったため対象外(SideNavHeading は accent 2px)。

**A 改訂 2(2026-09-04、所有者レビュー 2 回目 — ロゴ・サインインの位置・余白・Table / Settings テンプレート)**:
所有者の指摘 4 点への対応。(a) **ロゴ**: NavIcon(accent の円盤)の中に環付きの `MaruhiMark` を置いていたため
「円の中に円」に見えていた。`MaruhiMark` に `hasRing` を足し、円盤の中は環なしの字形だけ(`size="md"`、
円盤の約 6 割)にして favicon(DP1 裁定 E の反転版)と同じ「円盤 + 字形」に揃えた。(b) **サインインの位置**:
`Center minHeight="100%"` は親に高さが無く解決されず上に寄っていた → `minHeight="100dvh"`(`login`
テンプレートは body の高さを前提に `minHeight: '100%'` を style で置く。本リポジトリは style 禁止なので
ビューポート単位で同じ結果を得る)。(c) **Table / Form / Settings テンプレートの参照**: 改訂 1 は `shell-side-nav` /
`login` / `LayoutHeaderWithActions` のみを起点にしていた。`table-page`(`density="balanced"` + `hasHover`、
LayoutHeader の h1 + LayoutContent の VStack gap 4)、`settings`(節 = 見出し level 3 + 1 行の説明 + 内容、
節間は Divider、入力を伴う節は `Grid columns={{minWidth: 320}} gap={10}` の 2 列 = 見出し | 入力)、
`SectionWithDividers` を読み、次を採った: 全 Table を `balanced` + `hasHover`(compact は「ログを高速に
走査する領域」向けで、監査も所有者の「詰まっている」評価を優先して balanced)、節の見出しブロックを
`SectionHeader`(`shared.tsx` — `Heading level={3} accessibilityLevel={2}` + supporting の説明。見た目は
テンプレートの level 3、文書構造は h1 直下の h2 を保つ)に統一、S4 の「Open a project by ID」を settings
テンプレートの 2 列 Grid に、コントロールのサイズを md(balanced と対)に。`contact-form` は入力欄が無い
ダッシュボードには当てはまらない。(d) **余白**: ページ本文の節間 gap 6 → 8、節内(見出しブロック → 内容)
gap 4、概要タブの節間 gap 5 → 8、監査 / Load more 周りを gap 4。Astryx spacing docs の「tight は 0.5〜2、
section は 4〜8」に合わせ、詰め寄りだった 2〜3 を使わない。e2e 26 件・axe 18 態は不変で通過。

**A / C / J 改訂 3(2026-09-04、所有者レビュー 3 回目 — テンプレートを「参考に実装」・横幅・実 SVG)**:
所有者の指摘「Table / Form / Settings は採用 / 不採用の話ではなく、テンプレートを参考にして実装する」を
受け、画面ごとに最も近いテンプレートを 1 つ選んでその構造を写した。(a) **監査ビューア(C 改訂)= `incident-console`**
(「行の待ち行列 + 選択行のインスペクタ」。Rows, not cards)。行 = `List` の `ListItem`(label = イベント名、
description = seq〔応答適応〕+ 主体 + 座標の断片、endContent = サーバー時刻、`onClick` + `isSelected`)、
選択行の全フィールド = `MetadataList`(ラベル幅 96)+ 記録どおりの payload(`CodeBlock` json)+ var.read の
列挙。1024px 超(`INSPECTOR_VIEWPORT_QUERY`、テンプレートと同じ境界)はインスペクタを右に並べ(タブパネルの
中なので Layout の end スロットでなく HStack + 縦 Divider + `aside`)、以下は全画面 `Dialog`(`detail-page` の
モバイル型 — Escape で閉じる)。**Table は使わない**(D の Table → List 切替も不要になり `NARROW_VIEWPORT_QUERY`
を廃止)。項目・順序・文言・件数非表示は不変(§4)。(b) **プロジェクト画面 = `detail-page`(Order Detail)**:
header スロットに「← All projects」→ h1 → 全文 ID → `TabList`(タブは header に置き、本文が内部スクロール
しても見え続ける)。概要は横並びの `MetadataList`(Chain head / Head digest / Member head attestations)→
Members → Environments。「Head hash」は SPA バンドルの語 `hash` 禁止(AUTH_SPEC §15-3 の tripwire —
`write-headers.ts`)に当たるため「Head digest」。(c) **注記 = `CardCallout` ブロック**(muted の Card + 見出し +
本文): tokens / invites / rotation の CLI 案内。(d) **一覧 = `table-page`**(前回の改訂 2 のまま: balanced +
hasHover + LayoutHeader)。(e) **ロゴ(J 改訂)**: DP1 の実資産 `public/logo-inverted.svg`(朱の円盤に白抜きの
「秘」= favicon と同形)を `<img>` で使う(サイドバー 32px・サインイン 56px)。インライン SVG 部品
(`MaruhiMark`)は削除。色は朱で固定(ブラウザのタブの favicon と同じ見え方。dark で accent に追随させるなら
site と同じ生成物 `logo-inverted-dark.svg` + `<picture>` の案があるが、資産を増やすため見送り)。(f) **横幅**:
所有者の「コンテンツが横幅いっぱい」への見解 — Layout の `contentWidth` は 1040 で、1920px では中央に
キャップされる(Artifact の 1920 スクリーンショット)。1280px ではサイドバー 260 を引いた 1020 が上限なので
いっぱいに見える。Astryx の layout docs は「表・盤面は領域を満たし、散文・フォームはキャップ」で、テンプレートも
`table-page` = キャップなし、`settings` = 1440、`detail-page` = 1000。よって表のページは現状(1040)を維持し、
散文は `SectionHeader` の説明と注記(Card)で幅を絞る。960 に下げる案は表の列幅を圧迫するため採らない。
e2e 26 件(監査の指し方を行 + インスペクタに追随)、axe 24 態(1920 を追加)で違反 0。

**改訂 4(2026-09-05、所有者レビュー 4 回目 — 「本当に良いか」をユーザー体験で自問・横幅・ロゴ)**:
所有者の 3 点(自分でユーザー体験ベースに評価せよ / ページごとに横幅を変えるのはありえない / ロゴが大きい)
への回答と処置。(a) **自己評価で見つけた弱点と処置**: ① 失効の確認が行内の Cancel / Confirm revoke で、狭い
Actions 列に縦積みになり行の高さも変わっていた → Astryx の `AlertDialogAsyncAction` テンプレートの形
(モーダルの確認 + 対象名と帰結を本文に + 実行中は action にスピナー)へ。**裁定 CO(session-45 —
インライン 2 段階)の実装形を改める**(武装は常に 1 行・別行の武装で解除・in-flight 中は他行を無効化
〔PR #109〕は不変。帰結の注記はダイアログ本文で確認の場で読ませ、テーブル下の CardCallout にも残す)。
② 監査行の description が `seq 2 user_e2e target … chain seq 2` の等幅断片の塊で走査しにくい → 「by
<actor>」を先頭に、seq は endContent の時刻の下へ(誰が・何を・いつ、の順)。③ トークンの Scopes が
64 hex × 数件で 5 行に膨らみ表を壊す → `Token` chip(短縮 ID:permission、全文は aria-description)。
④ 概要の横並び MetadataList は 64 hex の digest が折り返して読めない → 単列(ラベル幅 200)。⑤ 変えない
と判断したもの: ページ末尾の `ServerReportedNote`(§4-1 の規律。全画面で 1 回)、プロジェクト一覧の
64 hex 表示(サーバー申告は ID と role だけで、名前は無い — ID が capability)、Row id(サポート時の参照)。
(b) **横幅**: ページごとに変える意図は無く、改訂 3 の説明が誤解を招いた。実装は最初からシェルの 1 値
(`contentWidth`)で全ページ共通。値は **1040 → 1200** に統一(1440px のノートで領域 1180 をちょうど満たし、
1920px で中央に収まる。監査のインスペクタ 380 を並べても行に 800 弱が残る)。(c) **ロゴ**: 同意 — 32px は
見出し文字(bold 16px)より 2 倍大きく浮いていた。サイドバー 24px(文字高と同格)、サインイン 40px
(56 → 40)。(d) 検証: e2e 26 件(失効の指し方を alertdialog に追随・in-flight のロックはモーダル + 行の
isDisabled で検査)、axe 24 態で違反 0。

**改訂 5(2026-09-05、所有者レビュー 5 回目 — 区切り線が多い・タブと header 線の組み合わせ・監査の左右分割)**:
所有者の 2 点: (1) header と本文を分ける線・本文内の線・表の枠線が重なって「どこからどのコンテンツか」が読めず、
タブの下線と header の線の組み合わせも据わりが悪い。線でなく余白で分ける案の提示あり。(2) 監査(project 軸 /
本人軸)の左右分割は、幅 1200 の領域で行と詳細の間が空きすぎて広い画面で変に見える。

**O. 区切りの規律(線か余白か)** — 列挙: (i) 現状(header の全幅 divider + タブの下線 + 節の間の Divider + 表の
行線 + 監査の縦 Divider)/ (ii) **余白だけ**(所有者案): header の divider と節間の Divider を消し、節間を
gap 10(40px)に広げ、線は表の行だけ / (iii) **タブ行を唯一の境界に**: (ii) に加え、タブがある画面では
`TabList hasDivider`(タブの下線と同じ線)が header と本文の境界を兼ねる。タブの無い画面は余白のみ /
(iv) header を固定したまま divider を消す / (v) 節を `Section`(dividers)や Card で囲う(線が増える — 棄却)。
→ **(ii) + (iii) を採用**。Astryx layout docs の容器の弱い順(gap → Divider → Section → Card)に従い、
「境界を線で引かず余白の対比(節内 4 / 節間 10)で読ませ、線は集合の内側(表の行・監査行の hairline)と
タブ行だけ」に固定する。(iv) は線なしの固定 header が本文と重なって読めないため採らず、**Layout を
`height="auto"` にしてページ全体をスクロール**させる(GitHub のリポジトリページと同じ形。ページが短く、
サイドバーは AppShell が固定する)。header の下余白 16px + 本文の `paddingBlockStart` 24px = 40px で節間と
同じ対比。節見出し(`SectionHeader`)は線の代わりに見出しの重さで節の始まりを示すので level 3 → **level 2**。
Projects 画面は h1 が一覧の見出しを兼ねる(1 領域に主見出しは 1 つ — layout docs)ため「Your projects」の
節見出しを外し、説明を intro に統合。表の `dividers="rows"` は据え置き(行の区切りは集合の内側)。

**P. 監査の形(左右分割の撤回)** — 列挙: (i) 現状の行 + 右インスペクタ(`incident-console`)で行の幅の
バグ(`align="start"` で List が縮む)だけ直す / (ii) 1 列 + 詳細は全幅で Dialog(現状のモバイル型を全幅に)/
(iii) **1 列 + 行をその場で展開**(`Collapsible` × `CollapsibleGroup hasDividers` — `CollapsibleDividedAccordion`
ブロックの形。トリガー = 要約、展開部 = MetadataList + payload + var.read の列挙)/ (iv) Table + 展開行
(モバイルで 5 列が横スクロール — HP5 に反する)/ (v) 左右分割のまま行の幅を 560 に固定(分割は残る)。
→ **(iii) を採用**。幅によらず同じ 1 列で、詳細は読んでいる行の直下に出る(視線が横へ飛ばない・1024px の
形の切替と縦 Divider が消える・モバイルと同じ操作)。single(1 行だけ開く)で展開部を読む間に他の行が
動かない。閉じた展開部は DOM に残る(hidden)ため e2e は可視要素だけを数える。行の並びは改訂 4 の
「主体 → 対象 → 時刻 / seq(右端)」のまま、チェブロンが行末に付く。`INSPECTOR_VIEWPORT_QUERY` と
`Dialog` / `EmptyState` / 縦 `Divider` は不要になり削除。項目・文言・seq の応答適応・件数非表示は不変。

検証: e2e 26 件(監査の指し方を「行 = button〔aria-expanded〕+ 可視の Row id」に追随、モバイル型の
Dialog 検査を「同じ列で展開・single で先の行が閉じる」検査に置換)、axe 24 態で違反 0。

**改訂 6(2026-09-05、所有者レビュー 6 回目 — 監査行の時刻が 2 段・Astryx に良い部品は無いか)**:

**Q. サーバー時刻の表示** — 列挙: (i) 現状(`formatServerTime` の UTC ISO 文字列 `2025-08-24T01:48:20.000Z` を
Text で。監査行では時刻と seq が右端で 2 段)/ (ii) ISO のまま seq と 1 行に並べる / (iii) **Astryx `Timestamp`
(`format="date_time"` + `isTimezoneShown`)**: 閲覧者の時間帯で `Aug 24, 2025, 1:48 AM UTC` の形、hover card に
UTC と Unix 秒(コピー可 — `tooltipEntries`)/ (iv) `Timestamp format="auto"`(直近は相対時刻)/ (v) `system_date_time`
(ISO 風)。→ **(iii) を採用**し、監査行だけでなくサーバー時刻の全表示(tokens の Last used / Expires、invites の
Expires、rotation の Recommended at、`ExpiryCell`)を `shared.tsx` の `ServerTime` 1 部品に揃える。Astryx の
Timestamp docs は「生の ISO を出さない」「監査ログでは時間帯の略称を出す」「正確な値が要る記録には
tooltipEntries でコピー行を付ける」を規範としており、そのまま従った。(iv) は監査の精度(いつ、が主役)に
合わないので棄却。表の列見出しから「(UTC)」を外す(表示は閲覧者の時間帯 + 略称で、UTC は hover card)。
値はサーバー申告の ms そのもので、換算は描画だけ — §4 の「as reported by the server」は崩れない。監査行の
トリガー(ボタン)の中では hover card を切る(`hasTooltip={false}` — 入れ子の対話要素を作らない)代わりに、
展開部に「Recorded at」として記録どおりの UTC ISO を出す。`formatServerTime` はその 1 用途に残す。
範囲外の ms(deepsec 2026-08-22 — Invalid Date)は従来どおり生の数値。監査行の右端は seq + 時刻の
1 行にし、イベント名の右に続ける(右端に寄せない — 広い画面で名前と時刻の間が空かない。狭い幅では
名前の下へ折り返す)。検証: e2e 26 件、axe 24 態で違反 0(Timestamp を button の中に置いても入れ子の
対話要素は無い)。

**改訂 7(2026-09-05、所有者レビュー 7 回目 — Astryx の部品が使えるのに自作している箇所の棚卸し)**:

**R. Astryx 部品への置換の棚卸し** — `apps/web/src` の全 JSX を Astryx の 163 部品(`astryx component --list`)と
突き合わせた。**置換したもの**: (1) `LoadingRow` の Spinner + Text の横並び → `Spinner` の `label` スロット(文字列は
aria-label も兼ねる — 見える文言と読み上げが 1 点)。(2) Projects の ID 直入力の形式エラー(Text `role="alert"`)→
`TextInput` の `status`(error + message、`statusVariant="detached"`)。あわせて `onEnter` で Enter でも Open。
(3) プロジェクト画面の戻りリンク(`Link` の「← All projects」)→ `Breadcrumbs` / `BreadcrumbItem`
(`variant="supporting"`。親 = Projects へのリンク、現在地 = 短縮 ID に aria-current。nav landmark が付く)。
`detail-page` テンプレートは Link + 矢印アイコンだが、階層を表す部品が存在するのでそちらに従う。
(4) 変数名の一覧(HStack の手組み行)と付与済みサーバー鍵(同)→ `Table`(compact、行の hairline。集合は
行で描く — layout docs)。サーバー鍵は節見出し(`SectionHeader`)付き。(5) CLI 案内の注記(muted Card +
Heading + Text の同形 × 3)→ `shared.tsx` の `Callout` 1 定義(Astryx の合成は不変 — 重複の解消)。
(6) 形式外 ID のページ(`InvalidProjectPage`)の Text → `Banner`(warning — 他の通知と同じ形)。
**置換しないもの(理由)**: (a) `icons.tsx` のインライン heroicons — Astryx はアイコン集合を持たず(`Icon` は
SVG 部品を受けるだけ)、テンプレート自身が @heroicons/react かインライン SVG。依存を増やさない方針で後者。
(b) `HexText`(xstyle の anywhere 折り)— `Text` に相当 prop が無い(裁定 H の昇格判断は人間)。(c) タブパネル
(`VStack role="tabpanel"`)— Astryx に TabPanel 部品が無い(`Tab` の `panelId` で結ぶ設計)。(d) `EmptyNotice` /
`SectionHeader` / `FailureNotice` / `RevokeDialog` — Astryx 部品の薄い包み(既定文言・置き方の規律を 1 点に持つ)。
(e) Load more の `Button` — `Pagination` はページ番号型で、カーソル型には合わない。(f) 監査の caption +
ToggleButtonGroup の HStack — `Toolbar` は操作の並び(above a table)用で、規定文言 + 1 つの切替には過剰。
(g) 環境表の「Variable names」ボタンで下に変数表を出す形 — `Collapsible` や Table の tree 行(`useTableTreeData`)
も可能だが、表の行の中に表を入れる形になるため据え置き(次の見直し候補)。(h) `HomePage` / `AboutPage` /
`CounterCard`(RSC の静的シェル + スパイク)— 生の `<main>` / `<h1>` / `<a>` のまま。DP3 のスコープ外
(W 系列の spike-a)で、Astryx 化は静的シェルでの `Theme` 適用の設計が要るため別 PR。
検証: e2e 26 件、axe 24 態で違反 0(Breadcrumbs の nav landmark が 1 つ増える)。

**改訂 8(2026-09-05、所有者レビュー 8 回目 — 表の枠線が節の幅を越えて伸びる違和感・Card で包む案)**:

**S. 節の容器(表の bleed をどう収めるか)** — 事実: Astryx の `Table`(scroll wrapper)は Layout の padding ぶん
(24px)負のマージンで領域の縁まで伸びる。Section も同じく縁まで伸びる。layout docs の「1 領域に 1 本の内容線 —
文字は線の上、行の hover 背景は縁まで bleed」の整列モデルで、`detail-page` テンプレートも同じ見え方。
列挙: (i) 現状(節見出し + 表。表が見出しの左右を越えて伸びる)/ (ii) **Card で包む**(所有者案 — 試作済み。
表は収まるが、`component Section` に "If you are tempted to use a Card for a page section, use Section instead"、
`component Card` に "Don't: Wrap page sections in cards"、layout docs に "x full-width Cards stacked as page
structure" と明記)/ (iii) `Section` で包む(規範どおりだが、neutral テーマでは section の面 = surface = 本文領域の
色で見えない)/ (iv) **Section + テーマで面の色**: defineTheme の `components.section['variant:section']`(カスタマイズ
順 ①)に `color-mix(in oklab, var(--color-background-body) 55%, var(--color-background-surface))` を与え、既定の
Section を「線を引かない薄いパネル」にする / (v) Section `dividers`(上下の hairline — 線が戻る)/ (vi) Section
`variant="muted"`(docs は attention 用に限る)/ (vii) Layout の padding を AppShell に移して bleed を 0 に(試作 —
AppShell の contentPadding が効かず、モバイルで文字が画面端に付くため棄却)。
→ **(iv) を採用**(所有者の選択)。Section docs の "Use it ... any time you need visual separation between parts of a
page" のとおり分離は Section の役目で、色はテーマの責務。Astryx の surface 階層(body → surface → card)に沿って
body 側へ半分寄せた色にし、生 hex は増やさない(トークン参照 + color-mix)。`shared.tsx` の `SectionBlock`
(Section padding 6 = Layout の padding と同じ 24px で、見出しはページの内容線に乗る。`title` を省くとページ h1 が
見出しを兼ねる一覧のパネル)で、**すべての集合**(Members / Environments / Granted servers / Invitations /
Projects / API tokens / Rotation flags / 監査行)を包む。表の行は Section の縁まで伸びるので節に収まって見える。
Callout(muted の Card)は注記のままで、パネルとは色相が違う。テーマの生成物(`maruhi.css` / `.js`)は
`bun run theme:build` で再生成(差分は section の 1 規則のみ)。site 側はトークンの写しなので漂流なし
(`apps/site` の theme:build で差分 0)。検証: e2e 26 件、axe 24 態で違反 0(パネル上の文字コントラストは
body 相当で AA)。

**改訂 9(2026-09-05、所有者レビュー 9 回目 — Section のパネルは不可。固定幅 + border)**:

**S 改訂: 集合の容器は `Card`(border 付きの固定幅の箱)**。改訂 8 の Section + テーマの面の色は、
所有者の判定で棄却(薄い wash では節が節として見えない)。「固定幅 + border」= 集合ごとの Card。Astryx の
docs(`component Section` / `component Card` / `docs layout`)は「ページの節に Card を使わない」とするが、
maruhi のテーマでは Section が節として見えず、境界を見せるには border しかない — **所有者判断で Astryx の
文言を上書き**する(理由は裁定録に残す。Card docs の "a hard boundary around critical content" の読みも
併記)。試作 2 案: (A) **見出しを箱の内側**(GitHub の設定画面の Box の形。見出し・説明・表が 1 つの境界に入り、
見出しの無い集合〔監査行・Projects・API tokens〕でも同じ箱で揃う)/ (B) 見出しを箱の外側(Vercel の形。箱は
データの容器だけを示し、箱と見出しの所属を余白に頼る)。→ **(A) を採用**(所有者の最終判断は保留中 —
B への切替は `SectionBlock` の 3 行)。実装: `shared.tsx` の `SectionBlock` = `Card padding={4}` + VStack
(SectionHeader? + children)。中の Table は Card の縁まで伸びる(Astryx の整列モデル)ので行の線は border の
内側で止まる。箱に入れるのは集合(Members / Environments / Granted servers / Invitations / Projects /
API tokens / Rotation flags / 監査行)だけで、概要のメタデータ(MetadataList)・「Open a project by ID」・
CLI 案内の注記(muted の Card)は入れない。テーマの `components.section` 上書きは取り消し(theme/ は
main と同一に戻る)。検証: e2e 26 件、axe 24 態で違反 0。

**改訂 10(2026-09-05、所有者レビュー 10 回目 — 案 A / B の最終判断: 見出しは箱の外)**:

**S 改訂 2: 見出し・説明はページの content line、`Card` が包むのは集合だけ(案 B)**。所有者の理由 —
案 A では節の見出しが Card の border 1px + padding 16px ぶん右にずれ、Card に入れていない文字(h1・パンくず・
説明・概要の MetadataList)と開始位置が揃わない。文字の開始線がページで 2 本になるのが違和感。案 B なら文字の
開始線は 1 本で、右にずれるのは枠線のある箱の中身だけ(枠線が「ここから別のフレーム」と説明する)。エージェントの
評価も同じ(Vercel / GitHub の設定画面の形。案 A の利点「箱の意味が箱だけで完結する」は 1 ページが短い本
ダッシュボードでは効かない)。副次効果: Card が包むのが節でなく集合(表・監査行)になるので、Astryx の
「ページの節に Card を使わない」との距離が縮み、Card docs の「自己完結した部品の硬い境界」の用途に近づく。
実装: `SectionBlock` = VStack gap 4(SectionHeader + `Card padding={4}`〔VStack gap 4 の children〕)。
`title` 省略時は Card のみ。監査タブの説明文(規定文言)と軸切替(ToggleButtonGroup)は改訂 5 から箱の外に
あり(見出し行に相当)、変更なし。`Callout`(muted の Card)の inset は枠のある箱なので同じ原則の内側。
縦のリズム: 見出し → 箱 16px、箱 → 次の見出し 40px(節間 `SECTION_GAP`)の対比で見出しが前の箱に付いて
見えない。検証: `bun run check` 7 段通過、e2e 26 件、axe 24 態で違反 0、CSP 違反 0。

**改訂 11(2026-09-05、PR #148 Cursor Bugbot 指摘 — シェルが遷移ごとに再マウントされる)**:

**T: 認証が要る画面は pathless の親ルート(`DashboardLayout`)の子に置き、シェルを 1 回だけマウントする**。
指摘: 各画面が自前で `DashboardShell`(セッション状態 + AppShell + SideNav)を持つため、Projects →
プロジェクト → API tokens → Account audit の遷移のたびに AppShell / SideNav がアンマウントされ、
「Checking your session」の全画面フレームが出て `GET /auth/me` を再取得してから遷移先が描かれる。
サイドバーは据え置かれず(折りたたみ状態も消える)、認証済みの遷移が 1 往復とクロームの点滅を払う。
検証: 事実(routes は App.tsx で並列に bindRoute、DashboardShell は useSession を持つ)。
候補: (1) **入れ子ルート**(funstack-router の `children` + `Outlet` — docs の「サイドバーが残る
ダッシュボード」がまさにこの用途)/ (2) モジュール階層のセッションキャッシュ(再取得と
loading フレームは消えるが、AppShell / SideNav の DOM は遷移ごとに作り直され、折りたたみ状態が
消える)/ (3) 画面側で条件描画(docs が避けよという形)。→ **(1) を採用**。
実装: routes.ts に `dashboardShellRoute = route({ id: "dashboard-shell" })`(pathless — パス名を
消費しないので 4 つの葉ルートのパスは不変、SPA_ROUTES と spa-topology テストも不変。パスを
持たないので目録には載せない)。App.tsx で 4 ルートをその子に。`DashboardShell.tsx` は 2 層に:
`DashboardLayout`(親。useSession + AppShell + SideNav + `Outlet`)と `DashboardShell`(画面の
枠。Layout の header = 見出し、content = 本文)。サイドバーの現在地とプロジェクトの子項目は各画面が
`destination` / `project` で申告し、context(useState の setter)+ `useLayoutEffect` で親へ上げる
(描画前に反映し、遷移直後の 1 フレームに前の画面の選択が残らない)。
棄却: URL から導く `useLocation` — router の Location が `.hash` を持ち、SPA バンドルに語 "hash" が
入って AUTH_SPEC §15-3 の tripwire(write-headers.ts — 裁定 BG)に当たる(実際にビルドが落ちた)。
SSG の注意: router は URL 無しの SSR で pathless ルートを描くが、本プロジェクトの静的シェルは
`#app` にエントリ用の span しか出さず(クライアント木はビルド時に描かない)、影響しない。
副次: プロジェクト ID の形式判定(64 hex)を `ids.ts` の `isProjectId` に集約(DashboardScreen /
ProjectScreen の重複リテラルを解消)。e2e を 1 件追加: サイドバーから API tokens → Account audit へ
SPA 遷移し、`/auth/me` が 1 回のまま・「Checking your session」が出ない・サイドバーの DOM ノードが
同一(data 属性の印が残る)・aria-current が移ることを検査。見た目の変化なし(スクリーンショット
33 枚中 29 枚がバイト一致、残り 4 枚はダイアログの backdrop 等のアニメーション途中の差)。
検証: `bun run check` 7 段通過、e2e 27 件、axe 24 態で違反 0、CSP 違反 0。

同時に pullfrog(ready for review 後の再レビュー)の 3 件に対応: (a) 見出しの無い箱(一覧・監査・
rotation — ページ h1 の直下)の `EmptyNotice` が既定の h3 で h1 → h3 の飛びになっていた →
4 か所に `headingLevel={2}`(裁定 E-(c) の「節 h2 → 空状態 h3」は節見出しがある前提。無い箱では
h2)。(b) `test/screenshots.ts` の s8 が Revoke クリック後に dialog を待たず、注記も改訂 4 以前の
インライン 2 段階のまま → `alertdialog` の出現を待つ + 注記を更新(待つようにしたら s8 の
スクリーンショットが改訂 10 とバイト一致した — 以前は競合で揺れていた)。(c) vendored heroicons
(5 パス)に MIT のライセンス本文が同梱されていなかった → `src/dashboard/MIT-heroicons.txt`
(フォントの `public/fonts/OFL-*.txt` と同じく、写した資産の隣に置く)+ icons.tsx 冒頭に参照。
(d) レビュー本文の指摘「axe 24 態の証拠は非空の画面だけ」— fixtures は全件非空で、空状態と
FailureNotice の状態は一度も監査を通っていなかった(実際 (a) は空状態だけの違反)。
`test/screenshots.ts` に `empty` モード(各集合を空で返す mock)と空状態 7 画面(projects /
overview〔環境〕/ audit〔project・self〕/ rotation / invites / tokens × light / dark / mobile =
21 枚)を追加し、axe を同じ 7 画面 × light / mobile = 14 態で実行(違反 0。見出し階層: 見出しの
無い箱は h1 → h2、Environments の空状態は h1 → h2 → h3)。裁定 E の「違反 0」の範囲は
「fixtures の非空 24 態 + 空状態 14 態」と明示する。未監査: 変数名の空状態(環境はあるが変数が
無い — empty モードでは環境も空になるので描けない)と FailureNotice の各状態(Banner の単純な
構造で、次の候補)。pullfrog の再々レビューで「script は 6 態、裁定録は 14 態」の不一致を指摘され、
環境の空状態を script 側に足して(`/environments` と metadata pull も empty に従う)一致させた。(e) nit: ProjectScreen の
`Banner` import を先頭コメントの下へ、shared.tsx からの import を辞書順に。
(f) 入れ子ルート化の副作用(pullfrog 再々レビュー): 途中でセッションが失効して画面のフェッチが
401 を返しても、シェルは 1 回しか /auth/me を確認しないので「サインイン済み」から戻れず、
「Signed out」Banner の「Go to sign-in」(/dashboard への SPA 遷移)も同じシェルの子に着地して
Banner が繰り返す(改訂 10 までは遷移で再マウントされて再確認 → サインイン画面だった)。
候補: (1) **401 の通知経路**(`session-expiry.ts` の context — FailureNotice が 401 を描くときに
親へ知らせ、シェルがその場で signed-out へ落としてサインイン画面を描く)/ (2) 復帰リンクを
`hardNavigate`(フルリロード — 改訂 11 以前の挙動を明示的に再現)/ (3) 遷移ごとに /auth/me を
再確認(1 往復が戻る — 改訂 11 の目的に反する)。→ (1) を採用(最初の 401 に反応するだけで
往復は増えない。再読込も不要)。e2e を 1 件追加(/auth/tokens が 401 → 同じ URL のまま
サインイン画面 + 「You are signed out.」)。

**検証(2026-09-04)**: `bun run check` 7 段通過(fallow は `DashboardShell` の CRAP 指摘を部品分割で解消)。
web e2e 25 件通過(`/auth/me` モックの追随・軸切替の指し方変更込み)。`astryx doctor` 新規指摘なし。
React Doctor(diff)指摘なし。axe-core 18 態で違反 0。スクリーンショット 33 枚(PR 本文の Artifact)。

### DP4 実装時の裁定録(2026-09-05)

対象はスクリプトなしの儀式ページ 11 態: CLI ログインの承認 / 完了 / 拒否 / 一様エラー / サインアップ案内
(signupPolicy 3 種)、サインアップ制御の closed / invite-required / invite-invalid、`/invite`。各裁定点は
DP1〜DP3 と同じループ(案を 3 つ以上列挙 → 上位互換 / 銀の弾丸を探索 → 新案が出ない周が 1 回あれば終了 →
選定)で決めた。判断基準は、CSP `script-src 'none'` と meta / ヘッダーの二重化を崩さない・スタイルは自己配信の
外部 CSS のみ(`style-src 'self'`。inline のハッシュ許可を増やさない)・ブランド値を `apps/web/theme/` の外へ
複製しない(ADR-0013)・AUTH_SPEC の表示要件と一様性を 1 つも崩さない・配信物にプレビュー用コードを混ぜない・
後戻りが安いこと。

**前提の訂正(実装で判明した事実)**: (1) `theme/maruhi.css`(`astryx theme build` の生成物)のブランドトークン
(`--color-accent` / `--font-family-*` / `--radius-*` 等)は `:root` ではなく `@layer astryx-theme` の
`@scope ([data-astryx-theme="maruhi"])` 配下の `:scope` に定義される。`:root` にあるのはデータ可視化色だけ。
よってテーマを消費するページは `<html data-astryx-theme="maruhi">`(ダッシュボードのルートと同じ印)が要る。
(2) Workers Static Assets の既定の配信ヘッダーは `Cache-Control: public, max-age=0, must-revalidate` + ETag
(wrangler dev で実測。Cloudflare の既定と同じ)。ブラウザは毎回再検証するので、名前固定の CSS を差し替えても
デプロイ直後の読み込みで新版に切り替わる(裁定 G)。(3) 未設定サーバー(`.dev.vars` なしの wrangler dev = e2e)
でも `GET /auth/cli/verify?flow=…` は一様エラーページ(400 / HTML)を返すため、サーバー配信ページの実配信は
e2e からスタイル込みで検査できる(裁定 I)。(4) axe は変更前から存在した違反を 1 件見つけた: `/invite` の
`pre`(横スクロール)が 390px でキーボード到達不能(`scrollable-region-focusable`、serious)。

**A. CSS の置き場と配信** — 列挙: (i) `apps/web/public` の静的アセット(`/invite.css` と同じ経路。同一オリジン・
セルフホストでも同梱・`write-headers.ts` のバイト等価検査に載る)/ (ii) Worker のルートで CSS を配信(server が
自己完結するが、api-schema にスタイル用のエンドポイントが混ざり、`index.ts` の `no-store` も外す必要がある)/
(iii) インライン `<style>` + ハッシュ許可(不変条件で禁止)/ (iv) Worker が CSS をテキストモジュールとして
バンドルに埋めて配信(ii の変種。web と server の二重管理)/ (v) `/invite.css` と 1 ファイルに共通化する。
第 1 周の新案: **(i)+(v) = `apps/web/public/pages.css` を /invite とサーバー配信ページの共有スタイルにする**
(あり)。第 2 周: なし。**選定 = (i)+(v)**。server 側 HTML は `/pages.css` を参照するだけで、実配信の到達性・
content-type・ソースとの一致は web の e2e が combined 構成(本番と同じ `apps/server/wrangler.jsonc`)で固定する。
`vite.config.ts` の `PUBLIC_PASSTHROUGH` と `write-headers.ts` の等価検査を `invite.css` → `pages.css` に。
`_redirects` の `/invite.css` の盾(200 リライト)は不要になり撤去(66 → 65 本)。名前は「儀式」の内部語を
避けて `pages.css`(用途 = スクリプトなしページ全般)。棄却: (ii)(iv) は上記。(iii) は禁止。

**B. ブランドトークンの取り込み** — session-41 裁定 BB-b(無彩色のみ)を ROADMAP DP4「自己配信 CSS でブランドを
統一」(所有者裁定 2026-09-03)が上書きする前提で列挙: (i) 無彩色を維持し ㊙ とワードマークだけで示す(所有者
裁定に反する)/ (ii) hex を手で写す(ADR-0013 違反)/ (iii) `maruhi.css` から生成 + 乖離テスト(`apps/site` の
`scripts/theme.ts` 方式。生成スクリプト・生成物・抽出器の複製が要る)/ (iv) **`theme/maruhi.css` そのものを
無変換で `/theme.css` として同梱し、`pages.css` は `var(--…)` で読むだけにする**(生成物 = テーマファイル
そのもの。24 KB / gzip 4 KB を儀式ページ 1 回ごとに読む)/ (v) `@layer astryx-base` の `:root` ブロックだけ
ビルド時に抽出(小さい生成器がまた要り、前提の訂正 (1) により肝心のトークンはそこに無い)。第 1 周の新案: (iv)
(あり — (iii) の利点〔単一の正・乖離ゼロ〕を保ち、生成器と写しを消す)。第 2 周: なし。**選定 = (iv)**。
`write-headers.ts` がビルド後に `theme/maruhi.css` → `dist/public/theme.css` を複製し、バイト等価を検査する
(`pages.css` / `invite.html` と同じ契約)。ページは `data-astryx-theme="maruhi"` を `<html>` に持つ(前提の
訂正 (1))。付随: Astryx の `@layer reset`(`:where(h1…p, code)` の型設定)も同じスコープで効くが、layer の
中にあるため `pages.css` の unlayered 規則が常に勝つ — 儀式ページの型は `pages.css` だけ読めば分かる。
`--font-family-body` の先頭の Figtree は読み込まない(ダッシュボードと同じくシステムフォントへ落ちる —
§1-3)。棄却: (i)(ii)(v) は上記。(iii) は (iv) に含意される。

**C. 共通枠 `page()` の構造** — 列挙: (i) 現状(h1 = 「㊙ maruhi」、ページの題は h2)/ (ii) 文書型の 1 カラム
(40rem)+ ブランドヘッダー(見出しでない `header` = ロゴ + ワードマーク)+ **ページの題を h1 に**(旧 h2 → h1、
h3 → h2)/ (iii) `login` テンプレート型の中央カード(ダッシュボードのサインインと同形。案内ページのような
長文には向かず、モバイルでは結局全幅)/ (iv) `/invite` と同型(= 文書型)。第 1 周の新案: (ii)+(iv) を 1 つの
枠に統合し、`/invite` も同じ枠へ寄せる(あり)。第 2 周: なし。**選定 = (ii)+(iv)**。ロゴ: (a) 絵文字 ㊙ の
テキスト(現状)/ (b) **`<img src="/logo-inverted.svg">` + `img-src 'self'`**(DP3 裁定 J 改訂 3 と同じ実資産・
同じ朱固定)/ (c) インライン SVG の currentColor(パスの二重管理 — DP3 で棄却済み)/ (d) CSS の
background-image(同じく `img-src 'self'` が要り、代替テキストの制御が減る)→ **(b)**。CSP は meta と
ヘッダーの両方で `style-src 'self'; img-src 'self'` に広げ(`'unsafe-inline'`・ハッシュは無し)、`/invite` の
per-path CSP も同じ形にした。`<meta name="color-scheme">` を CSS 到着前のダーク描画のために置き、favicon の
`<link rel="icon">` を SPA と同じく載せる。

**D. 確認コードの視認性(フィッシングガードの UX)** — 文字集合の確認: `generateUserCode`(cli-flow.ts)は
Crockford Base32 の 32 字(I / L / O / U 除外)× 8 字を `XXXX-XXXX` で表示する。残る混同候補は 0 / D、8 / B、
5 / S、2 / Z。列挙: (i) システム等幅を大きく(2.5rem)・字間 0.14em・単独の要素に置く / (ii) 等幅フォントを
自己配信(§1-3 の「問題があれば足す」)/ (iii) `font-variant-numeric: slashed-zero`(フォントが `zero` 機能を
持つときだけ効く。無ければ何も起きない)/ (iv) 群ごとに `span` に分けて間隔を広げる / (v) 文字種を色で塗り分ける
(コードの一部を強調する形は「ここだけ見ればよい」と誤読させる)。第 1 周の新案: (i)+(iii)(あり — 自己配信
フォント無しで 0 / D の判別を得る)。第 2 周: なし。**選定 = (i)+(iii)**。実機(Linux Chromium: Liberation Mono /
DejaVu Sans Mono)では 0 が斜線付きで D と判別でき、8 / B・5 / S・2 / Z も判別できた(スクリーンショット)。
macOS の SF Mono / Menlo と Windows の Consolas は既定または `zero` で斜線 / 点付きの 0 を持つ。**自己配信の
等幅フォントは提案しない**(問題が出なかった。CLI 側の表示は DP5)。文言は「Approve only if this code matches
the one shown in your terminal.」を太字で維持し、コードは "Confirmation code" のラベル付きの面に置く。
**Approve / Deny の区別**: (a) Approve = accent 塗り + on-accent、Deny = 同サイズの outline、順序は Approve →
Deny / (b) Deny を先に置く(読み順で拒否が先に目に入るが、正当な利用のたびに逆順を踏ませる)/ (c) 両方
outline(区別が付かない)/ (d) Approve の前に「一致を確認した」チェックボックス(スクリプトなしで必須化は
`required` で可能だが、承認の資格はチケットであり、形だけの摩擦を増やす)→ **(a)**。テキスト入力欄が無いので
Enter の暗黙送信は起きず、焦点はどちらのボタンにも自動では当たらない。

**E. サインアップ案内・拒否ページの文言と構成(H6 の明示項目)** — 列挙: (i) 文言はそのままで見た目だけ /
(ii) **4 系統(closed / invite-required / invite-invalid / CLI からの案内 × signupPolicy 3 種)を同じ 3 段に揃える:
何が起きたか(h1 + 1 文)→ 何が起きていないか(`outcome` 行 = 左に accent の線)→ 次にできること(h2 + 箇条書き)**
/ (iii) closed と invite-required を 1 枚に(ポリシーは公開情報で、出し分けは失敗理由の出し分けではないので
分ける価値が残る)/ (iv) 理由を詳しく出す(§3 / §4-2 の一様性に反する — 禁止)。**選定 = (ii)**。拒否 3 枚の
outcome 行は「No account was created.」、CLI 案内は「Nothing has been created or changed by opening this
page.」、一様エラーと拒否完了は「No token was issued.」。一様性は不変(invite-invalid は無効 / 失効 / 消費済みを
出し分けず、エラーページはフロー状態を出し分けない)。waitlist の収集面は作らず「contact the operator of this
server」まで(hosted-design.md §2-2)。既存テストの断言は文言の変更に追随させただけ(`no account was\n
created` → `No account was created.`)。

**F. `/invite` の扱い** — 列挙: (i) `invite.css` を残して見た目だけ寄せる(2 つの CSS が同じ規則を持つ)/ (ii)
**共通枠(`/theme.css` + `/pages.css` + ブランドヘッダー)へ移し、独立静的アセットとしての構成(per-path CSP・
`write-headers.ts` の機械検査・near-miss の 301)はそのまま** / (iii) `/invite` をサーバー配信に移す(§15-3 の
「独立静的アセット」の構成そのものが変わる — 棄却)。**選定 = (ii)**。h1 は「You have been invited to a maruhi
project」(旧 h1 はブランド名)。`pre` に `tabindex="0"`(前提の訂正 (4) の修正 — 共有の焦点リングが付く)。
機械検査は `src="/logo-inverted.svg"`(ルート相対)を既存規則で通し、`img-src 'self'` を meta と per-path CSP の
両方に足した。e2e の「`/invite.css` が盾で素通しされる」断言は対象が無くなったため外し、`/invite` 自身の 200 だけ
を残した。

**G. CSS 更新の反映(キャッシュ)** — 列挙: (i) **何もしない**(前提の訂正 (2): 既定が毎回再検証)/ (ii) HTML 側で
`?v=<hash>` を付ける(server が web のビルドハッシュを知る経路が要る)/ (iii) コンテンツハッシュ名(名前が安定
せず、サーバー描画 HTML から参照できない — session-41 BB-c と同じ)/ (iv) `_headers` に明示の `cache-control`
(既定と同値を書くだけ)。**選定 = (i)** + e2e で `/theme.css` / `/pages.css` の `must-revalidate` と ETag を
固定(既定が変わったら気付く)。Worker 応答(`no-store`)の HTML が古い CSS を掴む窓は「デプロイ直後に
再検証が 304 を返す」ケースだけで、ETag は内容から計算されるため起きない。

**H. a11y** — 方法は DP3 裁定 E と同じ(axe-core を一回性で注入 — 依存を増やさない)。範囲: 11 ページ × light /
dark / 390px light / 390px dark = **44 態で違反 0**(wcag2a / 2aa / 21a / 21aa / best-practice)。見出し階層は
h1 = ページの題 → h2 = 節(What will be granted / What you can do / What to do next / Accept the invite)。
ランドマークは `header`(banner)→ `main`。焦点リングは accent 2px offset 2px(DP3 E-(e) と同じ見え方)。
コントラストはテーマ値(text-primary / secondary on body、on-accent on accent、accent のリンク)で、axe の
color-contrast 指摘なし。直したもの: `/invite` の `pre`(F)。

**I. 目視とスクリーンショットの方法** — 列挙: (i) **描画関数(`render*`)に固定入力を与えて HTML を書き出し、
`pages.css` / `theme.css` / ロゴと同一オリジンで配信して Chromium で撮る(scratchpad の一回性スクリプト。
配信物は触らない)**、`/invite` だけ実配信(wrangler dev)/ (ii) 実フロー(`POST /auth/cli/start` → verify →
GitHub OAuth)を通す(OAuth App が要る — 本セッションでは不能)/ (iii) 配信物にプレビュー用ルートやモック
データを入れる(禁止)。**選定 = (i)**。加えて e2e が実配信の一様エラーページ(前提の訂正 (3))を Chromium で
開き、`.page` の幅(40rem)・body の背景色(テーマの変数が解決されたこと)・ロゴの読込・CSP 違反 0・
script 要素 0 を検査する。before / after は 11 ページ × 4 態 = 各 44 枚(PR 本文の Artifact)。

**新たに出た裁定点**: (J) スタイルシートのパス定数 `PAGE_STYLESHEETS` を export していたが消費者が無く fallow
の dead export に当たった → 非公開に(参照先の到達性は e2e が担う)。(K) 承認ページの正常系テストに CSP /
スタイルの断言を足したら cyclomatic 13 で fallow の複雑度閾値に当たった → `expectStyledScriptFreePage` ヘルパー
に抽出(ヘッダー / meta の両 CSP で `style-src 'self'` / `img-src 'self'` / `'unsafe-inline'` なし / ハッシュ
なし、`<link>` 2 本、script / style 要素・style 属性なし)。(L) 承認ページの付与内容は `<ul>` から `<dl>`
(ラベル / 値。狭い幅では 1 列)に。tokenName は `<code>` の不活性描画のまま、補足「Chosen by the requester,
shown verbatim.」を `<small>` に分離。

**B 改訂 1(2026-09-05、pullfrog の初回レビュー — 未定義トークン)**: 指摘 = `pages.css` が参照する
`--font-weight-semibold` / `--font-weight-medium` は `theme/maruhi.css` では**参照されるだけで定義されず**
(定義は Astryx core の `astryx.css` にあり、ダッシュボードはそれを追加で読むが儀式ページは読まない)、
未解決の `var()` が invalid at computed-value time で無言に落ちて、h1 / h2 / `strong`(フィッシングガードの
一文)/ outcome 行の太字が全部消えていた。目視・axe・e2e のどれも捕まえられない欠陥(スクリーンショットは
同じ 2 本の CSS を配信するので同じ欠落を再現し、axe は太さを見ず、e2e は背景色しか見ていなかった)。
列挙: (i) `defineTheme` の `tokens` に `--font-weight-*` を足して `theme:build`(テーマは本 PR の範囲外 —
触るなら所有者確認)/ (ii) `pages.css` に数値(600 / 500)を書く(Astryx の値の写し)/ (iii) **CSS の
キーワード `bold` を使う**(h1 / h2 / `strong` は UA 既定が bold なので宣言を置き換えるだけ、brand と
outcome 行も `bold`。`.code-label` と `.button` の medium は落とす — 大文字 + 字間 / 塗りで足りる)/ (iv)
`var(--font-weight-semibold, bold)` のフォールバック(後述の機械検査が「未定義だが許容」の例外を持つことに
なる)/ (v) Astryx core の stylesheet も同梱(数十 KB・儀式ページに不要な規則)。第 1 周の新案: 「参照集合 ⊆
定義集合」を `write-headers.ts` でビルド時に検査する(あり — 方式の如何に依らず同種の欠陥を構成で塞ぐ)。
第 2 周: なし。**選定 = (iii) + 機械検査**。テーマに `tokens` を足す (i) は所有者の判断として PR に残す
(semibold 600 を儀式ページで使うなら `maruhi.ts` への追加が正で、その時は `pages.css` を `var()` に戻す)。
検査は `pages.css` の `var(--…)` を集め、`theme/maruhi.css` の `--…:` 定義集合との差が空でなければ throw
(旧 `pages.css` に当てると 2 件を検出、新版は 0 件)。e2e に h1 / outcome 行の `font-weight` = 700 を追加。
同じレビューで「`theme.css` のバイト等価検査は同じスクリプトが直前に書いた 2 ファイルを比べるだけで
常に一致する(担保になっていない)」も受け、等価検査の対象から `theme.css` を外し(`invite.html` /
`pages.css` は vite の publicDir コピーを経由するので意味がある)、`/theme.css` の契約は上のトークン解決
検査が担う形に改めた。
**改訂 1 の追補(pullfrog 再レビュー)**: 検査が名前の存在しか見ておらず、「定義はあるが値が Astryx core の
トークンを `var()` で参照する」もの(`theme/maruhi.css` に `--text-heading-1-weight: var(--font-weight-semibold)`
等が 16 種以上)を `pages.css` が使うと通ってしまう穴を指摘された → 定義を `Map<名前, 値>` で持ち、値の
`var()` を再帰的に辿って未定義に当たったら経路つきで落とす形に(合成 CSS `var(--text-heading-1-weight)` で
`--text-heading-1-weight -> --font-weight-semibold` を検出することを確認)。

**検証(2026-09-05)**: `bun run check` 7 段通過(fallow は `FALLOW_AUDIT_BASE=origin/main`)。サーバーの
auth / signup-policy テスト 87 件通過。web e2e 30 件通過(`/theme.css` `/pages.css` の実配信・バイト一致・
再検証ヘッダー、一様エラーページのスタイル適用と太さを追加)。axe 44 態で違反 0。スクリーンショット
before / after 各 44 枚(改訂 1 後に撮り直し)、CSP 違反 0。

## 6. スコープ外

- 手動ダークトグル・**ダッシュボード(TCB)側の** Web フォント自己配信(必要になったら再訪 — §1-2 / §1-3)
- `maruhi ui`(ADR-0018 第 2 段)・値あり UI(第 3 段)
- 課金ページ・ステータスページ(H4 / GA)
