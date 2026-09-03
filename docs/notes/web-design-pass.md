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
`tokens` で明示する(裁定 A)。§1-1「彩度を落とさない」はこの明示で満たす。

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
