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
