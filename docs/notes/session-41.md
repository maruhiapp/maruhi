# セッション 41: W1 — 静的縮小形(/invite + per-path CSP)の実装裁定(BA〜BD)

日付: 2026-08-29。目的: PR-W1(web-dashboard-design.md §7)の実装上の裁定の記録。
規範 = AUTH_SPEC §15-3(招待リンク着地点 = 完全静的・フラグメント非解釈 —
PR #103 マージ = 所有者承認済み)と ADR-0018 改訂 2・5 項。本文書が裁定するのは
仕様が実装へ委ねた具体化(配信の形・per-path CSP の書き方・静的ページの styling・
固定検査の形)のみ。各裁定は「複数案 → 上位互換探索 → 3 周比較 → 自律選択」
(session-27 §14 の様式。記号は session-40 の AZ の続きで BA〜)。

前提資料: AUTH_SPEC §15-3、ADR-0018 改訂 2(5 項)、web-dashboard-design.md
§2〜§3(S1・S2)・§7、session-39(裁定 AR・§10-2)、ADR-0013 / ADR-0017、
apps/web/scripts/write-headers.ts(spike-a の CSP 生成)。

## 1. 裁定 BA: 配信の形(/invite をどのアセットとして置くか)

### 第 1 周

- **案 BA-a: SPA のルートとして追加**(`App.tsx` の `route({ path: "/invite" })`)—
  棄却: funstack バンドルのインラインブートストラップ script がページに載り、
  「スクリプトを一切持たない」が規約どまりになる(session-39 §10-2 が明示的に
  棄却した形。規範違反)
- **案 BA-b: vite `publicDir`(`apps/web/public/invite.html`)に置く** — vite が
  `dist/public/` へ無変換コピーし、Workers Static Assets が配信する。ソースが
  リポジトリにそのままレビュー可能な形で住む
- **案 BA-c: ビルド後スクリプトで HTML を生成**(write-headers.ts の同類)—
  棄却: 生成コード経由では「配信物 = レビューした字面」の直接性が失われ、
  生成ロジック自体が script 混入の新しい経路になる。テンプレートに載せる
  動的値も存在しない(完全静的)ため、生成の利点がゼロ

### 第 2 周(上位互換探索)

- **BA-b の配置内比較: `invite.html` vs `invite/index.html`** — Workers Static
  Assets の `html_handling` 既定(auto-trailing-slash)では `invite.html` の
  正規 URL が `/invite`(§15-3 のリンク形式と厳密一致)、`invite/index.html` は
  `/invite/` が正規になり `/invite` がリダイレクトされる。後者はリンク形式との
  不一致(表示 URL が変わる)なので **`invite.html`** 一択
- 実測(wrangler dev): `/invite` = 200 直接応答、`/invite.html`・`/invite/` は
  `/invite` へ 307 正規化(フラグメントはブラウザがリダイレクト越しに保持)。
  この挙動は e2e で固定した(裁定 BD)

### 第 3 周(再点検)

- SPA フォールバック(`not_found_handling: single-page-application`)との共存:
  実在アセットはフォールバックより優先されるため、`/invite` が SPA に飲まれる
  経路はない。SPA 側ルート定義にも `/invite` を追加しない(クライアント遷移の
  導線を作らない)
- vite `publicDir` のコピーは無変換(ビルドで script が注入されない)ことを
  実測で確認。ただし検査(BD)は将来のビルド変化に備えソースでなく
  **ビルド出力**に対して行う

**選択: 案 BA-b(`public/invite.html` → 正規 URL `/invite`)**。

## 2. 裁定 BB: 静的ページの styling(ADR-0013・`'unsafe-inline'` 禁止との整合)

### 第 1 周

- **案 BB-a: インライン `<style>` + per-path CSP でハッシュ許可** — 棄却:
  ハッシュ計算の機構(write-headers.ts の script ハッシュと同類)を style にも
  増やす対価が、単一ファイル化という美観だけ。CSP の例外面(許可ハッシュ)を
  増やす方向は CLAUDE.md の厳格 CSP の精神と逆向き
- **案 BB-b: 独立静的 CSS(`public/invite.css`、`style-src 'self'`)** —
  自己配信・例外なし。既存 `/*` の `style-src 'self'` と同じ形
- **案 BB-c: SPA のビルド済み CSS(Astryx/theme)を参照** — 棄却: ビルド出力の
  CSS はコンテンツハッシュ付きファイル名で、静的 HTML から安定参照できない。
  ハッシュなし複製を置くと theme の二重管理になる

### 第 2 周(上位互換探索)

- **BB-b のブランド色の扱い**: theme の導出アクセント(`--color-accent` =
  #b22a2b/#ffb3a8 系)を invite.css へ写す案を検討し、棄却 — ADR-0013 の
  「ブランド定義は `apps/web/theme/` が唯一の置き場所」に反する複製になり、
  theme 更新で乖離する。**無彩色 + システム既定色(`color-scheme: light dark` +
  `light-dark()`)のみ**とし、ブランド表現は ㊙ とワードマーク(テキスト)に
  限定する。ADR-0013 の生 hex 禁止は StyleX/xstyle の規律だが、その趣旨
  (ブランド値の散逸防止)を静的ページにも「ブランド値を持ち込まない」形で守る

### 第 3 周(再点検)

- ADR-0013 の適用範囲の確認: 同 ADR は Astryx SPA の styling 規律であり、
  SPA 外の静的ページは対象外(oxlint の className 禁止も JSX 対象)。ただし
  「外部 CSS を持ち込まない」(第三者 CSS)・全アセット自己配信は当然に適用され、
  invite.css は自作・自己配信で適合
- `'unsafe-inline'` 不使用(style も inline なし)、インライン `style` 属性なし

**選択: 案 BB-b(無彩色の独立 invite.css、`style-src 'self'`)**。

## 3. 裁定 BC: per-path CSP の書き方(_headers 上の表現)

### 第 1 周

- **案 BC-a: `/invite` ブロックで CSP を追加(デタッチなし)** — 棄却:
  Workers Static Assets の `_headers` は複数マッチルールのヘッダーを併記する。
  CSP 2 本はどちらも強制され(交差 = 実効 script-src 'none')安全側だが、
  「/invite の実効ポリシー」が 1 箇所で読めず、SPA 側ハッシュの変動が /invite の
  応答ヘッダーに漏れ続ける
- **案 BC-b: `! Content-Security-Policy` でデタッチしてから全置換** — /invite の
  ポリシーが 1 本の自己完結した宣言になる。他のセキュリティヘッダー
  (nosniff / Referrer-Policy / HSTS)は `/*` からそのまま継承

### 第 2 周(上位互換探索)

- /invite ポリシーの中身: `default-src 'none'; script-src 'none'; style-src
  'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`。
  `script-src 'none'` は default-src で被覆されるが、規範(§15-3)の字面その
  ものであるため**明示する**(検査対象の文字列でもある)。`img-src` / `font-src` /
  `connect-src` はページが使わないため許可しない(`/*` より狭い)。
  `form-action 'none'`(フォームなし — `/*` の 'self' より狭い)

### 第 3 周(再点検)

- デタッチ構文の実挙動を wrangler dev で実測: `/invite` の応答 CSP は置換後の
  1 本のみ。e2e で「`'self' 'sha256-` を含まない」を固定し、デタッチが将来の
  wrangler で無効化されたら検知される(裁定 BD)
- 既存パスの退行なし: `/*` ブロックの文字列は不変(e2e の既存アサーションが
  `script-src 'self'` + ハッシュを固定済み)

**選択: 案 BC-b(デタッチ + 全置換)**。

## 4. 裁定 BD: 固定検査の形(不変条件の機械検査)

### 第 1 周

- **案 BD-a: ビルド後スクリプト(write-headers.ts 内)での検査のみ** — ビルド
  出力の invite.html(配信バイト)に対し script ゼロ・インラインハンドラなし・
  `javascript:` なし・外部リソース参照なし(ナビゲーション `<a href>` の
  自リポジトリ GitHub のみ許可)を検査し、違反は throw = ビルド失敗。
  `_headers` は書き込み後の実ファイルを読み戻して `/invite` ブロックと
  `script-src 'none'` の存在を確認
- **案 BD-b: e2e テストのみ** — wrangler dev の実配信に対し、応答ヘッダー
  (per-path CSP の実効)と応答ボディ(script ゼロ)、ブラウザ実描画での
  `document.scripts.length === 0`・CSP violation ゼロを検証
- **案 BD-c: 両方(採用)** — BD-a は最速の失敗(ビルド段階)と「_headers の
  最終成果物」の検査、BD-b は「配信系(html_handling・デタッチ)を通した実効」の
  検査で、守る層が異なる。CI では web ビルド(ステップ 8)→ web e2e(ステップ 9)の
  両方が品質ゲートの経路に載っている

### 第 2 周(上位互換探索)

- 検査強度の統一: 当初 BD-a は HTML コメントを除去してから script タグを探して
  いたが、e2e(配信バイト全体)と強度が揃わない。**コメント内の字面も含めて
  `<script` をゼロに保つ**側へ統一した(コメントは不活性だが、検査を弱める
  例外を 1 つも持たないほうが規則として単純で、grep でも同じ結論になる)

### 第 3 周(再点検)

- 検査はソースでなく**ビルド出力**に対して行う(BA 第 3 周 — コピー・変換の
  経路ごと検査)
- e2e はダミーフラグメント付き URL(§15-3 のリンク形式を模倣)で実描画し、
  フラグメントの有無が挙動に影響しない(解釈するコードが存在しない)ことを
  script ゼロで担保
- 検査の書き忘れ・将来の退行: write-headers.ts が `/invite` ブロックを書か
  なくなった場合は自身の読み戻し検査で落ち、書いても配信で効かない場合は
  e2e で落ちる。invite.html 自体が消えた場合は readFileSync がビルドを落とす

**選択: 案 BD-c(ビルド時検査 + e2e の二層)**。

## 5. 実施記録

- `apps/web/public/invite.html` + `invite.css` — SPA 外の独立静的アセット
  (BA-b・BB-b)。文言は英語(ADR-0017)・ブランド表記は小文字 maruhi。
  `noindex`(招待着地ページを索引させない)
- `apps/web/scripts/write-headers.ts` — /invite の検査(BD-a)+ per-path CSP
  (BC-b)。既存 `/*` の CSP・ヘッダーは文字列不変
- `apps/web/test/e2e.test.ts` — /invite の 3 テスト追加(BD-b): per-path CSP の
  実効・正規化リダイレクト・実描画 script ゼロ + スタイル適用 + violation ゼロ
- `apps/web/src/pages/HomePage.tsx` — S1 の最小整理(タグライン + CLI 導入導線。
  e2e の機構検証フックは維持。本格ポリッシュは W2 以降)
- スコープ外の確認: サーバー・api-schema・CLI・packages/crypto に変更なし。
  仕様・ADR の文言変更なし(実装のみ)
