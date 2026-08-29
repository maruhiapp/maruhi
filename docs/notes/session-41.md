# セッション 41: W1 — 静的縮小形(/invite + per-path CSP)の実装裁定(BA〜BH)

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
- **残余(pullfrog レビュー指摘の記録 → 裁定 BF で大部分を解消)**: 上の保証は
  正規 URL とその正規化対象(`/invite.html`・`/invite/`・パーセントエンコード)に
  限られ、**near-miss パス(`/Invite`・`/INVITE`・`/invite/x` 等)はアセット
  キーに一致せず SPA フォールバックに落ちていた**(ブートストラップ script +
  `/*` CSP のシェルが 200 — 実測)。当初は W1 で受容・W2 へ申し送りとしたが、
  上位互換探索(所有者依頼)で `_redirects` による正規化(裁定 BF)を見出し、
  **大小変種 × 末尾続きのクラス全体を構成で閉じた**。残るのは生成源のない
  自由打鍵タイポ(`/invte` 等)のみで、これは任意の 404 パスと同じ扱い
  (SPA に `location.hash` を読むコードは無い)。`not_found_handling` 自体の
  設計判断は引き続き W2 の裁定に残る
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
- **申し送り(pullfrog レビュー指摘の記録 → 裁定 BE で非荷重化)**: Cloudflare
  ドキュメントは Workers Static Assets での `_headers`・`!` デタッチ構文・
  広いルールからのヘッダー継承までは明記するが、「同一ブロック内でデタッチ
  直後に同名ヘッダーを再宣言する」本パターンと wrangler dev / production の
  挙動一致は記述がない。当初これは「production で再宣言が落ちると CSP ヘッダー
  1 枚を失う」荷重付きの申し送りだったが、上位互換探索で **meta CSP の
  アセット内蔵(裁定 BE)**を追加し、ヘッダー層の挙動差から独立にスクリプト
  実行ゼロが強制されるようになった。初回デプロイ後の `/invite` 実応答ヘッダー
  確認は**確認として推奨のまま残す**が、不変条件の成立はそれに依存しない
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

## 5. 裁定 BE: meta CSP のアセット内蔵(強制の配信層非依存化 — 上位互換探索)

初版 PR(61d4a4d..b05616e)後の所有者依頼「銀の弾丸・上位互換の模索」による
追加探索。標的は裁定 BC の申し送り(`!` デタッチの production 挙動が
ドキュメント未記載 = ヘッダー層の強制が実測 1 点に依存する)。

### 第 1 周

- **案 BE-a: 現状維持(_headers のみ + デプロイ後確認)** — 強制がヘッダー層の
  1 経路に集中し、その経路の production 挙動が未文書。確認タスクは人間依存
- **案 BE-b: デタッチをやめ additive(CSP 2 本併記)に戻す** — 棄却: 2 本とも
  強制される(交差)ので安全側だが、「複数マッチルールの同名ヘッダーの併記」も
  同様にドキュメント未記載であり、不確実性の除去にならない。可読性だけ失う
- **案 BE-c: `<meta http-equiv="Content-Security-Policy">` を invite.html 自体に
  埋め込む** — 強制が**配信バイトと一緒に運ばれ**、`_headers` の解釈系
  (デタッチ・ルールマッチング・dev/prod 差)から完全に独立する。複数 CSP は
  交差で全ポリシー強制(CSP 仕様)なのでヘッダー CSP との併存は安全

### 第 2 周(上位互換探索)

- BE-c の制約確認: meta CSP は `frame-ancestors` / `report-uri` / `sandbox` を
  指定できない(CSP 仕様)→ **frame-ancestors だけは _headers 側が単独で担う**
  役割分担とする。meta の内容はそれ以外の全ディレクティブ
  (`default-src 'none'; script-src 'none'; style-src 'self'; base-uri 'none';
  form-action 'none'`)
- 固定検査への組み込み: ビルド時検査に「meta CSP が存在し `script-src 'none'` を
  含む」を追加、e2e に配信ボディの meta 存在アサーションを追加。**強制の 3 層**
  (①静的バイトに script ゼロ〔ビルド検査〕→ ②meta CSP〔アセット内蔵・
  ブラウザ強制〕→ ③per-path ヘッダー CSP〔配信層〕)が互いに独立の失敗モードを
  持つ形になる

### 第 3 周(再点検)

- meta CSP がページ自身の資源を壊さないこと: スタイルシートは `style-src 'self'`
  で許可(e2e のスタイル適用アサーションが回帰検査)。ページに script は無いので
  ブロック対象も violation も発生しない(e2e の violation ゼロで確認)
- パーサー挙動: meta CSP は出現位置以降に効くため `<head>` 先頭
  (charset 直後)に置く。ページは自前 script ゼロが別層で保証されており、
  「meta より前に script が挿入される」ケースはビルド検査が先に落とす
- 裁定 BC(デタッチ + 全置換)は不変。BC の申し送り(デプロイ後確認)は
  非荷重の推奨へ降格(§3 第 3 周に反映)

**選択: 案 BE-c(meta CSP 内蔵 + 検査 2 層への追加)**。

## 6. 裁定 BF: near-miss パスの `_redirects` 正規化(残余クラスの閉包 — 上位互換探索)

標的は裁定 BA の残余(`/Invite` 等の near-miss が script を持つ SPA シェルに
落ちる — pullfrog 指摘で W2 送りにしていたもの)。

### 第 1 周

- **案 BF-a: 現状維持(W2 送り)** — 残余は「規約で無害」のまま
- **案 BF-b: `not_found_handling` の変更(SPA フォールバック廃止)** — 棄却:
  `/about` 等の SPA 深リンクの成立が SPA フォールバックに依存しており
  (funstack-static はルートごとの静的 HTML を出さない)、W1 の縮小形の範囲を
  超える設計判断。W2 の裁定対象のまま
- **案 BF-c: web アプリに Worker スクリプトを足してパス正規化** — 棄却:
  現行 web は素の静的配信(Worker コードゼロ)であり、配信面に実行コードを
  足すのは ADR-0018「運営の配信面の最小化」と逆向き
- **案 BF-d: `_redirects`(Workers Static Assets が Pages 形式をサポート)で
  near-miss を `/invite` へ 301 正規化** — 静的宣言のみ・実行コードなし。
  フラグメントはブラウザがリダイレクト越しに保持するため、正規化後の
  `/invite`(script ゼロ)で案内が成立する

### 第 2 周(上位互換探索 — 実測駆動)

- wrangler dev 実測: `_redirects` は実効。マッチは**大文字小文字を区別**
  (`/Invite` のリテラルルールは `/INVITE` に効かない)→ 大小変種は列挙が要る
- 完全一致 + `/変種/*` の 2 形 × 64 変種 = 127 本を試行 → **全ルールが動的扱いで
  上限 100 本**(wrangler が「Maximum number of dynamic rules supported is 100.
  Skipping remaining 28 lines」で 101 本目以降を黙って落とす — 実測)。
  Pages の「静的 2000 + 動的 100」の区分はここでは効かない
- **圧縮形 `/{Variant}* /invite 301`(末尾スプラットを変種名に直結)**を実測:
  `/Invite`・`/Invite/x`・`/InviteXYZ` をまとめて捕捉 → **1 変種 1 本 = 64 本**で
  上限内。小文字だけは `/invite*` にすると正規パス自身(ループ)と
  `/invite.css`(スタイル破壊)に一致して事故るため `/invite/*` に限定

### 第 3 周(再点検)

- 閉じたクラス: 大小変種(2^6 = 64)× 末尾続き(`/x`・`XYZ`・`/` を含む)。
  系統的な生成源(モバイルの自動大文字化・貼り付け時の末尾ゴミ)を全て含む
- 残る残余: 生成源のない自由打鍵タイポ(`/invte` 等)。これは「無効な URL」で
  あり、任意の 404 パスが SPA シェルに落ちるのと同じクラス(SPA に
  `location.hash` を読むコードは無い)。フラグメント付きで踏む生成源が無い
- 既存挙動への影響: `/invite/` は従来の auto-trailing-slash(307)より
  `_redirects`(301)が先に効くようになる — 行き先は同じ `/invite`。
  `/invite.html` は 307 のまま。e2e の期待値を追随
- ルールは write-headers.ts が機械生成し、読み戻し検査(`/invite/*` と
  `/Invite*` の実在)+ e2e(7 near-miss 代表の 301 と Location)で固定

**選択(初版 78a2c50): 案 BF-d(圧縮形 64 本の機械生成)**。

### 第 4 周(pullfrog 指摘による改訂 — 200 リライトの盾)

- **第 3 周の生成源分析の誤りの訂正(pullfrog 実測指摘)**: 「貼り付け時の
  末尾ゴミ」は**小文字パス**(`/inviteXYZ`)に落ちる — 招待リンクは機械生成で
  常に小文字だからだ。初版 BF-d は小文字を `/invite/*` に限定していたため、
  **挙げていた生成源のうち最有力のものが残余側に残っていた**(記述と被覆の
  不一致。実測: `/inviteXYZ` → 200・SPA シェル)
- **改訂: 先勝ちマッチを利用した 200 リライトの盾** — pullfrog 提案・双方で
  実測確認。① `/invite /invite 200`・`/invite.css /invite.css 200`(自分自身への
  リライト = 素通し)を前置 → ② 大小変種 63 本 `/{Variant}*` → ③ 小文字総取り
  `/invite* /invite 301` を最後に。計 66 本(上限 100 の内、wrangler 全数
  parse)。初版が `/invite*` を掘下した理由 2 つ(自己ループ・`/invite.css`
  誤爆)が盾で両方消え、小文字 + 末尾続きも閉じる
- 実測(このビルド + wrangler dev): `/invite` = 200・**リライト後も per-path
  CSP 維持**・script ゼロ、`/invite.css` = 200 本文正常、`/inviteXYZ`・
  `/invite.html`(従来 307)・`/invite/`・`/invite/x`・大小変種 → すべて
  301 → `/invite`
- **新しい失敗モードの分析**: production で「盾だけ落ちて ③ が残る」と
  `/invite` が自己リダイレクトループになる(**可用性の喪失** — 秘匿・不変条件
  〔script 実行ゼロ〕には影響しない。開けば即分かり、`_redirects` 撤去で復旧)。
  wrangler dev と production の Workers Static Assets は同一のアセットワーカー
  実装(二重実装ではない)であり、選択的欠落を予期する根拠は無いが、
  デプロイ後確認(BC/BE の推奨)の確認対象に `/invite` が 200 で返ることを含める
- **ドキュメント裏取り(pullfrog 再レビューでの確認)**: Workers Static Assets
  (Pages ではなく)の公式 Redirects ドキュメントが、200 ステータスの
  proxy/rewrite ルールを正式機能として記載し、マッチ順も「同一 source への
  複数ルールは最上段が適用される」(先勝ち)と明記している(上限 = 静的
  2,000 + 動的 100)。盾の設計が依存する 2 性質(200 の受理・先勝ち)は実測 +
  ドキュメントの両方で裏付けられ、失敗モードの構造的不確かさは dev/prod
  パリティの一点に狭まった
- 固定検査の追随: 読み戻し検査に盾 2 本 + 総取りの実在と**順序**(盾が総取り
  より前 — ループ安全性の順序不変条件)を追加。e2e は 301 代表 9 パス +
  盾の素通し(`/invite`・`/invite.css` が 3xx でないこと)を固定
- 残余(最終): 語中タイポ(`/invte` 等)のみ = 任意の 404 パスと同じクラス

**選択(改訂): BF-d + 200 リライトの盾(66 本)**。

## 7. 裁定 BG: SPA バンドルのフラグメント非読取検査(最後の規約の検査化 — 第 2 次上位互換探索)

所有者依頼の第 2 次探索(BE・BF 実装後)。標的は最後に残った「規約どまり」の
保証 — 語中タイポ(`/invte` 等)が SPA シェルに落ちたときの無害性の根拠
「SPA に `location.hash` を読むコードは無い」が目視確認に依存している点。

### 第 1 周

- **案 BG-a: 現状維持(目視 + 設計上の事実)** — funstack-router は Navigation
  API ベースでハッシュを使わないが、将来のドリフト(機能追加でフラグメント
  読取が紛れ込む)を止める機構がない
- **案 BG-b: e2e で `location` を Proxy 化しハッシュ読取を実行時検出** — 棄却:
  検査できるのは e2e が踏んだコードパスのみ(部分被覆)。静的全量検査に劣る
- **案 BG-c: ビルド出力の全 JS + index.html への字面検査** — 実測: 現行バンドル
  (5 JS + インラインブートストラップ)に `.hash` メンバアクセス・分割代入
  `{hash}`・`["hash"]`・bare 識別子 `hash` は **0 件**(`location` 自体は 27 箇所
  — pathname / href 系のみ)。語 `hash` の全面禁止が誤検知ゼロで張れる

### 第 2 周(上位互換探索 — 検査強度の上限を実測で探る)

- **`location.href.split("#")` 型の回避も塞げるか**: bare `#` 文字列リテラルの
  全面禁止を試行 → **誤検知で棄却**(正当用途が実在: Astryx 色パーサの
  `startsWith(\`#\`)`・Intl 数値パターンの `#` 判定)。抽出イディオム限定
  (`split|indexOf|lastIndexOf` + `#` リテラル)に絞る版も試行 → **これも誤検知で
  棄却**(RSC ランタイムがモジュール参照 `"path#export"` を `lastIndexOf(\`#\`)` +
  `slice` で分割している — location と無関係の正当用途)。`#` 系の字面検査は
  正当用途と原理的に区別できない
- 確定形: **語 `hash`(大小無視)の全面禁止のみ**。フラグメントを読む意図の
  ある自然なコードは `location.hash` を書く — ドリフトの全字面形を被覆する。
  `href` 手動パース・難読化(`charCodeAt(35)` 等)は検知対象外と明記する
  (対象はドリフトであり、悪意あるコード挿入はレビュー・供給網の領分)

### 第 3 周(再点検)

- 持続可能性: funstack-router はハッシュルーティングを持たず、アンカーリンク
  (`#section`)は JS を要さないため、正当な `hash` 利用が入る見込みは低い。
  入る場合は検査が落ちて明示的な裁定を強制する — 既存の「インライン script は
  厳密に 1 本」検査と同じ「上流変化で意図的に割れる」型
- 検査対象は `dist/public/index.html` + `dist/public/assets/*.js`(配信される
  実行可能コードの全量。RSC ペイロード .txt はデータであり対象外)
- 効果の整理: これで「招待トークン(フラグメント)を読める字面が配信物の
  どこにも存在しない」が全パス(near-miss 正規化から漏れる語中タイポ含む)に
  ついて検査可能になり、§15-3 の「Web 受諾画面への漂流を構造的に断つ」が
  SPA バンドル側にも及ぶ

**選択: 案 BG-c(語 `hash` 全面禁止・`#` 系は棄却)**。

## 8. 裁定 BH: 既定依存の明示化と複製忠実性(第 2 次上位互換探索・小粒 2 件)

### html_handling の明示ピン

- `/invite` → `invite.html` の解決は wrangler `assets.html_handling` の**既定値**
  (auto-trailing-slash)に暗黙依存していた(既定が変わると `/invite` が SPA
  フォールバックに落ちる — e2e は検知するが構成としては既定依存)。スキーマ
  確認の上、`wrangler.jsonc` に明示ピンを追加
- **上位互換候補の実測棄却**: 盾ルールを `/invite /invite.html 200`(実ファイル
  への直接リライト)にすれば html_handling 依存自体が消えるという仮説を試行 →
  **リライト先が html_handling に再処理され 307 → `/invite` の無限ループ**に
  なることを実測で確認し棄却。盾は `/invite /invite 200` のまま + 明示ピンが正解

### 複製忠実性のバイト等価検査

- 「vite publicDir は無変換コピー」(裁定 BA 第 3 周の前提)を
  `public/invite.{html,css}` ↔ `dist/public/invite.{html,css}` のバイト等価と
  してビルド検査に固定。将来のビルドプラグインが HTML/CSS を変換し始めた
  場合に最速で検知する(「配信物 = レビューした字面」の直接性の保証)

**選択: 明示ピン + バイト等価検査(リライト直付け案は実測棄却)**。

## 9. 実施記録

- `apps/web/public/invite.html` + `invite.css` — SPA 外の独立静的アセット
  (BA-b・BB-b)。文言は英語(ADR-0017)・ブランド表記は小文字 maruhi。
  `noindex`(招待着地ページを索引させない)。meta CSP 内蔵(BE-c)
- `apps/web/scripts/write-headers.ts` — /invite の検査(BD-a + BE の meta 検査)+
  per-path CSP(BC-b)+ `_redirects` 生成・読み戻し検査(BF-d)+ バンドルの語 `hash` 検査・複製忠実性検査(BG・BH)。既存 `/*` の
  CSP・ヘッダーは文字列不変
- `apps/web/test/e2e.test.ts` — /invite の 3 テスト追加(BD-b): per-path CSP の
  実効・near-miss 正規化(BF の 7 代表パス)・実描画 script ゼロ + スタイル
  適用 + violation ゼロ + meta CSP 存在
- `apps/web/src/pages/HomePage.tsx` — S1 の最小整理(タグライン + CLI 導入導線。
  e2e の機構検証フックは維持。本格ポリッシュは W2 以降)
- スコープ外の確認: サーバー・api-schema・CLI・packages/crypto に変更なし。
  仕様・ADR の文言変更なし(実装のみ)
