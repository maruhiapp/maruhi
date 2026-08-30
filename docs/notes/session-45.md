# セッション 45: W3b — 失効系画面(S8 招待管理・S9 トークン管理)の実装裁定(CN〜)

日付: 2026-08-30。対象 PR: PR-W3b(設計文書 §7 の 6 — **web のみ**。server / CLI /
crypto 変更なし、api-schema は既存 export の消費のみ)。W 系列の最終 PR で、
W3a(PR #108)の API を消費する。様式は従来どおり「複数案 → 上位互換探索 →
3 周比較 → 自律選択」(session-27 §14 の様式。記号は session-44 の CM から
継続して CN〜)。規範 = ADR-0018 改訂 2(発行系・警告消去・チェーン書き込みを
置かない/サーバー申告表示)・設計文書 §3 S8/S9・§4 表示規律・§5 可視性・
AUTH_SPEC §5 / §6(0.15-draft)/ §15-2。W2 の実装様式(session-43 裁定
BM〜BS・CC・CD)を引き継ぐ。

## 1. 裁定 CN: CSRF ヘッダー名の束縛形(session-44 §9 の申し送りの解消)

前提: W3a が `CSRF_HEADER_NAME` を api-schema(auth-middleware.ts)へ export
済みで、server 側は束縛済み。web(dashboard/api.ts)のリテラル
`"x-maruhi-csrf"` の束縛だけが残っている。制約は裁定 BR/CD —
「Effect / api-schema の実行コードをバンドル(= TCB)へ持ち込まない」の
機械検査(値 import のソーストリップワイヤ)と衝突しない形であること。

### 第 1 周(複数案)

- **CN-a(素朴な値 import + トリップワイヤの限定許可)**: api.ts を CD の
  除外リストへ載せる。棄却 — 定数 1 個のために api-schema の**モジュール
  グラフ**(index 経由で effect の Schema 実行コード一式)がバンドル候補に
  入り、排除が tree-shaking の挙動依存になる。「検査可能な構成」(BG/CD の
  姿勢)から「バンドラの最適化を信じる」への逆行で、W2 で最も重い不変条件に
  例外を穿つ対価が定数 1 個
- **CN-b(テスト側でのリテラル照合)**: バンドルは純粋なまま、unit テスト
  (テストプロセスは値 import 可 — 裁定 BV と同じ位置づけ)がリテラルを
  `CSRF_HEADER_NAME` と照合する。束縛の検出がテスト実行時まで遅延する
- **CN-c(型レベル束縛)**: `import type { CSRF_HEADER_NAME }`(値バインディング
  の type-only import — typeof 文脈でのみ使用可)+
  `const CSRF_HEADER = "x-maruhi-csrf" satisfies typeof CSRF_HEADER_NAME`。
  api-schema 側は const 宣言でリテラル型を持つため、値のリネームはコンパイル
  エラーで割れる。バンドル影響ゼロ・トリップワイヤ変更ゼロ(`import type` は
  CD の走査対象外)— 裁定 CC(403 reason の satisfies 束縛)と同型

### 第 2 周(上位互換探索)

- CN-c は CN-a(バンドル影響)・CN-b(検出時点)の双方の上位互換。さらに
  CN-b を**併用**する: unit テストは apiPost / apiDelete が**実際に送る**
  ヘッダー名を api-schema の実値と照合する(型束縛は「リテラル ↔ 正」、
  実送信照合は「送信 ↔ 正」— 相補であり同語反復でない)

### 第 3 周(再点検)

- CN-c の残余: api-schema 側が将来 `: string` の型注釈を付けると literal 型が
  消え、`satisfies string` は何でも通る(束縛の無音失効)。CN-b の実値照合が
  この劣化も検出する(型が広がっても値照合は具体値のまま)— 二層で閉じる
- **採用: CN-c(型束縛)+ CN-b(テストの実送信照合)**

## 2. 裁定 CO: 失効の誤操作対策(確認 UI の要否と形)

前提の非対称性: 招待の失効は再発行(CLI)で回復可能。S9 の自トークン失効は
**稼働中の CLI / CI を即 401 にする**(トークンの再発行は device flow =
ブラウザ承認つきで、無人環境の復旧は人手を要する — 裁定 CF/CK の供給手順)。

### 第 1 周(複数案)

- **CO-a(確認なし・1 クリック失効)**: 棄却 — 上の非対称性に加え、Astryx の
  設計指針も destructive アクションの無確認を明示的に避けている。undo は
  構造的に置けない(undo = 再発行 = 資格の生成で、ADR-0018 改訂 2 の境界の
  外)ため、事前確認が唯一の誤操作対策
- **CO-b(ブラウザ native `confirm()`)**: 棄却 — スレッドをブロックし、
  スタイル・文言の一貫性(ADR-0013 / 表示規律)から外れ、e2e もダイアログ
  ハンドラ依存になる
- **CO-c(インライン 2 段階確認)**: 行の Revoke クリックで武装(armed)し、
  同じ行に Confirm revoke(destructive)+ Cancel を出す。武装は常に 1 行のみ
  (別行の武装・Cancel で解除)。追加コンポーネントなし・全状態が DOM に
  可視で e2e が素直
- **CO-d(モーダルダイアログ)**: 棄却 — 対象の詳細は一覧行に既に見えて
  おり、フォーカストラップ込みの新表面を足す利得がない

### 第 2 周(上位互換探索)

- CO-c + **帰結の警告文**: S9 の確認行に「Revoking immediately signs out any
  CLI or CI still using this token」を添える(S8 は招待リンクが使えなくなる
  旨)。確認の意味を「もう 1 クリック」から「帰結の提示」へ引き上げる
- 失効後は一覧を再取得する(サーバー申告の状態を写す — 楽観更新でクライアント
  推測の状態を描かない。表示規律 §4 と同じ側)

### 第 3 周(再点検)

- 武装の自動タイムアウト解除は棄却(非決定的挙動はテスト不能性を足すだけ)。
  画面遷移・再読込で自然に解除される
- **採用: CO-c + 帰結の警告文 + 失効後のサーバー再取得**

## 3. 裁定 CP: S8 / S9 の画面配置・ルーティング

### 第 1 周(複数案)

- **CP-a(S8 = ProjectScreen の第 4 タブ・S9 = 独立ルート /dashboard/tokens)**:
  軸の一致 — S8 は project 軸(認可も project のチェーン role)なので
  project 画面のタブ、S9 は user 軸(本人のトークン)なので account 系の
  独立ルート。裁定 BO「タブはルート化しない」を踏襲
- **CP-b(S8 も独立ルート /dashboard/projects/:id/invites)**: 棄却 —
  ルート表面(near-miss クラス)の増加で、BO 第 2 周の決定の蒸し返し
- **CP-c(S9 を /dashboard/account のタブへ統合)**: 棄却 — W2 の監査読み取り
  画面に失効 mutation 面が混載され、画面単位の縮退可能性(設計文書 §2)が
  弱まる。W2 画面の改造も伴う
- **CP-d(S9 を /dashboard 直下のセクションへ)**: 棄却 — S4(一覧)への
  mutation 混載で同上

### 第 2 周(上位互換探索)

- タブ名 "Invites" は S6 監査タブ内の invites 軸(SegmentedControl)と語が
  重なるが、片方は管理(一覧・失効・発行案内)・片方は監査イベント履歴で、
  文脈(タブ直下 vs Audit タブ内の軸)が分ける。改名(例: "Invitations")は
  同じ語を画面の別階層で使い分けるだけで衝突の実体がない — そのまま
- /dashboard/tokens は既設の BZ スイープ(SPA ルート × run_worker_first の
  非交差)・CA(spaPaths ビルダー束縛)が自動被覆する

### 第 3 周(再点検)

- S8 タブは role で事前に隠さない(admin 未満は 403 の役割文言 — 裁定 BQ の
  invites 監査軸と同じ「事前判定をクライアントへ複製しない」)
- **採用: CP-a**

## 4. 裁定 CQ: S9 の期限表示 — 期限切れと null(session-44 §9 の宿題)

- **期限切れ(expiresAtMs が過去)**: "Expired" Token + 申告時刻の併記。
  過去判定はクライアント時計との比較だが、表示の主体は常にサーバー申告の
  expiresAtMs(§4 の様式)。S8 の招待期限(expiresAtMs — 非 null)にも同じ
  表示部品を使う(様式の一元化)
- **null(移行前の旧無期限行)**: AUTH_SPEC §6(裁定 CE-c′)により検証側は
  NULL を**期限切れとして扱う(fail-closed)**。よって表示も "Expired" +
  "no expiry recorded" の注記とする — 仕様が定める挙動の写しであり、
  クライアントの捏造ではない
- 棄却: null を "Never expires" と表示(CE-c′ 後は虚偽 — 移行前の旧意味論の
  復唱)/ null 行の非表示(棚卸し面の否定 — CE 第 3 周の「期限切れに気づく
  導線 = 一覧での可視化」と矛盾)

## 5. 付随の具体化(裁定記号なし — BP の様式の拡張)

- **410(InviteGone)の分類**: 失効 DELETE の消費で初めて 410 が web に届く
  (W2 の消費面には存在しなかった)。api.ts の分類へ `gone`(+ サーバー申告の
  reason)を追加し、文言は「The server reports this invitation as
  {reason}.」— unreachable への畳み込み(初版の挙動)は「サーバー申告の
  写し」の規律に反するため分類を広げる
- **404 文言の対象名詞**: BP の "The server reports no such project for your
  account." は project 面の文言。S8 失効(invitation)・S9(token)用に
  FailureNotice へ subject(project / invitation / token)を導入し、一様
  404 の意味(他人の・存在しないを区別しない)は変えずに名詞だけ替える —
  文言の一元化(BP)は維持
- **失効ボタンの表示条件**: S8 は status が pending | accepted の行のみ
  (サーバーの受理条件 — 期限切れ pending の掃除も可 — の写し。
  handlers-invites.ts の B1a 裁定)。S9 は全行(期限切れ行の掃除は指定失効が
  担う — CE 第 3 周)
- **新規ビルダーのパスパラメータは encodeURIComponent を通す**(inviteId /
  tokenId はサーバー発行の不透明 id で、projectId のような形式検査を UI 側に
  持たない — 敵対的サーバーの id がパスを踏み外しても可視の 404/405 に留める)

## 6. 実施記録

- **api 層**: `apiDelete`(DELETE + CSRF ヘッダー)を追加。CSRF ヘッダー名は
  CN のとおり type-only import + `satisfies typeof CSRF_HEADER_NAME` で型束縛
  (変異検証: リテラル改変で TS1360)。分類へ `gone`(410 + reason)を追加し、
  403/410 の reason 取り出しを 1 実装に統合(fallow の cyclomatic ≤ 4 規律に
  合わせ reason 系 kind を lookup 化)
- **endpoints.ts**: `invites` / `inviteRevoke` / `tokens` / `tokenRevoke` の
  4 ビルダー + 目録 4 面(BW スイープが機械検査 — サンプルパラメータに
  `:tokenId` / `:id` を追加)。新ビルダーのパスパラメータは §5 のとおり
  encodeURIComponent を通す
- **S8**: `InvitesTab.tsx` — ProjectScreen の第 4 タブ(CP)。status Token
  (Object.hasOwn 自衛 — RoleToken と同型)・invited/accepted by・
  ExpiryCell・RevokeControl(pending | accepted 行のみ — リテラルは
  `satisfies ReadonlyArray<InviteStatus>` で型束縛)。発行の静的案内
  (`maruhi invite create`)+ 失効の帰結の注記を常時表示
- **S9**: `TokensScreen.tsx` — 独立ルート `/dashboard/tokens`(CP。routes.ts の
  定数 + SPA_ROUTES + spaPaths.tokens — BZ/CA スイープが自動被覆)。
  name / prefix / scopes / last used(null = "never")/ ExpiryCell(CQ)/
  RevokeControl 全行。ダッシュボードヘッダーに "API tokens" 導線。
  createdAtMs 列は置かない(発行の来歴は Account audit — S6 本人軸 — の領分。
  幅の対価に届かない)
- **共有部品**: `use-api-resource.ts`(W2 の ProjectScreen 内フックの独立
  モジュール化 — 挙動不変)・`use-revocation.ts`(CO の状態機械。武装 1 行・
  完了後の再取得。**状態は一覧リソースの外に持つ** — 再取得中のアンマウントで
  失敗表示が消えない)・shared.tsx の `ExpiryCell` / `RevokeControl` /
  `FailureNotice` の subject(§5)+ gone 表示
- **テスト**: web unit 29 件(apiDelete の CSRF 実送信を api-schema の実値と
  照合 = CN 二層目・410 分類・目録スイープ追随・spa-topology 追随)。
  e2e 24 件(S8 失効成功 + 一覧更新 + DELETE/CSRF 実送信・410 文言・403 役割
  文言・S9 Expired ×2 + no expiry recorded + never 表示・失効 + 一覧更新・
  一様 404 の token 文言・/dashboard/tokens の CSP ヘッダー実在)。
  フィクスチャは全件 Schema 実検証(BV)に追加
- **既設スイープの堅牢化(実測で発見)**: CD の値 import トリップワイヤが
  **コメント中の語「import」から実 import 文の from 句までを 1 マッチに繋げて
  誤検知**した(api.ts の CN 注記コメントが最初の踏み抜き)。正規表現を行頭
  アンカー(`^import` + m フラグ)へ強化 — import 文はトップレベル宣言で行頭に
  現れる。変異検証: 実際の値 import への改変で従来どおり検知
- **既存テストの追随**: W2 e2e の監査 invites 軸クリックが管理タブ "Invites"
  (S8)と同語衝突 → SegmentedControl(radiogroup)側を role で指す形へ。
  S8 の e2e は Overview タブの消費面もモックする(実サーバーの 401 応答は
  ボディ未読のまま networkidle を妨げる — W2 テストが全面モックである理由の
  実測確認)
- スコープ外の確認: server / api-schema / CLI / packages/crypto に変更なし。
  発行 UI・生値表示・S10・rotation dismiss は作っていない。BG 検査(語
  `hash` 0 件)はバンドル拡大後も無変更で通過
- `bun run check` 全通過(2211 件)+ e2e 24 件通過

## 7. 実装後の上位互換探索(生成規則を変えた反復 — 収束まで)

session-43 §10〜§14 / session-44 §7〜§14 の既知の生成規則を順に適用した:

1. **機械可読な正の手書き複製探し**: 新設コードの棚卸しで 2 件を型束縛へ —
   CSRF リテラル(裁定 CN 本体)と `isRevocable` の status リテラル
   (`satisfies` — CC と同型)。残るリテラルはビルダー定義・テスト期待値
   (意図的 — session-43 §13 の棄却と同じ)のみ
2. **不変条件の連鎖歩査**(定義 → 消費 → ワイヤ → サーバー): 「発行系を
   置かない」はサーバーの能力制限(W2b — invites.issue が SESSION_ALLOWED 外)
   が強制し、web は消費コード自体を持たない。「生値・ハッシュ非表示」は
   W3a のスキーマ構造(列がない)+ S8 で tokenHashHex を表示しない選択。
   「CSRF on DELETE」は api 層の単一点 + 型束縛 + 実値照合 + e2e 実送信 ×2。
   規約頼みのリンクは検出されなかった
3. **裁定合成の盲点**: CN(型束縛)× CD(トリップワイヤ)の合成が
   **トリップワイヤ自身の誤検知**を顕在化させた(§6 — 行頭アンカーで解消。
   束縛を書けば書くほど語「import」がコメントに増える構造だった)。
   CO(完了後再取得)× 一覧リソースの状態管理の合成は「再取得中の
   アンマウントで失敗表示が消える」を生む — 状態の持ち上げで解消(§6)
4. **新不変条件の逆流**(「web に破壊系 mutation がある」を旧前提の記述へ):
   api.ts の「mutation はログアウトのみ」コメントを更新。設計文書 §6 の
   XSS 残余評価は失効系悪用を織り込み済み(改訂不要)。BP の 404 文言は
   project 名詞が前提だった → subject 分岐(§5)
5. **ライフサイクル観測者歩査**: 招待(pending → accepted → completed /
   revoked / 期限切れ)・トークン(発行 → 使用 → 期限切れ → 失効)の全状態が
   一覧に可視で、失効可能な状態にだけ操作が出る。トークンの失効は行の削除
   だが、来歴は Account audit(auth.token_revoked)が観測者として残る
6. **推奨手順の実演走査**: S9 の注記(失効 → CLI 再ログインで代替発行)は
   CK/CM の供給手順(`maruhi login --show-token`)へ接続する。S8 の注記
   (失効 → `maruhi invite create` で再発行)も行き止まりなし

### 受容した残余(記録)

- ForbiddenNotice の一般 403 文言は "in this project" を含む — S9(token 面)の
  一般 403 はセッション主体では発生しない(CG-b: insufficient-permission は
  トークン主体条件、セッションは session-not-allowed の専用文言)ため、
  発生し得ない経路の名詞不整合として受容
- ExpiryCell の Expired 判定はクライアント時計との比較(CQ に記録済み —
  表示の主体は常にサーバー申告の expiresAtMs)
- 410 の reason はサーバー申告の防御的 string を英文へ埋め込む(React の
  エスケープ + 表示のみ — 他のサーバー申告 string と同じクラス)

## 8. レビュー反映(PR #109)

- **Bugbot + pullfrog(同一指摘 — 正当として修正)**: 失効の in-flight 中に
  他行の arm / 同行の再 confirm が可能で、後着の完了が武装状態を上書きし
  失敗の帰属が別の失効に見える(重複 DELETE は成功済み失効に偽の 404/410
  バナーも出しうる)。裁定 CO の「武装は常に 1 行」を in-flight にも拡張:
  `useRevocation` に pendingRef ガード(実行中は arm / confirm を無視)+
  `RevokeControl` の `isLocked`(他行の Revoke ボタンを無効化 — 効かない
  ボタンを作らない)。変異検証 = e2e にゲート付き DELETE の回帰テスト
  (in-flight 中の他行 disabled → 完了後に再有効化)
- **pullfrog(GoneNotice の名詞固定)**: 410 文言の名詞も subject 経由へ
  (NOT_FOUND_DESCRIPTION と同じ選び方 — 裁定 BP の単一実装点の一貫性)
- **pullfrog(トリップワイヤの再 export 穴)**: `export { X } from` /
  `export * from` も同じ実行コードをバンドルへ引き込む —
  `^(?:import|export)\s+(?!type\b)` へ拡大(変異検証: 再 export 追加で検知)
- **pullfrog(nit — e2e のヘッダー観測キー)**: e2e の
  `headers()["x-maruhi-csrf"]` を `CSRF_HEADER_NAME` の値 import へ束縛
  (実リクエスト観測にも裁定 CN の二層目が効く形。テストプロセスのみ —
  BV と同じ位置づけ)
- **pullfrog 第 2 波(ロック回帰 e2e のロケータ)**: Playwright の name 照合は
  既定で部分一致 — in-flight 中は実行行の "Confirm revoke"(isLoading で無効)
  が DOM 順の先頭に立ち、`isLocked` を外してもテストが通っていた。
  `exact: true` で未武装行だけを指す形へ修正。教訓: **コンポーネント変異の
  検証は必ずビルド後に走らせる**(e2e は dist のバンドルを検証する — 初回の
  変異検証はソース改変のみでビルドを忘れ、偽の成功を見ていた。修正後は
  isLocked 除去 + 再ビルドでテスト失敗 → 復元で全通過を実測)

### 収束の見立て

既知の 6 生成規則を一巡し、新発見は「スイープ自身の誤検知」(規則 3 の
合成盲点)1 件に縮んだ — 発見の規模は session-44 の弧(ワイヤ面 → 挙動 →
案内)からさらに縮んでいる。W 系列の消費面はこれで閉じ、次の正の増加
(新しい画面・新しい API)まで、この規則空間からの発見は尽きたと判断する。
