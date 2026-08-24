# deepsec 残課題（2026-08-22 全体レビュー）

> **2026-08-24 追記**: 残り 18 レコード(17 論点)は、本追記を含む修正 PR で
> すべて実装済み。各論点の対応内容はコミット履歴(`fix …deepsec…`)と PR の
> 説明を参照。deepsec の再実行(再検証)は Cloud 環境に資格情報がないため
> 未実施 — ローカルでの再スキャンで close すること(「Cloud 作業時の規律」6)。


## 位置づけ

deepsec の生成データは `.deepsec/data/` 配下にあり、gitignore 対象なので Cloud
環境や別チャットには引き継がれない。この文書を、再検証済み finding の追跡用
ハンドオフとする。

- 対象: 116 ファイル
- `process` run: `20260822050846-d58d658d7e9901fe`
- `revalidate` run: `20260822054606-13d8b765ba4462b8`
- モデル: Claude Opus 5、thinking `medium`
- 再検証結果: true-positive 20、false-positive 3
- 2026-08-24 時点: 空 `claimConstraints` の重複 2 レコードを実装修正済み
- 残り: true-positive **18 レコード、17 論点**
  - MEDIUM 5 レコード
  - BUG 13 レコード
  - M3 と B11 は同じ `/auth/device/exchange` 問題の重複

deepsec は修正後に再実行していないため、ローカル生成レポート上では、修正済みの
2 レコードも true-positive のままである。

## Cloud 作業時の規律

1. 1 論点または密接な同型だけを 1 PR にする。着手前に現行コード、仕様、ADR を
   読み、scanner の提案をそのまま実装しない。
2. `packages/crypto` の B12、B13 は、人間レビューとテストベクターを先に用意する。
   `docs/CRYPTO_SPEC.md` にない暗号操作を追加しない。
3. Drizzle を触る M4、B8、B9 はリポジトリサービス境界を守る。スキーマ変更が
   必要なら drizzle migration の手順に従う。
4. 平文 secret、鍵素材、外部 provider ID をログや append-only 監査 actor に
   追加しない。攻撃 PoC をリポジトリへ置かない。
5. ユーザー向け文言は英語。完了時は固定 Bun(`.bun-version`。現行 1.4.0)で `bun run check` を通す。
6. Cloud 環境には Claude Max のローカル認証がない。修正と通常テストは Cloud で
   できるが、deepsec の再検証は資格情報を別途用意しない限りローカルで行う。

## 修正済み（残り18件には含めない）

### F0. 空 `claimConstraints` が fail-open になる

元の finding は `apps/server/src/lease-policy.ts` と
`packages/api-schema/src/lease-api.ts` に対する重複 2 レコード。

実装済み:

- CLI は各 policy 要素の `claimConstraints` を必須かつ非空として拒否する
- server は既存チェーンに空要素があっても不一致として扱う
- AUTH_SPEC に fail-closed の評価意味論を記載する
- CLI と workerd の回帰テストを追加する
- CRYPTO_SPEC のチェーン形状と `packages/crypto` は変更しない

## MEDIUM（5レコード）

### M1. GitHub Actions OIDC の bearer token を未検証 URL へ送る

- 場所: `apps/cli/src/oidc-github.ts:34,78-86`
- deepsec slug: `ssrf`
- 状態: confirmed、confidence low
- 問題: `ACTIONS_ID_TOKEN_REQUEST_URL` を文字列として受け取り、既定の redirect
  follow で bearer token を送る。`https:`、host、redirect を検査していない。
- 推奨: URL を parse し、`https:` と許可 host を検証して
  `redirect: "manual"` を使う。GitHub Hosted Runner と GHES の host 規則を
  決めてから実装する。

### M2. `maruhi run` の実行制御 env denylist に抜けがある

- 場所: `apps/cli/src/run.ts:33,58-59,106`
- deepsec slug: `other-execution-control-env-injection`
- 状態: confirmed、confidence medium
- 問題: secret の変数名と値が子プロセス環境を上書きできる。現行 denylist は
  `HOME`、`PROMPT_COMMAND`、`NODE_REPL_EXTERNAL_MODULE`、`PYTHONINSPECT`、
  Windows の `PATHEXT` / `COMSPEC` / `SYSTEMROOT` などを拒否しない。
- 推奨: 不足する名前と prefix を追加し、POSIX と Windows の回帰テストを追加する。
  `NODE_` / `PYTHON_` / `BUN_` の prefix 拒否は互換性を確認して決める。

### M3. 未認証 device exchange が GitHub OAuth App の共有 quota を消費する

- 場所: `apps/server/src/auth.package/github.ts:110,115,190-192`
- 関連: B11 `packages/api-schema/src/auth-api.ts`
- deepsec slug: `rate-limit-bypass`
- 状態: confirmed、confidence medium
- 問題: 未認証の `/auth/device/exchange` が、形式上妥当な token ごとに GitHub の
  check-token API を呼ぶ。共有 quota の枯渇で全ユーザーの CLI login が止まる。
- 補足: token の prefix / length 検査と `docs/SELF_HOSTING.md` の WAF 推奨は既に
  あるが、既定デプロイでは rate limit を強制しない。
- 要判断: maruhi 側の短命 device code へ exchange を束縛するか、Cloudflare Rate
  Limiting を既定構成にするかを先に決める。B11 と同じ PR で扱う。

### M4. `auth.login_failed` の global cap が監査を失明させる

- 場所: `apps/server/src/db.package/audit.ts:81-82,271-285`
- deepsec slug: `other-audit-suppression`
- 状態: confirmed、confidence medium
- 問題: 1時間100件の上限を全 actor で共有するため、匿名の失敗で枠を使い切ると
  後続の targeted failure が記録されない。
- 要判断: limiter 用の別状態で粗い発信元単位に分けるか、上限到達時に
  `auth.login_failed_suppressed` のような集約イベントを残す。外部 provider ID や
  IP を append-only actor に書く案は採らない。AUDIT_SPEC の改訂要否も確認する。

### M5. lease endpoint が任意の有効 project ID で Durable Object を生成できる

- 場所: `apps/server/src/handlers-lease.ts:96,119-121`
- deepsec slug: `rate-limit-bypass`
- 状態: confirmed、confidence medium
- 問題: 有効な GitHub OIDC token があれば、多数の異なる64桁 hex project ID で
  DO を生成できる。各 DO の constructor は table を作り、回収経路がない。
- 補足: `ProjectIdSchema` の形式検査は既にある。元 recommendation の
  「projectId を検証する」は不要。
- 推奨: `projectStub` を呼ぶ前の request-level rate limit を設計する。DO 内の
  per-project counter では新規 DO 生成を止められない。

## BUG（13レコード）

### B1. 不正な audit timestamp で CLI が RangeError になる

- 場所: `apps/cli/src/audit.ts:188,264,348,412`
- deepsec slug: `other-unhandled-exception`
- 状態: confirmed、confidence medium
- 問題: server の無制限 `serverTs` を `Date#toISOString` に渡すため、
  `maruhi audit` 系が Effect の typed error ではなく defect で終了する。
- 推奨: wire schema で finite / Date 範囲を検証するか、formatter を total にする。
  B4、B5 と同型なので、共通方針を決めてから修正する。

### B2. config load が ENOENT 以外の read error も空設定として扱う

- 場所: `apps/cli/src/config.ts:98-103`
- deepsec slug: `other-error-swallowing`
- 状態: confirmed、confidence high
- 問題: EACCES、EISDIR、EIO も `{}` に変換する。`config set` が既存設定を警告なしで
  置換する可能性がある。
- 推奨: ENOENT だけを初回扱いにし、それ以外は typed `CliError` へ変換する。

### B3. device flow の `expires_in` と `interval` に上限がない

- 場所: `apps/cli/src/device-flow.ts:110-135`
- deepsec slug: `other-logic-bug`
- 状態: confirmed、confidence medium
- 問題: hostile または誤設定の endpoint が非常に大きい値を返すと、deadline の
  確認前に長時間 sleep する。
- 推奨: RFC 8628 と GHES の実値を確認して上限を定め、sleep 前にも deadline を
  検査する。

### B4. invite timestamp で CLI が RangeError になる

- 場所: `apps/cli/src/invite.ts:254,267-268,734`
- deepsec slug: `other-unhandled-defect`
- 状態: confirmed、confidence high
- 問題: server の `createdAtMs` / `expiresAtMs` が Date 範囲外だと invite create /
  list が defect で終了する。
- 推奨: B1 と同じ境界検証または total formatter を使う。

### B5. `maruhi key show` が不正 timestamp で RangeError になる

- 場所: `apps/cli/src/keygen.ts:159,171-172`
- deepsec slug: `other-unhandled-defect`
- 状態: confirmed、confidence high
- 問題: recovery status の `updatedAtMs` が Date 範囲外だと、ローカル鍵表示まで
  非ゼロ終了になる。
- 推奨: B1 と同じ境界検証を使い、recovery status は degraded display にする。

### B6. keychain write timeout 後に書き込みが完了し得る

- 場所: `apps/cli/src/live.ts:40-51`
- deepsec slug: `other-race-condition`
- 状態: confirmed、confidence medium
- 問題: Effect の timeout は進行中の `Bun.secrets.set` Promise を cancel できない。
  CLI が失敗を報告した後に key が保存され、次回の overwrite guard にかかり得る。
- 推奨: timeout 時に「保存された可能性がある」と明示し、確認・復旧手順を示す。
  post-timeout read も block し得るため、実装前に Bun keychain の挙動を検証する。

### B7. push 成功表示がローカル署名値ではなく server echo を使う

- 場所: `apps/cli/src/push.ts:951-953`
- deepsec slug: `other-trust-boundary`
- 状態: confirmed、confidence medium
- 問題: 表示する variable ID / version / epoch を server response から返す。一方、
  floor 更新は意図どおりローカル計算値を使っている。
- 推奨: ローカルで署名した値を返し、server echo が異なれば typed error にする。

### B8. audit read が D1 の全 NULL row を UPDATE する

- 場所: `apps/server/src/db.package/audit.ts:180,185,250-252`
- deepsec slug: `other-write-amplification`
- 状態: confirmed、confidence medium
- 問題: 取得 page に NULL `row_id` が1件あると、table 全体の NULL row を更新する。
  複数 reader や rollback 中の旧 worker と競合し得る。
- 推奨: page で観測した seq / row だけへ UPDATE を限定し、workerd + D1 テストで
  1 read あたりの更新件数を固定する。

### B9. recovery fetch counter が read-modify-write race を持つ

- 場所: `apps/server/src/db.package/repos.ts:579,594,607,614,618`
- deepsec slug: `other-race-condition`
- 状態: confirmed、revalidation 後 BUG
- 問題: 並行 request が同じ count を読み、複数成功しても count が1しか増えない。
  invite counter にも同型がある。
- 推奨: 条件付きの相対 UPDATE と `RETURNING` を1文で実行する。並行 workerd テストを
  先に作り、invite counter を同じ PR に含めるかは差分量で決める。

### B10. member user ID と server fingerprint の衝突で wrap count が満たせない

- 場所: `apps/server/src/dek-wraps.ts:46,56,129,231`
- deepsec slug: `other-logic-bug`
- 状態: confirmed、confidence medium
- 問題: expected count は member と server grant を別々に数えるが、storage key は
  recipient class を含めない。ID が衝突すると duplicate または missing になり、
  environment 作成と rotation が止まる。
- 推奨: member ID と in-scope server fingerprint の deduplicated union から expected
  count を求める。internal user ID の形式変更は AUTH_SPEC と既存チェーン互換性を
  確認せず行わない。

### B11. `/auth/device/exchange` に request rate limit がない

- 場所: `packages/api-schema/src/auth-api.ts:151,159-162`
- deepsec slug: `rate-limit-bypass`
- 状態: confirmed、revalidation 後 BUG
- 問題と対応: M3 と同じ根本原因。同じ PR で閉じ、2つの finding を重複として扱う。

### B12. 未知の chain `op` で verifier が TypeError を投げる

- 場所: `packages/crypto/src/internal.package/chain-verify.ts:102,247-248,551`
- deepsec slug: `other-uncaught-exception`
- 状態: confirmed、confidence high
- 問題: `PAYLOAD_SHAPES[entry.op]` の membership を確認せず呼ぶ。公開 verifier の
  「不正入力は `invalid-payload` を返し throw しない」という契約に反する。
- 到達性: 現行 production API は `ChainEntrySchema` で先に op を絞るため、
  defense-in-depth の契約不備であり、直接の exploit 経路は確認されていない。
- 制約: `packages/crypto` 変更。人間レビューを受け、未知 op のテストベクターを
  実装より先に追加する。

### B13. value-sign context が空 `variableId` を拒否しない

- 場所: `packages/crypto/src/internal.package/value-sign.ts:100,107,116`
- deepsec slug: `other-missing-validation`
- 状態: confirmed、confidence high
- 問題: project / environment / writer は非空検査するが variable ID だけ漏れている。
  API schema は空を拒否するため、外部からの forgery 経路ではなく caller bug の
  防御不足。
- 制約: `packages/crypto` 変更。`meta-sign.ts` と同じ期待値を先にテストベクターへ
  追加し、人間レビュー後に実装する。

## 対象外

再検証で false-positive になった次の3件は残課題に数えない。

- `requestOrigin()` と Host header
- `invalidValueMessage` の substring 判定
- `computeVariablesDigest` の UTF-16 / UTF-8 duplicate 判定

将来の hardening として扱う場合も、deepsec の true-positive 修正とは分ける。

## 推奨する着手順

1. B2、B3、B7。局所的で仕様判断が少ない。
2. B1、B4、B5。server timestamp の共通境界方針を決め、同型として直す。
3. M1、M2。外部 runtime と子プロセス環境の互換性テストを伴う。
4. B8、B9、B10。D1 / wrap invariant の回帰テストを先に置く。
5. M3 + B11、M4、M5、B6。運用またはアーキテクチャ判断を先に行う。
6. B12、B13。crypto の独立 PR とし、テストベクター先行・人間レビュー必須。
