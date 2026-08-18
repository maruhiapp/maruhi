# maruhi 監査ログ仕様書 (AUDIT_SPEC)

Version: 1.0-draft
Status: 0.6 までは所有者承認済み(0.3 は 2026-08-02 の PR #18 マージで承認。§3.3 の `dek.registered` への署名者鍵 FP の追加は CRYPTO_SPEC §5.1 として PR #21 で承認済み。§3.3 の署名付きデータ操作への actor 鍵 FP 拡張と §3.4 の `chain.environment_created` は CRYPTO_SPEC 0.4-draft の波及として 2026-08-04 の PR #27 マージで承認。0.6 = §5.2 案 A の D1 実装と §3.1 の記録細則 — 2026-08-10 セッション 21、マージをもって承認)。0.7-draft = Phase 2 機能裁定の起草(2026-08-12 セッション 22): §3.2 invite.* / §3.5 ワークロードリースへの改訂 / §4.1 revoke_server 変種の入力更新 / §6 可視性クラス(未決 #1 の解消)/ §7 読み取り API — **本改訂 PR のマージをもって所有者承認とする**。0.8-draft = Wave 2 B2 の所有者裁定(2026-08-15 セッション 25): §3.3 `rotation.recommended` / `rotation.dismissed` の記録粒度・actor・取り下げ権限、`dek.deleted` の自動掃除変種(AUTH_SPEC §12-6)、`var.version_pushed` の再暗号化マーカー payload / §4.1 手順 5 の解消導出からのマーカー付き push の除外(義務ローテーションの再暗号化 push による全自動誤解消 — 仕様内部の矛盾 — の解消)/ §7 取り下げ操作エンドポイント — **本改訂を含む実装 PR のマージをもって所有者承認とする**(PR #70 マージ済み = 承認済み)。0.9-draft = Wave 2 C1 の所有者裁定(2026-08-16 セッション 26): §5.1 `row_id` 列(ワイヤ行識別子 = ランダム値)/ §7 読み取り API のカーソル・行識別子の不透明化と `seq` の admin 限定開示(§7「件数にも漏らさない」と §6「欠番 = 削除の痕跡」の両立 — pullfrog レビュー指摘の解消)— **本改訂を含む実装 PR のマージをもって所有者承認とする**(PR #71 マージ済み = 承認済み)。1.0-draft = Wave 3 D の起草(2026-08-18 セッション 27 — 設計探索は docs/notes/session-27.md): §3.4 `chain.checkpointed` / §5.1 監査ヘッド累積ハッシュ / §6 チェックポイントによる事後改竄検出とヘッド申告を監査イベント化しない判断 / §8 未決 #2 の解消(CRYPTO_SPEC §6.2 `checkpoint` に統合)— **本改訂 PR のマージをもって所有者承認とする**

この文書は maruhi の監査ログ(何を・誰が・いつ)の設計を定める。
CRYPTO_SPEC(特に §6 メンバーシップログ、§7 要ローテーション検出)と AUTH_SPEC(§2 データモデル)を前提とする。

---

## 1. 目的と設計原則

1. **要ローテーション検出の成立**(最重要): メンバー削除・サーバー失効時に「その主体が閲覧可能だった変数 × 環境」を監査ログから算出できること(CRYPTO_SPEC §7)。スキーマはこのクエリ要件から逆算して設計する(§4)
2. **アイデンティティ規則(絶対)**: イベントの主体・対象の識別は**内部 user_id と鍵フィンガープリント(+ maruhi 発行 API トークン id)のみ**。GitHub ID・provider_user_id・provider login・メールアドレスを監査ログに書き込んではならない(CLAUDE.md。append-only 構造は書き換え不能であり、認証プロバイダから独立していなければならない)。認証手段の**種別名**(`github_oauth` / `device_flow` 等。AUTH_SPEC の auth_method と同じ語彙)は記録してよい
3. **秘密を含めない**: 変数の平文値・暗号文・nonce・鍵素材をイベントに含めない。変数名は v1 では平文メタデータ(CRYPTO_SPEC §4)なので、UI 利便のためスナップショットを payload に含めてよい
4. **append-only**: 監査イベントの更新・削除 API を作らない。リポジトリサービスは追記と読み取りのみを公開する(ImportLint の境界で強制)。訂正は打ち消しイベントの追記で表現する
5. **チェーンが正、ミラーは従**: メンバーシップ操作の真実源は署名チェーン(CRYPTO_SPEC §6)。監査ログのチェーンミラー(§3.4)は統一クエリのための導出データであり、矛盾時はチェーンが勝つ。ミラーはチェーンから再構築可能でなければならない

## 2. アクターモデル

すべてのイベントは `actor` を持つ:

```
actor: {
  type: "user" | "server" | "system",
  user_id?,             // type=user: 内部 user_id(ULID)
  key_fingerprint?,     // type=user: ユーザー鍵 FP / type=server: サーバー鍵 FP(CRYPTO_SPEC §3)
  api_token_id?,        // API トークン経由の操作のとき。トークン生値・ハッシュは不可
  auth_method?          // セッション経由の操作のとき("github_oauth" 等の種別名のみ)
}
```

- `type=server`: grant_server で開示されたサーバー(デプロイメント keypair)による操作。user_id は持たない
- `type=system`: 期限切れ処理等、主体のない内部処理。乱用しない(原則イベントには人かサーバーがいる)
- 鍵 FP は「その時点でその user_id が使っていた鍵」の証跡として重要(リカバリーによる鍵再ラップ後も過去イベントの FP は当時のまま)

## 3. 記録イベント一覧

イベント名は `領域.動詞` 形式。★ = 要ローテーション検出(§4)への入力。

### 3.1 認証系(ユーザー / セッション / トークン)

| イベント | 主な属性 | 備考 |
|---|---|---|
| `auth.login_succeeded` | auth_method | Web OAuth / device flow 完了 |
| `auth.login_failed` | auth_method, 理由種別 | state 不一致・検証失敗等。提示された外部 ID は**記録しない** |
| `auth.session_revoked` | 対象 session id | 明示ログアウト / サーバー側失効 |
| `auth.token_created` | token_id, name, scopes | |
| `auth.token_revoked` | token_id | |
| `auth.identity_linked` / `auth.identity_unlinked` | provider 種別名のみ | provider_user_id / login は**記録しない** |
| `auth.recovery_blob_fetched` | — | ラップ済み master 秘密鍵の取得(CRYPTO_SPEC §8。セキュリティ上の要監視イベント) |
| `auth.recovery_code_reissued` | — | 再発行(旧ラップ削除を含む) |
| `auth.user_created` | — | getOrCreateUser の新規作成分 |

- `auth.session_created` は `auth.login_succeeded` と 1:1 なので独立イベントにしない。Web ログインの `auth.login_succeeded` はセッション id(保存 id と同じハッシュ。生値ではない — AUTH_SPEC §10)を payload に写し、`auth.session_revoked` の対象 session id と突合できるようにする(2026-08-10)
- `auth.session_revoked` は**明示失効のみ**(ログアウト / サーバー側失効)。期限切れ行の掃除(resolve 時・cron)は失効イベントではないため記録しない(2026-08-10)
- `auth.login_failed` の actor は **user_id なしの type=user**(人はいるが特定できていない外部主体。type=system は主体のない内部処理用であり失敗試行には使わない — §2)(2026-08-10)
- `auth.login_failed` の記録は**固定窓の全体上限つき**(1 時間 100 行、超過分は記録しない。ベストエフォート): 本イベントは唯一の未認証経路からの書き込みであり、無効リクエストの洪水による D1 書き込み増幅(可用性・コスト攻撃)を有界にする。洪水そのものは窓内の上限到達として観測でき、要ローテーション検出(§4)の入力ではないため SHOULD 記録で足りる(2026-08-10 セッション 21 セキュリティレビュー対応)
- トークン**使用**はイベント化しない(高頻度・低情報。api_tokens.last_used_at と、データ系イベントの actor.api_token_id が代替)
- 同名トークンのローテーション(AUTH_SPEC §6 の置換)は `auth.token_created` 1 行で表し、置換された旧行の削除を独立の `auth.token_revoked` にしない(発行の意味論が「置換」であり、明示失効と区別する)(2026-08-10)

### 3.2 org 系

| イベント | 主な属性 |
|---|---|
| `org.created` / `org.renamed` / `org.deleted` | org_id(パーソナル org 自動作成も記録) |
| `org.member_added` / `org.member_removed` | target_user_id, org role |
| `org.member_role_changed` | target_user_id, 旧/新 role |
| `org.project_created` / `org.project_deleted` | project_id |
| `invite.created` / `invite.revoked` | project_id, 招待 id, role(2026-08-12 — AUTH_SPEC §15) |
| `invite.accepted` | project_id, 招待 id, target_user_id(受諾者), payload に受諾鍵 FP |

org ロールはプロジェクトアクセスに関与しない(AUTH_SPEC §9-2)ため、org 系イベントは要ローテーション検出に関与しない。

- パーソナル org 自動作成(AUTH_SPEC §9-1)は `org.created`(payload `personal: true`)+ 本人 owner の `org.member_added` として記録する。org 名スナップショットは payload に**写さない** — パーソナル org の名前は providerLogin 由来であり、§1-2 の禁止情報にあたる(2026-08-10)
- **招待イベント(2026-08-12 起草 — AUTH_SPEC §15)**: 招待レコードは D1 にあるため(受諾はプロジェクト非メンバーからの操作)、invite.* も D1 側に置き、発行・受諾・失効のレコード操作と**同一 batch** で追記する(§5.2 の同一トランザクション原則)。project_id 列で対象プロジェクトを参照する。プロジェクト DO 側の対応物は最終的な `chain.member_added`(§3.4)であり、招待ライフサイクル自体は DO へ二重記録しない。可視性は §6 のクラス 2(プロジェクト admin 以上)と同水準

### 3.3 プロジェクト データ系 ★

すべて project DO 内に記録(§5)。variable_id / environment_id は CRYPTO_SPEC §4 の識別子。

| イベント | 主な属性 | 備考 |
|---|---|---|
| `env.created` / `env.renamed` / `env.deleted` | environment_id, 名前スナップショット, **actor_key_fingerprint** | メタステートメント(CRYPTO_SPEC §4.2)の author 鍵 FP を写す(2026-08-03。env.created は 12-4 複合の一部) |
| `var.created` ★ | variable_id, environment_id, 変数名スナップショット, **actor_key_fingerprint** | 同上 + 同梱 version 1 の writer 署名(CRYPTO_SPEC §4.1) |
| `var.version_pushed` ★ | variable_id, environment_id, version, epoch, **actor_key_fingerprint** | 値の更新(平文・暗号文は含めない)。writer 署名(CRYPTO_SPEC §4.1)の鍵 FP を写す(2026-08-03) |
| `var.renamed` | variable_id, environment_id, 新名スナップショット, **actor_key_fingerprint** | メタステートメントの author 鍵 FP を写す(2026-08-03) |
| `var.deleted` ★ | variable_id, environment_id, **actor_key_fingerprint** | 削除しても過去の閲覧可能性は消えない(§4)。削除ステートメントの author 鍵 FP を写す(2026-08-03) |
| `var.read` ★ | variable_id, environment_id, epoch, version | **暗号文の配布**に対して記録する(pull / Web での取得)。一括 pull は変数ごとに 1 行(§4 のクエリ要件のため)。**メタデータのみモード(AUTH_SPEC §12-7)は暗号文を配布しないため記録しない**(読んでいないものを読んだと記録しない — 2026-08-10) |
| `dek.registered` | environment_id, epoch, target_user_id(受信者), **actor_key_fingerprint(署名者鍵 FP)** | DEK ラップの登録(AUTH_SPEC §12-6。**複合リクエストの同梱分 — 環境作成のエポック 1・ローテーションの新エポック(同 §12-4。2026-08-03)— を含む**)。actor_key_fingerprint には登録署名(CRYPTO_SPEC §5.1)の署名者鍵 FP を写す(署名との突合用。セッション 07 裁定 B) |
| `dek.deleted` | environment_id, epoch, target_user_id(受信者) | admin による毒ラップの削除(AUTH_SPEC §12-6 の修復経路) |
| `rotation.recommended` | target_user_id(remove 変種)/ target_key_fingerprint(revoke_server 変種), variable_id, environment_id, payload = { basis, triggerChainSeq } | §4 の算出結果の永続化(UI / CLI 表示用)。**1 (variable × environment) 1 行**(2026-08-15 明確化 — §4.2 Q5 の索引要件から。集合を 1 行に畳まない) |
| `rotation.dismissed` | variable_id, environment_id | 人間による明示的な取り下げ(append-only の打ち消しイベント)。1 対 1 行 |

- `var.read` の粒度と量: CI からの定期 pull で最も高頻度になるイベント。v1 は素直に 1 変数 1 行で記録し、ドッグフーディングで量を実測してから集約(例: 同一 (actor, variable, environment) の読みを日単位で 1 行に丸める)を判断する。**要ローテーション検出に必要なのは「期間内に読んだか否か」だけなので、集約しても検出は劣化しない**
- **`var.read` の意味論(2026-08-10 セッション 20)**: 記録条件は「暗号文を応答に含めて返したこと」であり、名前解決・一覧などメタデータだけを返す読み取りは対象外(AUTH_SPEC §12-7 のメタデータのみモード)。これは §4 の「確実に取得した」ランク(在籍区間内の `var.read` の有無)の入力純度を守るための規律である — 値を取得していないメンバーの解決操作が `var.read` に混入すると、要ローテーション検出が「取得した」を過大申告し、監査ログを読む人間を誤らせる
- **actor_key_fingerprint を持つデータ系イベント(2026-08-03 セッション 12 改訂)**: データ系イベントの actor は原則 user_id(+ トークン id / auth_method)のみで鍵 FP を持たない(FP を持つのはチェーンミラー §3.4)としてきたが、この例外は「**クライアント署名を伴う操作**」の類型として一般化する — `dek.registered`(登録署名 = CRYPTO_SPEC §5.1。2026-08-02 セッション 09)に加え、`var.version_pushed` / `var.created`(値の書き込み署名 = 同 §4.1)、`var.renamed` / `var.deleted` / `env.created` / `env.renamed` / `env.deleted`(メタステートメント署名 = 同 §4.2)が署名者鍵 FP を actor_key_fingerprint 列に写す。監査行(サーバー管理データ)とチェーン外署名(クライアント署名 = サーバーが偽造できない)を突合可能にするための記録であり、§2 のアクターモデル(type=user の key_fingerprint)の範囲内である。`dek.deleted` は署名を伴わない操作のため引き続き FP を持たない(この非対称は「FP = 署名の証跡」の意味論を保つためであり、均しにいかない)
- `dek.registered` / `dek.deleted` の粒度は **1 受信者 1 行**(2026-08-02 セッション 08 提案): §5.1 の列構造は 1 行 1 target(target_user_id は単値)であり、受信者ごとの行にすることで「この受信者宛のラップがいつ登録・削除されたか」を索引(target_user_id, seq)でそのまま引ける。登録はローテーション・メンバー追加時のみの低頻度イベントで、行数は AUTH_SPEC §12-8 のラップ行数上限が束縛する。v1 の要ローテーション検出(§4.1)には関与しない(候補集合は全メンバー × 全環境で算出するため)が、将来の環境スコープ role(CRYPTO_SPEC 未決 #11)で「誰がどのエポックの DEK を受け取ったか」が候補集合の入力になった場合の証跡を確保する
- 「新バージョン push」は要ローテーションフラグの解消条件でもある(§4。ただし再暗号化マーカー付き push を除く — 下記)
- **`var.version_pushed` の再暗号化マーカー(2026-08-15 セッション 25 所有者裁定 — Wave 2 B2)**: push リクエストの `reencryption` 申告(AUTH_SPEC §12-5 — writer の自己申告。サーバーは検証不能)を payload に写す(`{ reencryption: true }`。未申告・false は写さない)。§4.1 手順 5 の解消導出はマーカー付き push を解消と見なさない — CRYPTO_SPEC §7 の義務ローテーションは全アクティブ変数の再暗号化 = 通常 push を伴うため、これを除外しないと `remove_member` 直後の必須 sweep が記録直後の全フラグを自動解消してしまい、検出の目的(上流 credential のローテーション促し)が壊れる。「上流が実際にローテーションされた」ことの検証は E2EE では原理的に不可能であり(サーバーは平文を見られない)、解消シグナルは本質的に writer 申告である — マーカーはその申告の粒度を「push した」から「新しい値を push した」へ正すもの。虚偽の失敗方向は安全側(§12-5)
- **`rotation.recommended` の記録細則(2026-08-15 セッション 25 所有者裁定)**: actor は `{ type: "system" }`(検出は削除・失効エントリの受理に伴うサーバーの導出処理であり、削除実行者の行為ではない — 実行者は同時に記録されるチェーンミラーが保持し、payload の `triggerChainSeq` で突合できる)。payload の `basis` は `"read"`(§4.1 手順 3 の (a) 確実に取得した)| `"readable"`((b) 取得可能だった)。`chain_seq` 列は使わない(§5.1 のとおりチェーンミラー専有 — トリガーの chain seq は payload に載せる)。追記は §4.1 のとおり削除・失効エントリの受理と同一トランザクション(ミラーと同じ規律 — クラッシュでフラグだけ欠ける形を作らない)
- **`rotation.dismissed` の発行権限と導線(2026-08-15 セッション 25 所有者裁定 — §6 未規定部分の解消)**: 取り下げを宣言できるのは**チェーン role admin 以上 × トークンスコープ admin**(§12-3 のラップ削除と同水準 — 実ローテーションなしにクラス 1 の警告を全メンバーから消すリスク受容のガバナンス操作)。§7 のとおり生イベントの追記 API は作らず、専用の操作エンドポイント(対象 (variable × environment) の列挙 1 件以上、サーバー側でイベント生成)で行う。**現在有効なフラグ(§4.1 手順 5 の導出)が無い対への取り下げは 404 で拒否する**(黙って成功させない規律 — 破棄対象の実在しない打ち消しイベントを積まない)。actor は取り下げた本人(type=user)
- **`dek.deleted` の自動掃除変種(2026-08-15 セッション 25 所有者裁定 — AUTH_SPEC §12-6 の再追加受理時掃除)**: `add_member` 受理に伴うサーバーの旧鍵宛ラップ掃除は、admin の修復経路と同じ `dek.deleted` を actor `{ type: "system" }` + payload `{ cause: "member-readded", triggerChainSeq }` で記録する(署名を伴わない自動処理のため FP は持たない — 「FP = 署名の証跡」の意味論は不変。人間の削除操作と機械的な不変条件強制を actor 種別で区別する)

### 3.4 チェーン操作のミラー ★

チェーン追記の受理時(サーバー検証通過後)に、対応する監査イベントを同じ project DO に追記する。`chain_seq` で元エントリを参照し、actor はチェーンエントリの actor(user_id + 鍵 FP)をそのまま写す。チェーンエントリのクライアント時刻とサーバー受理時刻の両方を持つ。

| イベント | 対応する op(CRYPTO_SPEC §6.2) |
|---|---|
| `chain.genesis` ★ | `genesis`。**target_user_id には作成者(= actor.user_id)を入れる**(作成者の在籍区間の開始点を Q1 の索引で引けるようにするため) |
| `chain.member_added` ★ | `add_member`(target_user_id, role) |
| `chain.member_removed` ★ | `remove_member`(target_user_id) |
| `chain.role_changed` | `change_role` |
| `chain.environment_created` | `create_environment`(environment_id。dek_commitment は payload に写す — CRYPTO_SPEC §6.2。2026-08-03) |
| `chain.epoch_rotated` ★ | `rotate_epoch`(environment_id, 新エポック, 理由。dek_commitment は payload に写す — 2026-08-03) |
| `chain.server_granted` ★ | `grant_server`。**target_key_fingerprint に付与対象のサーバー鍵 FP** を入れ、スコープ(対象環境集合)は payload に写す |
| `chain.server_revoked` ★ | `revoke_server`。**target_key_fingerprint に失効対象のサーバー鍵 FP** を入れる |
| `chain.checkpointed` | `checkpoint`(CRYPTO_SPEC §6.2。2026-08-18)。payload に公証対象のダイジェスト(環境ごとの epoch / manifest_version / manifest_sig_hash / values_digest と audit_head_hash)を写す。**監査 seq・行数は payload にも写さない**(§7 の件数非漏洩と同じ理由 — チェーン payload 自体が seq を含まない設計。CRYPTO_SPEC §6.2) |

- **バックフィル(2026-08-02 セッション 07 裁定)**: ミラーの記録は監査ログ実装の導入後に受理されたエントリから開始する。導入前に受理されたチェーンを持つ DO は存在しない(未リリース)ため、v1 では既存チェーンのバックフィルを実装しない。将来スキーマ移行等で必要になった場合は、§1-5(ミラーはチェーンから再構築可能)に基づく再構築処理として設計する

### 3.5 grant_server 経由のサーバーアクセス ★(2026-08-12 改訂 — ワークロードリースへの対応)

サーバーが開示済み DEK を実際に行使した記録。actor は `{ type: "server", key_fingerprint }`(`server.lease_denied` のみ例外 — 下記)。

| イベント | 主な属性 | 備考 |
|---|---|---|
| `server.dek_unwrapped` | environment_id, epoch | サーバーがラップ済み DEK を復号した(リース発行に伴う) |
| `server.lease_issued` ★ | environment_id, payload = { grant_chain_seq, claims_digest, epochs } | ワークロードリースの発行(AUTH_SPEC §14)。**環境単位 1 行**(リースは環境単位配布であり変数粒度の選択がない)。外部識別子(リポジトリ名等)は書かない — 一致したポリシーはチェーン(grant payload)が保持し、grant_chain_seq + claims_digest で突合する(§1-2 の禁止情報をリース経路でも増やさない) |
| `server.lease_denied` | payload = { reason, claims_digest? } | **OIDC 署名検証を通過した後の拒否のみ**を記録し、固定窓の全体上限(1 時間 100 行、超過は不記録)を適用する — `auth.login_failed` と同じ規律(§3.1)。actor は `{ type: "system" }`(maruhi 上の識別を持たない外部ワークロードであり、サーバー鍵の行使でもない)。reason には先着束縛違反 `token-replayed`(AUTH_SPEC §14-1 — 2026-08-15 裁定)を含む — この行の claims_digest は正規ワークロードの発行行と同一になるため、所有者は**どのワークロードのトークンが盗まれたか**を突合できる |
| `server.value_decrypted` ★ | variable_id, environment_id, epoch, version | **予約(v1 リース経路では発生しない)**: リースにおいてサーバーは値を復号しない(CRYPTO_SPEC §9.1)。push 型同期アドオン(将来 — libsodium 例外の裁定を要する)を導入する場合に有効化する。1 変数 1 行 |

`revoke_server` 時の要ローテーション検出は §4.1 の revoke_server 変種(区間 = grant 区間、候補 = grant スコープ内、実読み取り = `server.lease_issued`〔発行時点の環境内アクティブ変数の全てをランク (a) に含める — 環境単位配布の帰結〕+ `server.value_decrypted`〔予約〕)で行う。

## 4. 要ローテーション検出からのクエリ要件(逆算)

### 4.1 アルゴリズム(CRYPTO_SPEC §7 の実装)

`remove_member(M)` の受理時、同じ project DO 内で:

1. **在籍区間の復元**: チェーンミラーから M の `chain.member_added`(または target_user_id = M の `chain.genesis`)〜 `chain.member_removed` の区間を全て求める(再追加があれば複数区間の和)
2. **候補集合(閲覧可能だった集合)**: v1 は全メンバーが全環境・全エポックの DEK を受け取る(CRYPTO_SPEC §3)ため、「在籍区間と存在期間が重なる全 (variable × environment)」が閲覧可能だった集合になる。`var.created` 〜 `var.deleted`(未削除なら現在まで)の存在区間と在籍区間の重なりで判定する。**削除済み変数も含める**(上流 credential は変数を消しても失効しない)
3. **根拠のランク付け**: 候補集合を 2 水準に分ける — (a) **確実に取得した**: 在籍区間内に M の `var.read` があるもの(API トークン経由を含む。actor.user_id で照合)、(b) **取得可能だった**: それ以外の候補全部。UI / CLI は (a) を強調表示する
4. **結果の永続化**: `rotation.recommended` イベントとして追記し、UI / CLI は「要ローテーション」フラグとして表示する
5. **フラグの解消**: 対象 (variable × environment) への `var.version_pushed`(= 上流をローテーションして新しい値を入れた。**再暗号化マーカー付き — §3.3 — を除く**: 義務ローテーションの再暗号化は同一平文の再 push であり上流の失効ではない。除外しないと手順 4 の直後に走る必須 sweep が全フラグを自動解消する — 2026-08-15 セッション 25 所有者裁定)または `rotation.dismissed` で解消。解消はイベントの seq 順で判定する(recommended より**後の** seq の解消イベントだけが効く)。解消状態はイベント列から導出する(フラグ自体を可変ストアに持たない)

**`revoke_server` の変種**: 同じ骨格で次を差し替える — 手順 1 の区間は当該サーバー鍵 FP の `chain.server_granted` 〜 `chain.server_revoked`(再 grant があれば区間ごと)。手順 2 の候補は各 grant のスコープ(対象環境の部分集合。CRYPTO_SPEC §6.2)に含まれる環境の変数に限定。スコープは**環境ごとの開示窓**として扱う: チェーン合意規則は同一鍵 FP への拡大再 grant を受理する(縮小のみ拒否)ため、拡大で後から加わった環境は「その環境を最初に含めた grant の seq」〜失効が窓になる(最初のスコープに固定すると拡大分が検出から漏れ、区間開始まで繰り上げると拡大前に削除された変数へ誤検出が出る — 2026-08-15 レビュー指摘)。手順 3 の (a) は `var.read` の代わりに `server.lease_issued`(actor_key_fingerprint = サーバー鍵 FP で照合。発行時点の環境内アクティブ変数の全てを (a) に含める — 環境単位配布)および `server.value_decrypted`(予約 — §3.5)を使う。手順 4〜5 は同じ。

環境スコープ role(CRYPTO_SPEC 未決事項 #11)が入った場合は、手順 2 の「全環境」が「M がアクセス権を持っていた環境」に狭まる。チェーンミラーが role / スコープを写しているため、この拡張はクエリの変更だけで成立する(スキーマ変更不要)。

### 4.2 スキーマが満たすべきクエリ要件

| # | クエリ | 必要な索引 |
|---|---|---|
| Q1 | user_id → 在籍区間(chain.member_added / removed / genesis の列) | (target_user_id, seq) |
| Q2 | (variable × environment) の存在区間(var.created / deleted の列) | (variable_id, environment_id, seq) |
| Q3 | user_id × 期間 → 読んだ (variable × environment) の distinct 集合 | (actor_user_id, seq) + イベント種別 |
| Q4 | (variable × environment) × 期間 → 閲覧・変更した主体一覧(逆引き。インシデント対応用) | Q2 と同じ索引 |
| Q5 | 現在有効な rotation.recommended − 解消イベント | イベント種別 + (variable_id, environment_id, seq) |
| Q6 | サーバー鍵 FP → grant 区間とスコープ(chain.server_granted / revoked の列)、および期間内の server.lease_issued(actor_key_fingerprint = サーバー鍵 FP で照合。§4.1 変種の (a) の主入力 — 2026-08-12)+ server.value_decrypted(予約 — §3.5) | (target_key_fingerprint, seq) + (actor_key_fingerprint, seq) |

これらは**単一の project DO 内で完結する**(クロス DO join なし)。§5 の配置はこの性質を保つことを最優先に選ぶ。

## 5. 保存先とスキーマ

### 5.1 プロジェクト系イベント(§3.3〜3.5): project DO 内 append-only(基本方針)

- 保存先はプロジェクト DO の SQLite。チェーン(同 DO)とデータ本体に併置することで、§4 のクエリがクロスストア join なしで成立し、チェーン追記とミラー追記を同一トランザクションで書ける(DO の直列化により seq が単調・無欠番になる)
- テーブル(Drizzle スキーマは実装時。ADR-0006 によりリポジトリサービス内に隔離):

```sql
audit_events (
  seq         INTEGER PRIMARY KEY,  -- DO 直列化による単調増加。欠番なし
  row_id      TEXT,                 -- ワイヤ行識別子(16 バイト乱数 hex。§7 — 採番と独立。UNIQUE 索引)
  server_ts   INTEGER NOT NULL,     -- サーバー受理時刻(unix ms)
  client_ts   INTEGER,              -- チェーンミラーのみ: エントリのクライアント時刻
  event       TEXT NOT NULL,        -- §3 のイベント名
  actor_type  TEXT NOT NULL,        -- 'user' | 'server' | 'system'
  actor_user_id          TEXT,
  actor_key_fingerprint  TEXT,
  actor_api_token_id     TEXT,
  target_user_id  TEXT,             -- メンバー操作の対象
  target_key_fingerprint TEXT,      -- grant_server / revoke_server の対象サーバー鍵 FP
  environment_id  TEXT,
  variable_id     TEXT,
  epoch           INTEGER,
  version         INTEGER,
  chain_seq       INTEGER,          -- チェーンミラーのみ
  payload         TEXT              -- JSON。名前スナップショット等の補足。§1-2/1-3 の禁止情報を含めない
);
CREATE INDEX ae_var    ON audit_events (variable_id, environment_id, seq);
CREATE INDEX ae_actor  ON audit_events (actor_user_id, seq);
CREATE INDEX ae_target ON audit_events (target_user_id, seq);
CREATE INDEX ae_target_fp ON audit_events (target_key_fingerprint, seq);
CREATE INDEX ae_actor_fp  ON audit_events (actor_key_fingerprint, seq);
CREATE INDEX ae_event  ON audit_events (event, seq);
```

- 頻出属性は列に昇格(索引のため)、それ以外は payload JSON。列は NULL 許容とし、イベント種別ごとの必須属性はアプリ層(Effect Schema)で強制する
- **監査ヘッド累積ハッシュ(2026-08-18 セッション 27 起草 — 未決 #2 の解消。CRYPTO_SPEC §6.2 `checkpoint` の入力)**: プロジェクト DO は監査行の追記時に累積ハッシュを維持する — `h_n = lower_hex(SHA-256(LP("maruhi/v1/audit-head", h_{n-1}, seq, row_digest)))`(`h_0` = 空文字列。LP は CRYPTO_SPEC §2.1)。`row_digest` は行の列を固定順(seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id, actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint, environment_id, variable_id, epoch, version, chain_seq, payload — 数値は 10 進文字列化、payload は保存された TEXT のバイト列そのまま)で LP 化した SHA-256。**NULL 許容列の LP フィールドはタグ付きバイト列とする: NULL = 1 バイト `0x00`、非 NULL = `0x01` + 値のバイト列**(NULL と空文字列を同一プリイメージにしない — 2026-08-18 pullfrog レビュー対応。LP の長さプレフィックスがタグ込みの境界を確定するため曖昧性はない)。**JSON の正規化は行わない**(保存バイト列を正とする — 正規化差異による照合分裂を構造的に避ける)。サーバーは任意の受理済み時点の累積ハッシュを検証可能に保持し(実装形は行への列併置等の実装詳細)、チェックポイントの受理検証(CRYPTO_SPEC §6.4 — 申告ハッシュが計算列に存在すること)と admin の突合(§6)に用いる。追記と累積ハッシュの更新は同一トランザクション。導入マイグレーションは既存行(append-only で全行残存)から累積ハッシュを再計算して初期化する — 初期化以前に行われた改竄は検出対象外である(チェックポイントの保証は「公証時点以降の事後改竄」に対するもの — §6 — であり、初期化はその起点を作るだけ)。**D1 側(§5.2 の user / org イベント)は対象外**: チェックポイントの置き場はプロジェクトチェーンであり、プロジェクトに属さない行を載せる場所がない(D1 側の改竄耐性は §6 の従来モデルのまま)
- **`row_id`(2026-08-16 セッション 26 所有者裁定 — C1)**: ワイヤ上の行識別子・ページングカーソルとして使う 16 バイト乱数(採番 `seq` とは独立)。`seq` は無欠番の共有採番であるため、序数をそのまま配布すると admin 未満の閲覧者が可視行の seq 差分から「隠れた行(クラス 2)の正確な件数と時刻窓」を推論できてしまう(§7 の件数非漏洩との矛盾)。乱数識別子は序数距離を運ばず、この推論を構造的に断つ。D1 側テーブル(§5.2)にも同じ列を持つ(あちらの `seq` はデプロイメント全体の autoincrement であり、序数配布はテナントを跨ぐ活動量推論になるため)。既存行は導入マイグレーションが backfill する。D1 側はデプロイ間隙(マイグレーション適用後・旧コード稼働中/ロールバック時)に `row_id` なしの行が書かれうるため、読み取りが NULL の `row_id` を観測したときに同一の backfill 文を冪等に再適用してよい(読み取り時の繰り延べ backfill)— これは合成識別子の採番であり、監査内容の列に触れない(§1-4 の append-only と両立)。全デプロイの安定後、NULL 再 backfill + NOT NULL 制約の追随マイグレーションを入れてこの繰り延べを不要化する(申し送り)

### 5.2 org / ユーザー系イベント(§3.1〜3.2)の置き場所: 選択肢比較

プロジェクト DO には置けない(プロジェクトに属さないイベントであり、ユーザーは複数プロジェクトにまたがる)。候補:

| 案 | 内容 | 利点 | 欠点 |
|---|---|---|---|
| **A: D1 に専用テーブル** | `user_audit_events` / `org_audit_events`(構造は 5.1 と同型、seq は autoincrement) | users / sessions / api_tokens / memberships が既に D1 にあり、参照整合と横断クエリ(「このユーザーの全認証イベント」)が自然。新しい DO クラス不要で v1 の実装量最小。書き込み頻度は低くロック競合の懸念なし | DO の直列化保証がなく seq の無欠番性が弱い(D1 の autoincrement で実用上は足りる)。「全ログは DO 内」という一貫性が崩れる |
| B: ユーザー DO + org DO を新設 | 主体ごとに 1 DO、5.1 と同じ構造 | 全ログが同一パターン。ホステッドでの分離が強い。将来のユーザー単位エクスポートが楽 | v1 で DO クラス +2。認証フロー(D1 トランザクション)とログ追記が別ストアになり原子性を失う。横断管理クエリ(不審ログイン監視等)がファンアウトになる |
| C: org DO のみ新設し、ユーザー系も所属パーソナル org に置く | DO パターンで統一しつつ +1 クラス | — | ユーザーは複数 org に属せるため「どの org に書くか」が人工的。リンク・リカバリー等 org と無関係なイベントの置き場が歪む |

**提案: 案 A(D1)を v1 に採用する。** 理由: (1) §4 の中核クエリはすべてプロジェクト DO 内で完結しており、org / 認証系イベントは検出に関与しない = DO 併置の利点がない。(2) 認証系イベントは記録対象(sessions / tokens)と同じ D1 に置くことで、発行・失効処理と同一トランザクションで追記できる。(3) append-only はどのストアでも「コード規律 + 追記専用サービス境界」で守るものであり、DO にしても自動では強くならない。案 B への移行はイベント構造が同型なので後からでも機械的に可能(ホステッド版のコンプライアンス要件が出た時点で再評価)。

**実装(2026-08-10 セッション 21)**: 案 A のとおり `user_audit_events`(§3.1)/ `org_audit_events`(§3.2)を D1 に実装した。列は §5.1 と同じ設計(頻出属性の列昇格 + payload JSON。auth_method は §2 どおり payload)で、D1 側イベントに現れない DO 専用列(チェーン・変数座標・鍵 FP・client_ts)は持たず、org 系の横断クエリ用に `org_id` / `project_id` を列昇格する。users への FK は張らない(監査行は記録対象の行より長生きし、参照整合が追記を阻害してはならない)。同一トランザクション追記(理由 (2))は各リポジトリが自分の D1 batch へ挿入文を同梱する形で実現し、主データ書き込みを伴わないイベント(`auth.login_failed` と device flow の `auth.login_succeeded`)のみ単独追記とする。記録は対応する操作 API が存在するイベントのみ(org の改名・削除・メンバー管理 API は未実装のため、該当イベントは API 導入時に記録を開始する)。読み取り API は §6〜§7 どおり作らない(Phase 2)。

### 5.3 保持と量

- v1 は無期限保持(削除 API を作らない)。DO SQLite は 10 GB / DO まであり、支配的な `var.read` の量はドッグフーディングで実測してから集約方針(§3.3)を決める
- プロジェクト削除時はチェーン・データもろとも DO ごと消える(監査ログだけ残す要件は v1 では持たない。ホステッド版で要検討 = 未決 #3)

## 6. 改竄耐性とアクセス制御

- 監査ログは**サーバー管理データであり、チェーンと違って暗号学的な改竄不能性はない**(サーバー = セルフホスト運営者は書き換え能力を持つ)。v1 の脅威モデルでは許容し、次で緩和する:
  - project DO の seq が単調・無欠番であること(欠番 = 削除の痕跡)
  - チェーンミラー部分はチェーン(署名付き)と突合して再構築・検証できること
  - **監査ヘッドのチェーンへのチェックポイント(2026-08-18 — 未決 #2 の解消。CRYPTO_SPEC §6.2 `checkpoint` / §5.1 の累積ハッシュ)**: **admin 以上**のクライアントがチェックポイント発行時にサーバー申告の累積ハッシュをチェーンへ公証する(checkpoint 自体の発行権限は member 以上だが、監査ヘッドの公証は申告取得の admin 限定 — AUTH_SPEC §16-2 — に従う。admin 未満の発行は公証なし = 空文字列)。**意味論は「発行時未検証の公証」**(発行者は全行を検証しない — クラス 2 の行は admin 未満に見えず、全行検証は重い): サーバーが「この時点でこの累積ハッシュだった」と主張した事実が署名済み・チェーン上に固定され、以後に公証済み接頭辞の行を改竄・削除すると、全行を読める admin の再計算と矛盾する(否認不能)。**admin の突合は「所属」に加えて「位置」を検査する(2026-08-18 pullfrog レビュー対応 — 陳腐化リプレイの遮断)**: 累積ハッシュ列を再計算しながら、**監査ヘッドを公証した(audit_head_hash が非空の)各チェックポイント**について、(a) 公証ヘッドが列に現れること、(b) その出現位置が公証チェックポイント間で非後退であること、(c) 出現位置が、**直前のチェックポイント(公証の有無を問わない — ミラー行はすべての checkpoint 受理が書く)自身のミラー行(`chain.checkpointed` — chain_seq で同定)以上**であること。公証の担い手は admin 以上の発行者に限られる(監査ヘッド申告の取得が admin 限定 — AUTH_SPEC §16-2 のタイミングサイドチャネル対応。CRYPTO_SPEC §6.3)。所属検査だけでは、悪意サーバーが実在する古い累積ハッシュ h_k を監査ヘッド取得(AUTH_SPEC §16-2)で返し続けることで、k 行目以降を無期限に改竄可能なまま全チェックポイントを通過できる(公証点の前進を何も強制しない)— (c) により保護接頭辞は各チェックポイントのミラー行まで単調に前進する。**同じ位置下限はサーバーの受理検証にも課される(CRYPTO_SPEC §6.4 — 正直なサーバーの下では (c) が構造的に必ず成立し、CAS 競合に敗れた正直な発行者の古い申告は受理段で拒否 → 申告の取り直しへ回る)。したがって突合での (b)(c) 違反は、良性の競合では生じえず、「受理ポリシーを執行しないサーバー」= 陳腐化リプレイを可能にする状態の証拠として扱う**(行の改竄そのものの証拠である所属違反とは区別して報告する — 2026-08-18 Bugbot / pullfrog 第 3 ラウンド対応)。チェックポイント追記自体がミラー行を書くため、この検査はチェーン・ワイヤに seq を追加せず(C1 裁定の件数非漏洩と両立)、全行を読める admin 側だけで完結する。**記録時点の虚偽(最初から偽の行を書く・書かない)は引き続き非保証**(本節の脅威モデルは不変 — 事後改竄の検出だけが新規利得)
  - **ヘッド申告(CRYPTO_SPEC §6.6)は監査イベント化しない(2026-08-18)**: 同期のたびに更新される高頻度・低情報の事象であり(var.read の肥大問題と同型)、要ローテーション検出(§4)に不寄与で、イベント化は「誰がいつ同期したか」の恒久的な行動記録を新設する — 本仕様のプライバシー最小化(§1-2 / 本節の可視性クラスの原則)と逆行する。申告の現在状態(メンバーごと最新 1 行)はデータプレーン(AUTH_SPEC §16-1)が保持し、サーバー受理時刻は配布しない
- **閲覧権限(2026-08-12 改訂 — 旧 v1 暫定案を置換。未決 #1 の解消)**: イベントを 2 つの可視性クラスに分ける。線引きの原則は「**人の行動の監視情報か、開示機構の作動か**」:
  - **クラス 1(チェーン role reader 以上 = 全メンバー)**: クライアント同期で既に配布・検証される事実、および開示機構の作動 — `chain.*` 全部、`env.*`、`var.created` / `var.renamed` / `var.deleted` / `var.version_pushed`、`server.*`、`rotation.recommended` / `rotation.dismissed`。チェーンミラーを admin に絞っても全メンバーはチェーン同期で同じ事実を検証・取得済みであり、絞りは見せかけの防御にしかならない。`server.*` は人ではなく開示機構の記録であり、自分の秘密の開示行使を知る正当な利害が全メンバー(reader 含む)にある(CRYPTO_SPEC §9 の常時明示義務の監査面)
  - **クラス 2(チェーン role admin 以上)**: 人間 actor の行動系 — `var.read`、`dek.registered` / `dek.deleted`、`invite.*`(保存は D1 = §3.2 だが可視性は同水準)、および他人が actor の行の横断検索。同僚の読み取りパターンはプライバシー情報であり、ガバナンス権限に束ねる
  - **本人が actor の行はクラスに依らず本人が閲覧可**。ユーザー系(§3.1)は本人のみ、org 系(§3.2)は org admin 以上(従来どおり)
  - **要ローテーションフラグの導出ビュー**(§4.1 の「現在有効な recommended − 解消」)はクラス 1 — 検出の目的は上流 credential のローテーションの促しであり、admin 限定では機能しない

## 7. API 境界

- 監査イベントの読み取りは HttpApi で公開する(ドメイン型のみ。Drizzle 型を出さない = ADR-0006)。追記 API は**公開しない**(イベントは各操作のサーバー側処理が生成する。クライアントが任意のイベントを書ける口を作らない)
- **読み取り API の形(2026-08-12 起草 — Phase 2)**: project DO 側は seq カーソルページング(limit ≤ 200)+ フィルタ(event 種別 / actor_user_id / target_user_id / variable_id / environment_id)。§6 の可視性クラスは認可段で強制し、クラス 2 の行・フィルタは admin 未満に対して**存在しないかのように振る舞う**(件数・ページングにも漏らさない)。要ローテーションフラグは独立の導出ビューエンドポイント(§4.1 の 5 の導出をサーバーが実行し、現在有効な集合を返す)。ユーザー系・org 系(D1)は同型のカーソルページング(本人 / org admin)。**例外: invite.*(保存は D1 — §3.2)の読み取りは org admin 軸に属さない**: プロジェクト監査の経路の一部として project_id スコープの D1 クエリで提供し、権限軸は当該プロジェクトの**チェーン role admin 以上**(§6 クラス 2 と同一)とする — org admin であることは invite.* の閲覧権限を与えず、チェーン role admin は org admin でなくても閲覧できる(2026-08-12 レビュー反映 — 保存先と権限軸を独立に定める)。CLI は `maruhi audit`、Web は監査 UI が消費する(Phase 2 C1 / W2)
- **カーソル・行識別子の不透明化と `seq` の admin 限定開示(2026-08-16 セッション 26 所有者裁定 — C1。pullfrog レビュー指摘の解消)**: 上記「seq カーソルページング」の順序付けは保存 `seq`(降順 = 新しい順)のままとするが、**ワイヤ上の行識別子とカーソルは `row_id`(§5.1 の乱数)を用いる** — 無欠番採番の序数を admin 未満に配ると、可視行の seq 差分からクラス 2 の件数・時刻窓が確定推論でき、本節の「件数にも漏らさない」と矛盾するため。カーソル(`before` = row_id)のサーバー側解決は**閲覧者の可視性述語つき**で行い、不可視・不明な row_id は同一に「空ページ」として振る舞う(カーソル探索を存在オラクルにしない。row_id は 128-bit 乱数であり推測自体も不能)。`seq` フィールドは **admin 可視(チェーン role admin × トークンスコープ admin)の project DO 応答にのみ**載せる: §6 の「欠番 = 削除の痕跡」検知は全行が見える閲覧者にだけ意味があり(admin 未満にとって欠番はクラス 2 秘匿と区別できない)、そこには保存する。**D1 経路(invite.* / ユーザー系)は `seq` を誰にも返さない**(§5.2 の autoincrement はデプロイメント全域の共有採番であり、序数はテナント・ユーザーを跨ぐ活動量を漏らす)。同じ理由で、**要ローテーションフラグの導出ビュー(§4.1 の 5)も監査 seq を運ばない**(順序は recommendedAtMs で足りる — B2 実装からの改訂)
- **取り下げの操作エンドポイント(2026-08-15 セッション 25 所有者裁定 — Wave 2 B2)**: `rotation.dismissed` は追記 API の例外ではなく**専用の操作エンドポイント**(`POST /projects/:projectId/rotation/dismissals` — 対象 (variable × environment) の列挙 1 件以上、all-or-nothing)として提供する。イベントはサーバー側処理が生成し(本節の原則のまま)、権限・対象検証は §3.3 の記録細則(admin 以上 × admin スコープ、有効フラグなしは 404)。要ローテーションフラグの導出ビュー(上記)は本エンドポイントの取り下げ対象の発見経路を兼ねる。CLI は `maruhi rotation list` / `maruhi rotation dismiss`(フラグビューと取り下げ — Wave 2 B2 で前倒し実装。生イベントの `maruhi audit` は C1 のまま)。表示名の解決はクライアントが検証済みメタステートメント(削除済み変数の tombstone ステートメントを含む — AUTH_SPEC §12-7)で行い、ビュー応答は識別子のみを運ぶ
- 例外: 将来 CLI / クライアントが「クライアント側でしか観測できない事象」を報告する必要が出た場合(例: エージェント環境検出による拒否)は、専用の狭い報告エンドポイントとして設計し、本仕様を改訂する

## 8. 未決事項

1. ~~監査ログ閲覧 UI の権限モデルの詳細~~ **解消(2026-08-12 — §6 の可視性クラス。本改訂 PR のマージをもって確定)**
2. ~~監査ヘッドのチェーンへのチェックポイント~~ **解消(2026-08-18 起草 — 本改訂 PR のマージをもって確定)**: CRYPTO_SPEC §6.2 `checkpoint` op に統合(§5.1 の累積ハッシュ + §6 の「発行時未検証の公証」意味論。旧 CRYPTO_SPEC 未決 #4 と同時解消)。実装は Phase 2 Wave 3 の後続 PR(設計比較は docs/notes/session-27.md)
3. プロジェクト削除後の監査ログ保全(ホステッド版のコンプライアンス要件が出た時点で: 削除前スナップショットの org 側への退避等)
4. `var.read` の集約方針(ドッグフーディングの実測後。§3.3 / §5.3)
5. エクスポート(SIEM 連携等)。テレメトリ禁止原則(CLAUDE.md)とは別物だが、明示操作のみ・pull 型のみで設計する
