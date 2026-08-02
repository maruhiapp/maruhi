# maruhi 監査ログ仕様書 (AUDIT_SPEC)

Version: 0.4
Status: 承認済みベース + 改訂レビュー中(0.3 は 2026-08-02 の PR #18 マージにより所有者承認確定。§3.3 の `dek.registered` への署名者鍵 FP の追加は 2026-08-02 のセッション 07 レビュー所有者裁定 2-E — CRYPTO_SPEC §5.1 — をセッション 09 で反映。この改訂の確定条件 = PR レビュー承認)

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

- `auth.session_created` は `auth.login_succeeded` と 1:1 なので独立イベントにしない
- トークン**使用**はイベント化しない(高頻度・低情報。api_tokens.last_used_at と、データ系イベントの actor.api_token_id が代替)

### 3.2 org 系

| イベント | 主な属性 |
|---|---|
| `org.created` / `org.renamed` / `org.deleted` | org_id(パーソナル org 自動作成も記録) |
| `org.member_added` / `org.member_removed` | target_user_id, org role |
| `org.member_role_changed` | target_user_id, 旧/新 role |
| `org.project_created` / `org.project_deleted` | project_id |

org ロールはプロジェクトアクセスに関与しない(AUTH_SPEC §9-2)ため、org 系イベントは要ローテーション検出に関与しない。

### 3.3 プロジェクト データ系 ★

すべて project DO 内に記録(§5)。variable_id / environment_id は CRYPTO_SPEC §4 の識別子。

| イベント | 主な属性 | 備考 |
|---|---|---|
| `env.created` / `env.renamed` / `env.deleted` | environment_id, 名前スナップショット | |
| `var.created` ★ | variable_id, environment_id, 変数名スナップショット | |
| `var.version_pushed` ★ | variable_id, environment_id, version, epoch | 値の更新(平文・暗号文は含めない) |
| `var.renamed` | variable_id, environment_id, 新名スナップショット | |
| `var.deleted` ★ | variable_id, environment_id | 削除しても過去の閲覧可能性は消えない(§4) |
| `var.read` ★ | variable_id, environment_id, epoch, version | 暗号文の配布(pull / Web での取得)。一括 pull は変数ごとに 1 行(§4 のクエリ要件のため) |
| `dek.registered` | environment_id, epoch, target_user_id(受信者), **actor_key_fingerprint(署名者鍵 FP)** | DEK ラップの登録(AUTH_SPEC §12-6。環境作成時のエポック 1 の同梱分を含む)。actor_key_fingerprint には登録署名(CRYPTO_SPEC §5.1)の署名者鍵 FP を写す(署名との突合用。セッション 07 裁定 B) |
| `dek.deleted` | environment_id, epoch, target_user_id(受信者) | admin による毒ラップの削除(AUTH_SPEC §12-6 の修復経路) |
| `rotation.recommended` | target_user_id, 対象 (variable × environment) 集合, 根拠種別 | §4 の算出結果の永続化(UI / CLI 表示用) |
| `rotation.dismissed` | 対象 (variable × environment) | 人間による明示的な取り下げ(append-only の打ち消しイベント) |

- `var.read` の粒度と量: CI からの定期 pull で最も高頻度になるイベント。v1 は素直に 1 変数 1 行で記録し、ドッグフーディングで量を実測してから集約(例: 同一 (actor, variable, environment) の読みを日単位で 1 行に丸める)を判断する。**要ローテーション検出に必要なのは「期間内に読んだか否か」だけなので、集約しても検出は劣化しない**
- `dek.registered` の actor_key_fingerprint(2026-08-02 セッション 09 反映): データ系イベントの actor は原則 user_id(+ トークン id / auth_method)のみで鍵 FP を持たない(FP を持つのはチェーンミラー §3.4)が、**dek.registered はこの例外**として、登録署名(CRYPTO_SPEC §5.1)の署名者鍵 FP を actor_key_fingerprint 列に写す。監査行(サーバー管理データ)とラップ行のチェーン外署名(クライアント署名 = サーバーが偽造できない)を突合可能にするための記録であり、§2 のアクターモデル(type=user の key_fingerprint)の範囲内である。`dek.deleted` は署名を伴わない操作のため FP を持たない
- `dek.registered` / `dek.deleted` の粒度は **1 受信者 1 行**(2026-08-02 セッション 08 提案): §5.1 の列構造は 1 行 1 target(target_user_id は単値)であり、受信者ごとの行にすることで「この受信者宛のラップがいつ登録・削除されたか」を索引(target_user_id, seq)でそのまま引ける。登録はローテーション・メンバー追加時のみの低頻度イベントで、行数は AUTH_SPEC §12-8 のラップ行数上限が束縛する。v1 の要ローテーション検出(§4.1)には関与しない(候補集合は全メンバー × 全環境で算出するため)が、将来の環境スコープ role(CRYPTO_SPEC 未決 #11)で「誰がどのエポックの DEK を受け取ったか」が候補集合の入力になった場合の証跡を確保する
- 「新バージョン push」は要ローテーションフラグの解消条件でもある(§4)

### 3.4 チェーン操作のミラー ★

チェーン追記の受理時(サーバー検証通過後)に、対応する監査イベントを同じ project DO に追記する。`chain_seq` で元エントリを参照し、actor はチェーンエントリの actor(user_id + 鍵 FP)をそのまま写す。チェーンエントリのクライアント時刻とサーバー受理時刻の両方を持つ。

| イベント | 対応する op(CRYPTO_SPEC §6.2) |
|---|---|
| `chain.genesis` ★ | `genesis`。**target_user_id には作成者(= actor.user_id)を入れる**(作成者の在籍区間の開始点を Q1 の索引で引けるようにするため) |
| `chain.member_added` ★ | `add_member`(target_user_id, role) |
| `chain.member_removed` ★ | `remove_member`(target_user_id) |
| `chain.role_changed` | `change_role` |
| `chain.epoch_rotated` ★ | `rotate_epoch`(environment_id, 新エポック, 理由) |
| `chain.server_granted` ★ | `grant_server`。**target_key_fingerprint に付与対象のサーバー鍵 FP** を入れ、スコープ(対象環境集合)は payload に写す |
| `chain.server_revoked` ★ | `revoke_server`。**target_key_fingerprint に失効対象のサーバー鍵 FP** を入れる |

- **バックフィル(2026-08-02 セッション 07 裁定)**: ミラーの記録は監査ログ実装の導入後に受理されたエントリから開始する。導入前に受理されたチェーンを持つ DO は存在しない(未リリース)ため、v1 では既存チェーンのバックフィルを実装しない。将来スキーマ移行等で必要になった場合は、§1-5(ミラーはチェーンから再構築可能)に基づく再構築処理として設計する

### 3.5 grant_server 経由のサーバーアクセス ★

サーバーが開示済み DEK を実際に行使した記録。actor は `{ type: "server", key_fingerprint }`。

| イベント | 主な属性 | 備考 |
|---|---|---|
| `server.dek_unwrapped` | environment_id, epoch | サーバーがラップ済み DEK を復号した |
| `server.value_decrypted` ★ | variable_id, environment_id, epoch, version | 同期処理での平文化。1 変数 1 行 |
| `server.sync_executed` | sync_config_id, 結果種別 | 外部への送出。宛先の詳細(リポジトリ名等)は可変ストアの設定を `sync_config_id` で参照し、ログには書かない |

`revoke_server` 時の要ローテーション検出は §4.1 の revoke_server 変種(区間 = grant 区間、候補 = grant スコープ内、実読み取り = `server.value_decrypted`)で行う。

## 4. 要ローテーション検出からのクエリ要件(逆算)

### 4.1 アルゴリズム(CRYPTO_SPEC §7 の実装)

`remove_member(M)` の受理時、同じ project DO 内で:

1. **在籍区間の復元**: チェーンミラーから M の `chain.member_added`(または target_user_id = M の `chain.genesis`)〜 `chain.member_removed` の区間を全て求める(再追加があれば複数区間の和)
2. **候補集合(閲覧可能だった集合)**: v1 は全メンバーが全環境・全エポックの DEK を受け取る(CRYPTO_SPEC §3)ため、「在籍区間と存在期間が重なる全 (variable × environment)」が閲覧可能だった集合になる。`var.created` 〜 `var.deleted`(未削除なら現在まで)の存在区間と在籍区間の重なりで判定する。**削除済み変数も含める**(上流 credential は変数を消しても失効しない)
3. **根拠のランク付け**: 候補集合を 2 水準に分ける — (a) **確実に取得した**: 在籍区間内に M の `var.read` があるもの(API トークン経由を含む。actor.user_id で照合)、(b) **取得可能だった**: それ以外の候補全部。UI / CLI は (a) を強調表示する
4. **結果の永続化**: `rotation.recommended` イベントとして追記し、UI / CLI は「要ローテーション」フラグとして表示する
5. **フラグの解消**: 対象 (variable × environment) への `var.version_pushed`(= 上流をローテーションして新しい値を入れた)または `rotation.dismissed` で解消。解消状態はイベント列から導出する(フラグ自体を可変ストアに持たない)

**`revoke_server` の変種**: 同じ骨格で次を差し替える — 手順 1 の区間は当該サーバー鍵 FP の `chain.server_granted` 〜 `chain.server_revoked`(再 grant があれば区間ごと)。手順 2 の候補は各 grant のスコープ(対象環境の部分集合。CRYPTO_SPEC §6.2)に含まれる環境の変数に限定。手順 3 の (a) は `var.read` の代わりに `server.value_decrypted`(actor_key_fingerprint = サーバー鍵 FP で照合)を使う。手順 4〜5 は同じ。

環境スコープ role(CRYPTO_SPEC 未決事項 #11)が入った場合は、手順 2 の「全環境」が「M がアクセス権を持っていた環境」に狭まる。チェーンミラーが role / スコープを写しているため、この拡張はクエリの変更だけで成立する(スキーマ変更不要)。

### 4.2 スキーマが満たすべきクエリ要件

| # | クエリ | 必要な索引 |
|---|---|---|
| Q1 | user_id → 在籍区間(chain.member_added / removed / genesis の列) | (target_user_id, seq) |
| Q2 | (variable × environment) の存在区間(var.created / deleted の列) | (variable_id, environment_id, seq) |
| Q3 | user_id × 期間 → 読んだ (variable × environment) の distinct 集合 | (actor_user_id, seq) + イベント種別 |
| Q4 | (variable × environment) × 期間 → 閲覧・変更した主体一覧(逆引き。インシデント対応用) | Q2 と同じ索引 |
| Q5 | 現在有効な rotation.recommended − 解消イベント | イベント種別 + (variable_id, environment_id, seq) |
| Q6 | サーバー鍵 FP → grant 区間とスコープ(chain.server_granted / revoked の列)、および期間内の server.value_decrypted(actor_key_fingerprint で照合) | (target_key_fingerprint, seq) + (actor_key_fingerprint, seq) |

これらは**単一の project DO 内で完結する**(クロス DO join なし)。§5 の配置はこの性質を保つことを最優先に選ぶ。

## 5. 保存先とスキーマ

### 5.1 プロジェクト系イベント(§3.3〜3.5): project DO 内 append-only(基本方針)

- 保存先はプロジェクト DO の SQLite。チェーン(同 DO)とデータ本体に併置することで、§4 のクエリがクロスストア join なしで成立し、チェーン追記とミラー追記を同一トランザクションで書ける(DO の直列化により seq が単調・無欠番になる)
- テーブル(Drizzle スキーマは実装時。ADR-0006 によりリポジトリサービス内に隔離):

```sql
audit_events (
  seq         INTEGER PRIMARY KEY,  -- DO 直列化による単調増加。欠番なし
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

### 5.2 org / ユーザー系イベント(§3.1〜3.2)の置き場所: 選択肢比較

プロジェクト DO には置けない(プロジェクトに属さないイベントであり、ユーザーは複数プロジェクトにまたがる)。候補:

| 案 | 内容 | 利点 | 欠点 |
|---|---|---|---|
| **A: D1 に専用テーブル** | `user_audit_events` / `org_audit_events`(構造は 5.1 と同型、seq は autoincrement) | users / sessions / api_tokens / memberships が既に D1 にあり、参照整合と横断クエリ(「このユーザーの全認証イベント」)が自然。新しい DO クラス不要で v1 の実装量最小。書き込み頻度は低くロック競合の懸念なし | DO の直列化保証がなく seq の無欠番性が弱い(D1 の autoincrement で実用上は足りる)。「全ログは DO 内」という一貫性が崩れる |
| B: ユーザー DO + org DO を新設 | 主体ごとに 1 DO、5.1 と同じ構造 | 全ログが同一パターン。ホステッドでの分離が強い。将来のユーザー単位エクスポートが楽 | v1 で DO クラス +2。認証フロー(D1 トランザクション)とログ追記が別ストアになり原子性を失う。横断管理クエリ(不審ログイン監視等)がファンアウトになる |
| C: org DO のみ新設し、ユーザー系も所属パーソナル org に置く | DO パターンで統一しつつ +1 クラス | — | ユーザーは複数 org に属せるため「どの org に書くか」が人工的。リンク・リカバリー等 org と無関係なイベントの置き場が歪む |

**提案: 案 A(D1)を v1 に採用する。** 理由: (1) §4 の中核クエリはすべてプロジェクト DO 内で完結しており、org / 認証系イベントは検出に関与しない = DO 併置の利点がない。(2) 認証系イベントは記録対象(sessions / tokens)と同じ D1 に置くことで、発行・失効処理と同一トランザクションで追記できる。(3) append-only はどのストアでも「コード規律 + 追記専用サービス境界」で守るものであり、DO にしても自動では強くならない。案 B への移行はイベント構造が同型なので後からでも機械的に可能(ホステッド版のコンプライアンス要件が出た時点で再評価)。

### 5.3 保持と量

- v1 は無期限保持(削除 API を作らない)。DO SQLite は 10 GB / DO まであり、支配的な `var.read` の量はドッグフーディングで実測してから集約方針(§3.3)を決める
- プロジェクト削除時はチェーン・データもろとも DO ごと消える(監査ログだけ残す要件は v1 では持たない。ホステッド版で要検討 = 未決 #3)

## 6. 改竄耐性とアクセス制御

- 監査ログは**サーバー管理データであり、チェーンと違って暗号学的な改竄不能性はない**(サーバー = セルフホスト運営者は書き換え能力を持つ)。v1 の脅威モデルでは許容し、次で緩和する:
  - project DO の seq が単調・無欠番であること(欠番 = 削除の痕跡)
  - チェーンミラー部分はチェーン(署名付き)と突合して再構築・検証できること
  - 将来オプション: 監査ログのヘッドハッシュを定期的にメンバーシップチェーンへチェックポイントとして追記し、署名で束縛する(CRYPTO_SPEC 未決事項 #4 と同じ機構。未決 #2)
- 閲覧権限(v1): プロジェクト監査ログはチェーン role の **admin 以上**。自分が actor のイベントは本人も閲覧可。ユーザー系(§3.1)は本人のみ、org 系(§3.2)は org admin 以上。Phase 2 の監査ログ UI で再設計する(未決 #1)

## 7. API 境界

- 監査イベントの読み取りは HttpApi で公開する(ドメイン型のみ。Drizzle 型を出さない = ADR-0006)。追記 API は**公開しない**(イベントは各操作のサーバー側処理が生成する。クライアントが任意のイベントを書ける口を作らない)
- 例外: 将来 CLI / クライアントが「クライアント側でしか観測できない事象」を報告する必要が出た場合(例: エージェント環境検出による拒否)は、専用の狭い報告エンドポイントとして設計し、本仕様を改訂する

## 8. 未決事項

1. 監査ログ閲覧 UI の権限モデルの詳細(Phase 2 の監査ログ UI と同時に設計。§6)
2. 監査ヘッドのチェーンへのチェックポイント(改竄検出の強化。CRYPTO_SPEC 未決 #4 と統合して設計)
3. プロジェクト削除後の監査ログ保全(ホステッド版のコンプライアンス要件が出た時点で: 削除前スナップショットの org 側への退避等)
4. `var.read` の集約方針(ドッグフーディングの実測後。§3.3 / §5.3)
5. エクスポート(SIEM 連携等)。テレメトリ禁止原則(CLAUDE.md)とは別物だが、明示操作のみ・pull 型のみで設計する
