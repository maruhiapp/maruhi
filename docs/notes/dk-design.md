# DK 設計録 — デバイス鍵分離(端末単位の失効)(2026-09-19 フェーズ 1 設計セッション・所有者承認待ち)

**位置づけ**: ROADMAP H 系列「仕様改訂群」の 3 つ目 = **DK: デバイス鍵分離 — 端末単位の失効**(CRYPTO_SPEC 未決 #2 の残り半分。順序は ES → PF1 → **DK** → PF2 → PF3 — 2026-09-14 所有者裁定)のフェーズ 1 成果物。設計の全体像・裁定の反復記録(巡数と棄却案を含む)・実装分割・承認依頼項目を持つ。仕様改訂の起草は docs/notes/dk-spec-drafts.md(CRYPTO_SPEC §3 / §5.1 / §6.2 / §6.3 / §6.4 / §6.5 / §7 / §8 / §11 / §13 / §14、AUTH_SPEC §5 / §6 / §11-1 / §12-3 / §12-6 / §12-8 / §13 / §16-1、AUDIT_SPEC §2 / §3.4 / §4.1 / §4.2 / §6)。**正本 3 文書・コード・テストベクターは本セッションでは触らない**(所有者が §4 の承認項目に答えた後、K1 以降を別セッションで行う — ES / KL3 と同じ手順)。様式は docs/notes/es-design.md に合わせる。

**前提**: (1) ES / PF1 は 2026-09-19 の K7(PR #183)で完了しており、本設計は ES の scope(`all` / `listed`・受信者集合 R(E)・原則 1)と PF1 の四眼(原則 2・票の (user_id, 鍵 FP) 束縛)を**前提として継承する**(蒸し返さない。帰結として既存規則の字面を変える必要が出た点は承認項目として提示する)。(2) KL3 の master 鍵ラップ台帳(CRYPTO_SPEC §8 — クラス S / G / H)と IV(§6.5 — リンク束縛 + 裏付け元)は実装済みで、DK はその上に載る。(3) **利用者がいないうちは古い実装をすべて削除してよい**(2026-09-14 所有者裁定)— 互換経路は持たず、旧クライアントは新 op に対して fail-closed になればよい。(4) 委任モデル(KL4)の据え置き(補足 19 19-3 (10))は蒸し返さず、DK の帰結として委任が構造的に安くなるかだけを見る。(5) ハードウェア封印(device-key-sealing.md 案 3)は DK の上に載る別項目で、本設計は「封印を妨げないこと」の確認だけを行う。

**用語(本設計録・ドラフト共通)**: **端末鍵(device key)** = 端末ごとに生成する enc(X25519)+ sig(Ed25519)の鍵対。チェーン上の鍵の単位であり、鍵フィンガープリント(§3 — `SHA-256(enc ‖ sig)` の先頭 16 バイト)で識別する。**予備鍵(reserve key)** = 端末鍵と同じ形の鍵対のうち、秘密鍵が **§8 の台帳にだけ住み、日常の端末には置かない**もの。全端末を失ったときに台帳から復元し、新しい端末鍵を登録するためだけに使う。チェーン上では普通の端末鍵と区別されない(区別は台帳側の事実)。**端末の上限(device cap)** = 端末鍵に付与する (role 上限, scope) の組。端末の**実効権限** = (min(人の role, 端末の role 上限), 人の scope ∩ 端末の scope)。旧「master keypair」の語は退役する(移行は裁定 DK-J)。

---

## 1. 全体像

### 1-1. 問題の再定義

現行(CRYPTO_SPEC §3 の v1 簡略化)は **1 ユーザー = 1 master keypair を全端末に複製する**。KL3 の台帳(§8)はこの複製を安全に運ぶ機構(リカバリーコード / パスキー PRF / 保護者 / 旧端末のハンドオフ)であり、複製そのものは変えていない。帰結:

- 「ノート PC を紛失した」に対して、その端末**だけ**を失効できない。紛失端末は master 鍵の平文をキーチェーンに持つため、台帳のラップを消しても API トークンを失効しても、鍵そのものは攻撃者の手元に残る。取れる手段は**鍵の再生成 = アイデンティティの作り直し**(`key generate` → 全プロジェクトで `remove_member` + 再招待 → 各プロジェクトの scope 全環境で rotate 義務 → リカバリー台帳の再構築)であり、ES で細かくした scope の意味論も四眼の票の束縛も、その作り直しの前では一律に「全部やり直し」に潰れる
- 端末を「他人に貸す」形の運用(CI 箱・Codespaces・電話)に、その端末の権限を人より狭くする手段がない。ES は**人**の scope を細かくしたが、同じ人の端末はすべて同じ鍵を持つため、端末を区別できない
- KL3 のハンドオフ(旧端末が B を新端末へ渡す)は master 鍵の**平文の移動**であり、移動のたびに全プロジェクトの全 DEK を開ける鍵が新しい端末に増える。増えた端末を後から減らす手段がない

DK が答える形: **鍵を端末に属させ、権限は人に属させたまま**にする。チェーンのメンバー(user_id・role・scope)は人であり、その人が持つ**端末鍵の集合**をチェーンが管理する。端末 1 台の失効 = その端末鍵を受信者集合 R(E) から外し(以後の DEK はその鍵へ包まれない)、その鍵による以後の署名を無効にし(値・メタ・チェーン op・票)、その端末が開けた DEK の rotate 義務を導出する — つまり **`remove_member` の端末版**である。人は残るので再招待も四眼の票の作り直しも要らない。

同時に「端末 = 鍵の単位」から自動的に従うもの:

- **義務の範囲**: 端末が開けた DEK は「その人の scope(∩ 端末の scope)の全環境」であり、失効の rotate 義務はそれと一致する(ES の帰結 — 端末は人の scope を超えない)
- **失効の履行者**: 端末を失効させる actor は同じ人の別端末(または本人を remove できる admin / owner)であり、いずれも当該環境の DEK を持つ(原則 1 の系)
- **予備鍵の必然**: 端末鍵しか無いと「全端末を失った人」は鍵をすべて失い、単独 owner のプロジェクトは死ぬ。よって**日常の端末に置かない鍵を 1 本、台帳にだけ置く**必要がある。これは KL3 の B(台帳のラップ対象)の意味を「複製の元」から「予備鍵」に変えるだけで、台帳の構造・バイト列は変えない

### 1-2. 機構の絵

```
人 U(チェーンのメンバー: user_id・role・scope — ES のまま)
├─ 端末鍵 D1(ラップトップ)     cap = (owner, all)            ← add_member / genesis で載る最初の鍵(payload 不変)
├─ 端末鍵 D2(電話)             cap = (owner, listed{})       ← add_device(D1 が署名)。DEK は受け取らない = 「票だけの端末」
├─ 端末鍵 D3(Codespace)        cap = (member, listed{dev})   ← add_device(D1 が署名)。dev だけ読める・書ける
└─ 予備鍵 R                     cap = (owner, all)            ← add_device(D1 が署名)。秘密鍵は §8 台帳にだけ住む

チェーン(1 プロジェクトに 1 本 — 不変)
  genesis      U   D1 の enc / sig                          scope = all
  add_device   U → R    [enc, sig, role_cap=owner, scope=all]           ← actor = (U, FP(D1))。本人だけが自分の端末を足せる
  add_device   U → D2   [enc, sig, role_cap=owner, scope=listed{}]      ← 新端末の cap ≤ 署名した端末の cap(単調性)
  add_device   U → D3   [enc, sig, role_cap=member, scope=listed{dev}]
  revoke_device U  [FP(D1)]                                            ← actor = (U, FP(D2)) — 電話から紛失ラップトップを失効。R(E) から D1 が外れ、
                                                                          D1 の以後の署名は無効。義務 = D1 の実効 scope(= all)の rotate

R(E) = { (m, d) | m ∈ 現メンバー, d ∈ devices(m), E ∈ scope(m) ∩ scope(d) } ∪ { g ∈ 有効 grant_server | E ∈ scope_environments(g) }
  R(prod) = { (U,D1), (U,R), … }        ← D2(scope 空)・D3(dev のみ)宛の prod ラップは生成も受理もされない
  R(dev)  = { (U,D1), (U,R), (U,D3), … }

署名者の同定 = (user_id, 鍵 FP) — 不変。FP が端末を指す。既存の「FP が一致し、その時点で user_id に束縛されていた鍵で検証する」(§5.1 / §6.3-1 / §6.6)は、
「その時点で有効(add_device 以後・revoke_device より前)だった端末鍵」と読めばそのまま成立する。
四眼の票 S の要素 (user_id, 鍵 FP) も不変。distinct は user_id で数える(同じ人の別端末は 1 票)。失効した端末の票は失効し、別端末で入れ直せる。

§8 台帳(KL3 — 構造・AAD・分片・ハンドオフの要求 / 承認 payload は不変)
  B = 予備鍵 R のブロブ(旧: master 鍵のブロブ — 同じ JSON 形)
  受信者: recovery-code / passkey-prf / guardian(保護者の**各端末鍵**へ分片を封印)
  ハンドオフ: 要求者 = 本人、承認者 = 保護者のみ(旧端末の承認 `kind = "device"` / `source = "device"` は不要になり削除 — 日常の端末は B を持たない)

端末の追加(儀式なし・秘密の移動なし)
  新端末: login → `device add`  → 端末鍵を生成 → 公開鍵を要求行として登録 → FP(12 語 / hex)を表示
  既存端末: `device approve <FP>` → 要求行の公開鍵を FP で照合 → 全プロジェクトへ add_device + 全エポックの DEK を新端末へバックフィル
  (運ぶのは FP = 公開情報。サーバーが公開鍵をすり替えても FP 照合で落ちる — §3 の FP 強度の前提どおり)
```

端末を失った人の導線(1 本): 別端末で `maruhi device revoke "MacBook"` → 全プロジェクトへ `revoke_device` → 履行できる rotate はその場で(sweep)→ 履行できないもの(reader のプロジェクト)は誰が rotate すべきかを表示 → 紛失端末の API トークンも失効。CLI の端末が無ければ Web でトークン失効(即時の遮断)→ `key recover` で予備鍵を復元 → 上の導線。

### 1-3. 影響範囲(仕様の節 × 実装ファイル)

| 層 | DK |
|---|---|
| CRYPTO_SPEC | §3(v1 簡略化の解消・端末鍵 / 予備鍵 / cap の定義・FP は端末を指す)/ §5.1(署名者 FP = 端末鍵の選択 — 字面の一般化)/ **§6.2**(role 表に reader の自己端末管理・新 op `add_device` / `revoke_device`・端末の実効権限の置換規則・単調性・鍵一意性の端末集合への拡張・R(E) の端末軸・四眼の票の端末語彙・検査順序)/ §6.3(1 の鍵選択と 3′ の端末実効 scope・ラップ先 R(E) の端末軸・(a) 招待者鍵の照合)/ §6.4(受理・端末数の受理ポリシー)/ §6.5(相互確認の対象 = 受諾**端末**の鍵 — 字面のみ)/ §6.6(申告者 = 端末)/ **§7**(`revoke_device` の rotate 義務・履行者・バックフィル経路)/ **§8**(B = 予備鍵・`kind = "device"` と `source = "device"` の削除・保護者分片の端末展開・台帳の変更に予備鍵の開封が要ること)/ §11(ベクター)/ §13 #2 の解消 / §14.2 保証 11・§14.3 非保証 10 |
| AUTH_SPEC | §5(セッション許可列挙に端末一覧の読み取り)/ §6(端末ごとのトークンと端末鍵の対応 — 既定名 `cli:<hostname>` の言及)/ §11-1(新 op のトークン水準)/ §12-3(DEK ラップ登録の reader 自己バックフィル)/ **§12-6**(受信者同定 = (user_id, 端末 enc 公開鍵)・スロットの端末軸・6 番目の登録経路・掃除規則)/ §12-8(端末数の上限)/ **§13**(B = 予備鍵・ハンドオフの device 経路削除・保護者分片の端末行・**新 §13-11 端末登録簿と端末追加要求 API**)/ §16-1(申告行を (user_id, 端末 FP) 単位に) |
| AUDIT_SPEC | §2(鍵 FP = 端末の注記)/ **§3.4**(`chain.device_added` / `chain.device_revoked` ★)/ §4.1(`revoke_device` 変種 — 端末の窓・(a) の照合に actor 鍵 FP)/ §4.2(Q1 の列挙)/ §6(クラス 1 の明記) |
| crypto | `chain-types.ts`(`ChainMember.devices`・`AddDevicePayload` / `RevokeDevicePayload`・`DeviceCap`)/ `chain-canonical.ts`(2 op のフィールド順・FP リストの入れ子 LP)/ `chain-verify.ts`(2 op の合意規則・実効権限の置換・単調性・鍵一意性の端末集合・票の端末妥当性)/ `chain-history.ts`(端末ごとの有効区間 (added_seq, revoked_seq, cap))/ `validate.ts` / `value-verify.ts` / `meta-verify.ts` / `manifest-verify.ts` / `attestation` の鍵選択(FP → 端末鍵・有効区間・実効 (role, scope))/ `member-scope.ts`(∩)/ `master-wrap.ts`(kind `device` の削除)/ `errors.ts`(理由コード) |
| test-vectors | `chain-entries.json` **追記**(seq 25〜: add_device / revoke_device の正例・負例・`expected_head_states` の members に `devices`。正規チェーン seq 1〜24 のバイト列は不変)、`value-signature.json` / `metadata-signature.json` / `env-manifest.json` / `head-attestation.json` に端末軸の負例を**追記**(既存正例・負例は不変 — 参照する seq ≤ 24 のハッシュが変わらないため)、`master-key-wrap.json` **再生成**(`handoff-device` 正例と `aad-kind-mismatch` の kind=device 形の削除 — 互換経路を作らない裁定の写し・README 規約 28 として意図的な例外)、`dek-wrap.json` / `dek-wrap-signature.json` / `dek-commitment.json` / `recovery-wrap.json` / `lease-wrap.json` / `invite-*.json` / `audit-head.json` / `checkpoint-digest.json` / `encoding.json` / `variable-encryption.json` は**不変**(HPKE info・AAD・発行文・受諾文に触れない) |
| api-schema | `chain.ts`(2 op)/ `dek-wraps`(受信者に端末 enc 公開鍵 — 既存フィールド)/ `key-wraps`(device 経路の削除・保護者分片の端末行)/ 新 `devices` グループ(登録簿・追加要求)/ `errors`(`DeviceLimit`) |
| server | `chain-accept.ts`(2 op の受理副作用: ミラー・要ローテーション検出・申告行削除)/ `dek-wraps.ts`(R(E) の端末展開・受信者判定・スロット主キーに enc 公開鍵)/ `do-schema.ts`(`dek_wraps` PK・`head_attestations` の端末軸)/ `rotation-detect.ts`(端末の窓)/ `handlers-key-wraps.ts` + `db.package/key-wraps.ts`(device 経路削除・分片の端末行)/ 新 `handlers-devices.ts`(登録簿・要求)/ `policy.ts`(端末数)/ `authz.ts`(reader の自己バックフィル)/ `core/audit.ts`(ミラー写像) |
| CLI | **新規 `device.ts`**(`device add / approve / list / revoke`)/ `keygen.ts`(端末鍵 + 初回のみ予備鍵)/ `recovery.ts` / `passkey.ts` / `guardian.ts`(B = 予備鍵・台帳変更時の予備鍵開封・保護者の端末列挙)/ `handoff.ts`(device 経路削除 → 保護者承認は `guardian approve`)/ `master-ops.ts`(端末鍵の狭い操作 — 名前は据え置き可)/ `dek-wrap.ts` / `backfill.ts`(R(E) の端末展開・add_device バックフィル)/ `rotation-sweep.ts`(第 5 種 `device-revoked`)/ `known-fingerprints.ts`(user_id → FP の集合)/ `context.ts` / `sync.ts`(自分の端末鍵の有効性・初回同期の端末登録)/ `member.ts`(`member list` に端末数)/ `login.ts`(トークンと端末 FP の紐付け — 任意)/ `effect-cli.ts` / `help.txt` |
| web | `chain-view.ts` / `ProjectScreen.tsx`(メンバー行に端末数 — 読み取りのみ)/ 端末一覧(登録簿 — 「サーバー申告」表示)・トークン失効への導線(既存機能) |
| docs | `apps/site/docs/recover-your-key.mdx`(予備鍵・ハンドオフの整理)/ `linux-keychain.mdx`(Codespaces = 端末として追加)/ 新規 `devices.mdx` / `invite-a-teammate.mdx`(`key publish` は端末ごと)/ `docs/SELF_HOSTING.md` "Updates" |

### 1-4. 変えないもの(制約の確認)

- **暗号プリミティブ・HPKE info・AAD は不変**: DEK ラップの info(§5 — `recipient_user_id` まで)は端末を含めない。同じ人の 2 端末は鍵が違うので、A 宛のラップを B が開くことは HPKE が既に拒む。登録署名(§5.1)は `recipient_enc_pub_hex` を束縛済みで、端末はそこで固定される。§8 の AAD / info・XOR 分片・ハンドオフの `handoff-wrap` info も不変(`kind` の値集合から `device` が消えるだけ)
- **「署名するのは人間だけ」**: 端末鍵の保持者は人。機械メンバー(サーバー鍵・ワークロード)の扱いは不変(裁定 DK-K)
- **チェーン・監査にプロバイダ ID を書かない**: 端末の表示名(「MacBook」)はチェーンに載せない。actor は (user_id, 鍵 FP) のまま — FP が端末を指す
- **意味論は署名バイト列の中(§1 原則 6)**: 端末の cap(role 上限・scope)は `add_device` payload の LP フィールド。端末の表示名・トークンの対応は署名の外(登録簿 — advisory)に置き、検証規則に用いない
- **ES の scope・原則 1・PF1 の原則 2 は前提のまま**: 端末の実効権限は人の権限との min / ∩ であり、人の権限を超えない。四眼の distinct は user_id、票は (user_id, FP)
- **`add_member` / `change_role` / `genesis` の payload は不変**: ES の `chain-entries.json` 正規チェーン(seq 1〜24)のバイト列は変わらない。新 op は末尾に追記する(§6.2 `checkpoint` op 追加時と同じ「追記で拡張」の型)
- **招待の形(IV1 / IV2)は不変**: 受諾する鍵 = 受諾した端末の鍵。裏付け元(GitHub 署名鍵)へは端末ごとに `key publish` する(GitHub は複数の署名鍵を持てる)。発行文・受諾文の LP は触らない
- **Web は鍵を持たない(ADR-0018)**: 端末の一覧は読み取り(サーバー申告)、端末の追加・失効はチェーン op なので CLI のみ。紛失時に Web でできるのは既存のトークン失効(資格を減らす方向 — 改訂 2 の境界内)
- **旧クライアントは fail-closed**: `add_device` / `revoke_device` は未知 op としてチェーン検証で拒否される(`invalid-payload`)。互換経路なし
