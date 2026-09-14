# ES 設計録 — 環境スコープの role + PF1 四眼(2026-09-14 フェーズ 1 設計セッション・所有者承認待ち)

**位置づけ**: ROADMAP H 系列「仕様改訂群」の 1 つ目 = **ES: 環境スコープの role**(CRYPTO_SPEC 未決 #11)と、同じ改訂サイクルで設計する **PF1: 四眼(チェーン上の複数署名承認)** のフェーズ 1 成果物。設計の全体像・裁定の反復記録(巡数と棄却案を含む)・実装分割・承認依頼項目を持つ。仕様改訂の起草は docs/notes/es-spec-drafts.md(CRYPTO_SPEC §3 / §6.2 / §6.3 / §6.4 / §6.5 / §7 / §11 / §13 / §14、AUTH_SPEC §6 / §9-2 / §11-1 / §12-3 / §12-4 / §12-6 / §12-7 / §12-8 / §14-1 / §15、AUDIT_SPEC §3.3 / §3.4 / §4.1 / §6)。**正本 3 文書・crypto・server・CLI はまだ触っていない**(承認後の K1 以降で反映)。様式は integration-options.md 補足 19(KL3)/ 補足 21(IV)に合わせ、独立ファイルに置く(value-free-schema-design.md の先例)。

**前提(2026-09-14 所有者裁定 — ROADMAP)**: ES / PF1 は H4 法務の前に着地する招待制ベータのゲート。両方とも CRYPTO_SPEC §6.2 の合意規則を変えるため 1 回の改訂・1 回のテストベクター再生成に束ねる。**利用者がいないうちは古い実装をすべて削除してよい** — 互換経路(旧形式の受理・フォールバック)は持たず、旧クライアントは新しい op / payload に対して fail-closed になればよい。DK(デバイス鍵分離)は本設計の結果を前提にするため後続。

**承認状況**: 未承認。§5 の承認依頼項目(1〜24)を所有者へ提示して止まる。

---

## 1. 全体像

### 1-1. 問題の再定義

現行 v1 の簡略化(CRYPTO_SPEC §3)は「**全メンバーが全環境の DEK を受け取る**」。プロジェクトに入れた相手は role が reader でも prod を復号できる。競合の RBAC は「サーバーの方針」で prod を隠すが、サーバーが侵害されれば方針は消える。maruhi の差別化(ADR-0014 決定 1「信じなくてよい相手の範囲が広い」)を環境軸へ延ばすには、**方針ではなく鍵配布で制限する**必要がある — スコープ外のメンバー宛には prod の DEK ラップが**存在しない**ので、サーバーが侵害されても開かない。

同時に、鍵配布で制限すると次が自動的に従う:

- **ラップの実行者は DEK 保持者**(§7)なので、「誰かをある環境へ入れる」操作は、その環境の DEK を持つ者にしかできない(暗号的必然 — 方針で緩められない)
- **メンバー削除時の rotate 義務**(§7 の「全環境」)は「そのメンバーが DEK を持っていた環境」に縮む — dev 専任メンバーの退職で prod をローテーションしなくてよくなる(競合との運用差)
- スコープの**縮小**は当該環境からの remove と等価であり、同じ rotate 義務を負う(`grant_server` の再 grant がスコープ縮小を拒否して `revoke_server` + rotate を強いる論理 — §6.3 — のメンバー版)

四眼(PF1)は別の問題に答える: 今は owner 1 人の署名で `grant_server`(サーバーに鍵を渡す)や `remove_member` が通る。owner のアカウント 1 つの乗っ取り・内部の 1 人の暴走で全部が動く。**2 人の owner の署名を要求すれば「1 人では危険な操作ができない」が暗号で保証される**(監査で気づくのではなく、そもそも通らない — 補足 17)。§6.2 の合意規則が変わる = 全クライアントの検証規則が変わるため、ES と同じ改訂で束ねる。

### 1-2. 機構の絵(鍵配布)

```
チェーン(署名付き・全メンバーへ配布・全クライアントが検証)
  genesis                 owner  A   scope = all(構造的に固定)
  add_member  B  role=member scope=all
  add_member  C  role=member scope=listed{dev, staging}   ← actor A の scope ⊇ {dev, staging}(包含規則)
  add_member  D  role=reader scope=listed{prod}
  change_role C  role=member scope=listed{dev}            ← 縮小 = staging からの remove 相当 → §7 義務(staging のみ rotate)

環境 E のラップ受信者集合 R(E) = { m ∈ 現メンバー | E ∈ scope(m) } ∪ { g ∈ 有効 grant_server | E ∈ scope_environments(g) }
  R(prod)    = { A, B, D }        ← C 宛の prod ラップは生成も受理も禁止(§6.3 の「ラップ先 = 現メンバーと厳密一致」の環境軸版)
  R(dev)     = { A, B, C }
  R(staging) = { A, B }(C の縮小後)
  新環境 E' の作成: actor の scope に E' が含まれる = scope = all の actor のみ(listed の scope に未存在の環境は入りえない)。R(E') = all-scope メンバー(+ 開示 grant)

スコープ外メンバー(例: C から見た prod)が受け取るもの(裁定 G):
  ○ チェーン(全エントリ — prod の checkpoint タプルも含む。検証は行うが基準としては使わない)
  ○ 環境の存在・表示名・変数名・スキーマ欄・マニフェスト・tombstone(平文メタ = 未決 #3 の線のまま。メタのみ pull は可)
  ✕ 暗号文・自分宛 DEK ラップ(値付き pull は拒否)・push / メタ書き込み / rotate / checkpoint(環境対象 op は scope 内のみ)
```

四眼(PF1)の絵:

```
  set_approval_policy  ops={grant_server, remove_member, change_role, set_approval_policy} required=2   ← owner ≥ 2 のときだけ有効化できる
  propose   #p1  op=grant_server payload=<正規化 payload> expires_at_ms=…   ← 提案者 = その op を実行できる role(owner が提案すれば 1 票)
  approve   #p1                                                            ← 別の owner。distinct owner の票が required に達した approve エントリの seq で内側 op を適用
  (適用時に内側 op の合意規則を「適用時点の状態」で再検査。remove_member の §7 義務は適用 seq から)
  withdraw  #p2                                                            ← 提案者または任意の owner が pending 提案を閉じる
```

### 1-3. 影響範囲(仕様の節 × 実装ファイル)

| 層 | ES | PF1 |
|---|---|---|
| CRYPTO_SPEC | §3(v1 簡略化の解消)/ §6.2(payload・合意規則・受信者集合)/ §6.3(ラップ先・宣言ヘッド時点のスコープ・DEK 受信規則)/ §6.4(受理検証)/ §6.5(発行文に scope)/ §7(義務の縮小・縮小義務)/ §11(ベクター)/ §13 #11 解消 / §14.2(保証の追加) | §6.2(新 op 4 種・合意規則)/ §6.3(検証状態に方針・pending 提案)/ §6.4(受理ポリシー)/ §7(義務の起点)/ §11 / §14.2 |
| AUTH_SPEC | §6(トークン環境スコープの将来項の整理)/ §9-2(実効権限の環境軸)/ §12-3(環境対象 op の scope 条件)/ §12-4(複合の受信者集合・actor scope)/ §12-6(受信者判定・バックフィル経路)/ §12-7(pull の scope 拒否)/ §14-1(合成なし = 不変の明記)/ §15(招待の scope) | §6(op 別権限水準に新 op)/ §11-1(提案・承認は汎用 append)/ §12-8(pending 上限) |
| AUDIT_SPEC | §3.3(`rotation.recommended` の縮小変種)/ §3.4(ミラー payload に scope)/ §4.1(候補集合 = 環境別アクセス窓)/ §6(可視性クラス不変の明記) | §3.4(`chain.proposed` 等 + 適用 op のミラー)/ §6(クラス 1) |
| crypto | `chain-types.ts`(ChainMember / AddMemberPayload / ChangeRolePayload に scope)/ `chain-canonical.ts`(payload_field_order・scope LP)/ `chain-verify.ts`(構造・包含・環境対象 op の scope 検査)/ `chain-history.ts`(tenure の (role, scope) span・`memberStateAt` に scope)/ `validate.ts`(`headAuthorizationReason` に environmentId)/ `value-verify.ts` / `meta-verify.ts` / `manifest-verify.ts`(理由コード)/ `invite-link.ts`(発行文)/ `errors.ts` | `chain-types.ts`(4 op)/ `chain-canonical.ts` / `chain-verify.ts`(提案台帳・適用)/ `chain-history.ts`(適用 seq での tenure 終了)/ `errors.ts` |
| test-vectors | `chain-entries.json` **全再生成**(add_member / change_role の payload 形式変更)、`invite-link.json` 再生成(発行文)、`value-signature.json` / `metadata-signature.json` / `env-manifest.json` はチェーンを読み込むため再生成、負例追加。`dek-*` / `recovery-*` / `master-key-wrap` / `lease-wrap` / `head-attestation` / `audit-head` / `checkpoint-digest` / `encoding` / `variable-encryption` は不変 | 同じ `chain-entries.json` に新 op の正例・負例・`expected_head_states` の方針・pending 提案 |
| api-schema | `chain.ts`(payload に scope)/ `invites-api.ts`(発行・一覧・受諾応答に scope)/ `data-api.ts`(pull の `InsufficientScope` エラー) | `chain.ts`(4 op)/ `errors`(`ProposalLimit`) |
| server | `dek-wraps.ts`(`expectedWrapRecipientCount` / `checkWrapRecipient` の scope)/ `data-plane.ts`(`requireMemberState` の環境軸 = `requireEnvironmentAccess`)/ `programs-dek.ts` / `programs-environment.ts` / `programs-variable.ts` / `composite-programs.ts` / `checkpoint-accept.ts`(scope 条件)/ `verify-value.ts` 等(理由コード)/ `rotation-detect.ts`(環境別アクセス窓)/ `chain-accept.ts`(縮小・降格の検出結線)/ `handlers-invites.ts` + `db.package`(招待行 scope)/ `authz.ts`(op 別水準) | `chain-accept.ts`(適用完了時の副作用・ミラー)/ `policy.ts`(pending 上限)/ `core/audit.ts`(ミラー写像) |
| CLI | `invite.ts`(`--env`)/ `member.ts`(add: 招待行の scope、change-role / scope: 拡大 backfill・縮小 sweep、**新設 `member list`**)/ `dek-wrap.ts`(`wrapRecipientsFor` の scope)/ `backfill.ts`(環境集合 = scope)/ `rotation-sweep.ts`(義務の環境集合・`scope-narrowed` 種別)/ `env-create.ts`(scope = all 前提検査)/ `pull.ts` / `values.ts` / `context.ts`(scope 外の明示エラー)/ `deks.ts`(scope 外ラップの警告)/ `effect-cli.ts` | 新規 `approval.ts`(`approval list / show / approve / withdraw`)/ `project.ts`(`project policy approvals`)/ 既存の member / server コマンドの提案化 / `effect-cli.ts` |
| web | `chain-view.ts` / `ProjectScreen.tsx`(member 行に scope 列) | pending 提案の表示(読み取りのみ — 署名は Web に置かない〔ADR-0018〕) |
| docs | `apps/site/docs/invite-a-teammate.mdx`(`--env`)/ 新規 `environment-scopes.mdx` / `docs/SELF_HOSTING.md` "Updates" | 新規 `four-eyes.mdx` |

### 1-4. 変えないもの(制約の確認)

- 暗号プリミティブは不変(Ed25519 署名・SHA-256・§2.1 LP のみ。scope は `grant_server` の `scope_environments_lp_hex` と同じ入れ子 LP の再利用。四眼は既存の署名 2 本を 2 エントリで数えるだけで、閾値署名・集約署名は導入しない)
- 「署名するのは人間だけ」(機械メンバーなし)。承認者も人間の owner
- チェーン・監査にプロバイダ ID を書かない
- 意味論は署名バイト列の中(§1 原則 6): scope・提案内容・期限・定足数はすべて LP フィールド
- 旧クライアントは fail-closed: payload 形式変更(add_member / change_role)は旧実装で `bad-signature`(正規化バイト列が異なる)または Schema の strict 拒否、新 op は `invalid-payload`(未知 op)で落ちる。互換経路なし

---

## 2. 裁定の反復記録(ES)

各裁定点で案を列挙し、上位互換・銀の弾丸を問い、連続 2 巡で新案が出なければ打ち止め。巡数は正直に記す(単巡で決めた項目はその旨)。

### 裁定 A: スコープをどこに置くか(2 巡・打ち止め)

| 案 | 内容 | 平文はどこに | 署名者 | 改訂範囲 | コスト | 整合 |
|---|---|---|---|---|---|---|
| A-1 **payload 拡張** | `add_member` / `change_role` の payload に scope フィールドを追加(形式変更 = チェーン全再生成) | チェーン(公開) | 操作の actor | §6.2 / §6.3 / §6.4 / §7 | 中(既存ベクター全再生成・既存チェーン無効) | ROADMAP の指示どおり。§6.2 が「予約済みの余地」と明記 |
| A-2 追加 op `set_member_scope` | add_member / change_role は不変(= scope all)。別 op で scope を設定。スコープ付き追加は (add_member, set_member_scope) の**原子ペア**で受理 | 同上 | 同上 | 同上 + 新 op + ペア複合エンドポイント | 中(既存ベクターは純追記で不変・既存チェーン有効) | ペアの間の状態(1 seq だけ scope=all)が意味論上の継ぎ目。非原子だと並行 rotate が新メンバー宛に全環境をラップする漏洩窓 |
| A-3 データプレーンの方針 | チェーンは変えず、招待者が「スコープ外の DEK をラップしない」+ サーバーが完全集合規則を緩める | サーバー設定 | なし(署名なし) | §12-6 のみ | 低 | **不可**: §6.3 の「ラップ先 = 現メンバーと厳密一致」(ゴーストメンバー対策)が壊れ、スコープが検証不能・帰属なし。「方針ではなく鍵配布で」の要件そのものに反する |
| A-4 role 文字列への埋め込み | `role = "member@prod,staging"` | チェーン | actor | §6.2 | 低 | 文字列ハック。role の閉集合・比較(ROLE_RANK)が壊れる。棄却 |

第 1 巡の候補は A-1 / A-2。**上位互換の探索**: A-2 の利点(既存チェーン・ベクターの温存)を A-1 で得る方法はない(署名対象が変わる以上、旧エントリは旧規則でしか検証できない)。A-1 の利点(1 エントリ = 1 事実、包含規則が単純)を A-2 で得るには add_member にペアを強制するしかなく、それは A-1 と同じ検証規則を 2 エントリで書き直したもの。**銀の弾丸**: 「スコープを役割の外に出す構造」を探した — 環境ごとに独立のチェーン(プロジェクト × 環境のメンバーシップ)を持つ案は、プロジェクト単位の owner / admin・grant_server・checkpoint・アンカーの全設計を環境単位に分割し直すことになり、規模が桁違い(棄却)。第 2 巡で新案なし → 打ち止め。

**採用: A-1**。棄却理由: A-2 はペア複合(新エンドポイント)と継ぎ目の説明を要し、得るものは「公開前の既存チェーン温存」だけ。2026-09-14 裁定「古い実装は削除してよい」と §11 の先例(grant_server のリースポリシー拡張 = 全再生成)に従い、公開前に形式を確定する。**帰結として、既存の検証デプロイのプロジェクト(add_member を含む既存チェーン)は新規則で無効になり再作成が要る**(承認項目 1 で明示。DK が add_member 形式に再度触れる可能性は補足 — §6 申し送り)。

### 裁定 B: スコープの符号化と構造規則(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| B-1 **kind + list** | `scope_kind` ∈ {`all`, `listed`} + `scope_environments_lp_hex`(`grant_server` と同じ入れ子 LP・hex 小文字)。`all` ⇒ リストは空(非空は `invalid-payload`) | 「全環境」が明示の署名対象になる。grant_server の先例の再利用(≤ 256 要素・順序は署名対象・生成は昇順 SHOULD・検証は集合) |
| B-2 list のみ、空 = all | フィールド 1 つ | **fail-open の形**: リストを落とす改竄・実装バグが「全環境」に化ける。棄却 |
| B-3 list のみ、番兵 `"*"` | environment_id の名前空間に予約値 | ID 形式は自由文字列(§11-1)で `*` を禁止する合意規則が要る。棄却 |
| B-4 list のみ、all を表現しない | 全員が列挙 | 新環境の作成のたびに全 all-scope メンバーの change_role が要る(作成者が全員分を署名する = 作成の複合が肥大)。棄却 |

構造規則(第 2 巡で確定): (1) `listed` の各 id は**その時点でチェーン上に `create_environment` が先行**していること(`unknown-environment` — rotate / checkpoint と同じ理由コード。typo を fail-closed にし、未存在環境への事前スコープは持たない)。削除済み(tombstone)環境は チェーンが削除を観測しないため列挙可(害なし)。(2) 重複 id は `invalid-payload`(checkpoint の先例 — 集合の意味論に重複は情報を持たないが、非決定性の芽を構造段で摘む)。(3) `listed` の**空リストは有効**(= どの環境の DEK も受け取らないメンバー。メタは見える。「後で入れる予定」「管理だけする admin」の表現。`all` と `listed{}` は別の状態で曖昧性なし)。**銀の弾丸**: 環境の名前空間をグループ化(タグ)して scope をタグで書く案 — タグはチェーン外の可変メタになり原則 6 に反する(棄却)。打ち止め。

**採用: B-1 + 構造規則 (1)(2)(3)**。

### 裁定 C: role とスコープの関係 — owner / admin もスコープを持つか(3 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| C-1 reader / member のみ | admin / owner は常に all。role ≥ admin のエントリは `scope_kind = all` 必須 | 単純。「prod は owner / admin のみ」の例はこれで書ける。dev チーム専任の admin は書けない |
| C-2 **owner のみ all 固定、admin 以下は listed 可** | 包含規則(裁定 D)と組で成立 | C-1 の上位互換: admin を all にすれば C-1 と同じ挙動。dev 専任 admin(dev のメンバー管理だけできる)が書ける |
| C-3 owner も listed 可 | — | 「最後の owner」保護・grant_server(全環境の開示)・全環境 rotate 義務の履行者が消える。棄却 |

第 1 巡: C-1。第 2 巡で C-2 が上位互換と判明(C-1 の全ケースを含み、規則は「owner は all」1 本 + 包含)。第 3 巡: C-2 の欠点 = 「admin が全環境を見られる」という現行の暗黙の期待が崩れる場面(admin でも scope を明示する) — CLI の既定を `all` にすれば体験は変わらない。新案なし → 打ち止め。

**採用: C-2**。合意規則 `scope-role-mismatch`: `role = owner`(genesis の owner を含む — genesis は構造的に all)で `scope_kind ≠ all` のエントリは無効。

### 裁定 D: (d) admin が自分のスコープ外の環境へ人を入れられるか(2 巡・打ち止め)

物理的制約が先に立つ: **ラップの実行者は DEK 保持者**(§7)。prod の DEK を持たない admin は新メンバー宛の prod ラップを作れない。

| 案 | 内容 | 評価 |
|---|---|---|
| D-1 **包含規則** | `add_member`(対象 scope)/ `change_role`(新 scope)/ `remove_member`(対象の現 scope)は、**actor の scope ⊇ 対象 scope** でなければ無効(`scope-not-contained`)。owner は all なので常に通る | 「入れられる = DEK を渡せる」「消せる = 義務の rotate を履行できる(再暗号化に旧 DEK が要る)」が構造的に一致。dangling(メンバーはいるがラップを作れる人がいない)状態を作らない |
| D-2 包含なし + バックフィル委任 | admin は任意 scope を付与でき、DEK は scope 内の別メンバー(member 以上)がバックフィルする | 「メンバーはいるがラップがない」状態が常態化(§12-4 の非対称が恒久化)。remove の rotate 義務も他人任せ。棄却 |
| D-3 C-1(admin = all)で不要化 | — | 裁定 C の上位互換で C-2 を採ったため、包含規則は必要 |

**銀の弾丸の探索**: 「actor の scope を検査しなくても DEK 保持の事実が構造的に強制される形」= バックフィルを add_member の複合に同梱する案。§12-4 が「全環境 × 全エポックは 1 リクエスト上限を超えうる」として複合化を退けた理由が残る(棄却)。第 2 巡で新案なし → 打ち止め。

**採用: D-1**。remove_member への適用は「消せる = rotate できる」の対称性のため(dev 専任 admin は prod メンバーを消せない)。検査順序(ベクターで固定): **scope 系の検査は既存の検査列の後ろに置く**(既存負例の期待理由をすべて温存する)— add_member = role 規則 → `duplicate-member` → `duplicate-member-key` → `unknown-environment` → `scope-role-mismatch` → `scope-not-contained`。change_role = role 規則 → `unknown-target` → `last-owner-protected` → `unknown-environment` → `scope-role-mismatch` → `scope-not-contained`。remove_member = role 規則 → `unknown-target` → `last-owner-protected` → `scope-not-contained`。四眼の `approval-quorum-unreachable` は各列の末尾。

### 裁定 E: 環境対象 op(create / rotate / checkpoint)とスコープ(2 巡・打ち止め)

| op | 規則 | 理由 |
|---|---|---|
| `rotate_epoch` | 対象 environment_id ∈ actor scope(`environment-out-of-scope`) | 再暗号化に旧 DEK が要る。scope 外の rotate は履行不能 |
| `checkpoint` | 全タプルの environment_id ∈ actor scope(同上) | values_digest の原像(value_sig_hash)は値付き pull でしか得られず、scope 外では取得できない。合意規則にするのは §6.3 の基準が「scope 外の member が公証したタプル」に依存しない形を全実装で揃えるため |
| `create_environment` | 新 environment_id ∈ actor scope = **`all` の actor のみ**(同上) | listed の scope に未存在の環境は含まれえない(裁定 B-(1))ので、専用規則を足さずに同じ 1 述語で落ちる。作成者が受け取れない環境を作る(= 作成直後に DEK を失う)形を避ける |

**上位互換の探索**: create で「作成者を暗黙に scope へ加える」案 — 署名対象にない scope 変化(原則 6 違反)。「listed の actor が create すると新環境が listed に自動追加」も同じ理由で棄却。第 2 巡で新案なし → 打ち止め。

**採用: 上表**。検査順序: role 規則 → `unknown-environment`(rotate / checkpoint)→ `environment-out-of-scope` → 既存の後続検査(エポック順序 / checkpoint-epoch-mismatch …)。create は role 規則 → `duplicate-environment` → `environment-out-of-scope`。

### 裁定 F: (a) スコープ縮小 = remove 相当か(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| F-1 **縮小を受理し §7 義務を負わせる** | `change_role` で旧 scope \ 新 scope ≠ ∅ の環境は「当該環境からの remove」= その環境の `rotate_epoch` 義務。義務の起点はエントリ seq | remove / 降格 / revoke と同じ中断復旧構造(rotation-sweep)に第 4 種 `scope-narrowed` を足すだけ |
| F-2 縮小を合意規則で拒否(grant_server 型) | 縮小は remove + re-add で行う | 招待からやり直し(受諾・裏付け・アンカー)・tenure 分断・監査の在籍区間が切れる。grant_server で縮小を拒否したのは「rotate なしの見せかけ縮小」を防ぐためで、義務を課せば同じ目的を達する。棄却 |

**要ローテーション検出**(AUDIT_SPEC §4.1)は候補集合を「環境別のアクセス窓」で求める — revoke_server 変種が拡大再 grant のために既に持つ構造(`grantIntervals` の `scopeStarts`)と同型。縮小時の検出は縮小分の環境に限り、`rotation.recommended` の起点は当該 `change_role` の seq。**拡大**は actor(DEK 保持者 — 包含規則)によるバックフィル義務(add_member 後と同型 — §12-6 の追記経路)。**降格**(member 未満)の義務は「対象の scope の環境」。**remove** の義務は「対象の現 scope の環境」— 過去に広かった分は縮小時の義務が別に残っている(sweep が独立に追う)ので、現 scope で足りる。第 2 巡で新案なし → 打ち止め。

**採用: F-1**。

### 裁定 G: (b) スコープ外メンバーに何が見えるか・環境横断の検証(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| G-1 存在も隠す | 環境一覧から除外 | **不可能**: 環境の存在は `create_environment` としてチェーン上にあり全メンバーが検証する |
| G-2 **メタは見える・値と DEK だけ受け取らない** | 環境の存在・表示名・変数名・スキーマ欄・マニフェスト・tombstone は配布(メタのみ pull 可)。値付き pull・自分宛 DEK・push・メタ書き込み・rotate・checkpoint は拒否 | 未決 #3(変数名の秘匿)の線と一致 — 「名前は運営可視」の現行方針をメンバー間にも延ばす。`maruhi schema`(値なし)がスコープ外でも動くのはエージェント用途で望ましい |
| G-3 暗号文も配る | DEK がないので復号不能 | 配る意味がなく、サーバー侵害 + 後日の DEK 漏洩の面を広げるだけ。`var.read`(値付き pull = 記録)の意味論も濁る。棄却 |

**環境横断の検証**: (i) `checkpoint` は環境の部分集合を公証できる(§6.2)ため、スコープ外環境のタプルは「検証は通す(合意規則の対象 — 発行者の scope 内であることを検証する)が、自分の基準には使わない」。§6.3 チェックポイント整合の基準は**自分が pull する環境**にしか要らない。(ii) マニフェスト検証は pull した環境のみ(不変)。(iii) ヘッド申告・招待リンクアンカーは環境を持たず不変。リポジトリアンカー(環境ごとのエポック)はチェーン導出値なので scope 外環境でも書ける(不変)。(iv) 床(§6.3 ローカル床)は「検証に成功した事実の join」なので scope 外環境の床は単に確立されない。**銀の弾丸**: なし(G-2 は既存の線の延長)。第 2 巡で新案なし → 打ち止め。

**採用: G-2**。拒否の形: 値付き pull / 自分宛 DEK 取得 / 環境対象の書き込みで対象環境 ∉ 呼び出し主体の scope は **403 型付き `InsufficientScope`**(環境の存在はチェーン導出で既知なので 404 に畳まない。role 不足 403 と同じ層)。

### 裁定 H: (c) 実効権限の環境軸と CI リースポリシーの合成(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| H-1 **チェーン scope のみ** | 実効権限 = min(トークンスコープ, チェーン role) を、環境 E について「E ∈ チェーン scope」で切る。トークン自体の環境スコープは導入しない | 鍵配布の制限は達成済み。トークン環境スコープは「本人の chain scope をさらに絞る」チェーン外 ACL で、後から加法的に足せる(AUTH_SPEC §6 の将来項をそのまま維持) |
| H-2 トークン環境スコープも同時導入 | `{ project, permission, environments? }` | ES の本質(鍵配布)と独立。CLI ログインの要求スコープ UI・`*` との合成が増える。今回は見送り(ROADMAP の (c) は「環境軸の追加」であり、チェーン側で追加する) |

**CI リースポリシー(§14-1)との合成**: ワークロードはメンバーではなく、リースの環境制限は `grant_server` の `scope_environments`(既存)が担う。ES はここに触れない — 合成規則は「変更なし」を明記するだけ。**銀の弾丸**: なし。打ち止め。

**採用: H-1**。§9-2 の文言を「実効権限 = min(トークンスコープ, チェーン role)、環境ごとの実効アクセス = 上記 ∧ 環境 ∈ チェーン scope」に改訂。

### 裁定 I: (e) 監査の可視性クラス(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| I-1 **クラス不変** | `chain.*`(scope 変更を含む)= クラス 1、`var.*` の名前系 = クラス 1(scope 外環境も)、`var.read` = クラス 2 | 裁定 G と整合: メタは全員可視。ミラーの全単射検証(`audit verify`)を scope で分岐させない |
| I-2 データ系イベントを scope で絞る | scope 外環境の `var.*` を隠す | 可視性述語に環境軸が入り、`audit verify` / reconcile / 要ローテーションフラグのビューが scope 依存になる。隠す情報(変数名・push の事実)は G-2 でどのみち見える。棄却 |

ミラー payload に scope を写す(`chain.member_added` = { role, scopeKind, scopeEnvironmentIds }、`chain.role_changed` = { newRole, scopeKind, scopeEnvironmentIds })— AUDIT_SPEC §4.1 の「チェーンミラーが role / スコープを写しているため、この拡張はクエリの変更だけで成立する」を実際に成立させる(現行 payload は role のみ)。`rotation.recommended` に縮小変種(payload.trigger = `change_role`)。要ローテーションフラグのビューはクラス 1 のまま。打ち止め。

**採用: I-1**。

### 裁定 J: 既存プロジェクト(スコープ無しのメンバー)の解釈(単巡)

A-1 の帰結として、旧形式の add_member を含むチェーンは新規則で無効になる(互換経路なし)。したがって「スコープ無しのメンバー」という状態は**存在しない** — 新規則下の全メンバーは明示の scope を持つ(genesis の owner は構造的に all)。明示初期化は不要(初期化すべき旧状態がない)。既存の検証デプロイのプロジェクトは再作成する(SELF_HOSTING "Updates" に移行手順として明記 — K7)。単巡で決めた(A-1 の帰結であり独立の裁定ではない)。

### 裁定 K: 招待でスコープをどう指定するか(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| K-1 **発行文に scope を含める** | `invite_issue_signed_bytes` の末尾に `scope_kind, scope_environments_lp_hex` を追加。D1 行に scope 列。リンクのフラグメントに `sk=` / `se=`(発行署名が覆う)。受諾者は「どの環境に入るか」を受諾前に読む。`member add` は招待行の scope で add_member を署名(role と同じ扱い) | role が既に発行文にある(2026-08-15 追補で改竄検出対象に格上げ)ので同型。`invite-link.json` 再生成 |
| K-2 招待は role のみ、scope は `member add` 時に指定 | — | 受諾者が自分の入る環境を事前に知れない。招待者が `member add --env` で発行時と違う scope を付けられる(受諾の同意の範囲外)。棄却 |

CLI: `maruhi invite create --role member --env dev --env staging`(`--env` 反復、省略 = all。`--env` なしを明示したい場合の `--all-envs` は冗長なので置かない)。`member add` の `--env` は持たない(招待行が正)。**銀の弾丸**: なし。打ち止め。

**採用: K-1**。

### 裁定 L: `grant_server` のサーバー鍵はスコープの対象か(単巡)

対象外 — サーバー鍵は `grant_server` payload の `scope_environments` で既に環境スコープを持つ(2026-08-02)。ES は**受信者集合の定義を一般化**するだけ: 環境 E の受信者 = { member | E ∈ scope } ∪ { grant | E ∈ scope_environments }(`expectedWrapRecipientCount` の 1 定義)。grant の実行者は owner(= all)なので包含規則は自明に成立。単巡(既存構造への追随)。

### 裁定 M: `member list` / Web の表示(単巡)

CLI に `maruhi member list` を新設(現状は `project verify` の出力にしかメンバー一覧がなく、`member` グループは add / remove / change-role のみ)。検証済みチェーンから user id・role・scope(`all` / 環境 id 列)・鍵 FP を表示。値ゼロなので agent-gate 非適用(`maruhi schema` と同じ許可側 — テストで固定)。`project verify` の member 行にも scope 列。Web `ProjectScreen` の member 行に scope 列(chain-view の fold に scope を写す。表示規律「サーバー申告・未検証」は不変)。単巡(表示の形は判断であり探索の対象ではない)。

### 裁定 N: DEK 受信側の規則(単巡)

§6.3 に追記: 自分宛のラップで環境 ∉ 自分の scope のものは**使用せず警告する**(サーバーが §12-6 の受理規則を執行していない証拠 — 開封して DEK を得ても、その環境への書き込みは scope 外として全検証者が拒否するため実害は「読める」に限られるが、規範として使わない)。ラップ生成側(`wrapRecipientsFor` / `buildWrapCompleteSet`)は scope 内メンバーのみを受信者にする。単巡(§6.3 の「ラップ先 = 現メンバーと厳密一致」の環境軸版で、独立の裁定ではない)。

---

## 3. 裁定の反復記録(PF1 四眼)

### 裁定 P1: 提案と承認の形(2 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| P1-1 **2 エントリ(`propose` + `approve`)** | 提案エントリが内側 op と payload を運び、承認エントリが提案を参照する。定足数に達した承認エントリの seq で内側 op を適用 | 新 op の追加 = §6.1 のエントリ形式(1 署名)は不変。checkpoint op 追加と同じ「追記で拡張」の型。承認者は非同期・別端末でよい |
| P1-2 1 エントリの共同署名 | `signatures: [...]` を持つエントリ形式 | §6.1 の形式変更(全 op のエントリ形式に触れる)。署名を集めるオフライン経路(提案の運搬)が別途要る。棄却 |
| P1-3 チェーン外の承認 API | 承認をサーバー行に置き、サーバーが「2 人揃った」と判定して 1 エントリを受理 | 承認が署名バイト列の外(原則 6 違反)。サーバーが承認を捏造できる。棄却 |

**上位互換**: なし。打ち止め。**採用: P1-1**。

### 裁定 P2: 定足数と有効化の置き場・既定(3 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| P2-1 genesis に固定 | 作成時に決める | 変更不能。単独で始めてチームになる流れ(AUTH §9-1 のパーソナル org と同じ成長)に合わない。棄却 |
| P2-2 **方針 op `set_approval_policy`** | payload = `[ops_lp_hex, required_approvals]`。方針なし(genesis 直後)= **オフ**。有効化(`required ≥ 2`)は現 owner 数 ≥ required が条件(`approval-quorum-unreachable`)。**`set_approval_policy` 自身は常に現方針に服す**(オン中の変更・オフは四眼を要する) | 既定オフ・単独 owner を壊さない。「オフにする」が 1 人でできない(でなければ四眼が無意味) |
| P2-3 プロジェクト設定(チェーン外) | AUTH §12-11 schemaPolicy 型 | 合意規則の入力がチェーン外(原則 6 違反)。棄却 |

第 2 巡: `required_approvals` を 2 固定にするか一般の n にするか。一般の n(≥ 2)は検証コスト同じ(distinct owner の票数 ≥ n)で、owner 数 ≥ n の条件が自然に一般化する。第 3 巡: 「owner 数を n 未満にする op(owner の remove / 降格)」は無効(`approval-quorum-unreachable` — `last-owner-protected` の一般化)としないと、四眼がオンのまま到達不能になる。新案なし → 打ち止め。

**採用: P2-2 + n 一般化 + 到達可能性の不変条件**。

### 裁定 P3: 対象 op の集合(2 巡・打ち止め)

対象にできる op: `grant_server` / `revoke_server` / `remove_member` / `change_role` / `add_member` / `set_approval_policy`。対象にできない op: `genesis`(構造)/ `create_environment` / `rotate_epoch` / `checkpoint`(データ・安全側の操作を止めない — rotate はインシデント対応であり四眼で遅らせてはならない)/ `propose` / `approve` / `withdraw`(再帰)。`set_approval_policy` は列挙に依らずオン中は常に対象(P2)。`revoke_server` を対象にできるのは「開示を止める」方向でも誤操作(リース経路の停止 = CI 停止)がありうるため — 既定推奨集合には含めない。既定推奨集合(CLI の `--ops` 省略時)= `{grant_server, remove_member, change_role, set_approval_policy}`(承認項目 17)。第 2 巡で新案なし。

### 裁定 P4: 承認者と提案者(2 巡・打ち止め)

- 承認者は **owner のみ**(distinct user_id)。admin を承認者に含める案は「admin 2 名で admin を消せる」= owner の管理権限(§6.2)の迂回になるため棄却
- 提案者は内側 op を**通常の role 規則で実行できる者**(admin が reader の remove を提案できる)。提案者が owner なら提案が 1 票に数える(2 owner の流れ = 提案 + 承認 1 回)
- 提案者は承認エントリを重ねて出せない(distinct)。承認の取り消しは持たない(提案ごと `withdraw`)

### 裁定 P5: 適用点と再検査(2 巡・打ち止め)

- 内側 op は、票数が `required` に達した **`approve` エントリの seq で適用**(inclusive 規約 — remove の tenure 終了・change_role の新 role はその seq で有効)
- 適用時に内側 op の合意規則を**適用時点の状態**で再検査する(対象の存在・role 規則・包含規則・最後の owner・鍵重複・到達可能性 …)。加えて**提案者が現メンバーで、提案時と同じ鍵 FP・内側 op に必要な role を持つ**こと(`proposal-void` — 提案後に提案者が削除・降格・鍵変更された提案は完成できない)
- 提案時にも同じ検査を行う(提案段で無効な op を pending に積まない — `propose` 自体が無効エントリ)。二重検査のコストはエントリ数分で無視できる
- 適用に失敗する承認エントリは**無効エントリ**(チェーンに載らない)。pending 提案はそのまま残る(withdraw で閉じる)。「適用失敗で提案が自動的に閉じる」形は、承認者の署名が「閉じる」効果を持つ二義性になるため棄却

### 裁定 P6: 提案の期限(3 巡・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| P6-1 期限なし + withdraw | pending は明示で閉じる | 古い提案が忘れられ、文脈を失った owner が後日承認する危険 |
| P6-2 seq 距離 | 提案から N エントリで失効 | seq は活動量であり時間ではない(静かなプロジェクトでは永遠に有効)。棄却 |
| P6-3 **`expires_at_ms` + 承認者の timestamp** | 提案 payload に `expires_at_ms`。合意規則: `approve` エントリの `timestamp_ms ≤ expires_at_ms`(`proposal-expired`) | チェーン検証で初めて timestamp を使う。`timestamp_ms` は承認者の自己申告なので、**期限は正直な承認者を文脈を失った承認から守る UX 安全装置であり、悪意の承認者に対する保証ではない**(過去方向に詐称すれば期限切れを承認できる — その承認者は正当な 1 票の主体)。§14.2-10 の保証は期限に依存しない |

第 3 巡: P6-3 の timestamp 利用が chain-history.ts の「timestamp は認可判定に使わない」規律と矛盾しないか — 規律の意図は「時刻で在籍・role を判定しない」(seq が正)であり、P6-3 は seq ベースの適用点を変えず、期限という追加の拒否条件に承認者自身の署名済み時刻を使うだけ。仕様には「timestamp を合意規則に用いる唯一の箇所」と明記する。既定期限 = 7 日(招待の期限と同じ起草値)。新案なし → 打ち止め。**追補(2026-09-14 pullfrog レビュー)**: 起草時の「効果は拒否方向のみ = fail-closed」は片側しか成り立たない(承認者は `timestamp_ms` を過去方向に詐称でき、チェーンに単調性も上界もない)ため撤回し、上表のとおり「悪意の承認者に対する保証ではない」と明記した。下界(提案エントリの timestamp 以上)を課す案は窓内の詐称を止められず保証を足さないため採らない。

**採用: P6-3 + `withdraw` op**。

### 裁定 P7: `remove_member` の rotate 義務の起点(単巡)

**適用時点**(承認完了の seq)。提案時にはメンバーは在籍しており、義務の対象(DEK 失効)は存在しない。rotation-sweep の義務導出は「適用された remove」を見る(提案エントリではなく、適用を完了した approve エントリの seq)。要ローテーション検出(AUDIT §4.1)も同じ seq で走る。単巡(適用の意味論から一意に決まる)。

### 裁定 P8: サーバー受理(§6.4)・監査ミラー(§3.4)・CLI(2 巡・打ち止め)

- 受理: `propose` / `approve` / `withdraw` / `set_approval_policy` は**汎用 append**(§11 — 付随データなし)。トークン水準は内側 op と同じ(admin)。受理ポリシー: pending 提案はプロジェクトあたり **32** 件まで(型付き 422 `ProposalLimit` — 合意規則ではない)
- 適用完了時の副作用(`chain-accept.ts` の `applyAcceptanceSideEffectsSync`): 完成した approve エントリに対し、内側 op の副作用(remove → 要ローテーション検出・申告行の削除、add → 旧鍵ラップ掃除・招待 completed 化)を走らせる
- ミラー: `chain.proposed` / `chain.approved` / `chain.proposal_withdrawn` / `chain.approval_policy_changed`(1 エントリ 1 行 — 全単射不変)。**完成した approve エントリは、加えて内側 op のミラー行**(`chain.member_removed` 等)を**同じ chain_seq** で書き、payload に `{ viaProposalSeq }` を付す(要ローテーション検出の在籍区間 Q1 が `chain.member_removed` を読む構造を変えない)。`audit verify` の全単射検査は「1 エントリ ↔ 1 行 + 完成 approve の適用行」に改める
- **四眼経由の `add_member` / scope 拡大のバックフィル履行者(2026-09-14 pullfrog レビュー対応)**: 適用は承認者の approve エントリの seq で起き、提案者のクライアントは通常動いていない。remove の sweep と対称に、**適用を完成させた承認者のクライアントがバックフィル(対象の scope の全環境 × 全エポック)も走らせる**。承認者 = owner = all なので DEK を持ち、包含規則から履行可能。AUTH_SPEC §12-6 の独立登録経路に 5 番目として明記(spec-drafts B-6 / A-6)。既定推奨集合に `add_member` は入っていないが `change_role` は入っており拡大は `change_role` で起きるため、既定構成でも到達する経路
- CLI: 新グループ **`maruhi approval`**(`list` / `show <id>` / `approve <id>` / `withdraw <id>` — `maruhi key approve <code>`〔KL3 ハンドオフ〕とは別グループで衝突しない。id = 提案エントリのハッシュ〔hex 64。先頭 8 文字の一意接頭辞を受け付ける〕)、**`maruhi project policy approvals --required N [--ops …]`**(オン / 変更 / `--off`)。既存の `member remove` / `member change-role` / `server grant` / `server revoke` / `member add` は方針が対象にしていれば `propose` を出して「needs N−1 more owner approval(s)」を表示して終了(rotate 義務は適用後に `member remove` の再実行または `approval approve` 側の sweep で収束 — 承認者が rotate を実行する)。**承認者の CLI が承認後に sweep を走らせる**(remove の完成者 = 承認者が §7 の履行者。包含規則により owner は all なので履行可能)
- Web: pending 提案の一覧表示のみ(署名は Web に置かない — ADR-0018)

第 2 巡で新案なし → 打ち止め。

---

## 4. 実装分割(K1〜K7)と独立停止可能性

系列はテストベクター → crypto → api-schema → server → CLI(CLAUDE.md の順序)。**ES → 四眼の順**。各段はマージ後にそこで止めても安全であることを要件とする。

| 段 | 内容 | 停止しても安全な理由 |
|---|---|---|
| **K1** | 仕様の正本へ反映(CRYPTO_SPEC 0.10 → **0.11-draft**、AUTH_SPEC 0.22 → **0.23-draft**、AUDIT_SPEC 1.7 → **1.8-draft**。Status 欄に改訂履歴) | docs のみ |
| **K2** | **テストベクターを先に書く**: `chain-entries.json` 全再生成(add_member / change_role の scope・新 op 4 種・`expected_head_states` に scope / 方針 / pending・正例・負例)、`invite-link.json` 再生成(発行文に scope)、チェーンを読み込む `value-signature.json` / `metadata-signature.json` / `env-manifest.json` の再生成 → `packages/crypto`(scope の型・正規化・合意規則 ES + PF1・履歴索引・宣言ヘッド時点の scope 検査・発行文)→ **api-schema のワイヤ + server / CLI の機械的追随**(scope は `all` 固定で発行、PF1 の op は生成しない)。**人間レビュー必須箇所を PR 本文に列挙** | 挙動変更なし(全メンバー = all のまま)。crypto が新規則を理解し、旧形式を拒否する。この段のデプロイで既存プロジェクトのチェーンは無効になるため、K2 のマージ = 検証デプロイの再作成のタイミング |
| **K3** | server(ES): 受信者集合 = scope(`expectedWrapRecipientCount` / `checkWrapRecipient`)、環境対象 op の scope 認可(`InsufficientScope`)、値・メタ・マニフェストの宣言ヘッド時点 scope 検査、招待行の scope、ミラー payload、要ローテーション検出の環境別窓・縮小変種。テストは `@cloudflare/vitest-plugin` | CLI はまだ all しか発行しないので配布は従来どおり。制限は眠ったまま |
| **K4** | CLI(ES): `invite create --env`、`member add`(招待行の scope)、`member change-role --env` / `member scope`(拡大 backfill・縮小 sweep)、**`member list`**、`wrapRecipientsFor` / backfill / sweep の scope 対応、`env create` の前提検査、pull / push / rotate の scope 外エラー、scope 外ラップの警告、`project verify` の scope 列 + Web `ProjectScreen` の scope 列。テストは Vitest | ES 完了。四眼は方針なし = オフのまま |
| **K5** | server(PF1): 受理ポリシー(pending 上限)、適用完了時の副作用、ミラー 4 種 + 適用行、`audit verify` の全単射規則 | CLI が提案を出さないので眠ったまま |
| **K6** | CLI(PF1): `approval` グループ、`project policy approvals`、既存コマンドの提案化、承認者側の sweep、Web の pending 表示 | 既定オフ。有効化は owner ≥ 2 の明示操作 |
| **K7** | docs: `apps/site/docs/`(`environment-scopes.mdx` 新規・`invite-a-teammate.mdx` の `--env`・`four-eyes.mdx` 新規)、`docs/SELF_HOSTING.md` "Updates" に移行順序(サーバー → 全メンバー CLI → 既存プロジェクトの再作成)、ROADMAP の完了記録 | docs のみ |

- 移行の順序要件: サーバー(K2 デプロイ)→ 全メンバーの CLI(K2 以降)。旧 CLI は新チェーンを `bad-signature` / 未知 op で拒否し(fail-closed)、新 CLI は旧サーバーへの add_member を新形式で送るため旧サーバーが拒否する(どちらの向きも黙って旧解釈しない)
- 見積もり: ROADMAP の概算(ES 2〜3 週・PF1 3〜4 週)は人手前提。実測(KL3 / IV)から、律速は所有者承認と crypto 人間レビュー

---

## 5. 承認依頼項目(所有者裁定を要するもの)

各項目に「採用案 / 棄却案 / 理由」の要約。仕様・暗号・チェーン規則・ワイヤ形式・監査事件の追加に係るものを積む。実装の内部構造・命名・テストの形は自分で決めて進める。

| # | 項目 | 採用 | 棄却 | 理由(要約) |
|---|---|---|---|---|
| 1 | スコープの置き場(裁定 A) | `add_member` / `change_role` の payload 拡張 = **チェーン形式変更・`chain-entries.json` 全再生成・既存チェーン無効(検証デプロイのプロジェクト再作成)** | 追加 op `set_member_scope`(純追記・ペア複合が必要)/ データプレーン方針 | 1 エントリ = 1 事実。公開前に形式を確定する §11 の先例(grant_server 拡張)。**再作成の帰結を承認いただきたい** |
| 2 | 符号化(裁定 B) | `scope_kind` ∈ {all, listed} + `scope_environments_lp_hex`(grant_server と同じ入れ子 LP・≤ 256・順序は署名対象・生成昇順 SHOULD) | 空 = all(fail-open)/ 番兵 `*` / all を表現しない | grant_server の先例の再利用。all の明示 |
| 3 | 構造規則(裁定 B) | all ⇒ 空リスト必須(`invalid-payload`)、listed の id は `create_environment` 先行必須(`unknown-environment`)、重複 = `invalid-payload`、listed の空リストは有効 | 存在検査なし / 空 listed の禁止 | fail-closed(typo)。`listed{}` = 管理のみ・後で入れる の表現 |
| 4 | role との関係(裁定 C) | owner = all 固定(`scope-role-mismatch`)。admin / member / reader は listed 可 | admin も all 固定 / owner も listed | C-2 は C-1 の上位互換(admin を all にすれば同じ)。dev 専任 admin が書ける |
| 5 | 包含規則(裁定 D) | add / change_role / remove で **actor scope ⊇ 対象 scope**(`scope-not-contained`)。検査順序: 既存の検査列(role → duplicate-* / unknown-target → last-owner)の**後ろ**に unknown-environment → scope-role-mismatch → scope-not-contained(既存負例の期待理由を温存) | 包含なし + 他メンバーによるバックフィル委任 | ラップ実行者 = DEK 保持者(§7)。消せる = rotate を履行できる |
| 6 | 環境対象 op(裁定 E) | rotate / checkpoint(全タプル)は env ∈ actor scope、create は all の actor のみ(すべて `environment-out-of-scope`) | 作成者の暗黙スコープ追加 | 原則 6(暗黙の scope 変化を作らない)。1 述語で 3 op を覆う |
| 7 | 縮小の意味論(裁定 F) | 縮小を受理し、縮小分の環境に §7 の rotate 義務(sweep 第 4 種 `scope-narrowed`)。降格 = 対象 scope の環境、remove = 対象の現 scope の環境 | 縮小を合意規則で拒否(grant_server 型) | remove + re-add の招待やり直し・tenure 分断を避ける。義務で同じ目的を達する |
| 8 | 拡大の義務(裁定 F) | change_role の拡大分は actor が全エポックをバックフィル(§12-6 の追記経路。複合化しない) | 複合化 | §12-4 の非対称(上限超過)の再確認 |
| 9 | スコープ外の可視範囲(裁定 G) | メタ(存在・名前・スキーマ・マニフェスト・tombstone)は見える、暗号文・DEK・書き込み・rotate・checkpoint は不可。拒否は 403 `InsufficientScope` | 存在も隠す(不可能)/ 暗号文も配る | 未決 #3 の線の延長。`maruhi schema` がスコープ外でも動く |
| 10 | 環境横断の検証(裁定 G) | checkpoint のスコープ外タプルは合意規則の検証のみ・基準に使わない。マニフェスト検証・申告・アンカー・床は不変 | — | 基準は pull する環境にしか要らない |
| 11 | 実効権限の環境軸(裁定 H) | 実効アクセス(E) = min(トークン, role) ∧ E ∈ チェーン scope。トークンの環境スコープは今回導入しない(AUTH §6 の将来項のまま)。CI リースポリシーとの合成は変更なし | トークン環境スコープ同時導入 | チェーン外 ACL は後から加法的に足せる |
| 12 | 監査の可視性(裁定 I) | クラス不変。ミラー payload に scope(`chain.member_added` / `chain.role_changed`)。`rotation.recommended` 縮小変種(trigger = change_role)。要ローテーション検出の候補 = 環境別アクセス窓 | データ系イベントを scope で絞る | メタは全員可視(G-2)。`audit verify` を scope 非依存に保つ |
| 13 | 既存プロジェクト(裁定 J) | 「スコープ無しのメンバー」は存在しない(全エントリが scope を持つ)。明示初期化なし。既存プロジェクトは再作成 | 移行操作 | 1 の帰結 |
| 14 | 招待(裁定 K) | 発行文の末尾に `scope_kind, scope_environments_lp_hex`(`invite-link.json` 再生成)、D1 行に scope、リンク `sk=` / `se=`、`invite create --env`(反復・省略 = all)。`member add` は招待行の scope | `member add --env` | 受諾者が入る環境を事前に読める。同意の範囲を固定 |
| 15 | grant_server(裁定 L) | 対象外。受信者集合 R(E) = { member: E ∈ scope } ∪ { grant: E ∈ scope_environments } の 1 定義 | — | 既存構造への追随 |
| 16 | 四眼の形(P1) | 2 エントリ `propose` / `approve`(+ `withdraw`) | 共同署名 1 エントリ / チェーン外承認 | §6.1 不変・追記で拡張・原則 6 |
| 17 | 方針の置き場と既定(P2 / P3) | 新 op `set_approval_policy` = `[ops_lp_hex, required_approvals]`。既定オフ。有効化は owner ≥ required。**方針 op 自身は常に現方針に服す**。owner 数を required 未満にする op は無効(`approval-quorum-unreachable`)。対象可能 op = grant_server / revoke_server / remove_member / change_role / add_member / set_approval_policy。既定推奨集合 = {grant_server, remove_member, change_role, set_approval_policy} | genesis 固定 / チェーン外設定 / 2 固定 | 単独 owner を壊さない。オフにするのに四眼が要る |
| 18 | 承認者と提案者(P4) | 承認者 = owner のみ(distinct)。提案者 = 内側 op を実行できる role。owner の提案は 1 票 | admin 承認者 | owner の管理権限の迂回を作らない |
| 19 | 適用点と再検査(P5) | 定足数到達の approve の seq で適用(inclusive)。提案時 + 適用時に内側 op の合意規則を検査、適用時は提案者の現在性(`proposal-void`)も | 適用失敗で提案が自動的に閉じる | 承認署名に「閉じる」効果を持たせない |
| 20 | 期限(P6) | `expires_at_ms`(既定 7 日)+ 合意規則 `approve.timestamp_ms ≤ expires_at_ms`(`proposal-expired`)。**timestamp を合意規則に用いる唯一の箇所。正直な承認者向けの UX 安全装置であり、悪意の承認者(過去方向の詐称)に対する保証ではない** | 期限なし / seq 距離 / 下界の追加(窓内詐称を止められない) | 文脈を失った承認の抑止。§14.2-10 の保証は期限に依存しない |
| 21 | remove の義務の起点(P7) | 適用時点 | 提案時点 | 適用前に失効する DEK はない |
| 22 | 受理・監査・履行者(P8) | 汎用 append。pending ≤ 32(受理ポリシー)。ミラー 4 種 + 完成 approve の適用行(同 chain_seq・`viaProposalSeq`)。`audit verify` の全単射規則の改訂。**四眼経由の add_member / scope 拡大のバックフィルと remove / 降格 / 縮小の rotate は、適用を完成させた承認者が履行**(§12-6 の 5 番目の経路) | 提案者による履行(適用時に不在) | 検出(Q1)の入力構造を変えない。承認者 = owner = all で履行可能 |
| 23 | CLI 名(P8) | `maruhi approval list / show / approve / withdraw`、`maruhi project policy approvals`。既存コマンドの自動提案化。承認者側で sweep | `maruhi key approve` との同居 | KL3 のハンドオフ承認と衝突させない |
| 24 | テストベクター(§11) | K2 で `chain-entries.json` 全再生成 + `invite-link.json` + チェーン依存 3 ファイルの再生成。他は不変(README 規約 27 として明記) | 純追記 | 1 の帰結 |

---

## 6. 申し送り・スコープ外

- **DK(デバイス鍵分離)**: (ii) 案(端末ごとの member 鍵)を採る場合 `add_member` の payload に再度触れる可能性がある。ES の形式確定と DK の設計は独立だが、再生成が 2 回になる。DK 設計セッションで「端末鍵をチェーンに載せる形」を選ぶ場合は ES の scope をそのまま継承する(端末は人の scope を超えない)
- **`revoke_server` の rotate 義務の範囲**: 現行 §7 は「全環境」。サーバー鍵は開示スコープの DEK しか持たないため、メンバーと同様「開示スコープの環境」へ縮める改訂が自然だが、本改訂の対象外(ES は member の scope に限る)。四眼で `revoke_server` を対象にする場合の履行者は承認者(owner)
- **トークンの環境スコープ**(AUTH §6 の将来項): チェーン外 ACL として後続。ES の実効権限規定はこれを受け入れる形(∧ で合成)にしてある
- **VH(値の履歴)との交差**: `var history` / `rollback` は scope 内環境に限る(K4 で `InsufficientScope` を踏む — VH 側で明示)
- **Web の pending 提案表示**は読み取りのみ。承認は CLI(署名を Web に置かない — ADR-0018)
