# ES 設計録 — 環境スコープの role + PF1 四眼(2026-09-14 フェーズ 1 設計セッション・同日所有者承認・K1 反映済み)

**位置づけ**: ROADMAP H 系列「仕様改訂群」の 1 つ目 = **ES: 環境スコープの role**(CRYPTO_SPEC 未決 #11)と、同じ改訂サイクルで設計する **PF1: 四眼(チェーン上の複数署名承認)** のフェーズ 1 成果物。設計の全体像・裁定の反復記録(巡数と棄却案を含む)・実装分割・承認依頼項目を持つ。仕様改訂の起草は docs/notes/es-spec-drafts.md(CRYPTO_SPEC §3 / §6.2 / §6.3 / §6.4 / §6.5 / §7 / §11 / §13 / §14、AUTH_SPEC §6 / §9-2 / §11-1 / §12-3 / §12-4 / §12-6 / §12-7 / §12-8 / §14-1 / §15、AUDIT_SPEC §3.3 / §3.4 / §4.1 / §6)。**正本 3 文書は K1(2026-09-14)で反映済み・crypto・server・CLI は K2 以降**(K1 の記録は末尾「K1 追記」)。様式は integration-options.md 補足 19(KL3)/ 補足 21(IV)に合わせ、独立ファイルに置く(value-free-schema-design.md の先例)。

**前提(2026-09-14 所有者裁定 — ROADMAP)**: ES / PF1 は H4 法務の前に着地する招待制ベータのゲート。両方とも CRYPTO_SPEC §6.2 の合意規則を変えるため 1 回の改訂・1 回のテストベクター再生成に束ねる。**利用者がいないうちは古い実装をすべて削除してよい** — 互換経路(旧形式の受理・フォールバック)は持たず、旧クライアントは新しい op / payload に対して fail-closed になればよい。DK(デバイス鍵分離)は本設計の結果を前提にするため後続。

**承認(2026-09-14)**: 所有者は §5 の承認依頼項目 1〜24 を「裁定事項について承認します」として一括承認した(所有者選択として併記した項目は採用案側で確定: 項目 1 = A-1〔既存プロジェクトは再作成〕、項目 13 = 再作成、項目 17 = 有効化条件は合意規則で `≥` のまま・運用前提〔CLI が owner ≥ required + 1 と全 owner のリカバリー登録を案内〕)。反復の実態は §2 / §3 の見出しの巡数ではなく §3-bis / §3-ter が正で、探索の網羅性は保証できない(3-ter 末尾)。レビュー(pullfrog 9 巡・Cursor Bugbot 3 巡)の指摘はすべて反映済み。**承認後の訂正(2026-09-14 pullfrog 第 9 巡)**: 項目 5 の包含規則は、承認時の「義務の環境集合」(原則 1 = 義務の履行可能性)では scope 不変の昇格が actor の scope 外で通る欠陥があり、原則 1 を「権限の変更可能性」(change_role で role が変わるなら 旧 ∪ 新)に改訂した — 承認済み文面より厳しい側への変更であり、所有者へ報告のうえ本 PR に含める(異議があれば K1 前に差し戻す)。項目 17 の常時対象の集合(方針変更 + owner 身元の追加)は変えていない。同じく承認後の追記として、項目 20 / 22 に受理ポリシーの `expires_at_ms` 上界(受理時サーバー時計 + 30 日)と pending 上限の期限切れ除外を加えた(制約が増える側・合意規則ではない)。以降はフェーズ 2(K1 正本反映から — 新しいセッションで開始)。

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

各裁定点で案を列挙し、上位互換・銀の弾丸を問い、連続 2 巡で新案が出なければ打ち止め。巡数は正直に記す(単巡で決めた項目はその旨)。**注(2026-09-14 追記)**: 本節と §3 の見出しにある「2 巡・打ち止め」「単巡」は起草時の表記であり、打ち止め条件を満たしていなかった。巡数の訂正と追加巡の記録は §3-bis が正である(見出しは時系列の記録として残す)。

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
| D-1 **包含規則** | 原則 1「権限の変更可能性」(3-ter — 2026-09-14 pullfrog 第 9 巡で「義務の履行可能性」から改訂)からの導出: エントリが環境 E におけるメンバーの権限(値の読み / 書き / rotate / checkpoint の可否)を変えるなら actor の scope ∋ E。**権限変化の環境集合** = `add_member`: 新 scope / `change_role`: role が変わるなら 旧 ∪ 新、scope だけが変わるなら 旧 △ 新(対称差)/ `remove_member`: 現 scope。**actor の scope ⊇ 権限変化の環境集合** でなければ無効(`scope-not-contained`)。集合代数は `all` = 全環境の集合 U(将来分を含む)、`listed{X}` = 有限集合 X として定義する(`all △ listed{X} = U \ X` — 旧か新が `all` の `change_role` は all の actor のみ。2026-09-14 Cursor Bugbot 指摘対応: `all` を現存環境の id に展開すると listed の admin が対象を `all` にできてしまう)。義務の環境集合(add = 新 scope、change_role = 対称差 ∪ 降格分、remove = 現 scope)は権限変化の環境集合の部分集合なので、義務の履行可能性は**系**として従う。owner は all なので常に通る。(経緯: 当初は「新 scope」だけで縮小分の rotate 義務が抜け、「旧 ∪ 新」へ訂正、3-ter で「義務の履行可能性」からの導出に置き換えたが、それは認可の必要条件に過ぎず、scope 不変の昇格〔dev 専任 admin が prod の reader を member に上げる — 義務の環境集合 = ∅〕が通った。権限の変更可能性を原則に置き、義務の履行可能性をその系に降ろして閉じた) | 「入れられる = DEK を渡せる」「消せる = 義務の rotate を履行できる(再暗号化に旧 DEK が要る)」が構造的に一致。dangling(メンバーはいるがラップを作れる人がいない)状態を作らない |
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

対象にできる op: `grant_server` / `revoke_server` / `remove_member` / `change_role` / `add_member` / `set_approval_policy`。対象にできない op: `genesis`(構造)/ `create_environment` / `rotate_epoch` / `checkpoint`(データ・安全側の操作を止めない — rotate はインシデント対応であり四眼で遅らせてはならない)/ `propose` / `approve` / `withdraw`(再帰)。`set_approval_policy` は列挙に依らずオン中は常に対象(P2)。`revoke_server` を対象にできるのは「開示を止める」方向でも誤操作(リース経路の停止 = CI 停止)がありうるため — 既定推奨集合には含めない。既定推奨集合(CLI の `--ops` 省略時)= `{grant_server, remove_member, change_role, set_approval_policy}`(承認項目 17)。第 2 巡で新案なし。**第 3 巡(2026-09-14 pullfrog レビュー — 既定構成の穴)**: 既定集合に `add_member` が無いと、owner 1 名が自分の第 2 の鍵対を owner として直接追記し、自作の 2 人目 owner で定足数を満たせる(`distinct` はチェーン上の身元であって人格ではない)。案 1 = owner role を確立する `add_member` / `change_role` を `set_approval_policy` と同じ論法で**常時対象**にする / 案 2 = 既定集合に `add_member` を加える(招待経路すべてが四眼になり、外した運用で穴が戻る)/ 案 3 = 保証外と明記 + CLI 警告。**案 1 を採用**(owner を増やせることは四眼の前提そのもの。案 2 の上位互換 — 既定集合は不変で、外した運用でも穴が開かない)。残余: 有効化前から同一人物が持つ複数 owner 身元は検証不能(§14.2-10 に明記)。方針変更と pending 提案の関係は「各 approve 時点の現方針で判定」と定めた(nit 対応 — A-2)。**第 4 巡(pullfrog レビュー — 常時対象化の対価)**: owner がちょうど required 名のとき 1 名が恒久的に欠けると、残る owner は owner 追加(常時四眼)・欠けた owner の削除 / 降格(`approval-quorum-unreachable`)・方針オフ(常時四眼)のいずれもできず、管理面がロックアウトする(データ面は動く。リカバリーラップ未登録の鍵紛失と「人が戻らない」ケースに迂回路なし)。案 = (i) 残余として明記 + CLI が有効化時に「owner ≥ required + 1」と全 owner のリカバリー登録を案内(運用前提)、(ii) 有効化条件を合意規則で `>`(予備 owner 必須)に強める、(iii) 時間錠つき break-glass(原則 6・P6 の timestamp 裁定に抵触 — 棄却)。**(i) を採用し、(ii) は承認項目 17 で所有者に選択を委ねる**(合意規則で強めると owner 2 名のチームが四眼を使えなくなる)

### 裁定 P4: 承認者と提案者(2 巡・打ち止め)

- 承認者は **owner のみ**(distinct user_id)。admin を承認者に含める案は「admin 2 名で admin を消せる」= owner の管理権限(§6.2)の迂回になるため棄却
- 提案者は内側 op を**通常の role 規則で実行できる者**(admin が reader の remove を提案できる)。提案者が owner なら提案が 1 票に数える(2 owner の流れ = 提案 + 承認 1 回)
- 提案者は承認エントリを重ねて出せない(distinct)。承認の取り消しは持たない(提案ごと `withdraw`)

### 裁定 P5: 適用点と再検査(2 巡・打ち止め)

- 内側 op は、票数が `required` に達した **`approve` エントリの seq で適用**(inclusive 規約 — remove の tenure 終了・change_role の新 role はその seq で有効)
- 適用時に内側 op の合意規則を**適用時点の状態**で再検査する(対象の存在・role 規則・包含規則・最後の owner・鍵重複・到達可能性 …)。加えて**提案者が現メンバーで、提案時と同じ鍵 FP・内側 op に必要な role を持つ**こと(`proposal-void` — 提案後に提案者が削除・降格・鍵変更された提案は完成できない)
- **票 = 今の `approve` の actor 自身 + 「今の `approve` エントリの時点でも owner である過去の投票者」**(2026-09-14 Cursor Bugbot 指摘対応・2 巡目で現承認者の算入を明記): 投票時の owner 資格だけを見ると、投票後に降格・削除された投票者の票が残り、残る owner 1 名が完成できてしまう(四眼の破れ)。票数は承認のたびに適用前状態で再計算し、現承認者は role 規則で owner が確認済みなので必ず算入する
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

- 受理: `propose` / `approve` / `withdraw` / `set_approval_policy` は**汎用 append**(§11 — 付随データなし)。トークン水準は内側 op と同じ(admin)。受理ポリシー: pending 提案はプロジェクトあたり **32** 件まで(型付き 422 `ProposalLimit` — 合意規則ではない。期限切れの提案は数えない。`expires_at_ms` は受理時サーバー時計 + 30 日を上界とする — 2026-09-14 pullfrog 第 9 巡)
- 適用完了時の副作用(`chain-accept.ts` の `applyAcceptanceSideEffectsSync`): 完成した approve エントリに対し、内側 op の副作用(remove → 要ローテーション検出・申告行の削除、add → 旧鍵ラップ掃除・招待 completed 化)を走らせる
- ミラー: `chain.proposed` / `chain.approved` / `chain.proposal_withdrawn` / `chain.approval_policy_changed`(1 エントリ 1 行 — 全単射不変)。**完成した approve エントリは、加えて内側 op のミラー行**(`chain.member_removed` 等)を**同じ chain_seq** で書き、payload に `{ viaProposalSeq }` を付す(要ローテーション検出の在籍区間 Q1 が `chain.member_removed` を読む構造を変えない)。`audit verify` の全単射検査は「1 エントリ ↔ 1 行 + 完成 approve の適用行」に改める
- **四眼経由の義務の履行者は内側 op の種類を問わず承認者(2026-09-14 pullfrog / Cursor Bugbot レビュー対応)**: 適用は承認者の approve エントリの seq で起き、提案者のクライアントは通常動いていない。remove の sweep と対称に、**適用を完成させた承認者のクライアントがバックフィル(add_member / scope 拡大 = 対象の scope の全環境 × 全エポックのメンバー宛、grant_server = 開示スコープ内全環境 × 全エポックのサーバー宛)と rotate(remove / 降格 / 縮小 / revoke_server)を走らせる**。承認者 = owner = all なので DEK を持ち、包含規則から履行可能。AUTH_SPEC §12-6 の独立登録経路に 5 番目として明記(spec-drafts B-6 / A-6)。既定推奨集合に `add_member` は入っていないが `change_role` は入っており拡大は `change_role` で起きるため、既定構成でも到達する経路
- CLI: 新グループ **`maruhi approval`**(`list` / `show <id>` / `approve <id>` / `withdraw <id>` — `maruhi key approve <code>`〔KL3 ハンドオフ〕とは別グループで衝突しない。id = 提案エントリのハッシュ〔hex 64。先頭 8 文字の一意接頭辞を受け付ける〕)、**`maruhi project policy approvals --required N [--ops …]`**(オン / 変更 / `--off`)。既存の `member remove` / `member change-role` / `server grant` / `server revoke` / `member add` は方針が対象にしていれば `propose` を出して「needs N−1 more owner approval(s)」を表示して終了(rotate 義務は適用後に `member remove` の再実行または `approval approve` 側の sweep で収束 — 承認者が rotate を実行する)。**承認者の CLI が承認後に sweep を走らせる**(remove の完成者 = 承認者が §7 の履行者。包含規則により owner は all なので履行可能)
- Web: pending 提案の一覧表示のみ(署名は Web に置かない — ADR-0018)

第 2 巡で新案なし → 打ち止め。

---

## 3-bis. 追加巡の記録(2026-09-14 所有者指示 — 打ち止め条件の厳密適用)

**訂正**: §2 / §3 の「2 巡・打ち止め」は、実際には「案を列挙した巡 → 新案なしの巡」の 1 往復で止めており、打ち止め条件(**上位互換も銀の弾丸も出ない巡が連続 2 巡**)を満たしていなかった。単巡と記した J / L / M / N / P7 は探索をしていない。レビュー 8 巡(pullfrog 5・Cursor Bugbot 3)で P3 / P5 / P6 に新しい穴が見つかったことがその証拠である。以下、各裁定について「従前の空巡数(最後の新案の後に新案が出なかった連続巡数)」と、追加巡で出た案・評価を記す。追加巡は新案が出た場合はさらに 1 巡を足し、空巡が連続 2 に達するまで回した。

| 裁定 | 従前の空巡 | 追加巡で出た案(評価) | 追加後の空巡(上位互換・銀の弾丸が出なかった連続巡数。棄却案しか出ない巡は空巡に数える) | 結論 |
|---|---|---|---|---|
| A 置き場 | 1 | **A-5** scope をチェーン外の署名付きステートメント(§4.2 型)で運ぶ — ラップ先一致(§6.3)・包含規則が「チェーン時点の actor scope」を要するのに真実源が 2 つになる。省略 = 不明が fail-open に化ける。棄却 / **A-6** 環境ごとの中間鍵(env KEK)を導入し DEK は KEK へ、KEK をメンバーへラップ — 「誰が受け取るか」の判定は変わらず、鍵層が 1 段増える(新プリミティブではないが層の追加)。棄却 / **A-7** `grant_member_env`(メンバー × 環境ごと 1 エントリ)— A-2 の粒度悪化。棄却 / **A-8(本命候補)** `add_member` は不変で **既定 scope = `listed{}`(何も受け取らない = fail-closed)**、新 op `set_member_scope [target, kind, list]` で拡大。A-2 の漏洩窓(既定 all の非原子ペアで並行 rotate が新メンバー宛に全環境をラップする)を既定 none で消し、原子ペアも不要。既存チェーンは再作成でなく `set_member_scope` の追記で移行できる。**ただし**「既存ベクターは純追記」の利点は成立しない: `value-signature.json` / `metadata-signature.json` / `env-manifest.json` は正規チェーンの member が値を書く正例を持ち、既定 none では宣言ヘッド時点の scope 検査で負例に転じる → 正規チェーンに `set_member_scope` を挿入 = seq が変わる = 全再生成。ベクターのコストは A-1 と同じで、残る利点は「デプロイ済みプロジェクトの追記移行」だけ。対価は「追加は常に 2 エントリ」「owner の add は構造的に all の特例」に加えて**移行の窓**(第 4 巡で判明): 既定 none では旧チェーンの既存メンバー全員が宣言ヘッド時点で R(E) から外れる一方、登録済みラップは残るため §6.3 の「ラップ先 = R(E) と厳密一致」が既存の全環境で破れ、owner が人数分の `set_member_scope` を追記するまで値付き pull / `project verify` / rotate が通らない。追記は旧サーバーが未知 op を拒否するためアップグレード前には打てない。さらに §4 の「旧 CLI は新チェーンを fail-closed で拒否する」は A-1 固有で、A-8 では `set_member_scope` を含まないチェーンを旧 CLI が旧解釈(全員 all)で受理しうる。よって A-8 の利点は「再作成不要」ではなく「再作成の代わりに owner が人数分追記する(その間は検証不能)」であり、検証デプロイ 1 個の現状では A-1 との差はほぼない | 2(第 3 巡で A-8 → 第 4・5 巡で上位互換なし) | **A-1 を維持**。A-8 は既存プロジェクトが多い場合の代替として承認項目 1 に併記(所有者選択) |
| B 符号化 | 1 | B-5 単一フィールドで all を特別 LP に符号化(B-3 と同じ問題)/ B-6 `create_environment` の seq 順ビットマップ(コンパクトだが順序依存で脆い)/ B-7 id でなく `create_environment` の seq で環境を参照(座標系が既存の environment_id と割れる)。いずれも棄却 | 2(第 2・3 巡で上位互換なし) | B-1 維持 |
| C role との関係 | 1 | C-4 owner にも scope を許し「管理は all・DEK 受領は scope」に分離 — prod DEK を持たない owner は remove 義務の rotate を履行できず包含規則と矛盾。棄却 / C-5 C-1(admin = all)の再検討 — C-2 の部分集合であることを再確認 | 2(第 4・5 巡で上位互換なし — §2 の見出しどおり第 3 巡まで済み) | C-2 維持 |
| D 包含規則 | 1 | **D-5** remove だけ包含を免除する(緊急削除を優先し rotate 義務は他の owner へ委ねる)— 削除自体は新規配布を止めるので緊急性の価値はあるが、義務の履行者が不在の dangling 義務が常態化する。owner は all なので緊急経路は常に存在する(dev 専任 admin が prod メンバーを消せないのは owner へのエスカレーションで足りる)。棄却 / D-6 add / change は包含、remove は「対象 scope ∩ actor scope ≠ ∅」— 中途半端。棄却 | 2(第 2・3 巡で上位互換なし) | D-1 維持 |
| E 環境対象 op | 1 | E-3 listed の actor が create するとき自分の scope を原子的に拡大する複合 — 署名対象の外の暗黙変化は避けられるが(拡大も同じエントリ列に載る)、create 複合が 3 エントリになる。用途(dev 専任メンバーの環境作成)が薄い。棄却 — 需要が出たら追記で足せる形 / E-4 create の payload に初期受信者集合を持たせる — R(E) の定義と二重化。棄却 | 2(第 2・3 巡で上位互換なし) | E 維持 |
| F 縮小の意味論 | 1 | F-3 縮小後に当該環境の値 pull を rotate 完了まで止める — 対象は既に scope 外で拒否されており、義務は既保持 DEK の失効なので無意味。棄却 / F-4 縮小 + 縮小分の rotate を 1 複合にする — §12-4 が複合化を退けた理由(環境数 × ラップ完全集合が上限を超える)がそのまま当たる。棄却 | 2(第 2・3 巡で上位互換なし) | F-1 維持 |
| G 可視範囲 | 1 | G-4 scope 外環境の表示名・変数名を当該 DEK で暗号化して隠す — 未決 #3(変数名の秘匿)そのもので、鍵なし Web(ADR-0018)が名前を出せなくなる対価を伴う。ES の対象外として据え置き(未決 #3 の改訂で扱う)/ G-5 scope 外環境の checkpoint タプルを配布しない — チェーン上にあるため不可能 | 2(第 2・3 巡で上位互換なし) | G-2 維持 |
| H 実効権限 | 1 | H-3 トークンの環境スコープをチェーン scope から自動導出 — H-1 の実効アクセス定義が既にそれ。新案ではない | 2(第 2・3 巡で上位互換なし) | H-1 維持 |
| I 監査 | 1 | I-3 scope 変更の `chain.*` をクラス 2 に — チェーン自体が全員配布・検証なので見せかけ。棄却 | 2(第 2・3 巡で上位互換なし) | I-1 維持 |
| J 既存プロジェクト | 0(単巡) | J-2 旧形式 add_member の受理を「移行期間だけ」許す — 互換経路を持たない裁定に反する。棄却 / J-3 A-8 採用時は `set_member_scope` の人数分追記で移行 — ただし追記完了までの検証不能な窓を伴う(A 行)。A の併記に含める | 2(第 2・3 巡で上位互換なし) | 項目 1 の選択に従う: A-1 = 再作成 / A-8 = 追記移行(窓つき) |
| K 招待 | 1 | **K-3** 招待の scope を上限とし `member add` で部分集合へ縮められる(`--env` は ⊆ 招待 scope)— 受諾者の同意は上限として保たれ、招待のやり直しなしに絞れる。K-1 の上位互換だが、クライアント側の検査のみで署名バイト列に触れないため**後から加法的に足せる**。今回は K-1(招待行の scope を厳密に使う)を維持し、K-3 は K4 の CLI 裁量に残す | 2(第 3 巡で K-3 — 第 2 巡は従前の空巡 — → 第 4・5 巡で上位互換なし) | K-1 維持(K-3 は後続の加法) |
| L grant_server | 0(単巡) | L-2 サーバー鍵を「scope を持つメンバー」に統合する — 受信者クラス・FP 定義・リースポリシーが別で、統合は §9 の再設計。棄却 | 2(第 2・3 巡で上位互換なし) | L 維持 |
| M 表示 | 0(単巡) | M-2 `member list` を新設せず `project verify` に scope 列を足すだけ — 検証出力に埋もれ、日常の確認コマンドがない。`member list` は値ゼロで安価。維持 | 2(第 2・3 巡で上位互換なし) | M 維持 |
| N DEK 受信規則 | 0(単巡) | N-2 scope 外ラップを受け取ったら pull 全体を拒否(fail hard)— サーバー非適合の証拠だが、拒否は可用性を落とすだけで機密性を足さない(scope 外 DEK で書いても全検証者が拒否する)。警告 + 不使用を維持 | 2(第 2・3 巡で上位互換なし) | N 維持 |
| P1 形 | 1 | P1-4 `approve` に内側 payload を再掲(自己記述)— ハッシュ参照で足り、二重化は分岐の芽。棄却 / P1-5 複数提案の一括 approve — 便宜のみ。後続の加法に残す | 2(第 2・3 巡で上位互換なし) | P1-1 維持 |
| P2 方針 | 1 | P2-4 genesis に初期方針 + 変更可 — P2-2 と同値 / P2-5 必要承認数を owner 数の過半数など比率で — owner 数に結合し到達可能性が動的になる。棄却 | 2(第 4・5 巡で上位互換なし — §3 の見出しどおり第 3 巡まで済み) | P2-2 維持 |
| P3 対象 op | 0(レビュー第 4 巡直後) | P3-5 `rotate_epoch` / `create_environment` を任意対象に含める — 安全側・データ面の操作を止めない原則に反する。棄却 / P3-6 既定推奨集合に `revoke_server` を含める — 開示停止の方向でも CI 停止の誤操作がありうるため含めない判断を再確認 | 2(第 5・6 巡で上位互換なし — §3 本文の第 4 巡の後) | P3 維持 |
| P4 承認者 | 1 | P4-3 提案者の票を数えない(提案者以外の owner 2 名を要求)— 四眼 = 2 名の目であり提案者も目。より厳しい運用は `required_approvals` を上げれば得られる。棄却 | 2(第 2・3 巡で上位互換なし) | P4 維持 |
| P5 適用点 | 0(レビュー第 2 巡直後) | P5-2 適用失敗の approve を「提案を閉じる」効果にする — 承認署名の二義性(既に棄却済みの再確認)/ P5-3 票の owner 資格を投票時のみで判定 — Bugbot 指摘で棄却済み | 2(第 2・3 巡で上位互換なし) | P5 維持 |
| P6 期限 | 0(レビュー直後) | P6-4 承認者 timestamp に下界(提案 timestamp 以上)— 窓内の詐称を止めない(棄却済みの再確認)/ P6-5 期限をサーバー受理時刻(監査行)で判定 — 合意規則の入力がチェーン外(原則 6 違反)。棄却 | 2(第 4・5 巡で上位互換なし — §3 の第 3 巡 + レビュー追補の後) | P6-3 維持 |
| P7 義務の起点 | 0(単巡) | P7-2 提案時点から rotate 義務を始める(先回りローテーション)— 適用前に失効する DEK はなく、提案が撤回されれば無駄な rotate になる。棄却 | 2(第 2・3 巡で上位互換なし) | P7 維持 |
| P8 受理・監査・CLI | 0(レビュー直後) | P8-2 承認者以外の owner が sync 時に未履行義務を検出して代行する — 承認者の履行が主、代行は `project verify` の未収束警告からの手動実行として既に成立。新案ではない | 2(第 2・3 巡で上位互換なし) | P8 維持 |

**最終確認(2026-09-14 — 所有者の「本当にこれ以上の案はないか」への回答前の敵対的読み直し)**: 裁定 D の `change_role` の包含が「新 scope」のみで、縮小分(旧 \ 新)が actor の scope 外でも通る欠陥を発見し、「旧 ∪ 新」に訂正した(A-2・承認項目 5)。採用案の構造は変わらないが、探索の網羅性は保証できない — レビュー 8 巡とこの読み直しで計 4 件の穴が後から見つかっており、正本反映(K1)前の所有者レビューと K2 のベクター設計(負例の列挙)が最後の網である。

**追加巡の帰結**: 採用案の変更はない。

## 3-ter. そもそもの見直し — 列挙から原則への置き換え(2026-09-14 所有者の問い「そもそもを見直すことで回避できるか」への回答)

**原因分析**: 後から見つかった 4 件の穴はすべて同じ型で、規則を「op ごとの特例の列挙」として書いたために、列挙し忘れた組み合わせが穴になった。

| 穴 | 列挙し忘れたもの |
|---|---|
| `change_role` の包含が「新 scope」だけ | 縮小分の rotate 義務 |
| `approval-required` が提案の内側 op にも掛かる閉路 | 「提案経由」という文脈 |
| 離脱済み投票者の票が残る | 票を数える時点 |
| owner 身元の自作で定足数を満たせる | 「owner を増やす op」が方針の一部であること |
| scope 不変の昇格が actor の scope 外で通る(原則への置き換え後 — pullfrog 第 9 巡) | (列挙ではなく)原則の被覆不足: 「義務の履行可能性」は認可の必要条件であり、義務が生じない権限変化を覆っていなかった |

列挙を増やしても次の組み合わせで再発するため、**規則を 2 つの原則に置き換え、op ごとの規則はその帰結として書く**(spec-drafts A-2 を改訂済み)。

- **原則 1 — 権限の変更可能性**(2026-09-14 pullfrog 第 9 巡で「義務の履行可能性」から改訂): エントリが環境 E におけるメンバーの権限(値の読み / 書き / rotate / checkpoint の可否)を変えるなら、actor の scope は E を含む。op ごとの**権限変化の環境集合**は role 表から導出する(add = 新 scope、change_role = role が変わるなら 旧 ∪ 新・scope だけなら対称差、remove = 現 scope)。集合代数では `all` を全環境の集合 U(将来分を含む)として扱う — `all △ listed{X} = U \ X` は `listed` に包含されないため、`all` を出入りする scope 変更は all の actor のみ(Cursor Bugbot 指摘対応)。**系 — 義務の履行可能性**: §7 / §12-6 の義務(rotate・バックフィル)は権限が変わる環境にしか生じないため、義務の環境集合(add = 新 scope、change_role = 対称差 ∪ 降格分、remove = 現 scope)⊆ 権限変化の環境集合 ⊆ actor scope が常に成り立ち、DEK を持つ者だけが義務を負う。当初 3-ter は「義務の履行可能性」を原則に置いたが、それは認可の必要条件であって十分条件ではなく、義務の環境集合が空になる scope 不変の昇格(dev 専任 admin が prod の reader を member に上げる)が通った(pullfrog 第 9 巡)。dev 専任 admin が {dev, prod} のメンバーの role を prod に触れずに変えられる「利得」は prod の書き手を増減できることと同義であり、利得ではなかった。scope だけを変える `change_role` は対称差の判定で従来どおり dev 専任 admin が行える
- **原則 2 — 署名者集合 S による認可**: 直接追記は S = {actor}、提案経由は S = 提案者 ∪ 承認者。required(op) ≥ 2 のとき、適用時点で owner である S の distinct 数 ≥ required(op)(required = 1 の op は通常の role 規則 = S = {actor} が op の role を持つこと、で判定する — 原則 2 は required ≥ 2 のときに掛かる追加条件であり、非 owner の直接追記を否定しない)。**不変条件「方針の単調性」**(2 つの帰結 — pullfrog 第 9 巡で分離): (a) 方針が有効な間、方針を変える op(`set_approval_policy`)と owner 身元を増やす op(owner を確立する `add_member` / `change_role`)は `ops` の列挙に依らず常に対象、(b) owner 数を required 未満にする op(owner の `remove_member` / owner からの `change_role`)は無効(到達可能性)。owner を減らす op は (b) で扱い、常時対象には**しない**(`ops` に含めなければ直接追記できる — 承認項目 17 / §14.2-10 の前提のとおり)。`approval-required` の除外規定・票の再計算・常時対象は、いずれもこの原則と不変条件の帰結になり、例外として列挙する必要がなくなる

**効果と限界**: 失敗の型が「列挙し忘れ」から「原則の適用ミス」と「**原則の被覆不足**(原則が旧規則の覆っていた範囲を落とす — 上表 5 行目。置き換え直後に実際に起きた)」に変わる。被覆不足は「置き換え前の各規則が原則から導出できるか」を 1 件ずつ確認することで検出できる(第 9 巡ではこの確認を怠り、`旧 ∪ 新` を「粗い近似」と片づけた)。後者は原則と照らして検証できる(K2 の負例は原則ごとに列挙する: 原則 1 = 権限変化の環境集合の各要素が actor scope 外〔scope 不変の昇格を含む〕、原則 2 = S の各要素が非 owner / 重複 / 時点違い)。ゼロ保証にはならないが、レビューの網が効く形になる。理由コードと検査順序は不変(ベクターの固定に必要)。

**最終読み直し(2026-09-14 — 所有者の「そのほかに欠陥はないか」への回答)**: 承認項目 1〜24 を 5 観点(義務の履行者の有無・不変条件を破れる状態への到達可能性・クライアント検証とサーバー受理の一致・時点のずれ・ES × 四眼の交差)で読み直した。裁定を変える欠陥は見つからず、補強 2 件を A-2 に追記した: (i) pending 提案の受理上限(32)は期限切れを数えない — 放置された提案を `withdraw` を待たず時間で解く(受理ポリシーなのでサーバー時計でよい。pullfrog 第 9 巡: 意図的な占有には `expires_at_ms` に上界がないと効かないため、受理ポリシーに上界 30 日を置いた。即時に解く手当は owner の `withdraw`)、(ii) 四眼経由の op では原則 1 の履行者は承認者(owner = all)であり構造的に満たされる。提案者に対する原則 1 の検査は「直接追記できる op か」の確認である。確認済みで問題なしと判断した交差点: owner → admin の降格は scope all → listed の縮小義務を伴い actor(owner)が履行できる / listed{} の admin は listed{} の対象しか追加できない(管理専任 admin)/ 提案者が自分自身の remove を提案できる(適用時点まで在籍)/ 競合する 2 提案は後の適用が内側 op の規則で失敗し pending に残る / 縮小の未履行義務は縮小の actor に帰属し、後の remove の actor(現 scope のみ)には帰属しない。**検証できていないもの**: 検査順序の相互作用と `audit verify` の全単射規則の細部は、K2 のベクターと K5 の実装テストでしか固定できない。

**所有者が案を出せないときの手順(一般)**: (1) 穴を「何を列挙し忘れたか」に言い換える、(2) その列挙を生んでいる上位の目的(ここでは「義務は履行できる者だけが生める」「定足数未満で方針を弱められない」)を 1 文で書く、(3) その 1 文を規則にし、個別規則を帰結へ格下げする、(4) **置き換え前の各規則(棄却した近似を含む)が新原則から導出できることを 1 件ずつ確認する** — 導出できない規則があれば原則が必要条件に留まっている証拠であり、原則を広げる(第 9 巡の教訓)。設計の見直しは案の再探索ではなく、**規則を生成している原則の抽出**として行う。承認項目 1 に A-8(既定 none + `set_member_scope`)を所有者選択の代替として併記し、K-3 を後続の加法として記録した。以後の裁定では「新案なしの連続 2 巡」を満たしてから打ち止めと書く。

## 4. 実装分割(K1〜K7)と独立停止可能性

系列はテストベクター → crypto → api-schema → server → CLI(CLAUDE.md の順序)。**ES → 四眼の順**。各段はマージ後にそこで止めても安全であることを要件とする。

| 段 | 内容 | 停止しても安全な理由 |
|---|---|---|
| **K1** | 仕様の正本へ反映(CRYPTO_SPEC 0.10 → **0.11-draft**、AUTH_SPEC 0.22 → **0.23-draft**、AUDIT_SPEC 1.7 → **1.8-draft**。Status 欄に改訂履歴) | docs のみ |
| **K2** | **テストベクターを先に書く**: `chain-entries.json` 全再生成(add_member / change_role の scope・新 op 4 種・`expected_head_states` に scope / 方針 / pending・正例・負例)、`invite-link.json` 再生成(発行文に scope)、チェーンを読み込む `value-signature.json` / `metadata-signature.json` / `env-manifest.json` の再生成 → `packages/crypto`(scope の型・正規化・合意規則 ES + PF1・履歴索引・宣言ヘッド時点の scope 検査・発行文)→ **api-schema のワイヤ + server / CLI の機械的追随**(scope は `all` 固定で発行、PF1 の op は生成しない)。**人間レビュー必須箇所を PR 本文に列挙**。**`docs/SELF_HOSTING.md` "Updates" に移行順序(サーバー → 全メンバー CLI → 既存プロジェクトの再作成)を同梱**(2026-09-14 所有者裁定 — K7 から前倒し。破壊的変更とその手順書を同じ PR で着地させる) | 挙動変更なし(全メンバー = all のまま)。crypto が新規則を理解し、旧形式を拒否する。この段のデプロイで既存プロジェクトのチェーンは無効になるため、K2 のマージ = 検証デプロイの再作成のタイミング |
| **K3** | server(ES): 受信者集合 = scope(`expectedWrapRecipientCount` / `checkWrapRecipient`)、環境対象 op の scope 認可(`InsufficientScope`)、値・メタ・マニフェストの宣言ヘッド時点 scope 検査、招待行の scope、ミラー payload、要ローテーション検出の環境別窓・縮小変種。テストは `@cloudflare/vitest-plugin`。**完了(2026-09-15 — 裁定は §9 K3 追記: 403 は `ForbiddenError{reason: insufficient-scope}`、判定順 role → scope → 存在、3′ は `chain-head-state-mismatch` に畳んだまま、R(E) は 1 述語、環境別窓は member / server 共有の窓導出、`rotation.recommended` に `trigger`、AUDIT_SPEC §4.2 Q1 の列挙訂正、`chain_seq` 全単射は K5 へ据え置き)** | CLI はまだ all しか発行しないので配布は従来どおり。制限は眠ったまま |
| **K4** | CLI(ES): `invite create --env`、`member add`(招待行の scope)、`member change-role --env` / `member scope`(拡大 backfill・縮小 sweep)、**`member list`**、`wrapRecipientsFor` / backfill / sweep の scope 対応、`env create` の前提検査、pull / push / rotate の scope 外エラー、scope 外ラップの警告、`project verify` の scope 列 + Web `ProjectScreen` の scope 列。テストは Vitest。**完了(2026-09-15 — 裁定は §10 K4 追記: `change-role` は 1 コマンドで (role, scope) を全置換〔省略 = 据え置き・`--all-envs`〕、通信前判定は前段 / 共通ガード / DEK 取得口 / 値付き pull の漏斗、sweep は義務ごとの環境集合を具体化、Web の scope 列は K4 で確定、受信側規則は取得口の型付きエラー)** | ES 完了。四眼は方針なし = オフのまま |
| **K5** | server(PF1): **K2-10 の受理ガード(`ApprovalNotAccepted`)の解除と同じ PR で。解除の前提 = 正本への申し送り ⑤(投票者の鍵束縛)の所有者裁定と、その反映(正本 → ベクター → crypto)が済んでいること — 解除した瞬間に ⑤ が実効化するため。2026-09-15 の K2-11 で裁定・反映済み(前提は満たされた)。K5 で判断する持ち越し: 鍵の再登録による票の復活(K2-11 ⑤ 行「失効は単調ではない」)を CRYPTO_SPEC §6.2 の一文として正本に載せるか設計録のままにするか、および CLI / UI が過去に見た鍵 FP の再登録に警告するか(pullfrog 第 3 巡の指摘)。さらに `required_approvals` 引き下げ後の pending 提案の完成(既投票 owner の approve は `duplicate-approval` — K2-11-bis の UX 上の難点)を CLI / UI の案内で扱うか合意規則で扱うか**: 受理ポリシー(pending 上限。8-bis K2-5 e-3: 作成時点で失効済みの提案〔`expires_at_ms` < 受理時サーバー時計〕の拒否も受理ポリシー候補)、適用完了時の副作用(要ローテーション検出・旧鍵ラップ掃除・申告行削除・成長ガード)、ミラー 4 種 + 適用行、`audit verify` の全単射規則。**完了(2026-09-16 — 裁定は §11 K5 追記: 受理ガード解除〔`ApprovalNotAccepted` はワイヤに残しサーバーは発生させない — K5-A〕、受理ポリシーは DO のみで上界 → pending 上限〔K5-B〕、失効済み提案は拒否しない〔K5-C〕、成長ガードは提案・承認の入口〔K5-D〕、適用行 = 同 chain_seq・actor = 提案者・`viaProposalSeq`〔K5-E〕、完成判定は core の `indexProposals` を server / CLI で共有〔K5-F〕、全単射は期待行集合との突合〔K5-G〕、DO の append が適用した提案を返し worker が D1 後処理〔K5-H〕、`ProposalLimit { reason, limit }`〔K5-I〕、持ち越し (i) = 設計録のまま・(ii)(iii) = CLI 案内で K6 実装〔K5-J〜L〕、提案 API は置かずクライアント導出〔K5-M〕)** | K2 のサーバーは 4 op を 422 で拒否する(受理ガード = 執行)→ K5 で解除 |
| **K6** | CLI(PF1): `approval` グループ、`project policy approvals`、既存コマンドの提案化、承認者側の sweep、Web の pending 表示 | 既定オフ。有効化は owner ≥ 2 の明示操作 |
| **K7** | docs: `apps/site/docs/`(`environment-scopes.mdx` 新規・`invite-a-teammate.mdx` の `--env`・`four-eyes.mdx` 新規)、~~`docs/SELF_HOSTING.md` "Updates" に移行順序~~(K2 へ前倒し — 2026-09-14 所有者裁定)、ROADMAP の完了記録 | docs のみ |

- 移行の順序要件: サーバー(K2 デプロイ)→ 全メンバーの CLI(K2 以降)。旧 CLI は新チェーンを `bad-signature` / 未知 op で拒否し(fail-closed — **A-1 固有**。A-8 では `set_member_scope` を含まないチェーンを旧 CLI が旧解釈で受理しうる — 3-bis 裁定 A 行)、新 CLI は旧サーバーへの add_member を新形式で送るため旧サーバーが拒否する(どちらの向きも黙って旧解釈しない)
- 見積もり: ROADMAP の概算(ES 2〜3 週・PF1 3〜4 週)は人手前提。実測(KL3 / IV)から、律速は所有者承認と crypto 人間レビュー

---

## 5. 承認依頼項目(所有者裁定を要するもの)

各項目に「採用案 / 棄却案 / 理由」の要約。仕様・暗号・チェーン規則・ワイヤ形式・監査事件の追加に係るものを積む。実装の内部構造・命名・テストの形は自分で決めて進める。

| # | 項目 | 採用 | 棄却 | 理由(要約) |
|---|---|---|---|---|
| 1 | スコープの置き場(裁定 A) | `add_member` / `change_role` の payload 拡張 = **チェーン形式変更・`chain-entries.json` 全再生成・既存チェーン無効(検証デプロイのプロジェクト再作成)** | 追加 op `set_member_scope`(A-2: 既定 all + 原子ペア — 漏洩窓)/ データプレーン方針 / **A-8: 既定 `listed{}` + `set_member_scope`(追加巡 — 3-bis)**: 漏洩窓なし。既存プロジェクトは owner が人数分 `set_member_scope` を追記して移行できるが、**アップグレード直後から追記完了までは §6.3 のラップ先厳密一致が破れ値付き pull / verify / rotate が通らない窓**があり(追記は旧サーバーが未知 op を拒否するため事前には打てない)、旧 CLI の fail-closed も成立しない(`set_member_scope` を含まないチェーンを旧解釈で受理しうる)。ベクターの全再生成は同じく必要。追加が常に 2 エントリ | 1 エントリ = 1 事実。公開前に形式を確定する §11 の先例(grant_server 拡張)。**再作成の帰結を承認いただきたい。A-8 は「再作成の代わりに人数分の追記 + その間の検証不能な窓」であり、検証デプロイ 1 個の現状では差がほぼない — 既存プロジェクトが増える前の今、A-1 で確定する判断を推奨** |
| 2 | 符号化(裁定 B) | `scope_kind` ∈ {all, listed} + `scope_environments_lp_hex`(grant_server と同じ入れ子 LP・≤ 256・順序は署名対象・生成昇順 SHOULD) | 空 = all(fail-open)/ 番兵 `*` / all を表現しない | grant_server の先例の再利用。all の明示 |
| 3 | 構造規則(裁定 B) | all ⇒ 空リスト必須(`invalid-payload`)、listed の id は `create_environment` 先行必須(`unknown-environment`)、重複 = `invalid-payload`、listed の空リストは有効 | 存在検査なし / 空 listed の禁止 | fail-closed(typo)。`listed{}` = 管理のみ・後で入れる の表現 |
| 4 | role との関係(裁定 C) | owner = all 固定(`scope-role-mismatch`)。admin / member / reader は listed 可 | admin も all 固定 / owner も listed | C-2 は C-1 の上位互換(admin を all にすれば同じ)。dev 専任 admin が書ける |
| 5 | 包含規則(裁定 D) | **原則 1「権限の変更可能性」からの導出**(3-ter。**承認後の訂正 — 2026-09-14 pullfrog 第 9 巡**: 承認時の文面「義務の環境集合」では scope 不変の昇格が通ったため、より厳しい側へ訂正した。所有者へ報告済み): add = 新 scope / change_role = role が変わるなら 旧 ∪ 新・scope だけなら 旧 △ 新 / remove = 現 scope について **actor scope ⊇ 権限変化の環境集合**(`scope-not-contained`)。義務の環境集合はその部分集合(系)。検査順序: 既存の検査列(role → duplicate-* / unknown-target → last-owner)の**後ろ**に unknown-environment → scope-role-mismatch → scope-not-contained(既存負例の期待理由を温存) | 包含なし + 他メンバーによるバックフィル委任 | ラップ実行者 = DEK 保持者(§7)。消せる = rotate を履行できる |
| 6 | 環境対象 op(裁定 E) | rotate / checkpoint(全タプル)は env ∈ actor scope、create は all の actor のみ(すべて `environment-out-of-scope`) | 作成者の暗黙スコープ追加 | 原則 6(暗黙の scope 変化を作らない)。1 述語で 3 op を覆う |
| 7 | 縮小の意味論(裁定 F) | 縮小を受理し、縮小分の環境に §7 の rotate 義務(sweep 第 4 種 `scope-narrowed`)。降格 = 対象 scope の環境、remove = 対象の現 scope の環境 | 縮小を合意規則で拒否(grant_server 型) | remove + re-add の招待やり直し・tenure 分断を避ける。義務で同じ目的を達する |
| 8 | 拡大の義務(裁定 F) | change_role の拡大分は actor が全エポックをバックフィル(§12-6 の追記経路。複合化しない) | 複合化 | §12-4 の非対称(上限超過)の再確認 |
| 9 | スコープ外の可視範囲(裁定 G) | メタ(存在・名前・スキーマ・マニフェスト・tombstone)は見える、暗号文・DEK・書き込み・rotate・checkpoint は不可。拒否は 403 `InsufficientScope` | 存在も隠す(不可能)/ 暗号文も配る | 未決 #3 の線の延長。`maruhi schema` がスコープ外でも動く |
| 10 | 環境横断の検証(裁定 G) | checkpoint のスコープ外タプルは合意規則の検証のみ・基準に使わない。マニフェスト検証・申告・アンカー・床は不変 | — | 基準は pull する環境にしか要らない |
| 11 | 実効権限の環境軸(裁定 H) | 実効アクセス(E) = min(トークン, role) ∧ E ∈ チェーン scope。トークンの環境スコープは今回導入しない(AUTH §6 の将来項のまま)。CI リースポリシーとの合成は変更なし | トークン環境スコープ同時導入 | チェーン外 ACL は後から加法的に足せる |
| 12 | 監査の可視性(裁定 I) | クラス不変。ミラー payload に scope(`chain.member_added` / `chain.role_changed`)。`rotation.recommended` 縮小変種(trigger = change_role)。要ローテーション検出の候補 = 環境別アクセス窓 | データ系イベントを scope で絞る | メタは全員可視(G-2)。`audit verify` を scope 非依存に保つ |
| 13 | 既存プロジェクト(裁定 J) | **項目 1 の選択に従う**: A-1 = 「スコープ無しのメンバー」は存在せず、明示初期化なし、既存プロジェクトは再作成 / A-8 = owner が人数分 `set_member_scope` を追記(完了までの検証不能な窓を伴う — 3-bis 裁定 A 行) | 移行期間の旧形式受理(互換経路) | 1 の帰結(1 と 13 を別々に裁定して矛盾する組み合わせにならないよう分岐を明示) |
| 14 | 招待(裁定 K) | 発行文の末尾に `scope_kind, scope_environments_lp_hex`(`invite-link.json` 再生成)、D1 行に scope、リンク `sk=` / `se=`、`invite create --env`(反復・省略 = all)。`member add` は招待行の scope | `member add --env`(任意指定)/ K-3 招待 scope を上限として `member add` で縮める(追加巡 — クライアント検査のみで後から加法的に足せるため今回は見送り) | 受諾者が入る環境を事前に読める。同意の範囲を固定 |
| 15 | grant_server(裁定 L) | 対象外。受信者集合 R(E) = { member: E ∈ scope } ∪ { grant: E ∈ scope_environments } の 1 定義 | — | 既存構造への追随 |
| 16 | 四眼の形(P1) | 2 エントリ `propose` / `approve`(+ `withdraw`)。**規則は原則 2「署名者集合 S による認可」+ 不変条件「方針の単調性」からの導出**として書く(3-ter — `approval-required` の例外規定・票の再計算・常時対象はいずれも導出) | 共同署名 1 エントリ / チェーン外承認 | §6.1 不変・追記で拡張・原則 6 |
| 17 | 方針の置き場と既定(P2 / P3) | 新 op `set_approval_policy` = `[ops_lp_hex, required_approvals]`。既定オフ。有効化は owner ≥ required。**方針 op 自身と owner role を確立する add_member / change_role は `ops` の列挙に依らず常に対象**(owner 身元の自作で定足数を満たす経路を閉じる)。pending 提案は各 approve 時点の現方針で判定。**可用性の対価**: 署名できる owner(鍵を保持し協力する owner)が required 未満になると管理面が復帰不能(チェーン上の owner 数は到達可能性の不変条件で減らない — §14.2-10 に明記)。緩和は運用前提(CLI が有効化時に owner ≥ required + 1 と全 owner のリカバリー登録を案内)— **有効化条件を合意規則で `>` に強めるかは所有者裁定**。owner 数を required 未満にする op は無効(`approval-quorum-unreachable`)。対象可能 op = grant_server / revoke_server / remove_member / change_role / add_member / set_approval_policy。既定推奨集合 = {grant_server, remove_member, change_role, set_approval_policy} | genesis 固定 / チェーン外設定 / 2 固定 | 単独 owner を壊さない。オフにするのに四眼が要る |
| 18 | 承認者と提案者(P4) | 承認者 = owner のみ(distinct)。提案者 = 内側 op を実行できる role。owner の提案は 1 票 | admin 承認者 | owner の管理権限の迂回を作らない |
| 19 | 適用点と再検査(P5) | 定足数到達の approve の seq で適用(inclusive)。提案時 + 適用時に内側 op の合意規則を検査、適用時は提案者の現在性(`proposal-void`)も。**票は現時点でも owner の投票者のみを数える**(離脱済み投票者の票は失効) | 適用失敗で提案が自動的に閉じる | 承認署名に「閉じる」効果を持たせない |
| 20 | 期限(P6) | `expires_at_ms`(CLI 既定 7 日。受理ポリシーの上界 = 受理時サーバー時計 + 30 日 — 合意規則ではない。pullfrog 第 9 巡)+ 合意規則 `approve.timestamp_ms ≤ expires_at_ms`(`proposal-expired`)。**timestamp を合意規則に用いる唯一の箇所。正直な承認者向けの UX 安全装置であり、悪意の承認者(過去方向の詐称)に対する保証ではない** | 期限なし / seq 距離 / 下界の追加(窓内詐称を止められない) | 文脈を失った承認の抑止。§14.2-10 の保証は期限に依存しない |
| 21 | remove の義務の起点(P7) | 適用時点 | 提案時点 | 適用前に失効する DEK はない |
| 22 | 受理・監査・履行者(P8) | 汎用 append。pending ≤ 32(受理ポリシー — 期限切れは数えない・`expires_at_ms` の上界 = 受理時サーバー時計 + 30 日。承認後の追記、pullfrog 第 9 巡)。ミラー 4 種 + 完成 approve の適用行(同 chain_seq・`viaProposalSeq`)。`audit verify` の全単射規則の改訂。**四眼経由の義務は内側 op の種類を問わず適用を完成させた承認者が履行**(add_member / scope 拡大 / grant_server のバックフィル = §12-6 の 5 番目の経路、remove / 降格 / 縮小 / revoke_server の rotate) | 提案者による履行(適用時に不在) | 検出(Q1)の入力構造を変えない。承認者 = owner = all で履行可能 |
| 23 | CLI 名(P8) | `maruhi approval list / show / approve / withdraw`、`maruhi project policy approvals`。既存コマンドの自動提案化。承認者側で sweep | `maruhi key approve` との同居 | KL3 のハンドオフ承認と衝突させない |
| 24 | テストベクター(§11) | K2 で `chain-entries.json` 全再生成 + `invite-link.json` + チェーン依存 3 ファイルの再生成。他は不変(README 規約 27 として明記) | 純追記 | 1 の帰結 |

---

## 6. 申し送り・スコープ外

- **DK(デバイス鍵分離)**: (ii) 案(端末ごとの member 鍵)を採る場合 `add_member` の payload に再度触れる可能性がある。ES の形式確定と DK の設計は独立だが、再生成が 2 回になる。DK 設計セッションで「端末鍵をチェーンに載せる形」を選ぶ場合は ES の scope をそのまま継承する(端末は人の scope を超えない)
- **`revoke_server` の rotate 義務の範囲**: 現行 §7 は「全環境」。サーバー鍵は開示スコープの DEK しか持たないため、メンバーと同様「開示スコープの環境」へ縮める改訂が自然だが、本改訂の対象外(ES は member の scope に限る)。四眼で `revoke_server` を対象にする場合の履行者は承認者(owner)
- **トークンの環境スコープ**(AUTH §6 の将来項): チェーン外 ACL として後続。ES の実効権限規定はこれを受け入れる形(∧ で合成)にしてある
- **VH(値の履歴)との交差**: `var history` / `rollback` は scope 内環境に限る(K4 で `InsufficientScope` を踏む — VH 側で明示)
- **Web の pending 提案表示**は読み取りのみ。承認は CLI(署名を Web に置かない — ADR-0018)

---

## 7. K1 追記(2026-09-14 — 正本反映時の裁定)

K1 は反映作業であり、承認済み項目 1〜24 は変えていない。正本に書く段階で生じた裁定は次の 1 件。

### K1-1. 原則 1 / 原則 2 の置き場 — CRYPTO_SPEC §1「設計原則」への昇格か §6.2 内か

ドラフト(spec-drafts A-2)は 2 原則を §6.2 の合意規則の中に置いている。§1 原則 6 の先例(「意味論は署名バイト列の中に置く」— 既存アーキテクチャの明文化として §1 に昇格)に倣うかを裁定した。

| 案 | 内容 | 評価(平文の所在・署名者・改訂範囲・コスト・整合) |
|---|---|---|
| K1-1a **§6.2 内に留める(ドラフトのまま)** | 2 原則は §6.2 の合意規則の冒頭で「以下の個別規則はこの原則からの導出」と宣言される | 平文・署名者には無関係。改訂範囲は §6.2 のみ。§1 の 6 原則は暗号設計全体(選択的開示・標準部品・文脈束縛・アジリティ・暗号の限界・署名バイト列)に掛かる横断原則であり、原則 1 / 2 はチェーン認可(§6.2)の内部規則を生成する原則で、§4 / §5 / §8 / §9 には掛からない。承認済みドラフトの文面をそのまま置ける |
| K1-1b §1 に原則 7 / 8 として昇格 + §6.2 に導出を残す | §1 = 「7. 環境 E の権限を変えられるのは E の DEK 保持者だけ」「8. 定足数未満で方針を弱められない」、§6.2 = 導出 | 先例(原則 6)と同型の見た目になる。ただし原則 6 が昇格したのは「全署名構造(値・メタ・チェーン・招待・申告)に掛かる」からで、原則 1 / 2 は §6.2 に閉じる。§1 に置くと同じ文が 2 箇所に現れ、改訂時の二重管理が生じる(spec-drafts と正本で「差異が生じた場合は正本が勝つ」規律の内部版が要る) |
| K1-1c §1 に 1 行の横断原則だけを置き、本文は §6.2 | 「7. 認可規則は列挙でなく原則から導出する(§6.2 の原則 1 / 2)」 | 規範の内容を持たない参照行。3-ter の「所有者が案を出せないときの手順」はプロセス規範であり、仕様の設計原則ではない(設計録に置く方が適切) |

第 1 巡: 上表の 3 案。第 2 巡(上位互換・銀の弾丸の探索): 「原則 1 / 2 が §6.2 以外にも掛かる面はないか」を確認した — §6.3 の 3′(宣言ヘッド時点の scope 検査)・§7 の義務・AUTH_SPEC §12-6 の受理条件は、いずれも §6.2 の検証状態(scope)の**消費者**であり、規則を生成する側ではない(義務の履行可能性は原則 1 の**系**として §6.2 に書いてある)。掛かる面が §6.2 に閉じる以上、K1-1b の利点(横断性の明示)を保つ対象が存在せず、上位互換なし。銀の弾丸(置き場の裁定を不要にする構造)もなし — 空巡。第 3 巡: 新案なし — 空巡。連続 2 空巡で打ち止め(正直な巡数: 列挙 1 巡 + 空巡 2)。

**原則の抽出**: 「§1 に置くのは、暗号設計の複数の機構に横断して掛かる原則だけ」(原則 6 の昇格理由の一般化)。置き換え前の各判断がこの原則から導出できることの確認: 原則 1〜5 = 全機構横断 ✓、原則 6 = 全署名構造横断 ✓、原則 1 / 2(ES / PF1)= §6.2 のみ → §6.2 内 ✓。導出できない判断はない。

**採用: K1-1a(§6.2 内に留める — ドラフトのまま)**。棄却理由: K1-1b は横断性のない原則を横断原則の列に混ぜ二重管理を生む、K1-1c は規範内容のない参照行。承認済み項目の変更は伴わない(項目 5 / 16 の「原則からの導出として書く」は §6.2 内で満たされている)。将来 DK(端末鍵)や PF2(ミラー)で原則 1 / 2 が §6.2 の外(例: 端末鍵の失効の認可)にも掛かることが判明した時点で、§1 への昇格を改訂として提示する。

### K1-2. ドラフトと §5 の食い違い

反映時に照合した範囲で食い違いは見つからなかった(理由コード名・検査順序・包含判定の集合代数・四眼の常時対象・票の再計算・pending 上限と `expires_at_ms` の上界はドラフトと §5 で一致)。正本には、ドラフトに無い既存本文の**相互参照の掃除**として次を最小限で書き換えた: CRYPTO_SPEC §4.3 検証規則 (2) と §6.3 規則 4・§14.2-3 / -4 の「全環境ローテーション」→「対象の scope の全環境」、§6.2 の既存 3 箇所の検査順序(鍵一意性・環境ライフサイクル・checkpoint)への scope 系検査の位置の注記、§6.3 (a) 招待リンクアンカーと §6.5 の改竄検出対象への scope の追加、§6.4「認可の真実源」への scope の併記、§6.5「`add_member` の形式は不変」の限定(IV に関して)、§7「全環境の全エポック DEK を現メンバーへ」→「scope 内の各環境 … を R(E) へ」、§13 #6 の #11 参照の解消注記 / AUTH_SPEC §12-4 の複合内ラップ集合の再作成条件(現メンバー集合 → R(E))/ AUDIT_SPEC §3.3 `dek.registered` 注記の将来項の解消。

### K1-3. PR #175 レビュー(pullfrog 第 1 巡)からの明確化・申し送り

- **DEK ラップ登録の署名者軸の理由コード**(nit): AUTH_SPEC §12-6 の「登録者(署名者)も対象環境を scope に含む」は、署名者 = 呼び出し主体(§12-6 (1))であるため §12-3 の呼び出し主体の scope 判定と同一 = 403 `InsufficientScope`。受信者軸は 422 `scope-out-of-range`。正本に明記した(新しい理由コードは増やさない — K2 のベクターはチェーン検証のみで、この判定はサーバー受理面〔K3〕)
- **`docs/SELF_HOSTING.md` "Updates" の参照**: K1 の対象外(所有者指示 — K7)。正本には「K7 で追記・再作成が必要になるのは K2 のデプロイ時点」と明記して行き止まりを避けた。**所有者裁定(2026-09-14): K2 の PR に同梱**(K1 では実装未確定で手順を正確に書けず、K7 では K2〜K6 の間に手順書のない破壊的変更がデプロイ済みになる。破壊的変更と手順書を同じ PR で着地させる — 境界チェックポイント移行の先例と同型)。§4 の K2 / K7 行を更新済み
- **K3 への申し送り**: AUDIT_SPEC §3.4 の四眼の適用行は同一 `chain_seq` に 2 行を置く。`chain_seq` の一意性を前提とする実装(`maruhi audit verify` の全単射検査・索引)は K3 / K5 で「1 エントリ ↔ 1 行 + 完成 approve の適用行」に改める(§3.4 に規定済み。UNIQUE 制約は現状なし — pullfrog 確認)

## 8. K2 追記(2026-09-14 — テストベクター先行 + 合意規則の実装時の裁定)

K2(ベクター → `packages/crypto` → ワイヤの機械的追随)で、正本が沈黙している点を §5 の手順(案の列挙 → 上位互換・銀の弾丸の探索 → 2 巡空振りで打ち止め → 原則の抽出 → 旧規則の導出確認)で裁定した。承認済み項目 1〜24・§7 の K1 裁定は変更していない。正本(CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC)の改訂は本 PR に含めない — 正本の変更を要する点は末尾「正本への申し送り」に分けて所有者へ提示する。

### K2-1. 検証状態のベクター表現(方針・pending・投票者)— 候補 (a)

| 案 | 内容 | 判断 |
|---|---|---|
| a-1 **メンバー = `{ role, scope }`、方針 = `{ ops, required_approvals }` / `null`、pending = 提案 hash → `{ proposal_seq, proposer_user_id, proposer_key_fingerprint_hex, proposer_role_at_proposal, inner_op, inner_payload, expires_at_ms, approvals[] }`** | §6.2 の「検証状態は方針(ops・required)と pending 提案の集合(提案 hash → 提案者・内側 op・期限・投票者集合)を導出する」をそのまま JSON にする。`approvals` は受理済み approve の actor の順序付き列 | **採用** |
| a-2 pending に票数(`votes`)も載せる | 票は「各 approve 時点の現 owner」で再集計する(原則 2)ため、状態に固定値を持つと再集計規則と二重管理になる | 棄却 |
| a-3 メンバーの scope を `environments: string[] | "all"` の 1 フィールドに畳む | payload の 2 フィールド(`scope_kind` / `scope_environments`)と 1:1 でなくなり、`listed` の空リストと `all` の区別を文字列とリストの型で表すことになる | 棄却 |

第 2 巡(上位互換の探索): 「ベクターは検証状態を持たず negative / valid_appends の受理結果だけを固定する」は、導出状態の間違い(票の数え方・pending の残り方)を検出できないため上位互換でない。打ち止め。**原則**: ベクターの検証状態は正本の「導出する」と書かれた状態を、payload と同じ語彙(snake_case・数値は 10 進文字列)で 1:1 に写す — 既存の `expected_head_states`(members / server_grants / environments)がこの原則の先例。`proposer_role_at_proposal` は情報値であり合意規則の入力ではない(K2-6 参照)。**→ 2026-09-15 の K2-11 ② で規則の入力になった**(提案署名を S に入れる条件)。

### K2-2. 派生チェーン(extended_chains)での提案 hash の参照 — 候補 (b)

approve / withdraw の `proposal_hash_hex` は提案エントリの entry_hash(§6.2)なので、生成器が派生チェーンの propose エントリを組んだ後にそのハッシュを計算して次のエントリに埋める(a-1 と同じ「生成器が正規化を持つ」前提)。`verify_reference.mjs` は派生チェーン内の approve / withdraw が同じチェーン内の propose の entry_hash を指すことを独立に検査する。代替(ベクターに `proposal_ref: <seq>` を書き検証側で解決)は、正本に無い間接参照をベクター形式に持ち込むので棄却。

### K2-3. 履歴索引の (role, scope) と提案経由の適用 seq — 候補 (c)

| 案 | 内容 | 判断 |
|---|---|---|
| c-1 **在籍区間ごとに `(role, scope)` の変化点(seq)の列を持つ。提案経由の適用は、定足数に達した approve エントリの seq を変化点にし、記録は「適用された内側 op + 帰属 actor(提案者)」を verifyChain のループが履歴索引へ渡す** | §6.2「履歴索引はメンバーの在籍区間ごとに (role, scope) の変化点(seq)を保持する」と「この approve エントリの seq で内側 op を適用する(inclusive)」の直訳 | **採用** |
| c-2 role と scope を別々の変化点列にする | change_role は (role, scope) の全置換なので変化点は常に同時 — 分けると照会が 2 回になるだけ | 棄却 |
| c-3 approve エントリ自体を履歴索引に載せる(内側 op を展開しない) | `memberStateAt` の照会側が内側 op の展開規則を持つことになり、検証ループと履歴索引で適用規則が二重になる | 棄却 |

実装形: `HISTORY_RECORDERS` の鍵を「エントリの op」から「適用された op(propose / approve / withdraw を除く 10 op)」へ変え、verifyChain の評価結果(`AppliedOperation = { operation, actorUserId }`)を渡す。propose / withdraw / 定足数未達の approve は状態遷移を伴わないので何も記録しない。

### K2-4. 型と集合代数(`all` = U の fail-closed)— 候補 (d)

payload 上は `scopeKind` / `scopeEnvironmentIds` の 2 フィールドを平坦に持つ(正規化フィールドと 1:1)。導出状態は `MemberScope = { kind: "all" } | { kind: "listed"; environmentIds }`。原則 1 の包含判定は `EnvironmentSet = { kind: "all" } | { kind: "listed"; ids: Set }` の代数で行い、`all` は U **または U の補有限部分集合**(`all △ listed{X} = U \ X`)を表す — どちらも `listed` の actor には包含されえないため、型の上で同じ「`all` 側」に倒す(fail-closed)。`all △ all = ∅`(listed の空集合)。第 2 巡で「集合を常に有限集合 + 補集合フラグで表す」案を検討したが、包含判定の結論が同じで表現だけが重いので採らない。**原則**: 「listed の actor が包含できる集合は有限集合だけ」— これから `all ∪ X = all`・`all △ X → all 側`・`listed ⊉ all` がすべて導出される(正本の集合代数の各行と一致することを確認済み)。

### K2-5. `expires_at_ms` / `timestamp_ms` の型 — 候補 (e)

どちらも非負の安全整数(§2.1 の数値 = 10 進文字列の符号化と、既存の `timestamp_ms` の形状検査と同じ)。`proposal-expired` は `timestamp_ms > expires_at_ms` の比較のみ(等号は受理 — `proposal-one-vote` の派生チェーンが境界を固定)。

### K2-6. 原則 2 の署名者集合 S と `duplicate-approval` / 票数

**→ 2026-09-15 の K2-11 ②・⑤ で改訂(本節は旧裁定の記録)**: S = {owner として提案した提案者} ∪ {approve の actor}、要素は (user_id, 署名時の鍵 FP)。昇格した提案者の自己承認は重複ではなく 1 票。

正本の個別規則「提案者が owner なら提案が 1 票」「owner として提案した提案者」と、原則 2 の「S = {提案者} ∪ {approve の actor 全員}、票数 = |S ∩ 適用時点の owners|」を、**原則の側で実装**する: S は提案者を常に含む(提案時の role に依らない)ので、(i) `duplicate-approval` = 「actor が既に S の要素」(提案者の自己承認・同じ owner の 2 票目)、(ii) 票数 = S ∪ {この actor} のうち**今の**owner の distinct 数。提案時に admin だった提案者が後に owner へ昇格した場合、原則ではその提案者は S の要素として票に数えられ、自己承認は `duplicate-approval` になる(個別規則の字面「owner として提案した」だけを読むと票に数えないが、原則 2 が「以下の個別規則はこの原則からの導出」と宣言しているため原則を優先した)。この形はベクターには現れない(派生チェーンに「提案者の昇格」の形は無い)ため、**正本への申し送り**(下記)に挙げる。`proposer_role_at_proposal` は状態に残すが合意規則の入力ではない。

### K2-7. `propose` の内側 op の運搬と構造検査

ワイヤ・型は内側 op を構造化して運ぶ(`inner: { op, payload }`)。正規化は `inner_payload_lp_hex` = 内側 op の `payload_bytes` の hex(§6.2)で、実装は `canonicalChainPayloadBytes` を再帰的に呼ぶ。構造検査は内側 op を既知 op の形状表で検査し、内側 op が `propose` / `approve` / `withdraw` なら構造段で `invalid-payload`(提案の入れ子は方針の対象になりえず、再帰的な形状検査を持たない — negative `propose-inner-op-nested`)。`genesis` / `create_environment` / `rotate_epoch` / `checkpoint` を内側 op に置く形は構造的には通り、認可段の `approval-not-required`(方針の対象外)で落ちる(negative `authz-propose-rotate-not-required`)。`set_approval_policy` の `ops` の重複は `grant_server` の scope と同じ集合意味論で構造段では拒否せず、導出状態では去重して保持する。

### K2-8. 検査順序のうちベクターで固定できない対

理由コードは合意規則の一部だが、次の対は同一エントリで同時に成立させられないため順序をベクターで固定できない(実装の順序を記録する): `add_member` の `duplicate-member` × `duplicate-member-key`(既存 — user_id → 鍵の順)、`change_role` の `last-owner-protected` × `approval-quorum-unreachable`(方針有効時は owner ≥ 2 が前提なので最後の owner は存在しえない — 実装は last-owner を先に判定)、`approve` の `insufficient-role` × `unknown-proposal`(非 owner の未知提案は role が先 — negative `authz-approve-role-precedes-unknown` で固定済み)。

### K2-9. head-attestation.json の再生成(§11 の不変リストとの食い違い)

CRYPTO_SPEC §11 / 本設計録 §1-3 は `head-attestation.json` を「不変」に分類していたが、ヘッド申告は正規チェーンの entry_hash(`chain_head_hash_hex`)を署名対象に含むため、`chain-entries.json` の全再生成に伴って**再生成が必要**だった(意味は不変 — 申告者・seq の意味論は変えず、参照するハッシュだけが新しい正規チェーンのものになる)。README 規約 27 に記録した。**正本への申し送り**: §11 の不変リストから `head-attestation.json` を外し「チェーン依存」へ移す(1 行の訂正 — 本 PR には含めない)。

### K2-10. サーバーの四眼 4 op の受理(独立レビュー F1 — 2026-09-14 所有者指示の Opus レビュー)

| 案 | 内容 | 判断 |
|---|---|---|
| j-1(当初) | 汎用 append の verifyChain で 4 op を受理する(構造・合意規則のみ)。副作用は K5 | **撤回**。完成した approve は verifyChain の中で内側 op を適用するが、サーバーの受理副作用(AUDIT_SPEC §3.4 の適用行・§7 の要ローテーション検出 `detectMemberRemoval`・再追加メンバーの旧鍵ラップ掃除 `deleteStaleMemberWraps`・申告行削除・§12-8 の成長ガード)はすべて `entry.op` で分岐するため拾えない。ミラー行は v1 でバックフィルしない(chain-commit.ts)ので**欠落が恒久化**し、`audit verify` の全単射も 1:1 のまま検知しない。「CLI が提案を出さないので眠ったまま」はクライアントの協力に依存する論拠で、受理面の執行ではない(§4 の要件「各段はマージ後にそこで止めても安全」に反する) |
| j-2 **採用** | worker ハンドラと DO `appendProgram` の両方で 4 op を `ApprovalNotAccepted`(422)として K5 まで拒否する(`composite-required` と同じ多層防御・同じ型付きエラーの形) | fail-closed で数行。api-schema の `ChainEntrySchema` から 4 op を外さない(K5 での再追加が重く、CLI の読み取り側は 4 op を含むチェーンを検証できる必要がある) |
| j-3 | 受理副作用を K2 で実装する | K5 の本体(検証状態を要するミラー行・`viaProposalSeq`・pending 上限)であり、K2 の範囲を越える。棄却 |

**原則**: 「サーバーが受理する op の集合 = 受理副作用が実装済みの op の集合」— 検証器が受理できることと受理面が受理してよいことは別であり、副作用が op 判定で分岐している限り、新 op の受理は副作用の実装と同じ PR で入れる。K5 の受理ガード解除はこの原則の適用(ミラー行・検出・掃除・上限を同時に入れる)。サーバーテスト: 正規チェーンの再生は seq 19(方針オフのヘッド)まで、seq 20〜24 と前提再生可能な四眼 op の negative は受理ガードでの 422 を固定、前提チェーンが四眼 op の受理を要する negative(12 + 派生チェーン 14 本)は crypto 層の 4 実行環境テストのみで固定(K5 でガードを外すときに復帰)。

### K2-11. 正本への申し送り ①〜⑤ の裁定(2026-09-15 所有者委任 — 「本当に問題ないと思うならそれで OK」)

所有者から裁定を委ねられたため、各項目を「現状で問題ないか」で判定し、変更を要するものは正本 → ベクター → crypto の順で反映した(PR #176 に続く追補 PR)。

| # | 判定 | 理由 | 反映 |
|---|---|---|---|
| ① `head-attestation.json` の分類 | **直す** | 正本 §11 が事実(申告はチェーンヘッドのハッシュに署名する = チェーン依存)と食い違ったままは「問題ない」ではない | CRYPTO_SPEC §11 の 0.11-draft 項を訂正(1 行) |
| ② 「owner として提案した提案者」の字面 vs 原則 2 の S | **字面の読みを採る(実装を変える)** | 判断材料(8-bis K2-6): 字面の読みには「数えられる票はすべて owner role で作られた署名」という不変条件があり、**監査は署名だけで定足数を追える**(AUDIT_SPEC の写しに投票者の役割履歴を要さない)。原則の読み(適用時点の role で数える)はこの性質を持たず、admin としての提案署名を昇格後に票と数える。原則 2 を「S = {owner として署名した者}」と定義し直せば例外列挙にはならず(3-ter の線)、昇格した提案者は owner として `approve` を追記できる(自己承認は S 外なので重複でない)ため機能も失わない。攻撃面は等価(いずれの読みでも完成には S 外の owner の approve が要る) | CRYPTO_SPEC §6.2 原則 2 の S の定義と `approve` の規則。実装: `signersOf`(提案者は `proposerRoleAtProposal === "owner"` のときのみ S)。派生チェーン `proposer-promoted` / `-self-vote` / `-completed`(K2-1 a-6 は解消 — `proposer_role_at_proposal` は規則の入力) |
| ③ AUDIT §3.4 のミラー行 | **現状維持** | K5 の受理面で揃える(受理ガードにより K5 まで四眼のエントリはサーバーに存在しない) | なし |
| ④ `set_approval_policy.ops` の重複 | **現状維持** | ops は閉集合 6 要素で、`applySetApprovalPolicy` が去重して保持するため導出状態は決定的。scope の重複拒否とは対象の性質が違う(独立レビューも同意) | なし |
| ⑤ 投票者の票の束縛 | **直す** | 鍵更新(削除 → 別鍵での再追加)が侵害鍵の票を失効させないのは鍵更新儀式の目的と矛盾する。S の要素を (user_id, 署名時の鍵 FP) で識別すれば提案者の `proposal-void`(鍵 FP 束縛)と対称になり、再追加された owner は新鍵で改めて投票できる。在籍区間(tenure)ではなく鍵 FP に束縛するのは、同一鍵での再追加(§6.2 で許容)は鍵の支配者が変わっていない = 票の失効理由がないため。**採らなかった案: 在籍区間束縛**(remove → 同一鍵での再追加でも旧票を失効させる)— 8-ter の申し送り文はこれを推奨していたが、§7 の rotate 義務は DEK の再配布のためであり署名の信用の失効ではなく、同一鍵の復帰は「同一人物の復帰」として §6.2 が明示的に許容する。S の要素に tenure の識別子を足す分の状態も増える。両案が分かれる唯一のケース(同一鍵での再追加)は派生チェーン `readded-approver-same-key` / `-completed` と負例 `authz-approve-readded-same-key-duplicate` で固定した(pullfrog 第 1 巡の指摘)。**失効は単調ではない**: 侵害鍵 A で投票 → 削除 → 新鍵 B で再追加(旧票は失効)→ 削除 → 鍵 A で再登録、とすれば (user_id, A) の票は復活する(独立レビューの実測)。再登録は owner 確立の `add_member` = 常時四眼の対象なので定足数の署名を要し穴ではないが、侵害既知の鍵の再登録を禁じるのは運用規律であって合意規則ではない | CRYPTO_SPEC §6.2 原則 2 / `approve`。実装: `ApprovalVote = { userId, keyFingerprintHex }`、`countOwnerVotes` は「同じ鍵 FP を持つ現メンバーとして owner」の distinct user_id 数、`duplicate-approval` は (user_id, 現鍵 FP) ∈ S。ベクター: `expected_pending.approvals` を `{user_id, key_fingerprint_hex}` の列に改め、派生チェーン `readded-approver-vote` / `readded-approver-revote` を追加。正規チェーン・既存の負例・既存の派生チェーンのバイト列は不変 |

**原則(②・⑤ を 1 文で)**: 「四眼の票は、owner role で作られ、かつ適用時点でも同じ鍵を持つ現 owner に帰属する署名である」— 署名時の条件(role)と適用時の条件(在籍・鍵・role)を両方課す。K5 の受理ガード解除の前提(§4 の K5 行)は本裁定の反映で満たされる。

### K2-11-bis. ①〜⑤ の追加巡・原則の抽出・ユーザー体験の点検(2026-09-15 所有者の問い「案が出なくなるまでループしたか / UX が悪くなる決定はないか」への回答)

**訂正**: K2-11 の裁定は ②・⑤ で 2〜3 案を比べただけで、3-bis の打ち止め条件(上位互換も銀の弾丸も出ない巡が連続 2 巡)と §5 手順の後半(原則の抽出 → 旧規則の導出確認)を形式的には回していなかった。以下、5 件すべてについて回し直し、あわせてユーザー体験(UX)の観点で各裁定を点検した。**結論: 裁定を変える上位互換・銀の弾丸はなし。UX を悪くする決定もなし(唯一の UX 上の難点は本裁定に由来しない既存挙動で、K5 に持ち越し)**。① からは機械検査 1 件を追加した。

| 裁定 | 追加巡で出た案(評価) | 空巡 | 原則(1 文)と導出確認 | UX の点検 |
|---|---|---|---|---|
| ① `head-attestation.json` の分類 | **a** §11 の分類を「改訂ごとの散文」でなく依存関係の表にする — 散文の改訂履歴が規範なので二重管理になる。棄却 / **b** 分類を機械検査で守る(不変とされたファイルに正規チェーンの entry_hash が 1 つも埋まっていないことをテストで固定)— **採用**(`vector-inventory.ts` に追加。8-ter K2-9 で手で走らせた照合の恒久化) / 第 3 巡: 新案なし | 2 | 「ベクターの不変性はバイト列の依存関係で決まり、分類は機械検査で守る」— §11 の分類・README 規約 27 の「他は不変」はこの原則の帰結 ✓ | 影響なし(開発者向け) |
| ② S = owner として署名した者 | **d** 承認者にも「署名時 role」を課す — 承認者は role 検査で常に owner なので同値。新案でない / **e** 昇格後の提案者に「再確認の署名」を求める — 採用案の「approve を追記する」と同じ / **f** 提案署名を票に数えず、票 = approve エントリのみ(owner の提案も自分の approve を要する)— 規則が最も一様(`proposer_role_at_proposal` が規則から消える)で監査も一様だが、**承認項目 18「owner の提案は 1 票」を覆す**ため委任の範囲外。CLI が propose 直後に自分の approve を自動追記すれば UX は同等(記録は 3 エントリ)。所有者が一様性を優先するなら K5 で再検討できる案として記録 / 第 3 巡: 昇格を暗黙の再署名とみなす — 原則 6(意味論は署名バイト列の中)に反する。棄却 | 2 | 「四眼の票は owner role で作られた署名」— 承認項目 18(owner の提案は 1 票)✓ 導出、`duplicate-approval`(自己承認は S の要素の重複)✓、昇格した提案者の approve は S 外なので有効 ✓、字面の approve 行 ✓ | **admin として提案した本人が昇格後に自分の提案を完成させたいときは approve を 1 つ追記する**必要がある(自動では数えない)。K6 の pending 表示で「あなたは approve できます」を出せば操作は 1 手。旧読み(自動で票になる)との差は「明示の 1 手」であり、その 1 手が監査の署名になる。悪化ではない |
| ③ AUDIT §3.4 のミラーは K5 | **c** ② でミラーの形が変わるか — admin 提案者の自己 approve は `chain.approved completed=false` の行として既存の形で表せる(独立レビュー)。変更不要 / 第 2・3 巡: 新案なし | 2 | 「受理する op の集合 = 受理副作用が実装済みの op の集合」(K2-10)— K5 まで四眼のエントリはサーバーに存在しないので、ミラーの空白は観測されない ✓ | 影響なし |
| ④ `ops` の重複 | **c** 生成側で ops を昇順 SHOULD にする — `scope_environments` と同じ扱いで既に負例 `policy-ops-reorder` が順序を署名対象として固定しており、検証は集合。新案でない / 第 2・3 巡: 新案なし | 2 | 「構造段で摘むのは非決定性の芽だけ」— ops は閉集合 6 要素で去重後の導出状態が決定的 ✓ | 影響なし |
| ⑤ 票の (user_id, 鍵 FP) 束縛 | **d** (user_id, 鍵 FP, 在籍開始 seq) の 3 つ組(鍵 + 在籍区間)— A→B→A の再登録で票が復活する非単調性を閉じる。ただし復活には既知の侵害鍵を owner 確立 op(常時四眼)で再登録する定足数の署名が要り、それは運用の失敗そのもの。対価は S の要素と `ChainMember` に在籍開始 seq を持たせる状態の追加と、同一鍵で復帰した owner が改めて approve し直す手間。**上位互換ではない(閉じるのは運用失敗の後始末だけ)**。棄却(K5 の持ち越し = 正本への一文 / UI の警告で扱う) / **e** 投票者のいかなる変化(降格・削除・鍵更新)でも票を永久失効 — d と同じ / **f** 鍵 FP のみ(user_id なし)で識別 — 鍵は現メンバーで一意だが身元は user_id であり、別 user_id への鍵の移転で票が移るのは誤り(独立レビューで「移らない」を実測)。棄却 / 第 3 巡: 新案なし | 2 | 「四眼の票は、owner role で作られ、かつ適用時点でも同じ鍵を持つ現 owner に帰属する署名」— 別鍵での再追加は失効 ✓、同一鍵での再追加は存続 ✓(§6.2 の「同一人物の復帰」)、提案者の `proposal-void`(鍵 FP)と対称 ✓、承認項目 19「離脱済み投票者の票は失効」✓ 導出 | **別鍵で再追加された owner は改めて approve する**(旧票は数えない)。鍵を替えた本人にとって自然な期待で、K6 の pending 表示が「あなたの旧票は失効しています」を出せば迷わない。同一鍵での復帰は票が生きるので手間なし。悪化ではない |

**UX 上の難点(本裁定に由来しない既存挙動 — 独立レビューの観察 ⑦)**: `required_approvals` を引き下げた後、既に足りている pending 提案は次の approve が来るまで適用されず、しかも既投票の owner が「完成させよう」と approve すると `duplicate-approval` で拒否される(閉じられるのは未投票の owner だけ)。これは承認項目 19(適用は定足数到達の approve の seq)と `duplicate-approval` の帰結で、K2-11 で変わっていない。**K5 に持ち越し**(K5 行に追記): 選択肢は (i) CLI / UI が「この提案は次の approve で完成します。approve できるのは未投票の owner: …」と案内する(規則不変。推奨)、(ii) `set_approval_policy` の適用時に既に足りている pending 提案を完成させる合意規則(正本の変更。承認項目 19 の改訂を要する)。

### 正本への申し送り(所有者へ — 2026-09-15 に所有者委任で裁定済み。K2-11 参照)

1. CRYPTO_SPEC §11: `head-attestation.json` は不変でなくチェーン依存(K2-9)。**→ ① 訂正済み(K2-11)**
2. CRYPTO_SPEC §6.2 の `approve` の個別規則の字面(「owner として提案した提案者」)を原則 2 の S の定義に揃える(K2-6 — 実装は原則側)。**→ ② 字面の読みを採用し実装を揃えた(K2-11)**。**判断材料(8-bis K2-6 の追加巡)**: 字面の読みには「数えられる票はすべて owner として作られた署名である」という不変条件があり、原則の読み(適用時点の role で数える — 承認者の失効票と対称)にはそれがない。どちらも他方を支配しない(8-bis K2-6 行)ので所有者裁定。裁定後に「提案後に昇格した提案者」の派生チェーンをベクターへ追加する(現ベクターはこの形を固定していない)。
3. AUDIT_SPEC §3.4 の四眼 4 op のミラー行(`proposalChainSeq` / `completed` / 適用行)は検証状態を要するため K2 のミラーは「エントリ単独から写せる値」(提案 hash)に留めた。K5 の受理面で正本どおりに揃える(§4 の K5 行)。
4. (任意・整合の確認)CRYPTO_SPEC §6.2 で `set_approval_policy.ops` の重複は `grant_server` の scope_environments と同じ集合意味論(構造段で拒否しない)だが、scope の `scope_environments` は重複を `invalid-payload` にする。意図的な非対称(ops は閉集合の 6 要素で非決定性の芽が小さい)なら現状維持、揃えるなら正本の改訂(8-bis K2-7 g-3)。
5. **CRYPTO_SPEC §6.2 `approve` の票数(8-ter K2-6)**: S の要素が user_id にしか束縛されないため、削除 → 新鍵で再追加された投票者の票が復活する(提案者は `proposal-void` で鍵 FP に束縛される非対称)。推奨: S の要素を在籍区間(user_id + 鍵 FP)に束縛し在籍終了で失効させる。合意規則の変更 = ベクター(派生チェーン `readded-approver-vote`)の追加を伴う。成立条件は **owner 数 > required**(`required = 2` でも owner 3 名で成立 — 独立レビューの実測、8-ter K2-6 行)。K2 のサーバーは 4 op を受理しない(K2-10)ため K5 まで到達不能だが、**K5 で受理ガードを外す前に裁定を要する**(§4 の K5 行)。**→ ⑤ 鍵 FP 束縛で修正済み(K2-11)**

## 8-bis. K2 裁定の追加巡の記録(2026-09-14 所有者の問い「各裁定で銀の弾丸・上位互換の探索を何巡回したか」への回答)

**訂正**: §8 の K2-1〜K2-9 は、3-bis で自ら定めた打ち止め条件(**上位互換も銀の弾丸も出ない巡が連続 2 巡**)を満たしていなかった。K2-1 / K2-4 は「案を列挙した巡 → 新案なしの巡」の 1 往復(空巡 1)、K2-2 / K2-3 は代替案を同じ巡で棄却しただけ(空巡 0)、K2-5〜K2-9 は単巡で探索していない(空巡 0)。以下、各裁定について追加巡を回し(新案が出た巡の後はさらに 1 巡を足し、空巡が連続 2 に達するまで)、出た案と評価を記す。**結論: 裁定を変える上位互換・銀の弾丸は 9 件のいずれにも出なかった**。副産物として、記述の不整合 1 件(K2-1 × K2-6: README 規約 27 と生成器コメントの「提案者の票は `proposer_role_at_proposal = owner` から導出する」は K2-6 の実装〔S ∩ 現 owner〕と食い違う — 本 PR で文言を訂正)と、所有者・K5 への申し送り 3 件(K2-5 e-3 / K2-6 f-3 / K2-7 g-3)を得た。

| 裁定 | 従前の空巡 | 追加巡で出た案(評価) | 追加後の空巡 | 結論 |
|---|---|---|---|---|
| K2-1 検証状態のベクター表現 | 1 | **a-4** pending を hash キーの map でなく配列にする — hash は正本の識別子であり、配列は重複を許す。棄却 / **a-5** `proposer_user_id` + `approvals` を S(署名者集合)1 本に畳む — withdraw(提案者 or owner)と `proposal-void`(提案者の鍵 FP)が提案者の区別を要する。棄却 / **a-6** `proposer_role_at_proposal` を状態から外す(合意規則の入力でない — pullfrog 第 3 スレッドの誤読の原因) — 正本の「導出する」列(提案者・内側 op・期限・投票者集合)に無い値を固定している点では K2-1 の原則により忠実だが、申し送り ② で所有者が字面の読み(「owner として提案した」)を採れば規則の入力になる。② の裁定前に外すのは先取り。**保留(② の裁定後に整理)→ K2-11 ② で字面の読みを採用し、`proposer_role_at_proposal` は規則の入力として残す(解消)** / **a-7** 現ヘッドの票数を `expected_votes` として出力側に固定する — a-2 と同型(再集計規則との二重管理)。`stale-*-vote` の派生チェーンが「有効だが適用されない approve」で同じ性質を固定済み。棄却 / **a-8** メンバー状態を `{ role, scope_kind, scope_environments }` に平坦化(payload と字面 1:1) — 検証力は同じで構造の違いだけ。棄却 | 3(第 2〜4 巡) | **a-1 を維持**。副産物: README 規約 27 と生成器コメントの提案者の票の導出の記述を K2-6 に揃える(本 PR) |
| K2-2 派生チェーンの提案 hash 参照 | 0 | **b-2** approve の payload に可読用の `proposal_seq` を併記 — payload は正規化の入力であり、strictPayload の実装が非正規フィールドを拒否する。棄却 / **b-4** `verify_reference.mjs` に「参照先が当該時点で pending か」の意味検査を足す — 独立検証器の役割(正規化・署名・連鎖)を越えて合意規則を持ち込む。実装テストの領分。棄却 / **b-5** テスト側で propose の entry_hash を再計算して参照と突合 — `verify_reference.mjs` が既に行っている(同一チェーン内の propose の探索 + hash 再計算)。新案でない | 2 | **維持** |
| K2-3 履歴索引の (role, scope) と提案経由の適用 seq | 0 | **c-4** span に `viaProposalSeq`(提案経由の出所)を持たせる — §6.3 の照会は要さず、AUDIT_SPEC §3.4 のミラー行(K5)の入力。K5 で必要なら足す(先取りしない)。棄却 / **c-5** 検証ループから適用 op を渡す代わりに、履歴側がエントリごとの**状態差分**を観測する(op 非依存 — 記録漏れの型が消える) — 記録漏れは既に網羅 Record で型が防いでいる。checkpoint タプルの衝突検出(`checkpointTupleFor`)は最新状態の差分では表せず(各 checkpoint エントリのタプルを要する)、混成になって単純化しない。棄却 / **c-6** 索引を持たず照会ごとに再生 — session-14 裁定 A の蒸し返し。棄却 / **c-7** 同一 (role, scope) の連続 span の去重 — 見た目だけ。棄却 / **c-8** `recordRoleChange` に適用後の `ChainMember` を渡して `recordTenureStartOf` と揃える — 同じ出所を読む書き換えのみ。棄却 | 2 | **c-1 を維持** |
| K2-4 型と集合代数 | 1 | **d-4** 集合代数を持たず「E ごとの権限変化の述語」で判定 — `listed{X} ⊇ 変化集合` は `変化集合 ∩ (U \ X) = ∅` と同値で、U を列挙できないため「変化集合が補有限か」の判定が不可欠。現設計の言い換え。新案でない / **d-5** `MemberScope`(順序付き配列)と `EnvironmentSet`(Set)を 1 型に統合 — 状態の順序は何も要さない(検証は集合)ので統合は可能だが、`scopePayloadFieldsOf` の逆変換が正規順(昇順)を決め打つことになり、検証力は同じで変換関数が 1 つ減るだけ。棄却(整理は K3 以降の任意) / 第 4 巡: `all △ all = ∅` の帰結(listed の admin が all の admin に同 (role, scope) の change_role を追記できる = 権限変化なしの no-op)を点検 — 原則 1 に整合、穴でない。新案なし | 2(第 3〜4 巡) | **維持** |
| K2-5 `expires_at_ms` の型と比較 | 0 | **e-2** `expires_at_ms = 0` を「期限なし」の番兵にする — 正本に無い(0 は「即時失効」)。受理ポリシーの上界(30 日)とも矛盾。棄却 / **e-3** `expires_at_ms < propose.timestamp_ms`(作成時点で失効済み)の提案を構造段で拒否 — 正本に無い合意規則の追加。**K5 の受理ポリシー候補**として申し送り(サーバー時計で判定できる) / **e-4** bigint / 文字列で 2^53 超に備える — 既存 `timestamp_ms` と同じ安全整数で十分。棄却 / 第 3 巡: approve の timestamp に単調性を課す — 正本が明示的に否定(単調性も上界もない)。棄却 | 2 | **維持**。e-3 を K5 の受理ポリシー候補に申し送り |
| K2-6 原則 2 の S と `duplicate-approval` / 票数 | 0 | **f-2** 字面の読み(提案者の票は「owner として提案した」場合のみ・昇格後の提案者は approve で票を入れられる)を採る — S の読みは `duplicate-approval` で厳しく、票数で緩い(admin として作った提案署名を昇格後に票と数える)。字面の読みは逆。攻撃面は等価(完成には S 外の owner の approve が常に要り、昇格自体が四眼の対象)。どちらも他方を支配しない → 申し送り ② のとおり所有者裁定。**字面の読みに固有の不変条件「数えられる票はすべて owner として作られた署名」を判断材料として ② に追記** / **f-3** 両方の厳しい側(自己承認は常に重複 + 昇格後の提案者の票は数えない)— 昇格した提案者は正当な distinct owner であり、票を永久に入れられなくする根拠がない。原則 2 からも字面からも導出できない。棄却 / 第 3 巡: 裁定後の派生チェーン追加は追加作業であり案でない。新案なし | 2 | **維持(② は所有者裁定)** |
| K2-7 内側 op の運搬と構造検査 | 0 | **g-2** ワイヤで内側 payload を `inner_payload_lp_hex`(不透明バイト列)のまま運ぶ — サーバーの strictPayload が内側の構造を検証できず、LP の復号器(op ごとの解釈)を新たに要する。棄却 / **g-3** `set_approval_policy.ops` の重複を scope と同じく構造段で拒否 — 正本は `grant_server` と同じ集合意味論を採っており、規則の追加は K2 の範囲外。**正本への整合確認として申し送り ④(任意)** / **g-4** 入れ子 propose を構造段でなく認可段の `approval-not-required` に落とす(genesis 内側と対称に) — 内側の形状検査が再帰になり、敵対入力に深さの上界を別途要する。構造段の拒否は fail-closed で有界。genesis 内側は `ROLE_RULES.genesis = null` → `approval-not-required` で落ちることを点検(整合)。棄却 / 第 3 巡: 深さ 1 を型(`ProposableOperation` が 3 op を除外)で固定 — 既にそうなっている。新案なし | 2 | **維持**。g-3 を申し送り ④ |
| K2-8 固定できない順序対 | 0 | **h-2** 共起不能な対を実装でも到達不能にする — 状態不変条件で既に到達不能。変更なし / **h-3** 不変条件(方針有効 ⇒ owner ≥ 2 等)を実装テストで直接固定 — `authz-policy-single-owner` 等のベクターが同じ不変条件を固定済み。冗長。棄却 / 第 3 巡: README 規約 27「固定できない組」に記録済み。新案なし | 2 | **維持** |
| K2-9 head-attestation.json の再生成 | 0 | **i-2** 旧チェーンの写しをファイル内に埋め込んで不変を保つ — 申告の検証は宣言ヘッド時点の role をチェーン状態から引くため、旧形式(`add_member` が `invalid-payload`)のチェーンでは正例が検証不能。棄却 / **i-3** 申告の署名対象から head hash を外し seq のみにする — §6.6 の意味(分岐の硬い証拠)を壊す正本変更。棄却 / 第 3 巡: 新案なし | 2 | **維持(① は所有者裁定)** |

**追加巡の副産物の処置**: (1) README 規約 27 と `generate_reference.py` の該当コメントを「提案者・投票者の票はいずれも S ∩ 現 owner から導出する(提案時 role は情報値 — K2-6・申し送り ②)」に訂正(本 PR)。(2) 申し送り ② に f-2 の判断材料を追記、④ を新設。(3) e-3 は K5 の受理ポリシー候補(§4 の K5 行に足す)。

## 8-ter. K2 裁定の原則の抽出と旧規則の導出確認(2026-09-14 所有者の問い「原則の抽出もしたか」への回答)

**訂正**: 8-bis は §5 手順の前半(案の探索 → 空巡 2 で打ち止め)で止まり、後半(**規則を生み出している原則の抽出 → 置き換え前の各規則が原則から導出できることの 1 件ずつの確認**)を K2-1・K2-4 以外で行っていなかった。以下、9 件すべてについて原則を 1 文で書き、導出確認と、原則から機械的に検査できるものは実際に検査した結果を記す。**原則から新しい発見が 3 件出た**(K2-6 の投票者の在籍束縛の非対称 = 正本への申し送り ⑤、K2-8 の未固定の隣接対 = 負例 4 件を本 PR で追加、K2-1 の `proposer_role_at_proposal` がどの正本の「導出する」列にもない = ② の裁定に連動)。

| 裁定 | 抽出した原則(1 文) | 旧規則の導出確認 | 原則から出た発見・検査 |
|---|---|---|---|
| K2-1 | ベクターの検証状態は、**3 正本のいずれかが「導出する」と書いた状態**を payload と同じ語彙で 1:1 に写す | members (role, scope) ← CRYPTO §6.2「検証状態は現メンバーごとの scope を導出する」✓ / policy・pending(提案者・内側 op・期限・投票者集合)← §6.2 末尾 ✓ / `proposal_seq` ← AUDIT §3.4 `proposalChainSeq` ✓ / `proposer_key_fingerprint_hex` ← `proposal-void`(同じ鍵 FP)✓ / **`proposer_role_at_proposal` ← どの正本にもない** | 原則に照らすと `proposer_role_at_proposal` は過剰固定(a-6)。申し送り ② で原則の読みが採られれば状態・ベクターから外し、字面の読みなら規則の入力として残す — ② に連動させる |
| K2-2 | ベクターの参照体系はチェーン形式の識別子(entry_hash)のみで、生成器は正規化の第 2 実装、`verify_reference.mjs` は第 3 実装として参照を独立に再計算する | approve / withdraw の参照 ✓(`verify_reference.mjs` が同一チェーン内の propose の探索 + hash 再計算)。harness の `chain` 名参照は payload 外(接続先の指定)で原則の対象外 ✓ | 新発見なし |
| K2-3 | 履歴索引は §6.3 の時点照会に必要な状態遷移だけを、検証ループが確定した (適用 op, actor, seq) から記録し、**照会側は適用規則を持たない** | (role, scope) の span ← 3 / 3′ ✓、在籍 ← 1 ✓、エポック ← 4 ✓、checkpoint タプル ← §4.3 (2) ✓。方針・pending は時点照会の入力でないため索引に載せない ✓。提案経由の add_member は approve の seq で在籍開始(inclusive)— 同 seq を宣言ヘッドとする値署名が有効になる形は直接追記と同じ ✓ | 新発見なし |
| K2-4 | listed の actor が包含できる集合は有限集合だけ(`all` = U は将来の環境を含む) | §8 で確認済み。追加: `all △ all = ∅`(listed の admin が all の admin に同 (role, scope) の change_role = no-op を追記できる)は権限変化なしで原則 1 に整合 ✓ | 新発見なし |
| K2-5 | 時刻は自己申告であり、合意規則が時刻に触れるのは `approve.timestamp_ms ≤ expires_at_ms` の 1 比較だけで、型は既存 `timestamp_ms` と同一 | 非負の安全整数 ✓、等号受理 ✓、作成時点で失効済みの提案の拒否(e-3)は合意規則から導出できない → 受理ポリシー(K5)✓ | 新発見なし |
| K2-6 | 原則 2(S ∩ 適用時点の owners)+ **帰属原則**「提案経由の適用は、適用 seq における提案者の直接追記と同じ検査(現在性・鍵 FP・role・scope)を受ける」 | `duplicate-approval` = actor ∈ S ✓ / 票数 ✓(字面「owner として提案した」だけが非導出 = ②)/ `proposal-void`(現メンバー・同じ鍵 FP・role)← 帰属原則 ✓ / 適用時の scope-not-contained ← 帰属原則 ✓ | **発見(申し送り ⑤)**: 帰属原則は提案者を鍵 FP(= 在籍区間)に束縛するが、原則 2 の S は投票者を **user_id にしか束縛しない**。投票後に削除され、新しい鍵で再追加された owner(再追加は owner 確立 = 四眼の対象)の票は、`stale-approver-vote` の「削除された投票者の票は失効」を再追加が**復活**させる。シナリオ: required = 3・owner A / B / C。B の鍵が侵害され、侵害鍵が A の提案 P を approve(A + B = 2)。侵害検知で B を remove → 新鍵で re-add(A・C の定足数)。C が P を approve → S = {A, B, C} ∩ 現 owner = 3 で完成 — 侵害鍵の票が鍵更新(remove / re-add)の後も生き残り、本人 B の新鍵での approve を代替する。正本の字面(「distinct はチェーン上の身元」= user_id、「この approve の時点でも owner である過去の投票者」)は B を数えるので**実装は正本どおり**であり、欠陥は正本側の非対称。推奨修正: S の要素を在籍区間(user_id + その時点の鍵 FP)に束縛し、在籍終了で失効させる(再追加後は新鍵で改めて approve できる — 提案者の `proposal-void` と対称)。現ベクターは降格(`stale-approver-vote`)のみ固定し、再追加は固定していない。成立条件は `required` の値ではなく **owner 数 > required**(投票者を 1 名抜いて再追加できること)。独立レビューの実測: `required = 2` × owner 3 名の正規チェーン(head 24)から、非 owner 提案 → owner A 承認(記録のみ)→ A を remove → 新鍵で owner として re-add → owner B の approve 1 本で完成(全ステップ ACCEPTED)。owner がちょうど `required` 名のときだけ到達可能性の不変条件が抜けを阻む |
| K2-7 | 内側 op はワイヤでは構造化して運び、正規化は §6.1 と同型の入れ子 LP、構造検査は内側 op の形状表を **1 段だけ**再利用する(再帰を持たない) | 入れ子 propose の構造段拒否 ✓ / genesis 内側 = `ROLE_RULES.genesis` → `approval-not-required` ✓ / ops の集合意味論 ← grant_server の先例 ✓ | 機械検査: フィールド上限(1024 B)は自由文字列(id・reason・claim 値)にのみ掛かり、内側 payload の hex には掛からない → **直接追記できる op は必ず提案できる**(256 環境の grant_server を含む)。非対称なし ✓ |
| K2-8 | §6.2 の各検査列で**隣接する対は、ベクターで固定されているか、状態不変条件で共起不能かのどちらか**でなければならない | 機械照合(`*-precedes-*` 負例 47 件 × §6.2 の検査列)。共起不能の 3 対は §8 のとおり | **発見**: 未固定の隣接対 = add_member `approval-required → duplicate-member` / `→ duplicate-member-key`、grant_server `approval-required → duplicate-server-key`(いずれも共起可能 — owner が既存 user / 既存鍵を owner として直接追記、既存メンバー鍵の直接 grant)、および K2 以前からの add_member `role → duplicate-member`(`role → duplicate-member-key` と `duplicate-member → duplicate-member-key` の推移からは決まらない)。**負例 4 件を追加して固定**(`authz-approval-required-precedes-duplicate-member` / `-duplicate-member-key` / `-duplicate-server-key`、`authz-add-member-role-precedes-duplicate-member` — 正規チェーン・既存負例は不変)。構築できず未固定のまま記録する対: grant_server `approval-required → grant-scope-narrowed`(head 24 に有効な grant が無い — 方針有効 + 有効 grant の派生チェーンが要る)、revoke_server `approval-required → unknown-server-key`(正規方針の ops に revoke_server が無い)。実装はいずれも role の直後で approval-required を判定する(`evaluateDirect`)ので順序は正本どおり |
| K2-9 | ベクターの不変性は仕様の分類ではなく**バイト列の依存関係**で決まる(正規チェーンの entry_hash を含むファイルはチェーン依存) | 機械照合: 旧チェーン 19 hash・新チェーン 64 hash(共通 = genesis 1 件)で全 JSON を走査 — 不変 11 ファイルは旧・新 hash を 1 つも含まず、チェーン依存 4 ファイル(value / metadata / env-manifest / head-attestation)と invite-link は新 hash(+ genesis)のみ ✓ | 分類どおり。新発見なし |

**処置**: (1) 申し送り ⑤ を新設(所有者裁定 — 正本の変更)。(2) K2-8 の負例 4 件を生成器に追加して再生成(生成器は oxfmt 後にバイト同一であることを再実行で確認済み。正規チェーン・既存の負例・派生チェーンは不変)。(3) K2-1 の `proposer_role_at_proposal` は ② に連動(本 PR では据え置き)。

### K2 の実装メモ(K3〜K7 への申し送り)

- CLI(K2 時点): `invite create` は scope = all のみ発行し、`member add` は招待行の scope で `add_member` を署名する。`change-role` は対象の**現 scope を据え置き**(owner への昇格時のみ all)、`--env` の指定は K4。**(K4 で置換済み — §10 K4-A: `--role` / `--env` / `--all-envs` の省略はそれぞれ据え置き)**
- サーバー: 四眼の 4 op は **K5 まで受理しない**(`ApprovalNotAccepted` 422 — worker + DO の多層ガード。K2-10)。scope の執行(R(E)・`InsufficientScope`・422 の scope 軸)は K3、受理ガードの解除 + pending 上限 `ProposalLimit`・四眼のミラー行 / 適用行・要ローテーション検出・ラップ掃除は K5(同じ PR で。**K5 で実施済み — §11**。提案 API は K5-M で置かないと裁定 = クライアント導出)。
- Web: `chain-view` の畳み込みは 4 op を無視する(方針・pending の表示は K6。**scope の表示は K4 で入れた — §10 K4-D で §4 の K4 行を正とした**)。K6 の pending 表示は `approvals` の記録を票数として出さず、必ず再集計する(記録は失効票を保持する — 同一鍵再追加による復活のために必要)。`required_approvals` を下げた後は、既に足りている pending 提案も次の approve までは適用されず、完成させられるのは未投票の owner だけ(既投票者の再投票は `duplicate-approval`)— CLI / UI はこの前提で案内する(独立レビューの観察 ⑦・⑧)。


## 9. K3 追記(2026-09-15 — サーバーの scope 執行時の裁定)

K3 は執行の段であり、承認済み項目 1〜24・§7 K1・§8 K2-1〜K2-11-bis を変えない。読み込み時点の現状(K2 後): scope は「受理・保存・合意規則で検証」まで済み、API 認可の scope 軸・R(E)・要ローテーションの環境別窓は未実装、3′ はサーバー写像表で `chain-head-state-mismatch` に畳まれていた。各裁定は所有者指示の手順(§3-bis / §3-ter の規律: 列挙 → 上位互換 / 銀の弾丸の探索 → 連続 2 空巡で打ち止め → 原則の抽出 → UX 点検 → 選択)で行い、巡数は正直に記す(「列挙 1 巡 + 空巡 2」= 探索 3 巡)。

### K3-A. 403 `InsufficientScope` のワイヤ表現(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 利点 | 欠点 | 正本との整合 |
|---|---|---|---|---|
| A-a **`ForbiddenError` の reason 閉集合に `insufficient-scope` を追加** | 既存の 403 型 1 つのまま、拒否の軸を reason で区別する | role 不足(`insufficient-role`)と同じ層・同じ型(§9-2「role 不足の 403 と同じ層」)。全エンドポイントのエラー union・CLI / Web の型に変更なし(reason は Literals の追加のみ) | 対象環境 id を載せられない | §12-3 は「403 `InsufficientScope`」とだけ書き、型名か理由コードかを規定しない。既存の role 403 も正本は「403」とだけ書き、実装は reason `insufficient-role` |
| A-b 新しい型付きエラー `InsufficientScopeError`(403、`{ environmentId }`) | 名前が正本の字面と一致 | 403 の型が 2 つになり、環境対象の全エンドポイントのエラー union・CLI `failure.ts`・Web の型へ機械的追加が要る。運ぶ情報(環境 id)は URL 座標から自明で、クライアントは自分の scope を検証済みチェーンから導出する(§12-7 — サーバー申告を検証規則の入力にしない)ため不要 | 同上 |
| A-c `ForbiddenError` に optionalKey `environmentId` | 中間 | 他の reason(csrf 等)で意味を持たないフィールドが型に載る。A-b と同じく不要な情報 | — |

**探索**: 第 2 巡(上位互換): A-a が A-b の利点(字面一致)を失うか — 正本の「`InsufficientScope`」は識別可能な 403 の名指しであり、既存の role 403 が「403」+ reason で実装されている先例(K1-3 nit の「§12-3 の呼び出し主体の scope 判定と同一 = 403 `InsufficientScope`」も理由コードの同一性を言っている)に照らして、reason での識別で満たす。銀の弾丸(403 を返さない構造)は §9-2 が 404 への畳み込みを明示的に否定しており、クライアント側判定のみに置く形は §6.4 の真実源に反する — なし(空巡)。第 3 巡: 新案なし(空巡)。打ち止め。

**原則**: 「認可の拒否は 1 つの 403 型と閉集合の理由コードで表し、拒否の軸(トークン水準 / actor / org / role / scope)を reason で区別する」。既存 `insufficient-permission` / `actor-mismatch` / `org-membership-required` / `insufficient-role` はすべてこの原則から導出できる。導出できない規則なし。

**UX**: CLI は `Insufficient permission (insufficient-scope)` に落ちる。K4 で CLI は通信前に検証済みチェーンから scope 外を型付きエラーにする(CRYPTO_SPEC §6.3「サーバーの 403 を待たない」)ため、この文言に到達するのはクライアントのチェーンが古い場合のみ。K3 では `failure.ts` の `ForbiddenError` 写像に reason 別の 1 文(scope 外は「対象環境が自分の scope 外」+ admin に拡大を依頼する案内。`project verify` の scope 列は K4 なので K3 の文言では案内しない — 独立レビュー B-2)を足す(§2 冒頭の「新しい理由コードを人が読める文にする場合のみ」に該当)。**採用: A-a**。

### K3-B. 3′(宣言ヘッド時点の scope)の HTTP 表現(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| B-a **現状どおり `chain-head-state-mismatch` に畳む** | `writer-/author-/issuer-environment-out-of-scope-at-head` → `chain-head-state-mismatch`(role 軸 `*-role-insufficient-at-head`・在籍軸・鍵軸・環境存在・エポックと同じ畳み込み) | §12-5 の仮裁定 C(値署名の 422 は仕様の 3 理由のみ)を保つ。§12-3 の二重判定は「受理時点 = 403、宣言ヘッド時点 = 署名検証段の 422」で role 軸と完全に対称。情報漏洩: 宣言ヘッド時点の状態はチェーン導出で全メンバー既知(§11-2 の存在秘匿はプロジェクト単位で、メンバーには関係しない)— 区別してもしなくても漏れない |
| B-b 新理由 `chain-head-scope-mismatch` を 3 語彙に足す | scope 軸だけ区別 | 仮裁定 C(3 理由)を破り、role 軸(畳んだまま)と非対称。クライアントは自分の履歴索引で 3′ を検証する(§6.3)ので、サーバーの理由コードに依存せず軸を特定できる = 追加情報に価値がない |
| B-c 宣言ヘッド時点の scope も署名検証前に 403 で返す | history から先に判定 | §12-3 の順(scope 403 は意味論的検査の前、署名検証は意味論的検査)と、`validate.ts` の「署名壊れを先に判定する」規律に反する。棄却 |

**探索**: 第 2 巡: 3′ の 422 に到達する状況は「受理時点は scope 内(403 を通過)だが宣言ヘッド時点は scope 外」= 拡大後に拡大前のヘッドを宣言した場合だけで、クライアントの再同期で解消する競合類。区別する価値が低く、上位互換なし。銀の弾丸(受理時点と宣言ヘッド時点の判定を 1 つにする)は宣言ヘッドが現ヘッドと異なりうる以上なし(空巡)。第 3 巡: 新案なし(空巡)。打ち止め。

**原則**: 「宣言ヘッド時点の状態不一致は、軸(在籍・鍵・role・環境存在・エポック・scope)を問わず 1 理由 `chain-head-state-mismatch` に畳み、軸の特定はクライアント自身の履歴検証(§6.3)に委ねる」。既存写像表の全 `*-at-head` 行と prev 系がこの原則から導出できる(`signature-invalid` / `chain-head-unknown` は別段)。

**UX**: 422 を受けた CLI は既存の「再同期して再署名」案内に乗る。**採用: B-a**(写像表は不変。サーバーテストで「listed writer の scope 内 = 200 / 受理時点 scope 外 = 403 / 宣言ヘッド時点のみ scope 外 = 422 `chain-head-state-mismatch`」を値・メタ・マニフェストで固定)。

### K3-C. scope 判定の実装位置と存在判定との前後(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| C-a `data-plane.ts` に `requireEnvironmentInScope(member, environmentId)` を足し、各プログラムが `requireMemberState` の直後に呼ぶ | 判定は共通、結線は各プログラム | 呼び忘れが構造で防げない |
| C-b **`requireMemberState` / `requireRole` の環境軸版(`requireEnvironmentAccess` / `requireRoleInScope`)を共通経路に置き、環境対象の全プログラムはこちらを通す** | role → scope を 1 呼び出しで済ませ、拒否種別 `insufficient-scope` を `data-http.ts` が `ForbiddenError` に写す | C-a の上位互換(呼び忘れ = 型が違う。環境を持たない経路〔環境一覧・メタのみ pull・フラグ一覧・監査〕は従来の `requireMemberState` のまま = §12-3 の「不問」行が構造で分かる)。複合(`loadChainForComposite`)と standalone checkpoint(`requireRole` 直呼び)も同じ基礎関数を通す |
| C-c worker の `authz.ts`(トークンスコープ層)に置く | — | 不可: scope はチェーン導出状態(DO 側)であり、worker はチェーンを持たない。トークンスコープ(§6)とチェーン scope(§6.2)は別の軸で、混ぜると「トークンの環境スコープ」(§6 の将来項)と衝突する |
| C-d 各ハンドラで個別に | — | 分散して漏れる。棄却 |

**存在判定との前後(§2 の候補 H)**: §12-3 は scope 403 を「環境の存在判定と同段」と書き、順序を規定しない。scope 判定はチェーン状態だけで決まり(環境の存在もチェーン導出だが、tombstone はデータ行)、`requireActiveEnvironment`(データ行の読み)より前に置ける。listed の主体が未存在 / tombstone の環境を指した場合、scope を先にすると 403、存在を先にすると 404 になるが、どちらも漏洩しない(環境の存在・tombstone は平文メタとして全メンバー可視 — 裁定 G-2)。fail-closed かつ単純なのは「チェーン状態だけで決まる検査を、保存状態を読む検査より先に置く」形 = **role → scope → 存在**。all-scope の主体には従来どおり 404(K3 単独デプロイでの不変性)。`membership-negatives-composite.test.ts` の `authz-rotate-unknown-precedes-out-of-scope`(listed member × 未作成環境)は K2 の 404 から 403 に変わる(理由を同ファイルのコメントに書く)。

**探索**: 第 2 巡: 「環境 id を `requireMemberState` の必須引数にして環境非対象の経路も強制する」— 環境一覧・メタのみ pull・フラグ一覧は環境を持たない / 不問なので、optional にすると「不問」と「忘れ」が区別できなくなる。関数を分ける C-b が上位。銀の弾丸(scope 判定を verifyChain 等の 1 箇所に集約)は、データ操作がチェーン op を伴わないため不可(空巡)。第 3 巡: 新案なし(空巡)。打ち止め。

**原則**: 「受理面の認可層(HTTP の 403 / 404 を返す層)では、チェーン導出状態だけで決まる検査(role・scope)を、サーバー保存状態を読む検査(存在・CAS・署名・内容突合)より先に置く」。§12-3 の順(role 403 → scope 403 → 意味論)、既存の role → 存在 → 意味論、いずれもこの原則から導出できる。合意規則層(verifyChain — `insufficient-role` / `environment-out-of-scope` の 422)は「意味論的検査」の一部であり、CAS の後に走る既存の順はこの原則の対象外(受理面の 403 が先に立った後の多層防御 — K3-G)。原則を「認可判定一般」と書くと既存のこの順が導出できなくなる(独立レビュー B-9 で訂正)。

**scope を問わない環境座標つき経路**: 要ローテーションフラグの取り下げ(`programs-rotation.ts` の dismiss)は環境座標を持つが §12-3 の表に無いガバナンス操作で、AUDIT_SPEC §6(フラグのビューはクラス 1・可視性述語に環境軸を入れない)と §4.1 手順 5(取り下げは admin の判断)により scope 非依存。環境座標を持つ経路で `requireMemberState` のまま残る唯一の書き込みとして、コードのコメントと `scope-invariants.test.ts` で固定する(独立レビュー B-1)。

**UX**: listed の主体が typo の環境 id で pull すると 403 `insufficient-scope`(「存在しない」とは言われない)。K4 の CLI は通信前に検証済みチェーンで存在と scope を判定して案内する(§6.3)ため実害なし。**採用: C-b + role → scope → 存在**。

### K3-D. R(E) の算出(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| D-a **`memberReceivesEnvironment(member, E)` = `scopeIncludesEnvironment(member.scope, E)` を、期待数(`expectedWrapRecipientCount`)と受信者判定(`checkWrapRecipient`)の両方で使う。grant 側は既存の `scopeEnvironmentIds.includes(E)`。理由コードは受信者クラスを跨いで同じ順: 同定(not-member / not-granted)→ 鍵(key-mismatch)→ scope(`scope-out-of-range`)** | 1 述語 | CRYPTO_SPEC §6.2「判定は受信者クラスを跨いで同一に適用」の直訳。既存の id 衝突除去(和集合)は不変 |
| D-b `recipientsOf(state, E)` の集合を 1 つ作り、期待数 = その大きさ、受信者判定 = 所属 | 集合 1 つ | 個別判定の理由コード(not-member / key-mismatch / scope)は所属判定からは出せず、結局 D-a の分岐が要る。上位互換ではない |

登録者(呼び出し主体)の scope(§12-6 末尾)は K3-C の共通経路(403)で判定し、`dek-wraps.ts` では判定しない(署名者 = 呼び出し主体〔§12-6 (1)〕なので同一判定 — K1-3)。複合(`ensureCompositeWrapSet`)は同じ期待数定義を共有するので 1 箇所の修正で両経路に効く。

**探索**: 第 2 巡: なし(空巡 — D-b は上位互換でない)。第 3 巡: なし(空巡)。打ち止め。

**原則**: 「R(E) の所属は受信者クラスを跨いで『同定(id + 鍵)∧ E ∈ scope』の 1 述語」。既存の grant 側 3 理由と member 側 2 理由はこの原則から導出でき、`scope-out-of-range` の member 側適用は原則の被覆が広がっただけで新規則ではない。

**UX**: K4 までクライアントは全メンバーへラップする(scope = all のみ発行)ので、K3 単独では挙動不変。K4 で `wrapRecipientsFor` を R(E) にする。**採用: D-a**。

### K3-E. 環境別アクセス窓・`change_role` 変種・`trigger`(列挙 1 巡 + 空巡 2・打ち止め)

| 論点 | 案 | 選択と理由 |
|---|---|---|
| Q1 の入力 | (i) `chain.role_changed` を Q1 の列挙に加え、`member_added` / `role_changed` の payload(role / newRole・scopeKind・scopeEnvironmentIds)を読む | 正本 §4.1 手順 2 の字面。索引 (target_user_id, seq) は不変(§4.2 Q1 の訂正は列挙の追記のみ) |
| 窓の復元 | (i) **在籍区間ごとに scope 状態(`all` \| listed 集合)の遷移点を畳み、環境 E について「E ∈ scope だった seq 区間の列」を導出する `accessWindows`**。(ii) grant 側の `scopeStarts`(開始 seq のみ)を member にも流用 | (i)。member の scope は縮小もありうる(grant は拡大のみ)ので「開始 seq」だけでは足りない。grant 側も同じ導出に統合できる(再 grant は縮小拒否なので窓は 1 区間になり、既存の `rotation.test.ts` の拡大再 grant テストはそのまま通る)— §4.1「実装は 1 つの窓導出を共有する」 |
| `all` の意味 | `all` = 全環境(将来分を含む) | 窓は seq 区間なので、`all` の期間中に作成された変数も存在区間との重なりで自然に候補になる |
| `change_role` の検出契機 | (i) **降格(旧 role ≥ member かつ新 role = reader)= 契機直前の scope の全環境、縮小 = 旧 \ 新の環境。同時に起きた場合は和集合で 1 (variable × environment) 1 行(§3.3 の粒度 — 候補 I)**。(ii) 降格を「窓を閉じる」と扱い在籍区間も閉じる | (i)。降格者は reader として DEK を受け取り続ける(§7)ので窓自体は閉じず、検出だけを「契機 seq で切った窓」で行う。後の remove で再び候補になるのは正しい(reader も DEK を持つ)。§4.1 change_role 変種の「閉じた窓の環境に限る」は検出範囲の限定であり、在籍区間の終了ではない |
| remove 時の候補 | (i) **在籍区間内の全窓(過去に縮小で閉じた窓を含む)** (ii) 現 scope のみ | (i) = §4.1 手順 2 の字面。縮小時に出した行と重複する行が remove 時に再度出うるが、同対の複数有効 recommended は既存規律(再削除等 — UI で束ねる)と同じで、検出は多く出す側が安全。CRYPTO_SPEC §7 の義務が「現 scope」なのは履行者側の話で、検出の候補とは別 |
| `trigger` | (i) **payload に `trigger`(3 変種すべて)。ワイヤ `RotationFlagSchema.trigger` は optionalKey で、サーバーは常に載せる(K3 前の保存行は target の有無から補完: targetUserId → `remove_member`、targetKeyFingerprint → `revoke_server`)** (ii) ワイヤを必須にする | (i)。`storedRecipientEncPubHex`(§12-6)の先例と同じ「後方互換の追加のみ」(新 CLI × 旧サーバーで decode が壊れない)。K3 前の行は K3-F のとおり存在しない前提だが、補完は無害 |
| 表示側 | (i) **Web `flagTrigger` と CLI `describeTarget` は `trigger` があればそれを使い、無ければ従来の推定** (ii) K4 / K6 へ送る | (i)。無いと `trigger = change_role` の行が「member removed」と誤表示する。読み取り専用の 1 行変更で、K3 が足したワイヤ欄の消費側 |

**探索(論点ごと — 独立レビュー B-7 で論点別に書き直した)**: 第 2 巡(上位互換 / 銀の弾丸): Q1 の入力 — 「ミラー行でなくチェーン本体から窓を復元する」案は AUDIT_SPEC §4.1 の「チェーンミラーが scope を写すためクエリの変更だけで成立」に反し、監査 seq 座標系(読み取り行との重なり判定)を失うため棄却。窓の復元 — 「窓導出を member / grant で共有する」は (i) に含めた(上位互換として採用済み)。`all` の意味 — 「`all` を現存環境の列挙に展開する」案は CRYPTO_SPEC §6.2 の集合代数(`all` = U、将来分を含む)に反し、`all` の期間中に作成された変数を見逃すため棄却(代替案なし)。`change_role` の検出契機 — 「降格で在籍区間を閉じる」(ii) は棄却済み(reader は DEK を受け取り続ける)、他に案なし。remove 時の候補 — 「現 scope のみ」(ii) は縮小時の検出が取り下げ済みだった場合に見逃しを生むため棄却(§4.1 手順 2 の字面に従う)。`trigger` — 「必須にする」は互換の欠点を持つため上位互換でない。表示側 — 「K4 / K6 へ送る」(ii) は誤表示を残すため棄却。銀の弾丸(窓を持たず「現 scope」だけで検出する)は §4.1 手順 2 の字面と、縮小前に読めた環境の見逃し(fail open)で棄却。以上、第 2 巡は棄却案のみ = 空巡。第 3 巡: 全論点で新案なし(空巡)。打ち止め(列挙 1 巡 + 空巡 2)。

**原則**: 「候補集合は『対象がその環境の DEK を持ちえた seq 区間』の窓から導出し、窓はミラー payload の scope 状態の遷移点だけで決まる(受信者クラスを跨いで同一の窓導出)」。既存の remove 変種(在籍区間 = `all` の窓)と revoke 変種(grant 窓)はこの原則から導出できる。導出できない規則なし。

**UX**: Web / CLI に「role/scope changed: <user>」の表示が加わる。取り下げ(dismiss)は不変。**採用: 上表の (i) 列**。

### K3-F. 既存データとの互換(単巡 — 事実確認)

- `apps/server/test/es-migration.test.ts` が旧形式の add_member / 招待発行の fail-closed(400 / 422 `bad-signature`)を固定し、`docs/SELF_HOSTING.md` "Updates"(2026-09-14 ES + PF1 K2 の段落)が既存プロジェクトの再作成を規定している。K2 以降に受理されたチェーンは全エントリが scope 付きで、`ChainMember.scope` は crypto の型で必須。したがって **互換経路は不要**。
- 監査ミラーの `chain.member_added` 行に scope が無い DO は「再作成対象」で存在しない前提だが、Q1 の payload 読み出しは防御的に parse し、scope が読めない行は **`all`(旧 v1 の意味論 = 全環境)として窓を開く**。検出は「見逃さない側」が fail-safe(拒否側ではない)。**同じ規律を全軸に適用する(独立レビュー B-3 / B-4 / B-5 で揃えた)**: `listed` で id 列が配列でない行も `all`(listed{} = 窓ゼロにしない)、role が読めない行は「降格だった」側(旧 role 不明 = 書き手だった、新 role 不明 = 書き手でなくなった)、在籍区間の外に現れた `update`(`chain.role_changed`)は open と同じに扱い、grant の再 grant は scope を単調に和集合で積む(縮小する再 grant が仮に通っても失効前に窓を閉じない)。**第 2 巡で揃えた残り 3 軸**(独立レビュー B′-1 / C′-1 / C′-2): grant 行の scope が読めない(配列でない・非 string 要素を含む)区間は全環境として窓を開く(grant の scope は `all` を持たないが、検出の倒し方は member 軸と同じ)、member 行の id 列に非 string 要素があれば黙って縮めず `all`、`change_role` の契機行の scope が読めない場合は縮小分を特定できないため降格と同じく契機直前の全窓を候補にする。到達不能な経路だが、原則(見逃さない側)と実装を全軸で一致させる。`scope-rotation.test.ts` の純関数テストで固定。

### K3-G. チェーン op を伴う経路の 403 と合意規則 422 の前後(列挙 1 巡 + 空巡 2・打ち止め)

| 経路 | K2 の挙動 | K3 | 理由 |
|---|---|---|---|
| rotate 複合 | `loadChainForComposite`(role)→ 存在 404 → CAS → verifyChain(`environment-out-of-scope` 422) | role → **scope 403(E ∈ actor scope)** → 存在 404 → … | §9-2「rotate は 403 `InsufficientScope`」。同じ状態を合意規則が 422 で二重に守る(多層防御) |
| create 複合 | role → CAS → verifyChain(`environment-out-of-scope` 422) | role → **scope 403(新 id ∈ actor scope = `listed` には未存在 id が含まれえないので `all` のみ通る — §6.2 と同じ 1 述語)** → … | §12-3 の表「環境の作成 = scope = all」 |
| standalone checkpoint | reader(404 秘匿)→ 監査ヘッド admin 403 → CAS → verifyChain(`environment-out-of-scope` 422) | reader → 監査 admin 403(role 軸)→ **scope 403(全タプルの環境 ∈ scope)** → CAS → verifyChain | §12-3 の順 = role 403 の直後。§6.2 の合意規則順(role → audit-role → unknown-env → out-of-scope)と同じ相対順 |
| 汎用 append の add_member / change_role / remove_member | `scope-not-contained` 422 | 不変 | 環境対象 op ではない(§12-3 の表に無い)。actor scope の包含は合意規則のみ |

**候補**: (a) 上表(403 を先)。(b) 合意規則の 422 に任せ 403 を出さない — §9-2 の字面に反し、role 403 が `insufficient-role` 422 に先行する既存の形(`authz-reader-rotate-epoch` = 403)とも非対称。棄却。(c) verifyChain の理由コードを事後に 403 へ写す — 理由コードの意味を層を跨いで変え、`chain-entry-invalid` の seq 情報が失われる。棄却。

**探索**: 第 2 巡: 「複合の scope 検査を verifyChain の適用後ビューで行う」— 追記前の actor scope で判定するのが §12-3(受理時点)であり、複合エントリ自身が actor の scope を変えることはない(環境対象 op)ので同値。上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。

**原則**: 「呼び出し主体の scope に関する拒否は、対象環境が API 座標またはエントリ payload から確定する経路ではすべて受理面の 403 で先に返し、合意規則の同名検査は多層防御として残す」。role 403 が `insufficient-role` 422 に先行する既存の形はこの原則の role 軸版。

**例外の記録(独立レビュー C-5)**: 環境の作成を「新 id ∈ actor scope」の 1 述語で判定するため、`listed` の主体が**自分の scope に既にある id** で create を試みた場合だけ 403 でなく合意規則の 422 `duplicate-environment` になる(受理される組は変わらず fail-closed)。「403 が 422 より先」の字面に対する唯一の例外。

**UX**: 403 は 422 `environment-out-of-scope` より先に出るので、クライアントは「自分の scope 外」と即座に分かる(K4 では通信前に判定)。`membership-negatives-composite.test.ts` の `authz-create-env-listed-*` / `authz-rotate-out-of-scope*` の期待を 422 → 403 に、`membership-negatives-append.test.ts` の checkpoint 分は既存どおり(前提チェーンが API では再生できないため crypto 層で固定)。**採用: (a)**。

### K3-H. `chain_seq` の全単射(K1-3 の申し送り)— K5 へ据え置き

四眼の適用行(同一 `chain_seq` に 2 行 — AUDIT_SPEC §3.4)がサーバーに現れるのは受理ガード(K2-10)を外す K5 であり、K3 の時点でサーバーには 1 エントリ 1 ミラー行しか存在しない。K3 の変更が `chain_seq` の一意性を新たに前提にしないことの確認: (1) 要ローテーション検出は監査 seq 順の畳み込みで、`chain_seq` は `triggerChainSeq` として payload に写すだけ、(2) Q1 の `chain.role_changed` 読み取りは seq 順の scope 遷移の畳み込みで、同一 `chain_seq` に適用行が加わっても(K5)遷移は監査 seq の順に 1 回ずつ適用されるだけで壊れない、(3) 3 変種の `trigger` は行の識別に `chain_seq` を使わない。したがって K1-3 の「K3 / K5」は **K5 に据え置く**(`audit verify` の全単射規則の改訂は K5 の PF1 ミラー行と同じ PR)。

### K3-I. 実装録(裁定の反映先)

- api-schema: `errors/auth.ts` の `ForbiddenReasonSchema` に `insufficient-scope`、`rotation-api.ts` の `RotationFlagSchema` に `trigger`(optionalKey)。`errors/deks.ts` は不変(`scope-out-of-range` の JSDoc に member 側の適用を追記)
- server: `data-plane.ts`(`insufficient-scope` 拒否種別・`requireRoleInScope` / `requireEnvironmentAccess`)、`data-http.ts`(写像)、環境対象の全プログラム(`programs-variable.ts` 5 経路・`programs-environment.ts` の rename / delete / 値付き pull・`programs-dek.ts` の登録 / 削除 / 自分宛取得・`composite-programs.ts`・`checkpoint-accept.ts`)、`dek-wraps.ts`(R(E))、`audit-store.ts`(Q1)、`rotation-detect.ts`(窓・change_role 変種・trigger)、`chain-accept.ts`(change_role の結線)
- core / CLI / Web: `packages/core/src/audit.ts` は不変。CLI `failure.ts` の reason 別文言と `rotation.ts` の trigger 表示、Web `ProjectScreen.tsx` の `flagTrigger`
- 正本: AUDIT_SPEC §4.2 Q1 の列挙訂正(索引要件の記述 — 合意規則ではない)+ Status 行
- テスト(`apps/server/test/`): 新規 `scope-authz.test.ts`(§12-3 の各行を 1 つずつ・判定順・チェーン op 経路の 403・3′)、`scope-dek.test.ts`(R(E))、`scope-rotation.test.ts`(環境別窓・change_role 変種・trigger・ミラー payload からの復元・窓導出の fail-safe)、`scope-invariants.test.ts`(リース不変・可視性不変)、`scope-invites.test.ts`(招待行の scope)、既存の composite negatives の期待更新(422 → 403)と `rotation.test.ts` の trigger 期待

### K3-J. 申し送り(K4 以降へ — PR #178 のレビューから)

- **scope 縮小後の旧ラップ**: K3 の 403 は受理面のガードであり、縮小で scope 外になったメンバーの手元の既存ラップ(保存済み DEK ラップ行を含む)を暗号的に無効化するのは K4 の sweep(縮小分の rotate 義務 — CRYPTO_SPEC §7)以降。K3 時点で `insufficient-scope` を「アクセス遮断」と説明しない(CLI 文言は現状そうなっていない — pullfrog 第 1 巡)
- **バックフィルの liveness**: DEK ラップ登録者は対象環境を scope に含む必要がある(§12-6 末尾)ため、「誰も scope に含まない環境」が生じるとバックフィルが詰まる。owner は常に `all`(§6.2 `scope-role-mismatch`)なので現状は生じないが、owner の scope を将来 listed にする改訂があれば、この不変条件を先に確認する(pullfrog 第 1 巡)
- **ベクター名と受理面の順**: `authz-rotate-unknown-precedes-out-of-scope` / `authz-create-env-duplicate-precedes-out-of-scope` は合意規則層の検査順を指す名前で、受理面では scope 403 が先(K3-G)。K3 はベクターを触らないため名前はそのまま(テストのコメントで明記)。次にベクターを再生成する段(K5 等)で改名してよい

## 10. K4 追記(2026-09-15 — CLI の環境スコープ実装時の裁定)

K4 は CLI の段であり、承認済み項目 1〜24・§7 K1・§8 K2-1〜K2-11-bis・§9 K3-A〜K3-J を変えない。読み込み時点の現状(K3 後): CLI は scope を**読める**(招待行・リンクの `sk=`/`se=`・`invite list` の `scope=` 列・受諾時の集合比較・検証済み `ChainMember.scope`)が、**発行・執行する箇所がゼロ**(`invite create` は `ALL_SCOPE` 固定、`change-role` は現 scope 据え置き、`wrapRecipientsFor` は member 全員、バックフィル / sweep は全環境、通信前 scope 判定なし、scope 外ラップの判定なし)。`packages/crypto` の公開 API は `MemberScope` / `memberScopeOf` / `scopeIncludesEnvironment` / `scopePayloadFieldsOf` / `ALL_SCOPE` / `MAX_SCOPE_ENVIRONMENTS` で、包含述語 `scopeContainsEnvironmentSet` と集合演算は internal のまま(K4 は crypto を触らない — K4-I)。各裁定は §9 と同じ規律(列挙 → 上位互換 / 銀の弾丸の探索 → 連続 2 空巡で打ち止め → 原則 → UX → 選択)で行い、巡数は正直に記す。

### K4-A. scope 変更のコマンド形(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 利点 | 欠点 |
|---|---|---|---|
| A-a `change-role --role <r> [--env <id>]…` のみ(`--role` 必須)。`--env` 省略 = **現 scope 据え置き** | 1 コマンド | scope だけを変えたい場合も role を打ち直す(打ち間違いで role が変わる) | — |
| A-b `--env` 省略 = all(招待と揃える) | 招待と同じ既定 | **fail-open の形**: listed の対象に role だけ変えるつもりで打つと all へ拡大し、prod の全エポックをバックフィルしてしまう(署名済みの不可逆な鍵配布) | 棄却 |
| A-c 別コマンド `member scope <user> --env …`(role 不変) | 名前が意図を表す | ワイヤは同じ `change_role`。事前検査・CAS・拡大バックフィル・縮小 sweep の後段が 2 コマンドに複製される。降格と縮小を同時にしたい場合は 2 回の追記(義務が 2 エントリに割れる) | — |
| A-d **`change-role <user> [--role <r>] [--env <id>]… [--all-envs]`**: `--role` / `--env` / `--all-envs` のうち少なくとも 1 つ必須。`--role` 省略 = 現 role 据え置き、`--env` / `--all-envs` 省略 = 現 scope 据え置き、`--env` と `--all-envs` は排他。`--role owner` は all 固定(`--env` 併用は usage エラー — `scope-role-mismatch`) | A-a と A-c の上位互換: 1 コマンド・1 エントリで role / scope / 両方を置換でき、省略は常に「変えない」(fail-closed)。「拡大を all にする」だけが明示フラグ | 招待の「省略 = all」と既定が違う(下記 UX で説明) |

**探索**: 第 2 巡(上位互換): A-d は A-a / A-c の利点を含む。`--env all` のような番兵は環境 id の名前空間と衝突する(裁定 B-3 と同じ理由)ので `--all-envs` を別フラグに置く — 招待で `--all-envs` を置かない裁定 K は「省略 = all なので冗長」という理由であり、change-role では省略 = 据え置きなので冗長ではない(K を覆さない)。銀の弾丸(scope 変更を change_role 以外の構造で表す)は §6.2 の全置換ワイヤで閉じており、なし(空巡)。第 3 巡: 新案なし(空巡)。打ち止め。

**原則**: 「署名済みの不可逆な変更(鍵配布・rotate 義務)を生む入力は、省略が『変えない』側に倒れ、拡大は明示の作為でのみ起きる」。招待の「省略 = all」はこの原則に反するように見えるが、招待は**新規メンバーの scope の初期値**であり「変えない」が定義できない(現状が無い)。既定 all は CRYPTO_SPEC §6.2「CLI の既定を all にすれば体験は変わらない」(裁定 C 第 3 巡)の導出で、原則の例外ではなく適用範囲外。既存の `remove` / `revoke` に省略可能な破壊的既定が無いことも整合。

**UX**: `member change-role alice --env dev` = role 不変で scope を {dev} に置換(拡大分はバックフィル、縮小分は rotate — K4-B)。`--role reader` だけなら scope 不変の降格。エージェント環境でも対話入力なし。`invite create` と既定が違う点は `--help` の文言に「omitted = keep the current scope」と書く。**採用: A-d**。

### K4-B. 縮小 + 拡大が同時の `change_role` の義務の直列化(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| B-a **追記 → 拡大分のバックフィル → 縮小分(+ 降格分)の rotate sweep** | 拡大分 = 新 \ 旧、縮小分 = 旧 \ 新、降格分 = 新 scope(CRYPTO_SPEC §6.2 系)。3 つは互いに素または縮小 ∩ 降格 = ∅(降格分は新 scope 内)なので順序に依存性はない。バックフィルは 409 で冪等、sweep はチェーン導出(第 4 種 `scope-narrowed`)で冪等 — 中断はどちらの再実行でも続きから収束する | 短い方(バックフィル)を先に置き、失敗しても sweep へ進む(両方の結果を報告して終了コードで部分完了を示す) |
| B-b sweep → バックフィル | — | 縮小分の rotate は新 DEK を R(E) へラップし、対象は縮小で R(E) から外れているので新 DEK は渡らない。拡大分のバックフィルとは環境が異なり、順序を入れ替える利点がない |
| B-c 縮小と拡大を 2 エントリに分けさせる(同時指定を拒否) | 単純 | 義務が 2 エントリに割れ、1 回の意図(「dev から staging へ移す」)が 2 回の署名になる。§6.2 は全置換を 1 エントリで受理する |

**探索**: 第 2 巡: 「拡大分のバックフィルを change_role の複合に同梱する」は §12-4 / 承認項目 8(複合化しない)で棄却済み。上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。

**原則**: 「1 エントリが生む複数の義務は、環境集合が互いに素である限り、それぞれ独立に冪等な収束手続きで履行し、順序は履行時間の短い順」。既存の `member add`(追記 → バックフィル)と `remove`(追記 → sweep)はこの原則の 1 義務の場合。

**UX**: 部分失敗はコマンドが終了コード 1 で報告し、再実行が続きから収束する(既存の member add / remove と同じ案内)。**採用: B-a**。

### K4-C. 通信前 scope 判定の置き場(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| C-a 各コマンドに個別 | — | 漏れる(pull / run / push / var rm / schema set / import / env rotate / env create / checkpoint / sync / バックフィル / sweep の 12 経路) |
| C-b `openEnvironment`(context.ts)に 1 検査 | `--env` を取る値系コマンド(pull / run / push / var rm / schema set / import / env rotate)を 1 か所で覆う。`openMetadataEnvironment`(schema show / export / lint)は別関数なので「不問」が構造で分かる(K3-C と同型) | 複数環境を 1 コマンドで開く経路(checkpoint / sync の 3 環境 / sweep / バックフィル)を覆わない |
| C-c **C-b + 共通述語 `requireEnvironmentInScope`(新設 `scope.ts`)を、複数環境経路が明示に呼ぶ + `requireWritingMember`(create / rotate の共通ガード)に scope 判定を組み込む + `environmentKeysFor`(自分宛 DEK の唯一の取得口 — deks.ts)で受信側規則(K4-F)を判定** | 述語は 1 つ。単一環境コマンドは前段で、複合ガードは `requireWritingMember` で、DEK 取得は `environmentKeysFor` で、それぞれ構造的に通る。残るのは checkpoint / sync の環境列挙だけ(明示呼び出し + テストで固定) | `pullVerifiedEnvironment`(values.ts)を唯一の漏斗にする形(K3 C-b と完全同型)は、values.ts が呼び出し主体の user_id を持たない(VerifiedProject は自分を知らない)ため、全呼び出し側の引数変更になる。DEK 取得口の判定が実質同じ漏斗になる(値付き pull は DEK なしに復号できない)ので採らない |
| C-d サーバーの 403 に任せる | — | CRYPTO_SPEC §6.3「サーバーの 403 を待たない」に反する。値付き pull は `var.read` を記録するため、403 前に到達させない意味もある(K3 では 403 時に記録しないが、規範はクライアント側判定) |

**古いチェーンの扱い**: 判定は検証済みチェーンに基づく。拡大直後に古いビューで実行すれば通信前に誤って拒否する(再実行で解消 — 前段は毎回全同期するので実際は起きにくい)。縮小直後に古いビューで通れば **サーバーの 403** に落ちる — `failure.ts` の `insufficient-scope` 文言に「ローカルのビューが古い可能性 — 再実行で再同期」を加える。

**探索**: 第 2 巡: 「`VerifiedProject` に自分の user_id を持たせて values.ts で判定」— VerifiedProject はリース(ワークロード)経路と共有され自分が無い形が正当なので、型に自分を混ぜると意味が濁る。上位互換でない(空巡)。銀の弾丸(判定を 1 か所に集約)は C-c の `environmentKeysFor` が DEK の唯一の取得口である以上、値付き経路については既にそこ(空巡)。第 3 巡: なし(空巡)。打ち止め。

**原則**: 「呼び出し主体の scope 判定は、対象環境が確定する最も手前の共通経路(前段・共通ガード・唯一の取得口)に置き、環境を持たない / 不問の経路は別の関数を通る」。K3-C の原則(受理面の順序)とは層が違うが、「不問と忘れを関数の違いで区別する」形は同じ。

**UX**: listed の主体が scope 外の環境で `maruhi pull` すると通信前に `Environment <id> is outside your environment scope on this project's chain (…). Ask a project admin to widen your scope with \`maruhi member change-role <you> --env <id>\`` で止まる。`maruhi schema` は動く。**採用: C-c**。

### K4-D. Web の scope 列の段(列挙 1 巡 + 空巡 2・打ち止め)

食い違い: 設計録 §4 の K4 行は「Web `ProjectScreen` の scope 列」を K4 に含めるが、`apps/web/src/dashboard/chain-view.ts` のコメントと §8-ter 直後の K2 実装メモは「scope の表示は K6」としていた。

| 案 | 内容 | 評価 |
|---|---|---|
| D-a **K4 で入れる(最小)**: `chain-view.ts` の fold に `scopeKind` / `scopeEnvironmentIds` を写し、`ProjectScreen` の Members 表に「Scope」列(既存の Granted servers 表の Scope 列と同じ描き方 — `Text type="supporting"`。新規の視覚パターンなし・`xstyle` なし) | K4 完了 = ES 完了(§4 の K4 行の停止条件)が Web を含めて成立する。変更は fold 2 フィールド + 列 1 つで、React Doctor / StyleX 規律に触れない | web のテストと doctor が K4 の品質ゲートに入る |
| D-b K6 へ送り §4 の行を訂正 | K4 が CLI に閉じる | ES の可視面が K6(四眼)まで欠け、「ES 完了」と言えない。K6 の pending 表示とは独立の変更なので束ねる理由がない |

**探索**: 第 2 巡: 上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。**原則**: 「段の停止条件(§4)が正で、コード内コメントは段の記述に従う」。**UX**: Web の Members 表に `all` / 環境 id 列が並ぶ(表示規律「サーバー申告・未検証」は不変)。**採用: D-a**(chain-view のコメントと K2 実装メモの記述を訂正する)。

### K4-E. `member list` の出力形と agent-gate(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| E-a 表のみ(`project verify` の member 行と同じ TSV 風) | 既存の行形式の再利用 | エージェントが読むには列の意味を推測させる |
| E-b **表 + `--json`**(`{ members: [{ userId, role, scope: { kind, environmentIds }, keyFingerprintHex }] }` を stdout へ 1 文書) | 人には表、エージェント / スクリプトには JSON。`maruhi sync preset`(JSON を stdout へ)の先例に倣う(`json-record.ts` は JSON **読み取り**の共通口であり出力の先例ではない — 最初の報告の訂正) | フラグ 1 つ増える |
| E-c JSON のみ | — | 人が読みにくい |

agent-gate: 出力は user_id・role・scope・鍵 FP のみで値ゼロ(裁定 M)。`ensureValueDisplayAllowed` を**呼ばない**ことをテストで固定する(エージェント検出 + 非 TTY で成功する)。`project verify` と同じく master 鍵を要求しない(`openMetadataProject`)。

**探索**: 第 2 巡: 上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。**原則**: 「値ゼロの読み取りは鍵なし・agent-gate 非適用で、機械可読形を併せ持つ」(`maruhi schema` の線)。**UX**: `maruhi member list --json | jq` がエージェント環境で動く。**採用: E-b**。

### K4-F. scope 外ラップの警告の出し方(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| F-a pull のたびに警告して継続(ラップは使わない) | 正本の字面「使用せず警告する」 | 値付き pull は K4-C で通信前に止まるため、この経路に到達するのは「DEK 取得口に scope 外の環境で入った」場合だけ = 呼び出し側のバグか、チェーンが同期の間に縮小した競合類。継続する意味がない(DEK を使わないなら復号できない) |
| F-b **`environmentKeysFor`(DEK の唯一の取得口)で環境 ∉ 自分の scope を型付きエラーにする**。文言は警告文の内容(「scope 外の環境のラップは使用しない — サーバーが §12-6 を執行していない証拠になりうる」)を含め、平文値・鍵素材・ラップの内容は出さない | 1 か所。取得口を通らない DEK は存在しないので「使用しない」が構造で成立する | 正本の「警告」を「エラーで中断」として実装する(使用しない結果は同じ。中断は fail-closed 側) |
| F-c `project verify` の未収束警告に統合 | — | verify は鍵なしで DEK を取得しない。自分宛ラップの scope 外は本人の値付き経路でしか観測できない |

**探索**: 第 2 巡: 上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。**原則**: 「受信側規則は資源の唯一の取得口で判定し、使わないものは取得口から出さない」(§5.2 コミットメント照合が `verifyAndUnwrapOne` の内側で完結する形と同じ)。**UX**: 到達は競合類のみ。文言は再同期の案内。**採用: F-b**(正本 §6.3 の「警告」は fail-closed 側の中断で満たす — 字面より厳しい側。所有者へ報告)。

### K4-G. 招待発行時の包含検査(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| G-a **エラー(発行しない)。逃げ道なし** | 発行者の scope が招待 scope を包含しない・`--env` の id がチェーン上に無い(`unknown-environment`)場合は通信前に型付きエラー | 発行できても受諾後の `add_member` が `scope-not-contained` / `unknown-environment` で通らない = 受諾者を無駄に儀式へ進ませる罠。発行時と add 時で状態が変わりうる(§15-2)のは「発行時に通っても add 時に落ちる」方向で、エラーにしても失うものがない |
| G-b 警告して発行 | 発行者の scope が後で広がる場合に備える | 招待は 7 日で切れる。scope の拡大は admin の 1 操作で、それを待ってから発行すればよい。警告は無視される(B2 裁定と同じ) |
| G-c `--force` | — | 逃げ道が要る場面がない(all の主体に頼めばよい) |

**探索**: 第 2 巡: 上位互換なし(空巡)。第 3 巡: なし(空巡)。打ち止め。**原則**: 「通信前の検査は、通しても後段で必ず落ちる入力を止めるもので、後段が受理しうる入力は止めない」。§15-2 の「検査は案内止まり」は「サーバーが検査しない」ことの記述で、CLI が止めることを禁じていない。**UX**: listed の admin が自分の scope 外を招待すると即座に理由が出る。**採用: G-a**。

### K4-H. docs の範囲(列挙 1 巡 + 空巡 2・打ち止め)

- `apps/site/docs/invite-a-teammate.mdx`: `--env` の 1 段落(K4 で利用者に見える挙動が変わる)を K4 に含める。`environment-scopes.mdx` の新規作成は K7。
- `docs/SELF_HOSTING.md` "Updates": サーバーの挙動は K3 で確定済みで K4 は CLI のみ。K2 の段落の末尾に「CLI が listed の scope を発行できるようになった(2026-09-15 K4)」の 1 文を足す(利用者が「いつから使えるか」を読める)。
- 探索: 第 2 巡・第 3 巡とも新案なし(空巡)。**原則**: 「利用者に見える挙動が変わる段で、その挙動の docs を同じ PR に載せる」(K2 の SELF_HOSTING 前倒しと同じ)。**UX**: `invite create --help` と docs の `--env` の説明が同じ既定(省略 = all)を言う。**採用: 上記**。

### K4-I. 包含述語の置き場(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| I-a crypto の `index.ts` に `scopeContainsEnvironmentSet` 等を再エクスポート | 1 実装 | `packages/crypto` への変更 = 人間レビュー必須・K4 の範囲外 |
| I-b **CLI に `scope.ts` を新設し、公開 API `scopeIncludesEnvironment` から導出する**: `scopeContains(actor, target)` = target が `all` なら actor が `all`、target が `listed{X}` なら ∀x ∈ X: `scopeIncludesEnvironment(actor, x)`。差集合は具体的な環境 id 列で表す(K4-J) | crypto 不変。CRYPTO_SPEC §6.2 の集合代数と同値(`all ⊇ 任意`、`listed ⊇ all` は偽、`listed{X} ⊇ listed{Y}` ⇔ Y ⊆ X)。テストで crypto の合意規則と同じ真理値表を固定 | 2 実装(CLI は通信前の案内、crypto は合意規則)。ズレは合意規則の 422 が最終判定として拾う |

**探索**: 第 2 巡・第 3 巡: なし(空巡)。**原則**: 「通信前の判定は公開 API から導出し、内部実装をコピーしない(CLAUDE.md の ImportLint 規律)」。**採用: I-b**(K5 以降でベクター再生成と同時に crypto 側の公開を検討してよい — 申し送り)。 **UX**: 通信前の文言(K4-C)は CLI 側の述語から出るので、crypto の理由コードと文面が二重になることはない(合意規則の 422 は `failure.ts` の既存写像)。

### K4-J. 義務ごとの環境集合と `sweepRotations` の一般化(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| J-a **`RotationMandate` に `environmentIds`(その義務の環境集合を、義務 seq 時点のチェーン導出環境集合に対して具体化した id 列)を持たせ、`sweepRotations` は「環境 → 基準 seq」の写像で走る** | remove = 対象の現 scope(`memberStateAt(target, seq-1).scope`)、降格 = 新 scope、縮小 = 旧 \ 新、revoke = 全環境(不変)。`all` は seq 時点で存在した全環境に具体化(`unconvergedMandates` の `createdAtSeq > seq` 除外と同じ線)。`all \ listed{X}` = 存在した全環境 − X。1 対象に複数の義務(縮小の後の remove)があれば環境ごとに最大の基準 seq を採る | 既存の「基準 seq より前に現エポックが始まった環境 = pending」の判定は不変。全環境 = 具体化した列の特殊形 |
| J-b 義務を「全環境 + フィルタ述語」で持つ | — | 未収束判定・案内文・sweep の 3 か所で述語を評価する形になり、具体化の方が単純。上位互換ではない |

**探索**: 第 2 巡・第 3 巡: なし(空巡)。**原則**: 「義務の環境集合は義務エントリの seq 時点のチェーン状態だけで決まり(K3-E の窓と同じ入力)、履行はその集合の各環境について独立」。既存 3 種はこの原則の「集合 = 全環境」の場合。**UX**: `member remove` の報告は「rotation of every environment」から「rotation of the N environments in the target's scope」になる。**採用: J-a**。

### K4-K. 「バックフィル未了を未収束警告に含める」(§7 末尾)— 据え置き(単巡 — 事実確認)

DEK ラップの配布は本人宛のみ(AUTH_SPEC §12-6「配布は本人宛のみ」)なので、**他人宛のラップの欠落は CLI から観測できない**。観測できるのは (i) 本人が自分宛の欠落を見る(`pullVariables` の欠落エポック警告 — 既存。scope 内の環境について全エポックを持つはず、という前提は ES 後も不変)、(ii) actor が自分のバックフィル実行の失敗を見る(`member add` / `change-role` の報告 — 既存 + K4)の 2 つ。`project verify` は鍵なし・DEK を取得しないため、他人の未了を表示する材料を持たない。したがって「未収束警告に含める」は本人側(i)と actor 側(ii)で満たし、第三者視点の検出は**据え置き**(材料がサーバーにしかなく、サーバー申告を警告の入力にしない規律 — §12-7 — と整合)。K7 の docs で「バックフィル未了は本人の pull が検出する」と書く。

### K4-L. 発行ピンに scope を持つか(単巡 — 既存構造への追随)

発行ピン(`invites/<projectId>.json` の `issued[<id>]` — AUTH_SPEC §15-3 の SHOULD)は `linkPubHex` / role / 期限 / 宛先 login を持つ。真実源は発行署名(scope を覆う)なので必須ではないが、role と同じ地位の scope をピンにも写し、`member add` の突合(role と同じ「一致しなければ拒否」)に加える。旧ピン(scope 無し)は突合をスキップ(追加のみ・後方互換)。

### K4-M. 実装録(裁定の反映先)

- 新設 `apps/cli/src/scope.ts`: `scopeContains` / `describeScope` / `requireEnvironmentInScope` / `scopeFromFlags`(`--env` 反復 → 昇順・重複拒否 → `ScopePayloadFields`)/ `environmentSetOfScopeAt`(義務の環境集合の具体化)
- `dek-wrap.ts`: `wrapRecipientsFor` の member 側を `scopeIncludesEnvironment` で絞る(R(E))。`requireWritingMember` に scope 判定(create は `all` のみ、rotate は環境 ∈ scope)
- `deks.ts`: `environmentKeysFor` の受信側規則(K4-F)
- `context.ts`: `openEnvironment` の scope 判定(`openMetadataEnvironment` は不問)
- `invite.ts`: `--env` の scope、存在検査 + 包含検査(K4-G)、発行ピンの scope(K4-L)、`reportIssued` に scope
- `member.ts`: add のバックフィルを対象 scope に限定、`change-role` の (role, scope) 全置換 + 拡大バックフィル + 縮小 / 降格 sweep、`member list`
- `rotation-sweep.ts`: 第 4 種 `scope-narrowed`、`environmentIds`、環境別基準 seq、案内文
- `checkpoint.ts`: `"all"` を自分の scope に絞る(scope 外は SHOULD 警告つきで除外 — §6.3 環境横断 (i))
- `effect-cli.ts`: `invite create --env`、`member change-role --role? --env… --all-envs`、`member list [--json]`、`project verify` の scope 列、sync の 3 環境の判定、文言
- `failure.ts`: `insufficient-scope` に再同期の案内
- Web: `chain-view.ts`(scope の fold)/ `ProjectScreen.tsx`(Scope 列)
- docs: `invite-a-teammate.mdx`(`--env`)、`SELF_HOSTING.md`(1 文)、ROADMAP の ES 行

### K4-N. 申し送り(K5 / K6 / K7 へ)

- **CLI が発行する scope 付きエントリの形**: `add_member` = 招待行の scope(`invite create --env` → 発行文 → D1 行 → 受諾 → `member add`)、`change_role` = `--role` / `--env` / `--all-envs` から組んだ新 (role, scope) の全置換(省略 = 据え置き)。生成は昇順・重複なし(SHOULD)
- **sweep の第 4 種** `scope-narrowed`(target = user_id、seq = change_role、environmentIds = 旧 \ 新 の具体化)。K6 の承認者側 sweep(四眼経由の適用)は `rotationMandates` に「適用 seq の approve エントリ」を義務エントリとして足すだけでよい(環境集合の導出は同じ関数)
- **通信前判定の置き場**(K4-C): `openEnvironment` / `requireWritingMember` / `environmentKeysFor` / `requireEnvironmentInScope`(checkpoint・sync の明示呼び出し)。K6 の `approval` コマンドは環境を持たないので不問
- **Web の scope 表示の段**: K4 で確定(`chain-view.ts` の fold + Members 表の Scope 列)。K6 は pending の表示のみ
- **VH との交差**(§6): `var history` / `rollback` は K4 時点で存在しない。実装時は `openEnvironment` を通せば scope 判定が自動で掛かる(値付き経路は `environmentKeysFor` でも止まる)
- **正本の字面との差**(所有者へ報告): §6.3 受信側の「使用せず警告する」を K4-F のとおり「取得口で型付きエラー(使用しない)」で実装した。字面より厳しい側で、緩める場合は F-a に戻すだけ
- **crypto の公開 API**: 包含述語は CLI に 2 実装目がある(K4-I)。次にベクターを再生成する段で `scopeContainsEnvironmentSet` / 集合演算の公開を検討し、CLI 側を差し替えてよい
- **バックフィル未了の第三者検出**は据え置き(K4-K)。docs(K7)で本人側検出を説明する
- **PR #179 レビューでの追補(pullfrog / Cursor Bugbot / 独立 Opus レビュー)**: (1) `change-role` の CAS リトライは据え置き側を**署名するビュー**の対象の現状から解決する(スナップショットを再署名しない)。(2) 拡大分のバックフィルは対象の **全 `change_role` 履歴**の拡大分の和集合 ∩ 現 scope から導く(最後の 1 件だけだと、中断中に第三者の change_role が挟まると再開されない)。sweep 側の「対象の全義務を畳む」と同じ形。(3) sweep の対象は**実行者の scope 内**に限り(§7「実行者も scope 外なら rotate できない」)、scope 外に残る他人の義務環境は失敗ではなく注記にする(常時警告が引き続き表示)。rotate エントリの `reason` は環境ごとの基準義務(最大 seq)の種別。(4) `member add` / `member remove` にも原則 1 の手前判定(add = 招待行の scope、remove = 対象の現 scope)。add は儀式の前に落とす(発行時検査 K4-G は発行者のもので、add の実行者は別人・別時点でありうる)。(5) `listed{}`(§6.2 の空 listed — 承認項目 3)を CLI から作れる `--no-envs` を `invite create` / `change-role` に置く(`--env` / `--all-envs` と排他)。K4-A の候補表には空 scope の扱いが無かった — 「省略 = 変えない」の原則から `--no-envs` は明示の作為で、原則と整合する。(6) `--role owner` は `--all-envs` なしで scope を all に全置換する(§6.2 owner = all)。これは K4-A の原則「拡大は明示の作為でのみ起きる」の唯一の例外で、owner 昇格という作為が全環境の付与を含意する(§6.2)ため原則の適用範囲外と整理する。ヘルプ文もそう書く。(7) `change_role` の義務導出で直前状態が導出できない場合は remove と同じく fail-closed(書き手だった・全環境を持っていた側)。(8) CLI の検査順を §6.2 の合意規則の順(role → last-owner → unknown-environment → scope-not-contained)に揃えた。(9) 拡大分のバックフィルは **実行者の scope 内**の環境に限る(scope 外の環境の DEK は実行者に無いので §6.3 の受信側規則で止まる — バックフィル前に切り分け、`widenedOutOfScopeEnvironmentIds` として報告し「その環境の書き手が `maruhi env rotate` か再度の change-role で埋める」と案内)。(10) sweep の「scope 外に残る義務」注記は **未消化(基準 seq より後に rotate が無い)かつ環境が未削除**のものだけ(消化済み・削除済みを毎回警告しない)。(11) `change-role` の「既に適用済み」再開判定は member 以上の役割にだけ許す(reader は追記できないので、再開の名目で成功扱いにしない)。(12) `--role owner` に `--env` / `--no-envs` を添えた usage 文は `--all-envs` への誘導を含む。(13) `member add` の包含判定は重複鍵の判定の後ろ(既存の順序に割り込まない)。(14) 拡大バックフィルの報告は「この変更で拡大した」ではなく「scope に加わった環境の未収束分」を指す文言にし、scope 外に残る拡大分の注記は自分の scope 内のバックフィルが無い場合(listed admin が他人の拡大の後に再実行する主経路)にも出す。(15) 履歴由来の拡大分から**検証済み削除**の環境を外す(削除済みは誰も埋められないので注記に出し続けない — 内側の `backfillAllEnvironments` の削除フィルタと同じ集合)。この問い合わせは拡大分が空なら行わない(追記後の余計な要求で exit を汚さない)。切り分け(削除済み除外 + 実行者 scope)は `splitWidenedByActorScope` に寄せた
- **独立 Opus レビュー 3 回目(MERGE-SAFE)の残 nit(未対応・申し送り)**: (a) S7 の否定側(消化済み / 削除済みの scope 外義務は注記しない)のテストが無い。(b) `member add` の追記済み再開経路は change-role 側(追補 (9))のような実行者 scope での切り分けを持たず、listed の実行者が scope 外環境を含む add を再開すると当該環境は §6.3 の受信側エラーとして環境ごとの失敗文言になる(冪等な再実行で収束するので実害は文言のみ)。並べ替え比較子の不揃い(素の `toSorted()`)は `compareCodePoints` に統一済み

## 11. K5 追記(2026-09-16 — サーバーの四眼受理面の実装時の裁定)

K5 は受理面の段(§4 の K5 行)。前提の再確認: 受理ガード解除の前提(申し送り ⑤ = 投票者の鍵束縛)は K2-11 で正本(CRYPTO_SPEC §6.2 原則 2 の S = (user_id, 署名時の鍵 FP))・ベクター(`readded-approver-*`)・crypto(`ApprovalVote`)に反映済みであることを PR #177 の差分で確認した — 満たされている。正本 3 文書と設計録の食い違いは §11 末尾の実装録に記す。以下、§5 の手順(候補 ≥ 3 → 上位互換 / 銀の弾丸の探索 → 空巡 2 で打ち止め → 原則の抽出と旧裁定の導出確認 → UX 点検 → 選択)を各裁定点で回した。巡数は回した分だけ書く。**巡の粒度の正直な注記(独立レビュー nit 7)**: K5-A / B / C / D / E / F / H の第 2 巡は具体の上位互換候補(版ズレ論・時計 2 つ・skew 幅・冗長判定・`client_ts` 変種・混成導出・層の問題)を挙げて棄却しているが、K5-G / I / J / L / M の第 2・3 巡は候補表の外に新案が出ず「空巡」の記録だけである(見出しにその旨を付す)。後者は候補表が正本の字面(§3.4 の全単射規則・§12-8 の型名・承認項目 19)にほぼ束縛されており探索の余地が小さかった、というのが実態で、巡を回したこと自体を成果として書かない。

### K5-A. `ApprovalNotAcceptedError` の去就(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| A-a 削除 | api-schema の型・エンドポイント宣言・DO の拒否種別・HTTP 写像・CLI 文言をすべて消す | ワイヤ形式の変更(公開エラー型の削除)= 所有者裁定を要する(§3 の「指示を仰ぐ範囲」)。K5 の自律実装の範囲外 |
| A-b **サーバーの発生源だけを消し、ワイヤの宣言は残す** | DO の拒否種別 `approval-not-accepted` と HTTP 写像・両層のガードを消す。api-schema の型と `append` の宣言、CLI `failure.ts` の文言は据え置き(JSDoc を「K5 以降のサーバーは発生させない」に改訂) | ワイヤ不変。**K5 以降の CLI(K6 の `approval` コマンド)が K2〜K4 のセルフホストサーバーへ四眼エントリを送ったとき**、旧サーバーはこの型で拒否するので CLI の文言(「later server release」)がそのまま正しい案内になる = 削除すると版ズレの型付き案内を失う。サーバー内に到達不能な分岐は残らない(fallow の未使用検出に掛からない) |
| A-c 用途変更(受理ポリシー違反に転用) | `ProposalLimit` の代わりに使う | AUTH_SPEC §12-8 が `ProposalLimit` の名を規定済み(承認項目 22)。転用は正本違反 |
| A-d 用途変更(「副作用未実装の op」の汎用ガードとして残す) | 将来の新 op 追加時に再利用する | 今は該当 op が無く到達不能の分岐 = 死んだコード。K2-10 の原則「受理する op = 副作用実装済みの op」は、新 op を足すときに同じ PR で副作用を入れる規律であって、恒常的なガードを要しない |

**探索**: 第 2 巡(上位互換): A-b の欠点は「サーバーが発生させない型が宣言に残る」ことのみで、それは版ズレ(旧サーバー × 新 CLI)では実際に発生する型なので欠点ではない。銀の弾丸(型を残すか消すかの判断を不要にする構造 — サーバーが機能フラグを配る等)は、四眼の受理可否は「サーバーのバージョン」そのものでありフラグを増やす利得がない。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「ワイヤに載る型の集合は所有者裁定でしか縮まず、サーバーがその型を発生させる分岐は受理副作用の実装状態に従う」— K2-10 の原則(受理する op = 副作用実装済みの op)はこの原則の「発生させる側」の帰結であり、K2 で型を**足した**判断(ワイヤの拡張 = 承認項目 22 の pending 上限と同じく承認済みの範囲)とも整合する。導出できない旧裁定なし。

**UX**: K5 以降のサーバーでは利用者がこの文言を見ることはない。旧サーバーに対しては K6 の CLI が四眼エントリを送った時点でこの文言に落ち、「サーバーを更新せよ」の案内として機能する。悪化なし。**採用: A-b**。ワイヤからの削除は所有者への提案として最終報告に載せる(採るなら独立 PR)。 **所有者裁定(2026-09-16・K5 マージ後)**: セルフホスト利用者は現状いないので削除する方向だが、**後回し**(K6 以降の独立 PR。api-schema `errors/chain.ts` / `membership-api.ts` / CLI `failure.ts` の 3 箇所)。

### K5-B. 受理ポリシーの判定層と判定順(列挙 1 巡 + 空巡 2・打ち止め)

対象: pending 上限(32・期限切れは数えない)と `expires_at_ms` の上界(受理時サーバー時計 + 30 日)。

| 案 | 内容 | 評価 |
|---|---|---|
| B-a worker + DO の両層 | `composite-required` / K2-10 のガードと同じ多層防御。上界は状態を要しないので worker でも判定できる | 上界の判定に**時計が 2 つ**(worker と DO)・定数が 2 箇所になる。状態を要する pending 上限は DO にしか置けないので、両層に置けるのは半分だけ = 「同じガードを両層に」の形にならない。既存の両層ガードは**op 種別だけ**で決まる無状態・無時計の判定であり、時計を持つ判定の先例ではない |
| B-b **DO のみ(受理判定の権威)** | `appendProgram` で `propose` に対し、メンバーシップ判定 → 成長ガード → **受理ポリシー(上界 → pending 上限)** → CAS → verifyChain の順 | 判定材料(現 pending 集合 = 導出状態のキャッシュ、サーバー時計)が 1 箇所。招待の先例(`invite-domain.ts` — UNIQUE → pending 上限 → 固定窓)と同じく「受理ポリシーは意味論的検査(CAS / 合意規則)の前」(AUTH_SPEC §12-8 の測定点の規律と同じ位置) |
| B-c verifyChain の中(crypto) | 合意規則の検査列に足す | 受理ポリシーは合意規則ではない(CRYPTO_SPEC §6.4 明記)。crypto は範囲外。棄却 |

判定順の内訳: 上界(エントリ固有・時計のみ)を pending 上限(プロジェクト状態)より先に見る — サイズ(エントリ固有)→ 容量(チェーン状態)の既存順と同じ「エントリ固有 → 状態」。両方に違反したとき返るのは上界側で、利用者が直せるのは自分のエントリ(`--expires`)なのでその順が案内としても正しい。

**探索**: 第 2 巡(上位互換): B-b に「worker の先行検査」を足す B-a′ は、DO を起こさずに拒否できる利得が上界違反(クライアントのバグか誤指定)のときだけで、DO の 1 往復を節約する価値より時計 2 つの費用が大きい。銀の弾丸(判定層の選択を不要にする構造 — 受理ポリシーを全部 worker に置ける形)は pending 集合が DO のチェーン導出状態にしか無いので存在しない。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「受理ポリシーは判定材料を持つ層に 1 箇所置き、多層に重ねるのは op 種別だけで決まる無状態のガードに限る」— `composite-required` / K2-10 の両層ガード(op 種別のみ)✓、サイズ検査の worker 先行(材料 = エントリ本体で両層が同じ材料を持つ)✓、成長ガード(`databaseSize` は DO にしか無い → DO のみ)✓、招待の pending 上限(D1 の行数 → worker / D1 のみ)✓。導出できない旧裁定なし。

**UX**: 拒否は型付き 422 `ProposalLimit`(K5-I)。CLI(K6)は上界違反を通信前に(`--expires` の上限を CLI 既定 7 日・最大 30 日として)拒める。pending 上限は `approval list` で期限切れの提案を見せ `withdraw` を案内する。**採用: B-b**。

### K5-C. 「作成時点で既に失効している提案」の扱い(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| C-a サーバー時計で拒否(`expires_at_ms < 受理時サーバー時計`) | §4 の K5 行の候補 | 受理ポリシーの時計と一致する。ただし**資源を守らない**: 失効済み提案は pending 上限の計算から既に除外されており、誰も承認できない(正直な承認者の `timestamp_ms ≤ expires_at_ms` が成立しない)ので占有もしない。守るのは「クライアントの意味論」であり、K6 の CLI が通信前に検査すれば足りる。副作用として、固定時刻のテストベクター(propose の `expires_at_ms` = 2025-08-08)をサーバーで再生できなくなる(サーバー時計 2026-09 で失効済み)= 検証デプロイの再生・サーバー統合テストの正規チェーン再生が時計に依存する |
| C-b 提案者の申告時刻で拒否(`expires_at_ms < propose.timestamp_ms` — 8-bis K2-5 e-3) | 時計を使わない構造的な検査 | 合意規則に無い検査を「受理ポリシー」の名で全サーバーに課す = 事実上の合意規則の追加(K2-5 の原則「合意規則が時刻に触れるのは 1 比較だけ」に反する方向)。しかも捕まえるのは「自分の申告時刻より前に失効する」形だけで、時計ズレによる実時間の失効は捕まえない |
| C-c 両方 | — | C-a と C-b の欠点の和 |
| C-d **拒否しない(受理ポリシーにしない)** | 失効済み提案は受理し、上限の計算から除外されるだけ | 資源保護に不要(上表)。合意規則も既に閉じている(承認は `proposal-expired`)。K6 の CLI が `propose` の生成時に `expires_at_ms > now` を検査する(クライアントの通信前検査 — K4-C と同じ置き場) |

**探索**: 第 2 巡(上位互換): C-a に許容幅(clock skew)を足す案は、幅の値が合意規則にも正本にも無く、時計を持つ判定を増やすだけ。銀の弾丸(失効の概念を受理面から消す)は C-d そのもの。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「受理ポリシーは**サーバーの資源**(pending 枠・ストレージ・チェーン容量)とストレージ収束を守るためにあり、クライアントの意味論の代行はしない」— pending 上限 ✓(枠)、上界 30 日 ✓(枠の占有時間)、サイズ / 容量 ✓、成長ガード ✓、招待の pending 上限 / 固定窓 ✓、`remove_member` 時の申告行削除・再追加時のラップ掃除 ✓(ストレージ収束)。CRYPTO_SPEC §6.4 の「提案者単位の副次上限は置かない(必要になれば加法的に)」もこの原則の帰結(必要 = 資源の観点で必要になったとき)。導出できない旧裁定なし。

**UX**: 時計の狂った端末から出た失効済み提案は `approval list`(K6)に「expired」として現れ、提案者が `withdraw` する。誰も承認できない提案が一時的に見える以外の悪化はなく、K6 の通信前検査で通常は到達しない。**採用: C-d**。§4 K5 行の「候補」は不採用として閉じる。

### K5-D. 成長ガード(§12-8)の四眼経由の適用点(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| D-a 直接追記の `add_member` / `grant_server` のみ(現状) | 四眼経由は素通り | 完成した approve が add_member を適用すると、バックフィルは拒否されるのに add は通る = §12-8 が入口で塞ごうとした「メンバーはいるがラップがない」中間状態が四眼経由で量産できる |
| D-b 完成する approve のみ | verifyChain 後に完成を知ってから判定 | 判定の位置が「意味論的検査の後」になり §12-8 の測定点の規律(CAS / 署名検証 / 意味論の前)に反する。提案者は成功、承認者だけが 422 = 別人が最後の一手で止められる UX |
| D-c **`propose`(内側 op が add_member / grant_server)と `approve`(参照先の pending 提案の内側 op が同じ)** | 参照先は CAS / verifyChain の前に現導出状態の `pendingProposals` から引く(未知の hash はガード対象外 — verifyChain が `unknown-proposal` で拒む)。完成するかどうかに依らず、成長提案への approve はガード下では受理しない | 提案の入口(提案者の `member add` / `server grant`)で直接追記と同じ位置・同じ材料で止まる。ガードの位置は既存と同じ(メンバーシップの後・CAS の前) |
| D-d 4 op 全部 | — | `withdraw`(解放)・`set_approval_policy`(セキュリティ設定)・remove / revoke / 縮小の提案と承認(是正)を総量で止める = §12-8 (b)(c) の「拒否下でも受理し続ける面」に反する |

**探索**: 第 2 巡(上位互換): D-c + D-b(完成時にも再判定)は D-c が approve を既に止めているので冗長。銀の弾丸(ガードを op 判定から外し「バックフィルの拒否」だけで足りるとする)は §12-8 が入口の拒否を明文で要求しており不可。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「成長ガードは**アクセス集合を拡げる意図が最初に現れるエントリ**で止める」— 直接追記の add / grant ✓、提案経由ではその提案と承認 ✓、ラップ登録(自然な後続)✓、schemaPolicy(内容の成長ではないが監査行の非有界)= 明示例外として §12-8 に列挙済み(原則からの導出ではなく列挙 — 既存の例外を維持)。`set_approval_policy` は監査行を 1 行積むがチェーン容量で有界(`change_role` 昇格と同じ扱い)= 原則どおりガード外。

**UX**: 9 GB 超では `member add` / `server grant` の提案が直接追記と同じ `DataLimitExceeded(project-storage-bytes)` で止まり、案内は既存の文言。**採用: D-c**。

### K5-E. ミラー行・適用行の書き込み単位と形(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| E-a **同一同期ブロックで「`chain.approved`(completed = true)→ 適用行 → 内側 op の副作用」** | `insertAcceptedEntrySync`(chain-accept.ts)の中。適用行 = 内側 op のミラー写像(`packages/core/src/audit.ts` の op 別 tail)+ `viaProposalSeq`、**actor = 提案者(propose エントリの actor = user_id + 鍵 FP)**、`chain_seq` = approve の seq、`client_ts` = approve エントリの `timestamp_ms`(適用を運んだエントリの時刻)、`server_ts` = 同一受理の nowMs | AUDIT_SPEC §3.4 の字面どおり。要ローテーション検出(Q1 = target_user_id の `chain.*` 行を監査 seq 順に畳む)は適用行を「直前に書いたミラー行」として読めるので、直接追記と同じ関数・同じ順序(ミラーの後に検出)で動く。`chain_seq` の UNIQUE 制約は現状なく(K1-3)、今後も置かない(2 行 / seq が正) |
| E-b 適用行を別の監査 seq 単位のトランザクションに分ける | — | 「チェーンだけ書けてミラーが欠ける」不整合の再導入(chain-commit.ts の原則に反する) |
| E-c 適用行を書かず `chain.approved` の payload に内側 op を写す | 行数 1:1 を保つ | Q1 / Q6 の入力構造(`chain.member_removed` 等を target 索引で引く)が変わり、検出の実装を 2 系統にする。AUDIT_SPEC §3.4 が明示的に棄却した形 |

**探索**: 第 2 巡(上位互換): 適用行の `client_ts` に提案時刻(propose の `timestamp_ms`)を置く変種は「適用の時刻」でなく「意図の時刻」になり、`chain.proposed` 行が既に持つ情報の重複。銀の弾丸(ミラー行を書かず必要時にチェーンから再構成する = AUDIT_SPEC §1-5)は監査の可視性クラスと Q1 の索引要件が同 DO 内の行を前提としており K5 の範囲で覆せない。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「ミラー行は、監査の索引(Q1 / Q6)が**受理された事実**を直接追記と同じ形で引けるように書き、経路(直接 / 提案)は payload の追記(`viaProposalSeq`)で区別する」— 承認項目 22(適用行 = 同 chain_seq・`viaProposalSeq`・actor = 提案者)✓ 導出、K3-H(`chain_seq` 一意性を前提にしない)✓、`rotation.recommended` の `triggerChainSeq` = approve の seq(裁定 P7)✓。導出できない旧裁定なし。

**UX**: `maruhi audit list` は同じ chain_seq の 2 行を別行として表示し(適用行は内側 op のイベント名)、突合はどちらの行も OK になる(K5-G)。**採用: E-a**。

### K5-F. 完成判定と提案の索引の導出(サーバーと CLI の共有 — 列挙 1 巡 + 空巡 2・打ち止め)

ミラー行の `proposalChainSeq` / `completed` と適用行の内側 op・提案者は、approve / withdraw エントリ単独からは写せない(K2 の申し送り 3)。

| 案 | 内容 | 評価 |
|---|---|---|
| F-a サーバー = 受理前後の `pendingProposals` の差分、CLI = 別の導出 | サーバーは安価(キャッシュ済み前状態 + 適用後状態)。CLI は検証済みチェーン(entries + 最終状態)から導く | 写像の入力の導出が 2 実装 = `packages/core/src/audit.ts` の冒頭が禁じるドリフト(検証器の誤検出 / 見逃し) |
| F-b crypto が検証ループの `AppliedOperation`(chain-verify.ts 内部)を公開する | 正確・安価 | `packages/crypto` の公開 API 変更 = K5 の範囲外(§3)。到達したら止まって諮る案件であり、共有導出(F-c)で足りるので諮らない |
| F-c **core に 1 実装 `indexProposals(entries, entryHashAt, finalPending)`** | 検証済みチェーン上で: 提案 P(propose エントリ・hash = entry_hash)が最終状態で pending でなく、P を参照する `withdraw` が無ければ、P を参照する**最後の** `approve` が完成エントリ(合意規則上、完成後の P への approve / withdraw は `unknown-proposal` で無効 = 検証済みチェーンには存在しない)。サーバーは `[...chain.entries, entry]` と適用後状態、CLI は `VerifiedProject.entries` と `state` で同じ関数を呼ぶ | O(n) の走査(署名検証を伴う verifyChain より軽い)。写像とその入力の導出が core の 1 実装に閉じる |

**探索**: 第 2 巡(上位互換): F-c をサーバーだけ F-a の差分で高速化する混成は、F-a の欠点(2 実装)を再導入する。銀の弾丸(approve エントリの payload に `proposal_seq` / `completed` を載せてエントリ単独から写す)はワイヤ = 合意規則の変更(K2-2 の b-2 と同型)で棄却済み。空巡。第 3 巡: 新案なし。空巡。打ち止め。

**原則**: 「ミラー写像とその入力の導出は core の 1 実装をサーバー(書き手)と CLI(検証器)が共有する」— K2 の `chainMirrorEvent` / `CHAIN_MIRROR_EVENTS` の置き場の裁定の延長 ✓。導出できない旧裁定なし。**採用: F-c**。

### K5-G. `audit verify` の全単射規則と `audit list` の突合(列挙 1 巡 + 空巡 2〔新案なし — 内容のある探索は第 1 巡のみ〕・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| G-a **seq ごとの期待行集合との突合** | 期待 = `chainMirrorEvents(entry, serverTs, index)`(1 行、完成 approve は 2 行)。観測行をイベント名で期待行に対応づけ、欠落 / 過剰(期待に無いイベント名の行・同名の重複)/ 各フィールドの不一致を列挙。`audit list` の行単位の突合は、観測行のイベント名に一致する期待行と比べる(適用行のイベント名は approve のミラー名と重ならない — 内側 op に `approve` は無い) | AUDIT_SPEC §3.4 の改訂規則の字面どおり(欠落・過剰・`viaProposalSeq` 不一致 = 失敗)。head より新しい行の連続性検査(`aheadContiguityProblems`)は、同一 seq の 2 行を許すため「重複 = 偽造」を「seq が飛ぶ = 偽造」に緩める(完成 approve の 2 行目が偽造と誤断定されない) |
| G-b 行数の一致だけを見る(1 または 2) | — | `viaProposalSeq` の不一致・適用行のすり替えを見逃す |
| G-c 適用行を検証対象から外す | — | 適用行が偽造の隠れ場になる |

**探索**: 第 2 巡(上位互換): なし。銀の弾丸(2 行を 1 行に畳む = K5-E の E-c)は棄却済み。空巡。第 3 巡: 新案なし。空巡。打ち止め。**原則**: 「検証器は書き手と同じ写像から**期待行の集合**を再構成して突合し、行数の規則は集合の帰結として得る」— 従来の 1:1 も「集合の大きさ 1」の特殊形 ✓。`audit-reconcile.ts` の `chain.checkpointed` の 1 行同定は、`checkpoint` が提案できない op(CRYPTO_SPEC §6.2)なので影響しない — 変更なし。**採用: G-a**。

### K5-H. 適用結果の worker への伝達(招待の completed 化・membership 投影 — 列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| H-a **DO の `append` の戻り値に `appliedProposal`(完成した提案の seq と内側 op)を足す** | worker は `entry.op` が add / remove のときと同じ D1 後処理(§15-2 の completed 突合・§11-5 の投影 upsert / delete)を「適用された内側 op」に対して行う。ワイヤ(HTTP 応答)は不変(ハンドラが `headSeq` / `headHashHex` だけを返す) | RPC は内部境界(structured clone)で、K5 の範囲。判定は受理面の権威(DO)が行い、worker は結果を写すだけ |
| H-b worker が受理後にチェーンを再取得して自分で完成判定 | — | RPC 1 往復の追加と、完成判定の 2 実装目(K5-F の原則に反する) |
| H-c DO が D1 を直接書く | — | DO は D1 バインディングを持たない(層の分離: D1 は worker の `db.package`) |

**探索**: 第 2 巡(上位互換 / 銀の弾丸): 投影・招待の突合を DO の受理タスク内に移す案は H-c と同じ層の問題。空巡。第 3 巡: 新案なし。空巡。打ち止め。**原則**: 「受理の判定は DO、D1 の導出状態の更新は worker — DO は判定結果を戻り値で渡す」(§11-5 (2)(3) の「DO 受理と別トランザクション」の規律のとおり)。**採用: H-a**。

### K5-I. `ProposalLimit` のワイヤ形(承認項目 22 の範囲内 — 列挙 1 巡 + 空巡 2〔新案なし — 内容のある探索は第 1 巡のみ〕・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| I-a **`{ reason: "pending-proposals" \| "proposal-lifetime", limit: number }`(422)** | `limit` は reason ごとの上限値(件数 32 / 生存期間 30 日のミリ秒) | `DataLimitExceeded { resource, limit }` と同じ語彙(閉集合の reason + 数値の上限)。1 型で 2 つの受理ポリシーを運ぶ |
| I-b 2 型(`ProposalLimit` と `ProposalLifetime`) | — | AUTH_SPEC §12-8 は 1 つの名 `ProposalLimit` を規定。型を増やすのは正本の字面の外 |
| I-c `DataLimitExceeded` の resource に `pending-proposals` を足す | 既存型の再利用 | §12-8 が `ProposalLimit` を名指し(承認済み)。上界は「resource の上限」ではない |

**探索**: 第 2 巡: 上位互換・銀の弾丸なし(空巡)。第 3 巡: 新案なし(空巡)。打ち止め。**原則**: 「型付きエラーは正本が名指す 1 型 + 閉集合の reason + 上限値」(K3-A の 403 の原則と同型)。**採用: I-a**。DO の拒否種別は `proposal-limit`。

### K5-J. 持ち越し (i) — 鍵の再登録による票の復活を正本に載せるか(列挙 1 巡 + 空巡 2〔新案なし — 内容のある探索は第 1 巡のみ〕・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| J-a CRYPTO_SPEC §6.2 に 1 文を足す | 「同一鍵での再登録は旧票を復活させる(侵害既知の鍵の再登録は運用で禁じる)」 | 正本の変更 = 承認が先に要る(§3)。規則を変えない説明文であっても K5 で勝手には足せない |
| J-b **設計録のまま(K2-11 ⑤ 行)+ K7 の docs で運用規律として書く** | 正本の規則(S の識別 = (user_id, 鍵 FP)・適用時点の現 owner)からの帰結であり、規則の追加ではない | 正本を変えない。利用者向けの説明(`four-eyes.mdx`)に「侵害した鍵を再登録しない」を置く |
| J-c 合意規則で塞ぐ(在籍区間束縛) | K2-11-bis ⑤ d で棄却済み | 蒸し返さない |

**探索**: 第 2 巡: なし(空巡)。第 3 巡: なし(空巡)。**原則**: 「正本には規則を書き、規則の帰結の説明は設計録と docs に置く」(K1-2 の相互参照の掃除と同じ線)。**採用: J-b**。J-a は所有者への提案として最終報告に載せる(採るなら K7 で正本に 1 文)。 **所有者裁定(2026-09-16・K5 マージ後)**: J-a を採る — CRYPTO_SPEC §6.2 `approve` に「失効は単調ではない」の注記を 1 文追加(規則不変・帰結の明記)。

### K5-K. 持ち越し (ii) — 過去に見た鍵 FP の再登録への警告(列挙 1 巡 + 空巡 2・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| K-a サーバーが拒否(受理ポリシー) | — | 同一鍵での再追加は §6.2 が明示的に許容する(同一人物の復帰)。受理ポリシーで合意規則の許容を狭めるのは K5-C の原則(資源の保護に限る)に反する |
| K-b **CLI が `add_member` の署名前に警告(K6)** | 対象の鍵 FP が検証済みチェーンの履歴(`sigKeyByFingerprint` / `keyHistory`)に**別の在籍区間**として現れるとき、「この鍵は以前 X として在籍していた。侵害で削除した鍵なら再登録しないこと」を出す(agent-gate の対象外 — 値を表示しない)。直接追記・提案の両方(`member add` が propose を出す経路も同じ関数) | サーバーは何もしない。警告であって拒否ではない(合意規則の許容を保つ) |
| K-c 何もしない | — | K2-11-bis ⑤ が「運用規律」と定めた以上、その規律を利用者に伝える口が要る |

**探索**: 第 2 巡: サーバーが「再登録された鍵」を監査に印す案(`chain.member_added` の payload に `rebound: true`)は、ミラー写像がエントリ単独から写す規律(K2)と、監査行は検証済みチェーンから再構成できる原則(AUDIT §1-5)に照らして、チェーンから導ける情報の重複。空巡。第 3 巡: なし(空巡)。**採用: K-b — 実装は K6**(申し送り)。

### K5-L. 持ち越し (iii) — `required_approvals` 引き下げ後の pending 提案の完成(列挙 1 巡 + 空巡 2〔新案なし — 内容のある探索は第 1 巡のみ〕・打ち止め)

| 案 | 内容 | 評価 |
|---|---|---|
| L-a **CLI / UI の案内で扱う(規則不変)** | K6 の `approval list / show` が現方針で票数を再集計し、「この提案は次の approve で完成する。approve できるのは未投票の owner: …」を表示。既投票 owner が approve を試みたら通信前に `duplicate-approval` を予告する | 承認項目 19(適用 = 定足数到達の approve の seq)と `duplicate-approval` を変えない。K2-11-bis が推奨した (i) |
| L-b `set_approval_policy` の適用時に既に足りている pending を完成させる合意規則 | — | 正本の変更(承認項目 19 の改訂)。方針変更のエントリが別 op を適用する二義性(裁定 P5 が「承認署名に閉じる効果を持たせない」と同じ線で棄却する形) |
| L-c 既投票 owner の再投票を許す(`duplicate-approval` の緩和) | — | 同一鍵の 2 票目を認める = 原則 2 の distinct の破れ |

**探索**: 第 2 巡: なし(空巡)。第 3 巡: なし(空巡)。**採用: L-a — 実装は K6**。サーバー(K5)には該当する振る舞いがない(合意規則は crypto、案内は CLI)。

### K5-M. 提案の読み取り口(列挙 1 巡 + 空巡 2〔新案なし — 内容のある探索は第 1 巡のみ〕・打ち止め)

ROADMAP の PF1 行と §8「K2 の実装メモ」は受理面に「提案 API」を数えるが、§4 の K5 行には無い(粒度の差 — 報告)。

| 案 | 内容 | 評価 |
|---|---|---|
| M-a 提案 API(`GET /projects/:id/proposals`)を K5 で置く | サーバーが pending 一覧を返す | エンドポイント宣言の追加 = 諮る案件。しかも返す内容(提案者・内側 op・期限・投票者)は**検証済みチェーンの導出状態 `ChainState.pendingProposals` そのもの**で、クライアントは同期のたびに自分で導出する(§6.3)。サーバー申告の pending を表示に使うと「サーバー申告を検証規則の入力にしない」(§12-7)線に近づく |
| M-b **K6 送り = クライアント導出(API なし)** | `maruhi approval list / show` は `VerifiedProject.state.pendingProposals` から出す。票数は K2 の実装メモどおり再集計 | サーバーに何も足さない。Web の pending 表示も `chain-view` の畳み込み(検証済みチェーン)から |
| M-c ミラー行(`chain.proposed` / `chain.approved`)から一覧を作る | 監査 API の再利用 | 監査行はサーバー管理データで検証の入力にしない(AUDIT §6)。棄却 |

**探索**: 第 2 巡: なし(空巡)。第 3 巡: なし(空巡)。**原則**: 「認可・方針・pending の真実源はチェーンで、クライアントは検証済みチェーンから導出する」(§6.4)。**採用: M-b**。K6 が API を必要とする理由(例: Web が全チェーンを畳むコスト)が出たら、その時点で諮る。

### K5-N〜K5-Q. 事実確認(単巡)

- **K5-N 四眼経由の義務の履行者(承認項目 22)との整合**: サーバーの要ローテーション検出は「誰が履行するか」を持たない(`rotation.recommended` の `trigger` = 内側 op の種別、`triggerChainSeq` = 完成した approve の seq — 裁定 P7 / AUDIT §4.1 change_role 変種の末尾)。適用行が直接追記と同じ形で書かれるため検出関数(`detectMemberRemoval` / `detectRoleChange` / `detectServerRevocation`)は変更なしで、`triggerChainSeq` に approve の seq を渡すだけ。K6 の承認者側 sweep は K4-N のとおり「適用 seq の approve エントリ」を義務エントリとして足す。ずれなし
- **K5-O `requiredPermissionForEntry`**: 4 op は既定分岐で `admin`(`checkpoint` / `create_environment` / `rotate_epoch` 以外はすべて admin)。裁定 P8「トークン水準は内側 op と同じ(admin)」と一致。変更なし
- **K5-P スキーマ移行**: 不要。pending 集合はチェーン導出状態(メモリキャッシュ)で保存しない。適用行は `audit_events` の既存列(`chain_seq` に UNIQUE 制約なし — K1-3)に収まる。D1 も変更なし
- **K5-Q サーバーテストの分割数**: `membership-negatives-append.test.ts` の `EXPECTED_PARTITION` は実測で更新する(K2-10 末尾の「12 + 派生チェーン 14 本」は当時の数字。実測は実装録に記す)

### K5-R. 実装録(裁定の反映先)

- api-schema: `errors/chain.ts` に `ProposalLimitError`(422、`{ reason: "pending-proposals" | "proposal-lifetime", limit }`)と `ProposalLimitReasonSchema` を新設し、`membership-api.ts` の `append` 宣言に追加(K5-I)。`ApprovalNotAcceptedError` は宣言を残し JSDoc を「K5 より前のサーバーが返す型」に改訂(K5-A)
- core(`packages/core/src/audit.ts`): `chainMirrorEvent` を `chainMirrorEvents(entry, serverTs, index)`(1 行、完成 approve は 2 行)に置き換え、`indexProposals(entries, entryHashAt, pendingHashes)` / `ProposalIndex` / `IndexedProposal` / `ProposeEntry` を新設(K5-F)。op 別の写像(`mirrorTails`)を「op + payload + actor」の入力に一般化し、適用行は内側 op の写像 + `viaProposalSeq`・actor = 提案者・`client_ts` = approve の `timestamp_ms`(K5-E)。approve / withdraw 行の payload は `proposalChainSeq`(+ `completed`)— K2 の `proposalHashHex` は正本(AUDIT §3.4)の字面に置き換え
- server:
  - `policy.ts`: `MAX_PENDING_PROPOSALS = 32` / `MAX_PROPOSAL_LIFETIME_MS = 30 日`。`quotas.ts`: `proposalIsLive` / `proposalLifetimeExceeded` / `pendingProposalsExceeded` / `countLivePendingProposals` / `ensureProposalAdmitted`(上界 → pending 上限 — K5-B)
  - `data-plane.ts`: 拒否種別 `approval-not-accepted` を削除し `proposal-limit { reason, limit }` を追加。`data-http.ts`: `ProposalLimitError` への写像
  - `chain-do.ts`: 受理ガードを削除。`growsAccessSet`(直接追記の add / grant + 内側 op が成長 op の `propose` + 参照先 pending の内側 op が成長 op の `approve` — K5-D)で成長ガードを判定し、`propose` に `ensureProposalAdmitted`(位置: メンバーシップ → 成長ガード → 受理ポリシー → CAS → verifyChain)。`loadChainForMember` が現導出状態(`state`)を返す。`append` の戻り値 `AppendValue = ChainHeadValue & { appliedProposal }`(K5-H)
  - `chain-accept.ts`: `insertAcceptedEntrySync` が `chainMirrorEvents` の行を書き、完成した approve では内側 op の副作用を approve の seq で走らせる(`applyAcceptanceSideEffectsSync(stores, operation, seq, nowMs)` — 入力を op + payload に一般化)。`proposalIndexOf` / `AppliedProposal` を新設。複合経路(`insertAcceptedEntryPairSync`)は提案できない op しか運ばないので空索引
  - `chain-commit.ts`: `commitAcceptedEntry(chain, entry, applied, canonicalBytes, extraSync?)` が受理後チェーンの提案索引を作り、適用した提案を返す。`checkpoint-accept.ts` は `appliedProposal: null`
  - `handlers-membership.ts`: 受理ガードを削除。D1 後処理(招待の completed 突合・membership 投影の upsert / delete)を「直接追記の op、または `appliedProposal.inner`」に対して行う
  - `authz.ts` / `rotation-detect.ts` / `audit-store.ts` / `do-schema.ts`: 変更なし(K5-N / K5-O / K5-P)
- CLI(`apps/cli/src/audit.ts`): `proposalIndexOf(verified)`(core の `indexProposals` を `VerifiedProject` に適用)、`expectedRowFor`(観測行のイベント名で期待行を選ぶ)、`entryMirrorProblems`(期待行集合との突合 — 欠落 / 重複 / 過剰 / フィールド不一致)、`aheadContiguityProblems`(同一 seq 最大 2 行)。`failure.ts` に `ProposalLimit` の文言(K5-I)。`audit-reconcile.ts` は変更なし(`checkpoint` は提案できない op)
- テスト: `apps/server/test/approval-accept.test.ts`(新規 — 受理ポリシー 2 件・完成 approve の副作用 3 件〔remove の検出 / 申告行 / 投影・提案経由 add_member の招待 completed 化 + 投影・withdraw と方針変更の無副作用〕)、`proposal-policy.test.ts`(新規 — 純関数)、`membership.test.ts`(正規チェーン 24 本の全再生・四眼 5 エントリのミラー行と適用行・派生チェーン `proposal-completed` の未完成 / 完成の分岐と投影削除)、`membership-negatives-append.test.ts`(**実測の分割**: checkpoint 20 / composite 24 / structureBeforeSignature 1 / wireSchema 8 / consensus 104 = 157 — K2-10 の `skipped` 58 + `fourEyesGuard` 7 は consensus +57 / wireSchema +7 / structureBeforeSignature +1 に戻った。K2-10 末尾の「12 + 派生チェーン 14 本」は当時の見積もりで、実測は 58 件)、`storage-guard.test.ts`(四眼経路の成長ガード)、`data-policy.test.ts`(拒否種別の網羅表)、`apps/cli/test/audit.test.ts`(完成 approve の 2 行の全単射 OK・適用行の欠落・`viaProposalSeq` / `completed` の改変・未完成 approve への過剰な適用行・`audit list` の 2 行の突合)
- 正本との照合で見つけた食い違い: なし(CRYPTO_SPEC §6.4 / AUTH_SPEC §11-1 / §12-8 / AUDIT_SPEC §3.4 の字面どおりに実装できた)。設計録側の古い記述: ROADMAP PF1 行の K2 記録「汎用 append で受理」(受理ガード導入前)を訂正、§8「K2 の実装メモ」の「提案 API は K5」は K5-M で K6 送り(API なし)に更新

### K5-S. 申し送り(K6 / K7 へ)

- **受理ポリシーの実装位置と判定順**: DO の `appendProgram`(`chain-do.ts`)で `propose` にのみ、メンバーシップ判定 → 成長ガード → **上界(`expires_at_ms ≤ サーバー時計 + 30 日`)→ pending 上限(期限内 32 件)** → CAS → verifyChain。worker には置かない。失効済み提案は拒否しない(K5-C)— **K6 の CLI は `propose` の生成時に `expires_at_ms > now` と `≤ now + 30 日` を通信前に検査し、既定 7 日・最大 30 日で案内する**。422 `ProposalLimit` の文言は `failure.ts` にある
- **ミラー適用行の形**: 完成した approve の chain_seq に `chain.approved { proposalChainSeq, completed: true }` と内側 op のミラー行(actor = 提案者の user_id + 鍵 FP、`client_ts` = approve の `timestamp_ms`、payload = 内側 op の写像 + `viaProposalSeq`)の 2 行。全単射規則 = 「1 エントリ ↔ 1 行、完成 approve は + 1 行」(`chainMirrorEvents` が期待行の集合)。`chain.approved { completed: false }` / `chain.proposal_withdrawn { proposalChainSeq }` は 1 行。要ローテーション検出の `triggerChainSeq` は approve の seq、`trigger` は内側 op
- **提案の読み取り口**: K5 では置かない(K5-M)。K6 の `maruhi approval list / show` と Web の pending 表示は `VerifiedProject.state.pendingProposals`(`chain-view` の畳み込み)から出し、票数は現方針で再集計する(記録は失効票を保持する — §8 K2 の実装メモ)。サーバー API が要る理由が出たら諮る
- **持ち越し (ii)**(鍵 FP 再登録の警告): K-b を採用、**実装は K6**。`member add`(直接追記 / 提案化の両方)の署名前に、対象の鍵 FP がチェーン履歴の別の在籍区間に現れるとき警告する(拒否ではない)
- **持ち越し (iii)**(`required_approvals` 引き下げ後の pending): L-a を採用、**実装は K6**。`approval list / show` が現方針で再集計し「次の approve で完成・approve できるのは未投票の owner」を案内、既投票 owner の approve は通信前に `duplicate-approval` を予告する。合意規則は不変
- **持ち越し (i)**(同一鍵再登録による票の復活の正本への 1 文): J-b(設計録のまま)。K7 の `four-eyes.mdx` に「侵害した鍵は再登録しない」を運用規律として書く。正本への追記は所有者提案(最終報告)
- **K6 の CLI が前提にしてよいサーバーの振る舞い**: (1) 4 op は汎用 `POST /projects/:id/chain/entries` で受理され、応答は他の op と同じ `{ projectId, headSeq, headHashHex }`(適用の有無は応答に載らない — クライアントは再同期した検証済みチェーンの `pendingProposals` の変化で知る)。(2) 完成した approve の受理と同一タスクで、内側 op の副作用(要ローテーション検出・申告行削除・招待の completed 化・投影)が走る — 承認者の CLI は承認後に再同期し、`rotationMandates` に「適用 seq の approve エントリ」を義務エントリとして足して sweep / バックフィルを走らせればよい(K4-N)。(3) 成長ガード下(9 GB 超)では add_member / grant_server の提案・承認が `DataLimitExceeded(project-storage-bytes)` になる。(4) 旧サーバー(K2〜K4)は 4 op を `ApprovalNotAccepted` で拒否する — 文言は据え置き
- **`ApprovalNotAccepted` のワイヤからの削除**: 所有者裁定待ち(K5-A)。採るなら api-schema / CLI `failure.ts` / `membership-api.ts` の 3 箇所の独立 PR
- **K3-J のベクター名の改名**(`authz-rotate-unknown-precedes-out-of-scope` 等): K5 はベクターを再生成しないので据え置き
- **crypto 側の不変条件「期限切れの提案は pending 集合に残る」の固定**(独立レビュー第 2 巡 nit 12): core の `indexProposals` の完成導出(K5-F)とサーバーの適用行・受理副作用は、`chain-verify.ts` が pending から要素を消すのが定足数到達(`completeProposal`)と `withdraw` の 2 箇所だけであることに依存する(期限切れは `proposal-expired` の拒否理由であって削除ではない)。破れると偽の適用行 + 実際の副作用(削除・検出・投影削除)が走る。次に `packages/crypto` を触る段(ベクター再生成の機会)で、`authz-approve-expired` 系の negative に `expected_pending` を足すか、当該 2 箇所に「ここ以外で pending から削除しないこと(core の `indexProposals` が依存)」の注記を入れる。core 側は `packages/core/test/audit.test.ts` の冒頭にこの依存を明記済み
