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
| **K3** | server(ES): 受信者集合 = scope(`expectedWrapRecipientCount` / `checkWrapRecipient`)、環境対象 op の scope 認可(`InsufficientScope`)、値・メタ・マニフェストの宣言ヘッド時点 scope 検査、招待行の scope、ミラー payload、要ローテーション検出の環境別窓・縮小変種。テストは `@cloudflare/vitest-plugin` | CLI はまだ all しか発行しないので配布は従来どおり。制限は眠ったまま |
| **K4** | CLI(ES): `invite create --env`、`member add`(招待行の scope)、`member change-role --env` / `member scope`(拡大 backfill・縮小 sweep)、**`member list`**、`wrapRecipientsFor` / backfill / sweep の scope 対応、`env create` の前提検査、pull / push / rotate の scope 外エラー、scope 外ラップの警告、`project verify` の scope 列 + Web `ProjectScreen` の scope 列。テストは Vitest | ES 完了。四眼は方針なし = オフのまま |
| **K5** | server(PF1): **K2-10 の受理ガード(`ApprovalNotAccepted`)の解除と同じ PR で**: 受理ポリシー(pending 上限。8-bis K2-5 e-3: 作成時点で失効済みの提案〔`expires_at_ms` < 受理時サーバー時計〕の拒否も受理ポリシー候補)、適用完了時の副作用(要ローテーション検出・旧鍵ラップ掃除・申告行削除・成長ガード)、ミラー 4 種 + 適用行、`audit verify` の全単射規則 | K2 のサーバーは 4 op を 422 で拒否する(受理ガード = 執行) |
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

第 2 巡(上位互換の探索): 「ベクターは検証状態を持たず negative / valid_appends の受理結果だけを固定する」は、導出状態の間違い(票の数え方・pending の残り方)を検出できないため上位互換でない。打ち止め。**原則**: ベクターの検証状態は正本の「導出する」と書かれた状態を、payload と同じ語彙(snake_case・数値は 10 進文字列)で 1:1 に写す — 既存の `expected_head_states`(members / server_grants / environments)がこの原則の先例。`proposer_role_at_proposal` は情報値であり合意規則の入力ではない(K2-6 参照)。

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

### 正本への申し送り(所有者へ — 本 PR に含めない)

1. CRYPTO_SPEC §11: `head-attestation.json` は不変でなくチェーン依存(K2-9)。
2. CRYPTO_SPEC §6.2 の `approve` の個別規則の字面(「owner として提案した提案者」)を原則 2 の S の定義に揃える(K2-6 — 実装は原則側)。**判断材料(8-bis K2-6 の追加巡)**: 字面の読みには「数えられる票はすべて owner として作られた署名である」という不変条件があり、原則の読み(適用時点の role で数える — 承認者の失効票と対称)にはそれがない。どちらも他方を支配しない(8-bis K2-6 行)ので所有者裁定。裁定後に「提案後に昇格した提案者」の派生チェーンをベクターへ追加する(現ベクターはこの形を固定していない)。
3. AUDIT_SPEC §3.4 の四眼 4 op のミラー行(`proposalChainSeq` / `completed` / 適用行)は検証状態を要するため K2 のミラーは「エントリ単独から写せる値」(提案 hash)に留めた。K5 の受理面で正本どおりに揃える(§4 の K5 行)。
4. (任意・整合の確認)CRYPTO_SPEC §6.2 で `set_approval_policy.ops` の重複は `grant_server` の scope_environments と同じ集合意味論(構造段で拒否しない)だが、scope の `scope_environments` は重複を `invalid-payload` にする。意図的な非対称(ops は閉集合の 6 要素で非決定性の芽が小さい)なら現状維持、揃えるなら正本の改訂(8-bis K2-7 g-3)。
5. **CRYPTO_SPEC §6.2 `approve` の票数(8-ter K2-6)**: S の要素が user_id にしか束縛されないため、削除 → 新鍵で再追加された投票者の票が復活する(提案者は `proposal-void` で鍵 FP に束縛される非対称)。推奨: S の要素を在籍区間(user_id + 鍵 FP)に束縛し在籍終了で失効させる。合意規則の変更 = ベクター(派生チェーン `readded-approver-vote`)の追加を伴う。required = 2 では悪用不能、required ≥ 3 で侵害鍵の票が鍵更新後も残る。

## 8-bis. K2 裁定の追加巡の記録(2026-09-14 所有者の問い「各裁定で銀の弾丸・上位互換の探索を何巡回したか」への回答)

**訂正**: §8 の K2-1〜K2-9 は、3-bis で自ら定めた打ち止め条件(**上位互換も銀の弾丸も出ない巡が連続 2 巡**)を満たしていなかった。K2-1 / K2-4 は「案を列挙した巡 → 新案なしの巡」の 1 往復(空巡 1)、K2-2 / K2-3 は代替案を同じ巡で棄却しただけ(空巡 0)、K2-5〜K2-9 は単巡で探索していない(空巡 0)。以下、各裁定について追加巡を回し(新案が出た巡の後はさらに 1 巡を足し、空巡が連続 2 に達するまで)、出た案と評価を記す。**結論: 裁定を変える上位互換・銀の弾丸は 9 件のいずれにも出なかった**。副産物として、記述の不整合 1 件(K2-1 × K2-6: README 規約 27 と生成器コメントの「提案者の票は `proposer_role_at_proposal = owner` から導出する」は K2-6 の実装〔S ∩ 現 owner〕と食い違う — 本 PR で文言を訂正)と、所有者・K5 への申し送り 3 件(K2-5 e-3 / K2-6 f-3 / K2-7 g-3)を得た。

| 裁定 | 従前の空巡 | 追加巡で出た案(評価) | 追加後の空巡 | 結論 |
|---|---|---|---|---|
| K2-1 検証状態のベクター表現 | 1 | **a-4** pending を hash キーの map でなく配列にする — hash は正本の識別子であり、配列は重複を許す。棄却 / **a-5** `proposer_user_id` + `approvals` を S(署名者集合)1 本に畳む — withdraw(提案者 or owner)と `proposal-void`(提案者の鍵 FP)が提案者の区別を要する。棄却 / **a-6** `proposer_role_at_proposal` を状態から外す(合意規則の入力でない — pullfrog 第 3 スレッドの誤読の原因) — 正本の「導出する」列(提案者・内側 op・期限・投票者集合)に無い値を固定している点では K2-1 の原則により忠実だが、申し送り ② で所有者が字面の読み(「owner として提案した」)を採れば規則の入力になる。② の裁定前に外すのは先取り。**保留(② の裁定後に整理)** / **a-7** 現ヘッドの票数を `expected_votes` として出力側に固定する — a-2 と同型(再集計規則との二重管理)。`stale-*-vote` の派生チェーンが「有効だが適用されない approve」で同じ性質を固定済み。棄却 / **a-8** メンバー状態を `{ role, scope_kind, scope_environments }` に平坦化(payload と字面 1:1) — 検証力は同じで構造の違いだけ。棄却 | 3(第 2〜4 巡) | **a-1 を維持**。副産物: README 規約 27 と生成器コメントの提案者の票の導出の記述を K2-6 に揃える(本 PR) |
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
| K2-6 | 原則 2(S ∩ 適用時点の owners)+ **帰属原則**「提案経由の適用は、適用 seq における提案者の直接追記と同じ検査(現在性・鍵 FP・role・scope)を受ける」 | `duplicate-approval` = actor ∈ S ✓ / 票数 ✓(字面「owner として提案した」だけが非導出 = ②)/ `proposal-void`(現メンバー・同じ鍵 FP・role)← 帰属原則 ✓ / 適用時の scope-not-contained ← 帰属原則 ✓ | **発見(申し送り ⑤)**: 帰属原則は提案者を鍵 FP(= 在籍区間)に束縛するが、原則 2 の S は投票者を **user_id にしか束縛しない**。投票後に削除され、新しい鍵で再追加された owner(再追加は owner 確立 = 四眼の対象)の票は、`stale-approver-vote` の「削除された投票者の票は失効」を再追加が**復活**させる。シナリオ: required = 3・owner A / B / C。B の鍵が侵害され、侵害鍵が A の提案 P を approve(A + B = 2)。侵害検知で B を remove → 新鍵で re-add(A・C の定足数)。C が P を approve → S = {A, B, C} ∩ 現 owner = 3 で完成 — 侵害鍵の票が鍵更新(remove / re-add)の後も生き残り、本人 B の新鍵での approve を代替する。正本の字面(「distinct はチェーン上の身元」= user_id、「この approve の時点でも owner である過去の投票者」)は B を数えるので**実装は正本どおり**であり、欠陥は正本側の非対称。推奨修正: S の要素を在籍区間(user_id + その時点の鍵 FP)に束縛し、在籍終了で失効させる(再追加後は新鍵で改めて approve できる — 提案者の `proposal-void` と対称)。現ベクターは降格(`stale-approver-vote`)のみ固定し、再追加は固定していない。required = 2 では S 外の owner の approve が常に要るため悪用できず、影響は required ≥ 3 |
| K2-7 | 内側 op はワイヤでは構造化して運び、正規化は §6.1 と同型の入れ子 LP、構造検査は内側 op の形状表を **1 段だけ**再利用する(再帰を持たない) | 入れ子 propose の構造段拒否 ✓ / genesis 内側 = `ROLE_RULES.genesis` → `approval-not-required` ✓ / ops の集合意味論 ← grant_server の先例 ✓ | 機械検査: フィールド上限(1024 B)は自由文字列(id・reason・claim 値)にのみ掛かり、内側 payload の hex には掛からない → **直接追記できる op は必ず提案できる**(256 環境の grant_server を含む)。非対称なし ✓ |
| K2-8 | §6.2 の各検査列で**隣接する対は、ベクターで固定されているか、状態不変条件で共起不能かのどちらか**でなければならない | 機械照合(`*-precedes-*` 負例 47 件 × §6.2 の検査列)。共起不能の 3 対は §8 のとおり | **発見**: 未固定の隣接対 = add_member `approval-required → duplicate-member` / `→ duplicate-member-key`、grant_server `approval-required → duplicate-server-key`(いずれも共起可能 — owner が既存 user / 既存鍵を owner として直接追記、既存メンバー鍵の直接 grant)、および K2 以前からの add_member `role → duplicate-member`(`role → duplicate-member-key` と `duplicate-member → duplicate-member-key` の推移からは決まらない)。**負例 4 件を追加して固定**(`authz-approval-required-precedes-duplicate-member` / `-duplicate-member-key` / `-duplicate-server-key`、`authz-add-member-role-precedes-duplicate-member` — 正規チェーン・既存負例は不変)。構築できず未固定のまま記録する対: grant_server `approval-required → grant-scope-narrowed`(head 24 に有効な grant が無い — 方針有効 + 有効 grant の派生チェーンが要る)、revoke_server `approval-required → unknown-server-key`(正規方針の ops に revoke_server が無い)。実装はいずれも role の直後で approval-required を判定する(`evaluateDirect`)ので順序は正本どおり |
| K2-9 | ベクターの不変性は仕様の分類ではなく**バイト列の依存関係**で決まる(正規チェーンの entry_hash を含むファイルはチェーン依存) | 機械照合: 旧チェーン 19 hash・新チェーン 64 hash(共通 = genesis 1 件)で全 JSON を走査 — 不変 11 ファイルは旧・新 hash を 1 つも含まず、チェーン依存 4 ファイル(value / metadata / env-manifest / head-attestation)と invite-link は新 hash(+ genesis)のみ ✓ | 分類どおり。新発見なし |

**処置**: (1) 申し送り ⑤ を新設(所有者裁定 — 正本の変更)。(2) K2-8 の負例 4 件を生成器に追加して再生成(生成器は oxfmt 後にバイト同一であることを再実行で確認済み。正規チェーン・既存の負例・派生チェーンは不変)。(3) K2-1 の `proposer_role_at_proposal` は ② に連動(本 PR では据え置き)。

### K2 の実装メモ(K3〜K7 への申し送り)

- CLI(K2 時点): `invite create` は scope = all のみ発行し、`member add` は招待行の scope で `add_member` を署名する。`change-role` は対象の**現 scope を据え置き**(owner への昇格時のみ all)、`--env` の指定は K4。
- サーバー: 四眼の 4 op は **K5 まで受理しない**(`ApprovalNotAccepted` 422 — worker + DO の多層ガード。K2-10)。scope の執行(R(E)・`InsufficientScope`・422 の scope 軸)は K3、受理ガードの解除 + pending 上限 `ProposalLimit`・四眼のミラー行 / 適用行・要ローテーション検出・ラップ掃除・提案 API は K5(同じ PR で)。
- Web: `chain-view` の畳み込みは 4 op を無視する(scope の表示と方針・pending の表示は K6)。

