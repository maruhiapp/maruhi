# ES 仕様改訂ドラフト — 環境スコープの role + PF1 四眼(2026-09-14 起草・所有者承認待ち)

**位置づけ**: ES / PF1 フェーズ 1(設計セッション)の成果物。設計の全体像・裁定の反復記録・実装分割・承認依頼項目は docs/notes/es-design.md。本ファイルは正本 3 文書(CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC)へ反映する**改訂本文の起草**であり、**正本はまだ触っていない**(承認後の K1 で反映し、以後は正本が正。差異が生じた場合は正本が勝つ)。

各ドラフトは「差し替え」または「追記」で示す。既存本文のうち変えない部分は引用しない。版番号は CRYPTO_SPEC 0.10 → **0.11-draft**、AUTH_SPEC 0.22 → **0.23-draft**、AUDIT_SPEC 1.7 → **1.8-draft**。各 Status 行への追記文(KL3 / IV と同じ書式)は末尾 D に置く。

用語(本ドラフト共通): **scope(環境スコープ)** = メンバーが DEK ラップを受け取る環境の集合。`all`(全環境 — 将来作成される環境を含む)または `listed`(environment_id の有限集合)。**受信者集合 R(E)** = 環境 E の DEK ラップの宛先の完全集合 = { 現メンバー m | E ∈ scope(m) } ∪ { 有効 grant_server g | E ∈ scope_environments(g) }。**提案 / 承認** = 四眼(PF1)の `propose` / `approve` エントリ。**方針** = `set_approval_policy` が確立する四眼の設定(対象 op 集合と必要承認数)。

---

## A. CRYPTO_SPEC の改訂案

### A-1. §3 の差し替え(1 項目)

> - ~~v1 では全メンバーが全環境の DEK を受け取る(環境別の閲覧制限は Phase 2 の設計課題。**未決事項 #11**)~~ **2026-09-14 改訂(ES — 未決 #11 の解消)**: 各メンバーはチェーン上の **scope**(`add_member` / `change_role` の payload — §6.2)に含まれる環境の DEK だけを受け取る。scope は `all`(全環境 — 以後に作成される環境を含む)または `listed`(環境 id の有限集合)。環境別の閲覧制限は**サーバーの方針ではなく鍵配布**で実現する: scope 外の環境の DEK ラップは生成も受理もされない(§6.3 / AUTH_SPEC §12-6)ため、サーバーが侵害されても scope 外の DEK は存在せず開かない。設計録は docs/notes/es-design.md

### A-2. §6.2 の差し替え(role 表の直後・op 表・合意規則)

> チェーン上の role は **owner / admin / member / reader** の 4 段とする:
>
> | role | できること |
> |---|---|
> | `reader` | scope 内の環境の値の取得・復号のみ(DEK ラップは scope 内の環境について受け取る)。チェーン追記不可 |
> | `member` | + scope 内の環境の値の更新(新バージョンの push)、`rotate_epoch`、`checkpoint`。scope = all なら `create_environment` |
> | `admin` | + 自分の scope に包含される scope を持つ reader / member を対象とする `add_member` / `remove_member` / `change_role` |
> | `owner` | + admin の管理、`grant_server` / `revoke_server`、`set_approval_policy`、プロジェクト削除。**scope は常に all**。最後の owner は削除・降格不可 |
>
> - **環境スコープ(2026-09-14 ES 改訂 — 旧未決事項 #11)**: `genesis` / `add_member` / `change_role` はメンバーの **scope** を確立する。scope の正規化は payload の 2 フィールド `scope_kind`(`"all"` | `"listed"`)と `scope_environments_lp_hex`(environment_id リストを §2.1 で LP 化した hex 小文字文字列 — `grant_server` の `scope_environments` と同じ入れ子 LP。リストの順序は署名対象バイト列の一部。生成時はコードポイント昇順・重複なしで並べることを推奨〔SHOULD〕し、検証は集合として扱う)。`genesis` は payload に scope を持たず、作成者の scope は構造的に `all` である。合意規則:
>   - **構造(payload 構造検査の段 — 認可判定に先行)**: `scope_kind = "all"` のとき `scope_environments` は空リストでなければならない(非空は `invalid-payload`)。リストは 256 要素以下(§6.1 の `grant_server` と同じ上限)。**重複 environment_id を含むリストは無効**(`invalid-payload` — `checkpoint` と同じ「非決定性の芽を構造段で摘む」線)。`scope_kind = "listed"` の**空リストは有効**(= どの環境の DEK も受け取らないメンバー。平文メタは §6.3 のとおり見える)
>   - **環境の存在(認可段)**: `listed` の各 environment_id は、そのエントリ時点でチェーン上に `create_environment` が先行していなければならない(拒否理由 `unknown-environment` — `rotate_epoch` / `checkpoint` と同じ理由コード。typo を fail-closed にし、未存在環境への事前スコープは持たない)。削除済み環境はチェーンが削除を観測しないため列挙してよい(害はない)
>   - **owner は all(認可段)**: `role = owner` を確立する `add_member` / `change_role` は `scope_kind = "all"` でなければ無効(拒否理由 `scope-role-mismatch`)。owner は「最後の owner」保護・`grant_server`(全環境の開示)・全環境の rotate 義務の履行者であり、scope を持てない。admin / member / reader は `listed` を持てる(dev 専任の admin が書ける — 設計録 裁定 C)
>   - **包含規則(認可段)**: `add_member`(対象の scope)・`change_role`(対象の**旧 scope ∪ 新 scope** — 2026-09-14 最終確認で訂正: 新 scope だけを見ると、縮小分〔旧 \ 新〕が actor の scope 外でも通り、actor が履行できない rotate 義務が生じる)・`remove_member`(対象の**現** scope)は、**actor の scope が対象の scope を包含**していなければ無効(拒否理由 `scope-not-contained`。`all` は全てを包含し、`listed` は `listed` の部分集合のみを包含する — `listed` は `all` を包含しない)。根拠は暗号的必然: DEK のラップは DEK 保持者が行う(§7)ため、対象を環境 E へ入れられるのは E の DEK を持つ者だけであり、対象を消せる(= §7 の rotate 義務を履行できる — 再暗号化に旧 DEK が要る)のも同じ者である。owner は all のため常に通る
>   - **環境対象 op**: `rotate_epoch` の対象 environment_id、`checkpoint` の全タプルの environment_id は actor の scope に含まれていなければならない(拒否理由 `environment-out-of-scope`)。`create_environment` の新 environment_id も同じ述語で判定する — `listed` の scope に未存在の環境は含まれえないため、**環境の作成は scope = all の actor のみ**ができる(作成者が受け取れない環境を作る形・署名対象にない暗黙の scope 変化を作らない)
>   - **検査順序(理由コードごとテストベクターで固定。scope 系の検査は既存の検査列の後ろに置き、既存負例の期待理由を温存する)**: `add_member` = role 規則 → `duplicate-member` → `duplicate-member-key` → `unknown-environment`(scope の各 id)→ `scope-role-mismatch` → `scope-not-contained`。`change_role` = role 規則 → `approval-required`(直接追記のみ — 下記)→ `unknown-target` → `last-owner-protected` → `unknown-environment` → `scope-role-mismatch` → `scope-not-contained` → `approval-quorum-unreachable`(四眼有効時 — 下記)。`remove_member` = role 規則 → `approval-required` → `unknown-target` → `last-owner-protected` → `scope-not-contained` → `approval-quorum-unreachable`。`add_member` / `grant_server` / `revoke_server` の `approval-required` も同じ位置(role 規則の直後)。`rotate_epoch` = role 規則 → `unknown-environment` → `environment-out-of-scope` → エポック順序。`create_environment` = role 規則 → `duplicate-environment` → `environment-out-of-scope`。`checkpoint` = role 規則 → 非空監査ヘッドの admin role → `unknown-environment` → `environment-out-of-scope` → `checkpoint-epoch-mismatch` → `checkpoint-regression`(段ごとに全タプルを走査 — stage-wise)
>   - **検証状態**は現メンバーごとの scope を導出する(§6.3 のラップ先一致検査・宣言ヘッド時点の scope 検査・AUTH_SPEC §12-3 の認可の入力)。履歴索引はメンバーの在籍区間ごとに (role, scope) の変化点(seq)を保持する
>   - **受信者集合 R(E)**(§6.3 / §7 / AUTH_SPEC §12-4 / §12-6 の 1 定義): 環境 E の DEK ラップの宛先の完全集合 = { 現メンバー m | E ∈ scope(m) } ∪ { 有効 `grant_server` g | E ∈ scope_environments(g) }。`grant_server` のサーバー鍵は自前の `scope_environments` を持つため ES の対象外であり、判定は受信者クラスを跨いで同一に適用する
>   - **縮小は remove 相当(§7)**: `change_role` で旧 scope \ 新 scope が非空のとき、縮小分の各環境について `remove_member` と同じ `rotate_epoch` 義務を負う(合意規則ではなく §7 の義務 — `grant_server` の再 grant がスコープ縮小を合意規則で拒否するのと対照的に、メンバーの縮小は受理して義務を課す。招待のやり直し・在籍区間の分断を避けるため — 設計録 裁定 F)。拡大分は actor が全エポックの DEK をバックフィルする(AUTH_SPEC §12-6)
>   - 本規則の導入(2026-09-14)は `add_member` / `change_role` の payload 形式変更であり、**導入前に受理された既存チェーンは新規則で無効になる**(互換条項を持たない — 2026-09-14 所有者裁定「利用者がいないうちは古い実装をすべて削除してよい」。既存プロジェクトは再作成する — docs/SELF_HOSTING.md "Updates")。`chain-entries.json` は全再生成する(§11)
>
> | op | payload | 権限 |
> |---|---|---|
> | `genesis` | プロジェクト作成者の公開鍵一式 | 作成者自身(owner・scope = all となる) |
> | `add_member` | 対象 user_id、対象の enc/sig 公開鍵、role、**scope_kind、scope_environments_lp_hex** | admin 以上(admin / owner の付与は owner のみ)。対象 scope ⊆ actor scope |
> | `remove_member` | 対象 user_id | admin 以上(admin / owner の削除は owner のみ)。対象の現 scope ⊆ actor scope。**対象の現 scope の全環境**の `rotate_epoch` を伴う(§7) |
> | `change_role` | 対象 user_id、新 role、**scope_kind、scope_environments_lp_hex**(新 (role, scope) の全置換) | admin 以上(admin / owner が関わる変更は owner のみ)。旧 scope ∪ 新 scope ⊆ actor scope。member 未満への降格は対象 scope の全環境の、scope の縮小は縮小分の環境の `rotate_epoch` を伴う(§7) |
> | `create_environment` | 対象 environment_id、エポック 1 の dek_commitment_hex(§5.2) | member 以上・scope = all |
> | `rotate_epoch` | 対象 environment_id、新エポック番号、理由、新エポックの dek_commitment_hex(§5.2) | member 以上・対象環境 ∈ scope |
> | `grant_server` | サーバー鍵の公開鍵・フィンガープリント、許可スコープ(対象環境の部分集合を含む)、リースポリシー | owner のみ(明示操作) |
> | `revoke_server` | 失効対象 | owner のみ |
> | `checkpoint` | 環境ごとの (environment_id, epoch, manifest_version, manifest_sig_hash, values_digest) + 監査ヘッド累積ハッシュ(省略 = 空文字列) | member 以上(非空の監査ヘッドを公証する actor は admin 以上)・全タプルの環境 ∈ scope |
> | **`set_approval_policy`** | **対象 op 集合(ops_lp_hex)、必要承認数(required_approvals)** | **owner のみ。現方針が有効なら四眼の対象(下記)** |
> | **`propose`** | **内側 op 名、内側 payload(inner_payload_lp_hex — 当該 op の正規化 payload_bytes)、期限(expires_at_ms)** | **内側 op を実行できる role(内側 op の規則で判定)** |
> | **`approve`** | **提案エントリのハッシュ(proposal_hash_hex)** | **owner のみ(提案者と distinct。owner の提案は 1 票に数える)** |
> | **`withdraw`** | **提案エントリのハッシュ(proposal_hash_hex)** | **提案者または owner** |
>
> - payload の正規化フィールド順(チェーン正規化ベクターで固定): `add_member` = `[target_user_id, enc_pub_hex, sig_pub_hex, role, scope_kind, scope_environments_lp_hex]`、`change_role` = `[target_user_id, new_role, scope_kind, scope_environments_lp_hex]`(いずれも既存フィールドの**末尾**に追加)、`set_approval_policy` = `[ops_lp_hex, required_approvals]`(`ops_lp_hex` = op 名リストの入れ子 LP の hex。順序は署名対象。生成はコードポイント昇順 SHOULD・検証は集合)、`propose` = `[inner_op, inner_payload_lp_hex, expires_at_ms]`(`inner_payload_lp_hex` = 内側 op の `payload_bytes` — §6.1 の入れ子 LP — の hex 小文字)、`approve` = `[proposal_hash_hex]`、`withdraw` = `[proposal_hash_hex]`(いずれも hex 小文字 64 = 提案エントリの entry_hash)
> - **四眼(2026-09-14 PF1 — 複数署名承認。設計録 docs/notes/es-design.md §3)**: 危険操作を「提案 → 承認」の 2 段エントリで受理し、**distinct な owner の署名が必要承認数に達したときにだけ**内側 op が適用される。閾値署名・集約署名は導入しない(既存の Ed25519 署名を 2 エントリで数えるだけ)。合意規則:
>   - **方針**: `set_approval_policy` は方針 { ops, required_approvals } を確立する。方針が一度も確立されていない(または `required_approvals = 0`)状態は**オフ**(既定 — 単独 owner のプロジェクトは何も変わらない)。`required_approvals` は 0(オフ)または 2 以上。**有効化・変更は、その時点の現 owner 数 ≥ required_approvals でなければ無効**(拒否理由 `approval-quorum-unreachable`)。`ops` は次の集合の部分集合でなければならない(構造検査 — `invalid-payload`): `grant_server` / `revoke_server` / `remove_member` / `change_role` / `add_member` / `set_approval_policy`。`create_environment` / `rotate_epoch` / `checkpoint`(データ・安全側の操作を止めない — rotate はインシデント対応であり遅らせてはならない)、`genesis` / `propose` / `approve` / `withdraw` は対象にできない。**方針が有効な間、`set_approval_policy` 自身と、owner role を確立する `add_member` / `change_role` は `ops` の列挙に依らず常に対象**(オフにするにも四眼が要る — でなければ四眼が無意味。owner を増やす op を四眼の外に残すと、owner 1 名が自分の第 2 の鍵対を owner として直接追記し、自作の 2 人目 owner で定足数を満たせる — 2026-09-14 pullfrog レビュー対応。`distinct` はチェーン上の身元であって人格ではないため、身元の追加経路そのものを四眼に入れる)
>   - **到達可能性の不変条件**: 方針が有効な間、現 owner 数を `required_approvals` 未満にする op(owner の `remove_member`・owner から他 role への `change_role`)は無効(`approval-quorum-unreachable` — `last-owner-protected` の一般化。検査順序は各 op の末尾)
>   - **対象 op の直接追記の拒否**: 方針が有効で `ops` に含まれる op(および `set_approval_policy`・owner role を確立する `add_member` / `change_role` — 常時対象)を**直接**追記したエントリは無効(拒否理由 `approval-required`。検査は role 規則の**直後**・その他の認可検査の前 — 提案経由でしか通らないことを構造段の次で確定する)。**この検査は `propose` / `approve` が内側 op を評価する文脈では適用しない**(適用すれば対象 op の提案が自己矛盾で必ず落ち、四眼をオフにする `set_approval_policy` の提案も通らなくなる — 2026-09-14 pullfrog レビュー対応)
>   - **`propose`**: actor は内側 op を通常の規則で実行できる role を持ち、内側 op はその時点の状態で合意規則(構造・認可・包含・最後の owner・到達可能性 … — ただし `approval-required` を除く)を満たさなければならない(満たさない提案は無効 — pending に積まない。理由コードは内側 op の理由をそのまま用いる)。`inner_op` は方針の対象(`ops` + 常時対象の op)でなければならない(`approval-not-required` — 対象外の op を提案しても意味を持たない)。`expires_at_ms` は非負の安全整数。提案は pending として検証状態に載る(識別子 = 提案エントリの entry_hash)。**方針がオフのときの `propose` は無効**(`approval-not-required`)
>   - **`approve`**: actor はその時点の owner であること(`insufficient-role`)。参照先が pending の提案であること(`unknown-proposal` — 適用済み・撤回済み・未存在)。actor が当該提案に未投票であること(提案者が owner なら提案が 1 票 — `duplicate-approval`)。**`approve` エントリの `timestamp_ms` が提案の `expires_at_ms` 以下であること(`proposal-expired`)** — 本仕様で timestamp を合意規則に用いる**唯一の箇所**。`timestamp_ms` は承認者の自己申告(チェーンに単調性も上界もない)であるため、**期限は正直な承認者を文脈を失った承認から守る UX 上の安全装置であり、悪意の承認者に対する保証ではない**: 承認者が過去方向に時刻を詐称すれば期限切れの提案を承認できる(その承認者は owner として四眼の 1 票を正当に持つ主体であり、期限が守る対象ではない。2026-09-14 pullfrog レビュー対応 — 旧「拒否方向のみ = fail-closed」の主張は撤回)。§14.2-10 の保証は期限に依存しない。票数 = **この `approve` エントリの actor 自身**(owner — role 規則で検査済み)に、**この `approve` エントリの時点でも owner である**過去の投票者(過去の `approve` の actor と、owner として提案した提案者)を加えた distinct な数。提案後に降格・削除された過去の投票者の票は数えない(過去の投票者の owner 資格を判定する状態は「今の `approve` エントリの適用前状態」— 2026-09-14 Cursor Bugbot 指摘対応: 投票者の owner 資格を投票時にだけ検査すると、残る owner 1 名が離脱済み投票者の票を使って完成できてしまう。owner 2 名・`required_approvals = 2` では「owner の提案 + 別 owner の approve」または「非 owner の提案 + owner 2 名の approve」で完成する)。票数が `required_approvals` に達したとき、**この `approve` エントリの seq で内側 op を適用する**(inclusive 規約 — `remove_member` の在籍終了・`change_role` の新 role / scope はこの seq で有効。§7 の rotate 義務・要ローテーション検出の起点もこの seq)。適用時は内側 op の合意規則を**適用時点の状態**で再検査し、加えて**提案者がその時点の現メンバーで、提案時と同じ鍵 FP を持ち、内側 op に必要な role を持つ**こと(拒否理由 `proposal-void` — 提案後に提案者が削除・降格・鍵変更された提案は完成できない)。適用時の検査に失敗する `approve` エントリは無効エントリであり、提案は pending のまま残る(`withdraw` で閉じる — 承認署名に「閉じる」効果を持たせない)。適用した内側 op の actor は**提案者**として扱う(在籍・帰属の記録)
>   - **方針変更と pending 提案の関係(2026-09-14 pullfrog レビュー対応)**: pending 提案は提案時の方針をスナップショットせず、**各 `approve` エントリの時点の現方針**で判定する — 必要承認数は現方針の `required_approvals`、内側 op が現方針の**対象**(`ops` + 常時対象の op — `propose` / 直接追記の拒否と同一の述語。常時対象の op は方針が有効な限り対象から外れない)でなくなっていれば(方針オフ、または常時対象でない op の `ops` からの除外)その `approve` は `approval-not-required` で無効となり、提案は pending のまま残る(`withdraw` で閉じる。対象外になった op は直接追記で実行できる — 常時対象の op にはこの経路はない。2026-09-14 Cursor Bugbot 指摘対応)。`required_approvals` の引き下げは pending 提案にも即時に効く(既に足りている票数で次の `approve` が完成させる)
>   - **`withdraw`**: actor は提案者または owner。参照先が pending であること(`unknown-proposal`)。提案を closed にする(状態変化なし)
>   - **検査順序**(理由コードごとベクターで固定): `set_approval_policy` = role 規則(owner)→ `approval-required`(現方針が有効なら直接追記は不可)→ `approval-quorum-unreachable`。`propose` = role 規則(内側 op の規則で判定)→ `approval-not-required` → 内側 op の合意規則(`approval-required` を除く — 内側 op の理由コード)。`approve` = role 規則 → `unknown-proposal` → `duplicate-approval` → `approval-not-required`(方針変更後の対象外 — 上記)→ `proposal-expired` → (定足数到達時)`proposal-void` → 内側 op の合意規則。`withdraw` = role 規則 → `unknown-proposal`
>   - 検証状態は方針(ops・required)と pending 提案の集合(提案 hash → 提案者・内側 op・期限・投票者集合)を導出する。**pending 提案の件数上限は合意規則に置かない**(サーバー受理ポリシー — §6.4 / AUTH_SPEC §12-8)
>   - 4 op の導入は「未知 op = チェーン無効」の下で全実装の同時更新を要するが、既存 op の payload 形式には触れない(ES の add_member / change_role 変更とは独立)。テストベクターは ES と同じ再生成に束ねる(§11)

### A-3. §6.3 の追記(3 箇所)

> - **DEK のラップ先はチェーン導出の受信者集合 R(E)(§6.2 — scope 内の現メンバー + 開示スコープ内の有効な grant_server)と厳密に一致しなければならない(2026-09-14 ES 改訂)**。scope 外のメンバー宛のラップの生成・受理は禁止(ゴーストメンバー対策の環境軸版)。**受信側**: 自分宛のラップで環境 ∉ 自分の scope のものは、開封できても**使用せず警告する**(サーバーが AUTH_SPEC §12-6 の受理規則を執行していない証拠。当該環境への書き込みは scope 外として全検証者が拒否するため実害は「読める」に限られるが、規範として使わない)
> - 値・メタデータステートメント・マニフェストの検証(1〜6)に **scope の認可時点検査**を加える: **3′. スコープ(環境対象の署名)**: 宣言ヘッド時点のチェーン導出状態で、writer / author / issuer の scope が当該 environment_id を含むこと(拒否理由 `writer-environment-out-of-scope-at-head` / `author-environment-out-of-scope-at-head` / `issuer-environment-out-of-scope-at-head` — 3 の role 検査の直後)。環境メタステートメント(rename / delete)・変数メタステートメント・マニフェストはすべて環境対象であり対象になる。環境作成複合の同梱ステートメント / マニフェストは、宣言ヘッドが追記前ヘッド(AUTH_SPEC §12-4)で環境未存在だが、作成者は scope = all(§6.2)であるため空虚に成立する
> - **スコープ外環境の扱い(2026-09-14 ES 改訂 — 設計録 裁定 G)**: メンバーは scope 外の環境について、チェーン(全エントリ — 当該環境の `checkpoint` タプルを含む)・環境の存在・表示名・変数名・スキーマ欄・マニフェスト・tombstone(平文メタ = 未決 #3 の線)を受け取り検証できる(メタのみ pull — AUTH_SPEC §12-7)。暗号文・自分宛 DEK ラップは受け取らず、書き込み・rotate・checkpoint はできない。**環境横断の検証**: (i) `checkpoint` の scope 外環境のタプルは合意規則(§6.2)として検証するが、チェックポイント整合の**基準には用いない** — 基準は自分が値付き pull する環境にしか要らない、(ii) マニフェスト検証は pull した環境のみ(不変)、(iii) ヘッド申告・招待リンクアンカーは環境を持たず不変。リポジトリアンカーの環境ごとのエポックはチェーン導出値であり scope 外環境についても書ける(不変)、(iv) ローカル床は「検証に成功した事実の join」であり scope 外環境の床は確立されないだけ(拒否・警告の対象にならない)
> - 検証状態に四眼の方針と pending 提案を含める(§6.2)。クライアントは自分の scope・方針を検証済みチェーンから導出し、操作の前に scope 外・提案要の操作を型付きエラー / 提案の作成として扱う(サーバーの 403 を待たない)

### A-4. §6.4 の追記(2 項目)

> - **スコープと四眼の受理(2026-09-14)**: §6.2 の合意規則(scope の構造・包含・環境対象 op・四眼の提案 / 承認 / 方針)はチェーン受理時に verifyChain が検証する(受理 4 手順は不変)。**四眼の適用完了**(定足数に達した `approve` エントリ)の受理副作用(要ローテーション検出・申告行の削除・旧鍵ラップ掃除・招待の completed 化)は、内側 op を直接受理した場合と同一に、当該 `approve` エントリの受理タスク内で走らせる(AUDIT_SPEC §3.4 のミラーも同様)。**受理ポリシー**: pending 提案はプロジェクトあたり **32** 件以下(超過は型付きエラー — AUTH_SPEC §12-8。合意規則ではない)。`propose` / `approve` / `withdraw` / `set_approval_policy` は汎用チェーン追記 API(AUTH_SPEC §11)で受理する
> - **DEK ラップ受理の受信者集合**は §6.2 の R(E)(AUTH_SPEC §12-6 — 完全一致・受信者判定とも scope を含む)

### A-5. §6.5 の差し替え(発行文)

> - **発行文と発行署名**: 招待者は発行文(招待 id・リンク公開鍵・検証済みヘッド・role・**scope**・自分の同一性)にチェーン署名鍵(Ed25519)で署名し、**サーバー行とリンクの両方**に載せる:
>
>   ```
>   invite_issue_signed_bytes = LP("maruhi/v1/invite-issue",
>                                  invite_id, project_id, link_pub_hex, head_hash_hex, head_seq, role,
>                                  inviter_user_id, inviter_enc_pub_hex, inviter_sig_pub_hex,
>                                  scope_kind, scope_environments_lp_hex)
>   ```
>
>   - **scope(2026-09-14 ES 改訂)**: 付与予定の scope(§6.2 と同じ符号化)を発行文の**末尾**に加える。role と同じく改竄検出の対象であり、受諾者は「どの環境に入るか」を受諾前に読む。`add_member` は招待行の role / scope で署名する(AUTH_SPEC §15-2 — 招待者が受諾後に別の scope を付けることはできない: 同意の範囲を発行時に固定する)。`invite-link.json` は再生成する(§11)

### A-6. §7 の差し替え(1〜2 項目・追記 1 項目)

> - メンバー削除・サーバー失効時は必ず `rotate_epoch` を伴う。**対象環境の集合(2026-09-14 ES 改訂)**: `remove_member` は**対象の現 scope の環境**(scope = all なら全環境)、`revoke_server` は全環境(不変 — 改訂は ES の対象外・設計録 §6)。環境ごとに新 DEK を生成し、現在値を新 DEK で再暗号化し、新 DEK を受信者集合 R(E)(§6.2)へラップする。「全環境」の定義(検証済み削除ステートメントで削除済みでないもの)と 404 時の中断規律は不変。**scope 外の環境を rotate の対象に含めてはならない**(対象は DEK を持たず、義務は存在しない — 実行者も scope 外なら rotate できない。包含規則 — §6.2 — により、remove の actor は対象の scope を包含するため履行可能)
> - **member 未満への降格(`change_role` で reader 化)は対象の scope の環境の `rotate_epoch` を伴う**(動機はエポックアンカーの健全性 — 不変。範囲だけが scope に縮む)
> - **scope の縮小(2026-09-14 ES 改訂)**: `change_role` で旧 scope \ 新 scope が非空のとき、縮小分の各環境について `remove_member` と同じ `rotate_epoch` 義務を負う(機密性 — 対象が保持する縮小分の DEK の失効)。義務の起点は当該 `change_role` の seq。要ローテーション検出は縮小分の環境に限って走る(AUDIT_SPEC §4.1)。**scope の拡大**は actor(包含規則により DEK 保持者)が拡大分の環境について全エポックの DEK を対象へラップして登録する(AUTH_SPEC §12-6 の追記経路 — add_member 後のバックフィルと同型。複合化しない)
> - **ラップの実行者**: (不変)。メンバー追加時は招待者のクライアントが**対象の scope の**全環境の全エポック DEK を新メンバーの公開鍵へラップする。ローテーション時は実行者のクライアントが新 DEK を R(E) へラップする
> - **四眼の下の義務の起点と履行者(2026-09-14 PF1)**: 提案経由の `remove_member` / 降格 / 縮小 / `revoke_server` の rotate 義務、および `add_member` / scope 拡大のメンバー宛バックフィル義務・`grant_server` のサーバー宛バックフィル義務(開示スコープ内全環境 × 全エポック — AUTH_SPEC §12-6)は、いずれも**適用時点**(定足数に達した `approve` エントリの seq)から始まる。提案時には対象は在籍しており失効する DEK はなく、適用前の対象にラップを登録することもできない(受信者集合 R(E) に未だ含まれない — AUTH_SPEC §12-6 は拒否する)。**履行者は適用を完成させた承認者**(owner — scope = all なので全環境の DEK を持ち、包含規則により履行可能)であり、承認クライアントは適用後に sweep(rotate 義務)とバックフィル(メンバー宛 / サーバー宛の全エポックのラップ登録 — AUTH_SPEC §12-6 の 5 番目の経路)を実行する。「ラップの実行者 = 招待者 / 拡大を署名した actor / grant 実行者」の規定は直接追記の場合のものであり、四眼経由では**内側 op の種類を問わず**承認者に移る(2026-09-14 pullfrog / Cursor Bugbot レビュー対応)。未履行のまま放置された状態は既存と同じ「メンバーはいるがラップがない」(AUTH_SPEC §12-4 の非対称)であり、`project verify` の未収束義務の警告(rotation-sweep の常時警告)にバックフィル未了も含めて表示する

### A-7. §11 の追記

> - 0.11-draft(ES + PF1)で改訂・追加されるベクター(**所有者承認後の実装 PR〔K2 — 実装分割は docs/notes/es-design.md §4〕で、実装より先にコミットする**): `chain-entries.json` の**全再生成**(`add_member` / `change_role` の payload 形式変更 — §6.2。正規チェーンは scope = all / listed の両方のメンバーと、`set_approval_policy` → `propose` → `approve` の完成列を含む。`expected_head_states` に scope・方針・pending 提案を追加。負例 = `scope-role-mismatch`〔owner に listed〕・`scope-not-contained`〔add / change_role / remove の各形〕・`unknown-environment`〔scope の typo〕・`environment-out-of-scope`〔listed actor の create / scope 外 rotate / scope 外タプルの checkpoint〕・all に非空リスト・重複 id・`approval-required`〔方針下の直接追記〕・`approval-not-required`〔方針オフの propose / 対象外 op の propose / 方針変更後に対象外となった提案への approve〕・`approval-quorum-unreachable`〔owner 1 名での有効化 / owner を required 未満にする remove〕・`unknown-proposal`・`duplicate-approval`〔提案者 owner の自己承認〕・`proposal-expired`・`proposal-void`〔提案者の削除後の完成〕・内側 op の適用時失敗・フィールド順の入替・scope LP の平坦連結 — と各検査順序の固定形)、`invite-link.json` の**再生成**(発行文に scope — §6.5。負例に scope の差し替えを追加)、`value-signature.json` / `metadata-signature.json` / `env-manifest.json` の**再生成**(正規チェーンを読み込むため。正例の意味は不変。負例に `*-environment-out-of-scope-at-head` を追加)。**他のベクターは不変**(README 規約 27 として明記)

### A-8. §13 の差し替え(#11)

> 11. ~~環境スコープの role~~ **解消(2026-09-14 起草 — 本改訂 PR のマージをもって確定)**: `add_member` / `change_role` の payload に scope(`all` / `listed`)を追加し、DEK ラップの受信者集合を scope で限定(§3 / §6.2 / §6.3 / §7、AUTH_SPEC §9-2 / §12、AUDIT_SPEC §4.1)。設計録は docs/notes/es-design.md

### A-9. §14.2 の追記(2 項目)

> 9. **環境スコープの鍵配布保証(2026-09-14 — ES)**: 検証済みチェーン上でメンバー m の scope に含まれない環境 E について、m 宛の E の DEK ラップは仕様適合クライアントによって生成されず、仕様適合サーバーによって受理されない(§6.3 / AUTH_SPEC §12-6)。サーバーが侵害されても E の DEK を m へ渡す材料が存在しない。**保証しないもの**: scope に入っていた期間に取得した DEK・平文の取り消し(§1 原則 5 — 縮小・削除時の rotate 義務と要ローテーション検出が補う)、および平文メタ(存在・名前・スキーマ欄)の秘匿(未決 #3)
> 10. **四眼の適用保証(2026-09-14 — PF1)**: 方針が有効なプロジェクトで対象 op が適用されるのは、distinct な owner の署名(提案 + 承認)が必要承認数に達したエントリ列のみ(§6.2)。owner 1 名の鍵の漏洩・暴走では対象 op は適用されない。**保証しないもの**: 必要承認数以上の owner の共謀、方針オフ状態のプロジェクト(既定)、対象外の op。owner 身元の追加(`add_member` / `change_role` で owner を確立する op)と方針の変更は `ops` の列挙に依らず常に四眼の対象であり(§6.2)、単独 owner が身元を増やして定足数を満たす経路は閉じている — ただし方針を有効化する前から存在する owner 身元の同一人物性は検証しない(有効化時点で既に 2 身元を持つ人物は四眼の外)。**可用性(2026-09-14 pullfrog レビュー対応)**: 方針が有効な間、チェーン上の現 owner 数は到達可能性の不変条件(§6.2)により `required_approvals` 未満にはならないが、**署名できる owner**(鍵を保持し協力する owner)が `required_approvals` 未満になった場合(owner の鍵の恒久的な喪失・離職 — チェーン上は owner のまま)、残る owner は owner の追加・欠けた owner の削除 / 降格・方針の変更のいずれも単独では完成できず、**対象 op と方針の変更は復帰不能**になる(データ面 — push / rotate / create_environment — は動き続ける。break-glass の時間錠は原則 6 と timestamp の扱いに抵触するため置かない)。緩和は運用前提: 有効化は現 owner 数 ≥ `required_approvals` **+ 1**(予備 owner)を推奨し、CLI は有効化時にこの条件と各 owner のリカバリー登録(§8)を案内する(合意規則の有効化条件は ≥ のまま — 承認項目 17 で所有者裁定)

---

## B. AUTH_SPEC の改訂案

### B-1. §6 の差し替え(1 文)

> - スコープ: プロジェクト単位 × 権限(read / write / admin)。実効権限は min(トークンスコープ, 所有者のチェーン role)(§9-2)。**環境ごとの実効アクセスはチェーン上の scope(CRYPTO_SPEC §6.2 — 2026-09-14 ES)が決める**。将来: トークン単位の環境スコープ(チェーン scope をさらに絞るチェーン外 ACL — 加法的に追加できる形で未着手)、エージェント用の短命リーストークン(Phase 3)
> - 操作が要求する権限水準: … `add_member` / `remove_member` / `change_role` / `grant_server` / `revoke_server` / **`set_approval_policy` / `propose` / `approve` / `withdraw`** = admin(四眼の 4 op は内側 op と同じ水準 — 2026-09-14 PF1) …

### B-2. §9-2 の追記(1 項目)

> - **環境軸(2026-09-14 ES)**: 環境 E に対する実効アクセス = min(トークンスコープ, チェーン role) **かつ E ∈ チェーン導出の scope**(CRYPTO_SPEC §6.2)。scope 外の環境への値付き pull・自分宛 DEK 取得・書き込み・rotate・checkpoint は **403(`InsufficientScope`)** で拒否する(環境の存在はチェーン導出で全メンバーに既知のため 404 に畳まない — role 不足の 403 と同じ層)。メタのみ pull(§12-7)は scope に依らず reader 以上で可

### B-3. §11-1 の追記(1 文)

> - **四眼の 4 op(`set_approval_policy` / `propose` / `approve` / `withdraw` — CRYPTO_SPEC §6.2。2026-09-14 PF1)は汎用追記 API で受理する**(付随データを持たない)。定足数に達した `approve` の受理副作用は内側 op と同一(CRYPTO_SPEC §6.4)。pending 提案の上限は §12-8

### B-4. §12-3 の差し替え(表 + 1 項目)

> | op | トークンスコープ | チェーン role | scope(2026-09-14 ES) |
> |---|---|---|---|
> | 一括 pull(値付き)・自分宛 DEK 取得 | read | reader 以上 | 環境 ∈ scope |
> | 一括 pull(メタデータのみ)・環境一覧 | read | reader 以上 | 不問(全環境) |
> | 変数の作成(declared 作成・activation 複合を含む)・push・改名・スキーマ設定・削除、環境の改名、DEK ラップ登録 | write | member 以上 | 環境 ∈ scope(DEK ラップ登録は受信者側も — §12-6) |
> | 環境の作成 | write | member 以上 | scope = all(CRYPTO_SPEC §6.2) |
> | 環境の削除、DEK ラップの削除(§12-6 の修復経路) | admin | admin 以上 | 環境 ∈ scope |
>
> - 判定順: 認証(401)→ サイズ(413)→ トークンスコープ(404 / 403)→ チェーン導出メンバーシップ(404)→ チェーン role(403)→ **scope(403 `InsufficientScope` — 環境の存在判定と同段: 環境の存在はチェーン導出で既知)**→ 意味論的検査。**認可時点の二重判定**(署名を伴う操作)は scope にも及ぶ: 受理時点と宣言ヘッド時点の両方で環境 ∈ scope(CRYPTO_SPEC §6.3 の 3′)

### B-5. §12-4 の追記(2 箇所)

> - 作成複合: (3) のラップ完全集合の対象は **受信者集合 R(E)(CRYPTO_SPEC §6.2 — scope に E を含む現メンバー + 開示スコープ内の有効 grant_server)**。作成者は scope = all でなければならない(合意規則 `environment-out-of-scope` — チェーンエントリの検証で落ちる)ため、R(E) は all-scope メンバー(+ 開示 grant)になる
> - ローテーション複合: 新エポックのラップ完全集合の対象は R(E)。actor は E ∈ scope(合意規則)。**add_member 後・scope 拡大後のバックフィルは複合化しない**(意図的な非対称 — 不変)

### B-6. §12-6 の差し替え(3 箇所)

> - 受信者の同定は **user_id と enc 公開鍵の両方**とし、チェーン導出の現メンバーと両方が厳密一致し、**かつ対象環境が受信者の scope に含まれる**(2026-09-14 ES。scope 外は 422 `scope-out-of-range` — サーバー宛の開示スコープ外と同じ理由コード)でなければ受理しない
> - (環境, エポック) のラップ集合の**初回登録**は R(E)(scope 内の現メンバー + 開示スコープ内の有効 grant_server)との**完全一致**を要求する。判定は受信者クラスを跨いで同一
> - 独立登録 API が残る経路は「add_member 後の新メンバー宛バックフィル(対象の scope の環境)」「**scope 拡大後の拡大分の環境のバックフィル**(2026-09-14 — 拡大を署名した actor が全エポックを登録する。包含規則により actor は DEK を持つ)」「grant_server 受理直後のサーバー宛バックフィル」「修復経路の再登録」「**四眼経由で適用された add_member / scope 拡大(メンバー宛)・grant_server(サーバー宛)の、適用を完成させた承認者(owner)によるバックフィル**(2026-09-14 PF1 — CRYPTO_SPEC §7。受理規則は他の経路と共通: 署名者 = 呼び出し主体、受信者 = R(E)、上書き禁止)」の 5 つ。**登録者(署名者)も対象環境を scope に含む**こと(DEK を持てない者の登録は構造上ありえないが、受理条件として明記)

### B-7. §12-7 の追記(1 項目)

> - **スコープ(2026-09-14 ES)**: 値付き一括 pull は対象環境 ∈ 呼び出し主体の scope を要求する(403 `InsufficientScope` — §9-2)。**メタデータのみモードは scope に依らず reader 以上で可**(CRYPTO_SPEC §6.3 — 平文メタは全メンバーに見える線。`maruhi schema` が scope 外環境でも動く)。環境一覧は全環境を返す。応答に「呼び出し主体の scope に含まれるか」の advisory フィールドは**載せない**(クライアントは検証済みチェーンから自分の scope を導出する — サーバー申告を検証規則の入力にしない)

### B-8. §12-8 の追記(表 1 行)

> | pending 提案(四眼 — CRYPTO_SPEC §6.2)| プロジェクトあたり 32 | 型付き 422 `ProposalLimit`。withdraw / 適用で解放 |

### B-9. §14-1 の追記(1 文)

> - **メンバーの環境スコープ(CRYPTO_SPEC §6.2 — 2026-09-14 ES)はリース経路に関与しない**: ワークロードはメンバーではなく、リースの環境制限は grant の `scope_environments` が担う(不変)。合成規則の追加はない

### B-10. §15 の差し替え(15-1 / 15-2 / 15-3)

> - 15-1 `invitations` に **`scope_kind TEXT NOT NULL`('all' | 'listed')、`scope_environments TEXT NOT NULL`(environment_id の JSON 配列 — 発行文の `scope_environments_lp_hex` の入力列。表示・`add_member` の入力)** を追加。発行文(`head_hash` / `head_seq` / `role` / scope)+ `issue_signature` は招待者クライアントが `add_member` の前に検証する材料
> - 15-2 発行 body に `scopeKind` / `scopeEnvironmentIds` を追加(形式検査のみ: kind の閉集合・all なら空配列・256 要素以下・各 id は §12-1 形式。**存在検査はしない** — 合意規則は add_member 受理時に verifyChain が検査する)。一覧行(`InvitationSummary`)・受諾応答に scope を載せる。**role = admin の招待の発行は owner のみ**(不変)。発行者の scope が招待 scope を包含することは発行時に検査しない(add_member 受理時の包含規則が最終判定 — 発行時の状態は変わりうる)が、CLI は通信前に検査して案内する
> - 15-3 リンクのフラグメントに **`sk=<scope_kind>&se=<environment_id の comma 区切り>`** を加える(発行署名が覆う — `r=` と同じ地位)。受諾クライアントは role と scope を表示し、受諾応答の scope と食い違えばエラー。CLI: `maruhi invite create --role <role> [--env <environment-id>]…`(`--env` は反復可。省略 = all。role = owner は招待不可 — 不変)。`maruhi member add` は招待行の scope で `add_member` を署名する(`--env` は持たない)

---

## C. AUDIT_SPEC の改訂案

### C-1. §3.3 の差し替え(`rotation.recommended` 1 行)

> | `rotation.recommended` | target_user_id(remove / 降格 / **縮小** 変種)/ target_key_fingerprint(revoke_server 変種), variable_id, environment_id, payload = { basis, triggerChainSeq, **trigger** } | §4 の算出結果の永続化。**1 (variable × environment) 1 行**。**`trigger` = `remove_member` \| `change_role`(降格・縮小 — 2026-09-14 ES)\| `revoke_server`**。四眼経由の適用は完成した `approve` エントリの seq を `triggerChainSeq` に持つ(PF1) |

### C-2. §3.4 の差し替え(表 + 1 項目)

> | `chain.member_added` ★ | `add_member`(target_user_id, role, **scopeKind, scopeEnvironmentIds** — payload。2026-09-14 ES) |
> | `chain.member_removed` ★ | `remove_member`(target_user_id) |
> | `chain.role_changed` ★ | `change_role`(target_user_id, newRole, **scopeKind, scopeEnvironmentIds** — payload。**降格・縮小は §4.1 の検出契機になる**ため ★) |
> | **`chain.approval_policy_changed`** | `set_approval_policy`(payload = { ops, requiredApprovals }。2026-09-14 PF1) |
> | **`chain.proposed`** | `propose`(payload = { innerOp, expiresAtMs }。内側 payload は写さない — 正はチェーン) |
> | **`chain.approved`** ★ | `approve`(payload = { proposalChainSeq, completed: boolean }) |
> | **`chain.proposal_withdrawn`** | `withdraw`(payload = { proposalChainSeq }) |
>
> - **四眼の適用行(2026-09-14 PF1)**: 定足数に達した `approve` エントリ(`completed = true`)は、`chain.approved` に加えて**内側 op のミラー行**(`chain.member_removed` 等 — 表の該当行)を**同じ chain_seq** で書き、payload に `{ viaProposalSeq }` を付す。actor は提案者(内側 op の actor)。§4.1 の在籍区間(Q1)・grant 区間(Q6)の入力構造を変えないための規律。`maruhi audit verify` の全単射検査は「1 エントリ ↔ 1 ミラー行、ただし完成 approve は + 内側 op の適用行 1 行」に改める(適用行の欠落・過剰・`viaProposalSeq` の不一致は検証失敗)

### C-3. §4.1 の差し替え(手順 2 + 変種 + 末尾段落)

> 2. **候補集合(閲覧可能だった集合)**: **環境別のアクセス窓(2026-09-14 ES)**: M の各在籍区間について、環境 E のアクセス窓 = 「区間内で E が M の scope に含まれていた seq 範囲」(`chain.member_added` / `chain.role_changed` の payload の scope から復元 — `all` は在籍区間の全体、`listed` は含まれる間。scope の変化点で窓が開閉する)。候補 = 「アクセス窓と存在期間が重なる全 (variable × environment)」。`var.created` 〜 `var.deleted`(未削除なら現在まで)の存在区間との重なりで判定する。**削除済み変数も含める**。revoke_server 変種の「環境ごとの開示窓」(下記)と同じ構造であり、実装は 1 つの窓導出を共有する
>
> **`change_role` の変種(2026-09-14 ES)**: 降格(member 未満へ)と scope の縮小は `remove_member` と同じ骨格で検出する — 手順 1 の区間は当該 `change_role` の seq で閉じる窓(降格 = 対象 scope の全環境の窓を閉じる、縮小 = 縮小分の環境の窓を閉じる)、手順 2 の候補は閉じた窓の環境に限る、手順 3〜5 は同じ。`rotation.recommended` の `trigger = change_role`。**降格で機密性上の失効は起きない**(対象は reader として新 DEK を受け取り続ける — CRYPTO_SPEC §7)が、閉じた窓の値は「上流の credential を知る者が権限を失った」事実として検出の対象にする(取り下げは admin の判断 — §7)
>
> ~~環境スコープ role(CRYPTO_SPEC 未決事項 #11)が入った場合は、手順 2 の「全環境」が「M がアクセス権を持っていた環境」に狭まる。…~~ **2026-09-14 解消(上記の環境別アクセス窓)**。チェーンミラーが scope を写す(§3.4)ため、クエリの変更だけで成立する(スキーマ変更不要 — 不変)

### C-4. §6 の追記(1 項目)

> - **環境スコープは可視性クラスを変えない(2026-09-14 ES — 設計録 裁定 I)**: クラス 1 のデータ系イベント(`var.created` / `var.renamed` / `var.schema_reissued` / `var.deleted` / `var.version_pushed`・`env.*`)は scope 外環境のものも全メンバーに見える(平文メタは全員可視 — CRYPTO_SPEC §6.3)。`chain.*`(scope 変更・四眼の提案 / 承認 / 方針を含む)はクラス 1。`var.read` はクラス 2 のまま。可視性述語に環境軸を入れない(`audit verify` / reconcile / 要ローテーションフラグのビューを scope 非依存に保つ)

---

## D. Status 行への追記文

- CRYPTO_SPEC: 「0.11-draft = ES + PF1 の起草(2026-09-14 — 設計録 docs/notes/es-design.md): §3 の v1 簡略化の解消 / §6.2 の scope(add_member / change_role の payload 拡張・構造規則・owner = all・包含規則・環境対象 op・受信者集合 R(E))と四眼(`set_approval_policy` / `propose` / `approve` / `withdraw`・到達可能性・期限)/ §6.3 のラップ先・宣言ヘッド時点の scope・スコープ外環境の扱い / §6.4 の受理・pending 上限 / §6.5 発行文の scope / §7 義務の範囲と縮小・四眼の起点 / §11 ベクターの全再生成 / §13 #11 の解消 / §14.2 の保証 9・10。**本改訂 PR のマージをもって所有者承認とする**」
- AUTH_SPEC: 「0.23-draft = ES + PF1(2026-09-14): §6 / §9-2 の環境軸 / §11-1 の四眼 op / §12-3 の scope 列 / §12-4 / §12-6 の R(E) と拡大バックフィル / §12-7 の scope 拒否とメタのみの例外 / §12-8 の pending 上限 / §14-1 の不変の明記 / §15 の招待 scope。**本改訂 PR のマージをもって所有者承認とする**」
- AUDIT_SPEC: 「1.8-draft = ES + PF1(2026-09-14): §3.3 `rotation.recommended` の trigger / §3.4 のミラー payload の scope・四眼 4 種と適用行 / §4.1 の環境別アクセス窓と change_role 変種 / §6 の可視性クラス不変。**本改訂 PR のマージをもって所有者承認とする**」
