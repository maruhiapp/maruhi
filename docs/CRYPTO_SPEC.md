# maruhi 暗号仕様書 (CRYPTO_SPEC)

Version: 0.11-draft
Status: 0.4 までは所有者承認済み(§4.1 値の書き込み署名 / §4.2 メタデータステートメント / §5.2 DEK コミットメント / §6.2 の `create_environment` と環境ライフサイクル規則 / §6.3〜§6.4 の追補 / §14 保証と非保証は 2026-08-04 の PR #27 マージで承認。§6.2 のメンバー鍵の一意性は PR #22、§5.1 は PR #21 のマージで承認済み。§6.3 ローカル床の列挙追補 — 規則 (c) の床にない変数 = version 0 相当・環境メタステートメントの床・メタ signed_bytes ハッシュの保存 — は、2026-08-04 のセッション 16 所有者裁定 — PR #33 マージで承認 — をセッション 16.5 で反映)。0.5-draft = Phase 2 機能裁定の起草(2026-08-12 セッション 22 — 設計探索の経緯は docs/notes/session-22.md): §3 FP のワード表示 / §6.2 grant_server payload のリースポリシー拡張とサーバー鍵の一意性 / §6.3 再 grant 規則の二層化・帯域外アンカー / §6.5 招待受諾署名(未決 #9 の解消)/ §9.1 ワークロードリース(PR #56 マージで承認済み)。§9.1 の有効期間内リプレイの扱い(サーバー先着束縛の採用と非保証の縮小 — AUTH_SPEC §14-1)は 2026-08-15 の所有者裁定で確定(設計比較は docs/notes/session-24.md)。0.6-draft = Wave 3 D の起草(2026-08-18 セッション 27 — 設計探索・残余対応表・却下案は docs/notes/session-27.md): §4.3 環境マニフェスト / §6.2 `checkpoint` op / §6.3 チェックポイント整合検証・床のマニフェスト拡張・ヘッドゴシップの具体化 / §6.6 ヘッド申告 / §13 未決 #4・#12 の解消(AUDIT_SPEC 未決 #2 と統合)/ §14 の保証・非保証の改訂。**本改訂 PR のマージをもって所有者承認とする**(PR #80 マージ済み = 承認済み)。§6.3 の移行の明示初期化操作(`maruhi env rotate --init-manifest` — 欠落の許容のみ・床確立後の欠落は拒否)と、床規則 (c) のマニフェスト適用の基準(pull 時点エポック床と床マニフェスト自身の epoch の大きい方)の明確化は 2026-08-18 の PR-M1 実装起草 — 本改訂を含む実装 PR のマージをもって所有者承認とする(PR #81 マージ済み = 承認済み)。0.7-draft = PR-M1 マージ後監査(docs/notes/session-31.md)の裁定 1〜3 の起草(2026-08-19 セッション 32 — 設計比較・棄却案は session-31 §7 と docs/notes/session-32.md §2・§4〜§5。裁定 2 = 案 2-G′・裁定 3 = 3-D + 3-E + 3-E′ + 3-F の選択は 2026-08-19 所有者裁定済みで、本 PR は仕様文言の承認): 裁定 1 = §1 原則 6(意味論は署名バイト列の中に置く — 既存アーキテクチャの明文化。AUTH_SPEC §12-10 と対)。裁定 2 = §4.3 検証規則 (2) のエポック整合をチェックポイント束縛の MUST 形へ改訂(旧 H+1 例外の廃止)・§4.3 発行契機と §6.3 への境界チェックポイント必須同梱(複合の H+2、当該環境 1 タプル)・§6.2 の境界チェックポイント注記(合意規則の例外不要)・§6.4 の同梱分突合基準(複合の適用後状態)。裁定 3 = §6.3 ローカル床の「検証済み観測の単調 join」への一般化・追記専用観測ログ + fold の保存形・スナップショットレコードのコンパクション・journal-before-release / before-send(intent レコード)の記録規律 — **本改訂 PR のマージをもって所有者承認とする**。§2.1 の数値境界(非負の安全整数のみ — 既存実装の明文化・挙動変更なし)は 2026-08-28 セッション 34(PR-F4。裁定は docs/notes/session-34.md §2)— **同 PR のマージをもって所有者承認とする**。0.8-draft = S0(値なしスキーマ〔フル〕— ADR-0014 Phase 3 ①)の起草(2026-08-30 セッション 46 — 検討メモは docs/notes/value-free-schema.md、裁定・棄却案は docs/notes/session-46.md 裁定 CR〜CX、CLI・付帯面と実装分割は docs/notes/value-free-schema-design.md): §4.2 変数メタステートメントのレイアウト v2(スキーマ欄 = 型・必須・説明、`declared` 状態、ドメイン分離文字列の版上げとレイアウト選択規則・旧検証者の破壊様式)/ §4.3 のスキーマ被覆確認(entry の meta_sig_hash 束縛によりマニフェスト層は無変更)/ §6.2 `checkpoint` values_digest の declared 除外 / §6.3 の active ステートメントの値配布要求(明文化)/ §11 テストベクター改版方針(実ベクターは S1 の頭で先行コミット)/ §14 保証の分割(presence 硬 / type 柔)。受理・配布面は AUTH_SPEC 0.16-draft §12 — **本改訂 PR のマージをもって所有者承認とする**。§6.5 の明示確認の充足形(検証済み指紋帳の解釈の規範化 — 出荷済み挙動〔PR #164 / #165〕の明文化であり暗号操作・ワイヤ形式の変更なし)は 2026-09-12 の所有者委任による裁定(裁定録は docs/notes/integration-options.md 補足 17 の KF 裁定)— **本改訂 PR のマージをもって所有者承認とする**。0.9-draft = KL3(master 鍵ラップ台帳 — 2026-09-12 設計セッション。設計録・裁定の反復記録は docs/notes/integration-options.md 補足 19、起草時のドラフトは docs/notes/kl3-spec-drafts.md): §8 の一般化(受信者クラス S / G / H — リカバリーコードは不変)/ §11 `master-key-wrap.json` / §13 #2 の注記 / §14.3 非保証 8。設計の 13 項目は 2026-09-12 に所有者承認済み — **本改訂を含む実装 PR のマージをもって仕様文言の承認とする**。0.10-draft = IV(招待儀式の軽量化 — 2026-09-13 設計セッション。設計録・裁定の反復記録は docs/notes/integration-options.md 補足 21、起草時のドラフトは docs/notes/iv-spec-drafts.md): §6.3 (a) 招待リンクアンカーの発行署名化 / §6.5 の全面改訂(リンク鍵・発行署名・受諾の共同署名〔invite-accept-v2〕・裏付け元・明示確認の充足形 4 の既定化)/ §11 invite-accept-signature.json の再生成と invite-link.json / §13 #9 の注記 / §14.3 非保証 9。設計の 16 項目は 2026-09-13 に所有者承認済み — **本改訂を含む実装 PR のマージをもって仕様文言の承認とする**。0.11-draft = ES + PF1 の起草(2026-09-14 — 設計録 docs/notes/es-design.md、起草時のドラフトは docs/notes/es-spec-drafts.md): §3 の v1 簡略化の解消 / §6.2 の scope(add_member / change_role の payload 拡張・構造規則・owner = all・包含規則・環境対象 op・受信者集合 R(E))と四眼(`set_approval_policy` / `propose` / `approve` / `withdraw`・到達可能性・期限)/ §6.3 のラップ先・宣言ヘッド時点の scope・スコープ外環境の扱い / §6.4 の受理・pending 上限 / §6.5 発行文の scope / §7 義務の範囲と縮小・四眼の起点 / §11 ベクターの全再生成 / §13 #11 の解消 / §14.2 の保証 9・10。設計の 24 項目は 2026-09-14 に所有者承認済み(項目 5 は承認後の訂正あり — 設計録冒頭) — **本改訂 PR のマージをもって所有者承認とする**

この文書は maruhi の暗号設計の唯一の正である。ここに記述のない暗号操作を実装してはならない。
変更はこの文書の改訂 → 人間の承認 → 実装、の順で行う。

---

## 1. 設計原則

1. **選択的開示 E2EE**: デフォルトは完全なゼロ知識(サーバーは暗号文のみを保持)。サーバーによる復号は、ユーザーがプロジェクト単位で明示的に許可した場合のみ可能になる(サーバーを「メンバー N+1」として扱う)
2. **標準部品のみ**: 独自プロトコル・独自プリミティブを発明しない。使用するのは WebCrypto、HPKE (RFC 9180)、およびそれらを提供する監査済みライブラリのみ
3. **文脈束縛**: すべての暗号文は AAD / info により使用文脈(プロジェクト、エポック、受信者等)に暗号学的に束縛される。文脈外での再利用(移植攻撃)は復号失敗となる
4. **暗号アジリティ**: すべての永続データ構造はスイート識別子を持ち、将来のアルゴリズム移行を可能にする
5. **暗号の限界の明示**: 暗号は「既に読まれた値」を取り消せない。失効の実効性は上流 credential のローテーションで担保し、それを製品機能として支援する
6. **意味論は署名バイト列の中に置く**(2026-08-19 セッション 32 — 既存アーキテクチャの明文化): security-critical な意味論(検証規則の入力になる値・検証の分岐を決める情報)は、必ずドメイン分離文字列付きの正規化 LP 署名バイト列(§2.1)の中に置く。署名対象の外にある運搬フィールドは advisory であり、検証規則の分岐に用いてはならない。これにより意味論の変更は LP フィールド列の変更となり、旧実装では署名検証の不一致として構造的に拒否される(wire 非互換変更の構造マーカーを兼ねる — AUTH_SPEC §12-10 (2))。既知の残余は受理側の検証モード選択(どの検証規則を適用するかが署名バイト列に入らない形 — session-31 §7 裁定 2 の対象)であり、その解消は同裁定の帰結に従う

## 2. アルゴリズムスイート

スイート識別子: `maruhi/v1`

| 用途 | アルゴリズム |
|---|---|
| データ暗号化(変数値) | AES-256-GCM(96-bit ランダム nonce) |
| 鍵ラップ(DEK → 受信者) | HPKE Base mode: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM |
| 署名(メンバーシップログ等) | Ed25519 |
| ハッシュ(チェーン、フィンガープリント) | SHA-256 |
| 鍵導出(リカバリーコード等) | HKDF-SHA256 |

- 実装: AES-GCM / Ed25519 / HKDF は WebCrypto。HPKE(X25519 KEM を含む)はライブラリ `hpke`(panva)1.x 系を使用する(**2026-08-01 決定**。厳密ピン。退避経路: hpke-js(dajiaji)。選定経緯は docs/notes/spike-c.md)
- HPKE の Open(Decap)には受信者の **KeyPair(公開鍵込み)を渡す実装を標準とする**。秘密鍵単体渡しは extractable=true を強制されるため使用しない(非抽出鍵での運用と両立させる。スパイク C の検証知見)
- 将来 `maruhi/v2` として KEM を X25519+ML-KEM-768 ハイブリッドへ移行する余地を確保する(Phase 2 以降)

### 2.1 AAD / info のエンコーディング規約(必須)

本仕様で `A || B || C` と表記される AAD / info / 正規化バイト列は、単純な文字列連結で実装してはならない(`("ab","c")` と `("a","bc")` が同一バイト列になる曖昧性がドメイン分離を破壊する)。必ず以下の決定論的エンコーディングを用いる:

- 各フィールドを UTF-8 バイト列とし、`uint32-BE 長さプレフィックス + 本体` で連結する
- 数値フィールド(epoch, version, seq)は 10 進文字列化してから同様に扱う
- 数値フィールドとして有効なのは**非負の安全整数(0 〜 2^53 − 1)のみ**であり、非整数(例: 1.5)と 2^53 以上は不正入力として拒否する(fail-closed。2026-08-28 セッション 34 の明文化 — 既存実装の挙動変更なし)。根拠: float64 の精度喪失域では 10 進文字列化が値と一対一にならず、同一値に対する正規化バイト列の一意性 — 本節の眼目 — が壊れる。境界の拒否は各実行環境のハーネス検査で固定する(test-vectors/README.md 規約 21)
- このエンコーダ / デコーダは `packages/crypto` に 1 実装のみ置き、全用途(AAD、HPKE info、チェーン正規化)で共有する。テストベクターで固定する

## 3. 鍵階層

```
User master keypair(ユーザーごと)
├─ enc: X25519(HPKE 受信用)
└─ sig: Ed25519(メンバーシップログ署名用)
        │
        └─ ラップ対象: Environment Epoch DEK(プロジェクト × 環境 × エポックごと)
                └─ 暗号化対象: 変数値、および将来の秘匿メタデータ
```

- **User master keypair**: サインアップ時にクライアントで生成。秘密鍵はサーバーに送信しない。保存先はデバイスのセキュアストレージ(CLI: OS キーチェーン、ブラウザ: IndexedDB + 非抽出設定が可能な範囲で)
- **鍵フィンガープリント**: `SHA-256(enc公開鍵 || sig公開鍵)` の先頭 16 バイト。ログ・UI での鍵識別に使う
- **フィンガープリントのワード表示(2026-08-12 起草)**: 人間の帯域外照合(招待の相互確認 = §6.5、grant_server 実行時のサーバー鍵確認 = §9)に用いる表示形式は、16 バイト FP の BIP39 英語ワードリストによるニーモニック符号化(12 語。エントロピー 128 bit + SHA-256 先頭 4 bit チェックサム)とする。表示言語・ロケールに依らず**常に英語リスト 1 本**(両者の表示が一致しなければ口頭照合が成立しない)。**短縮コードへの切り詰めは行わない**: 照合の一方の鍵は攻撃者が自由に選べるため、表示強度の切り詰めはそのまま第二原像探索(2^N)への強度低下になる。これは表示符号化であり新しい暗号プリミティブではない(SHA-256 + 固定辞書)
- **環境(environment)**(2026-08-01 決定・旧未決事項 #6): プロジェクト配下の名前空間(例: dev / staging / prod)。環境の**存在はチェーン導出**(`create_environment` — §6.2。2026-08-03 改訂)、表示名は平文メタデータ(真正性は §4.2 のステートメントが束縛)とする。暗号文脈(AAD / info)には、改名の影響を受けない安定識別子 `environment_id`(環境作成時にクライアントが採番)を用いる
- **Environment Epoch DEK**: 256-bit ランダム。プロジェクトの各環境 × 各エポックに 1 つ。クライアントで生成し、各受信者(メンバー、および許可時のサーバー)の enc 公開鍵へ HPKE でラップして保存する
- エポックは (プロジェクト, 環境) ごとに独立して進む(prod のローテーションが dev のエポックに波及しない)。環境の初期エポックは 1 とし、`rotate_epoch` はエポックを必ず 1 ずつ進める(検証規則は §6.3。**2026-08-02 決定**)
- ~~v1 では全メンバーが全環境の DEK を受け取る(環境別の閲覧制限は Phase 2 の設計課題。**未決事項 #11**)~~ **2026-09-14 改訂(ES — 未決 #11 の解消)**: 各メンバーはチェーン上の **scope**(`add_member` / `change_role` の payload — §6.2)に含まれる環境の DEK だけを受け取る。scope は `all`(全環境 — 以後に作成される環境を含む)または `listed`(環境 id の有限集合)。環境別の閲覧制限は**サーバーの方針ではなく鍵配布**で実現する: scope 外の環境の DEK ラップは生成も受理もされない(§6.3 / AUTH_SPEC §12-6)ため、サーバーが侵害されても scope 外の DEK は存在せず開かない。設計録は docs/notes/es-design.md
- v1 の簡略化: デバイスごとの鍵は持たず、master keypair を各デバイスに配置する。デバイス追加はリカバリーコードの入力による(§8)。デバイス鍵分離とパスキー PRF は将来課題(**未決事項 #2**)

## 4. 変数の暗号化

- 変数値は `AES-256-GCM(key = 当該エポックの DEK)` で暗号化する
- AAD(必須): `suite || project_id || environment_id || epoch || variable_id || version`
- 変数は環境ごとに独立の値集合を持つ(variable_id は環境内で一意。環境間の変数名照合 = パリティチェックは平文メタデータの変数名で行う)
- 変数名は v1 では平文メタデータとする(パリティチェック・UI 検索のため)。値のみ暗号化。※変数名秘匿は将来オプション(**未決事項 #3**)。名前と variable_id の対応の真正性は §4.2 の署名付きステートメントが担う(平文であることと非認証であることは別問題)
- nonce はランダム生成し暗号文と併置。nonce 再利用は絶対に許されない(テストで検査)

### 4.1 値の書き込み署名(2026-08-03 セッション 12 起草)

AES-GCM の認証タグは共有鍵(DEK)の保持を証明するだけであり、DEK 保持者 — 全メンバー、およびチェーン履歴上の鍵保持者(削除済み元メンバー・漏洩した旧鍵を含む)— なら誰でも、任意の座標に対して「正しく復号できる」暗号文を偽造できる。悪意あるサーバーがこれを配布すると、受信者は偽値を正規値として受け入れる(セッション 11 レビューループの既知残余)。これを塞ぐため、**すべての変数値バージョンは、writer のチェーン署名鍵(Ed25519)による署名を伴う**。既存部品(Ed25519 + SHA-256 + §2.1 LP)のみで構成し、新しいプリミティブは導入しない。

- **署名対象の正規化バイト列**(§2.1 のエンコーディング):

  ```
  value_signed_bytes = LP("maruhi/v1/value-sig",
                          project_id, environment_id, epoch, variable_id, version,
                          nonce_hex, ciphertext_hex,
                          prev_value_sig_hash_hex,
                          writer_user_id, chain_head_hash_hex, chain_head_seq)
  ```

  - ドメイン分離文字列は `<suite>/value-sig`(§5.1 と同型。スイート識別子の束縛はドメイン文字列が担い、suite 不一致の署名移植は検証失敗となる)
  - バイナリ列(nonce・暗号文・ハッシュ)は §5.1 / §6.2 の先例に倣い **hex 小文字文字列**として LP に載せる。数値(epoch・version・chain_head_seq)は §2.1 のとおり 10 進文字列化する
  - `prev_value_sig_hash_hex` = 同一変数の直前 version の `value_signed_bytes` の SHA-256(hex 小文字)。version 1 では**空文字列**。これにより変数ごとのバージョン履歴がハッシュ連鎖し、同一 version の分岐(サーバーの equivocation)・履歴の差し替えが、後続バージョンとの連鎖不整合または「同一座標に異なる signed_bytes を持つ 2 つの有効署名」という**暗号学的証拠**として固定される(§14.3 — 分岐の防止ではなく証拠化)
  - **バージョン連鎖に沿ったエポック単調性(検証規則)**: version N の epoch は version N−1 の epoch **以上**でなければならない(検証は直前 version を知る検証者が行う — §6.3-6)。正規のフローは push を現エポックのみ受理する(AUTH_SPEC §12-5)ためこの規則を常に満たす(受理順に現エポックは非減少)。一方、削除済みメンバーの鍵による「前進 version への旧エポック値の注入」は、直前 version が新エポックへ再暗号化済みであればエポック後退として検証で落ちる(残余は §14.3-5)。なお**宣言ヘッド seq の単調性は規則にしない** — 同期時期の異なる正直な並行 writer は、直前 version より古いヘッドを宣言して正当に push しうる(検討経緯はセッション 12 ノート §12)
  - `writer_user_id` は署名者自身の内部 user_id(§5.1 の signer_user_id と同じ帰属束縛。鍵流用による帰属の付け替えを署名自体が拒否する)
  - `chain_head_hash_hex` / `chain_head_seq` は writer が署名時点で最後に検証したチェーンヘッドの entry_hash(§6.1)と seq(**認可時点の束縛**。この値の検証規則は §6.3 / §6.4)。hash が束縛の本体であり、seq は検証側がエントリを引くための位置指定(両方を署名対象に含め、不一致は検証失敗とする)
- **AAD(§4)は不変**: 署名は AAD の全構成要素(suite はドメイン文字列で)+ nonce + 暗号文を覆う。AAD は GCM 層の文脈束縛(復号失敗による移植拒否)として独立に維持し、既存の variable-encryption テストベクターに変更はない
- **署名の意味論**: 「writer_user_id が、チェーン位置 (chain_head_hash, chain_head_seq) の状態を知った上で、この座標(project / environment / epoch / variable / version)のこの暗号文を書いた」ことの帰属・内容真正性・認可時点束縛である。**平文の正しさは証明しない**(正規権限を持つ writer が不正な値を書くことは防げない — §14.3)。**鮮度も証明しない**(古い正規値の再配布は署名検証を通る。最新性の扱いは §6.3 のローカル床と §14.3)
- ローテーション時の現在値の再暗号化(§7)は新 version の通常 push であり、**ローテーション実行者が writer として署名する**。署名の帰属は「この暗号文を書いた者」であって平文の由来ではない(再暗号化で writer が変わることは意図された意味論)
- サーバー検証(受理時)・クライアント検証(配布時)は §6.3 / §6.4 に規定し、ワイヤ・受理条件の具体化は AUTH_SPEC §12
- テストベクター: `test-vectors/value-signature.json`(正例 + 改竄・座標移植・署名者付け替え・ヘッド差し替え・連鎖不整合・分岐の負例)

### 4.2 変数・環境メタデータの署名付きステートメント(2026-08-03 セッション 12 起草)

変数名・環境名は平文メタデータ(§4)だが、名前 ↔ ID の対応が非認証だと、悪意あるサーバーは名前と暗号文の対応を付け替えられる(例: `DATABASE_URL` と `DEBUG_ENDPOINT` の名前を入れ替え、アプリに別の値を注入する。セッション 11 レビューループの既知残余)。名前を値の AAD に含める案は、rename に全バージョンの再暗号化を強制し、過去バージョンの検証に名前履歴を要するため採らない(比較はセッション 12 ノート)。代わりに、**改名の影響を受けない安定識別子(§3 の environment_id / §4 の variable_id)へ名前と状態を束縛する、バージョン付き署名ステートメント**を導入する:

```
var_meta_signed_bytes = LP("maruhi/v1/var-meta-sig",
                           project_id, environment_id, variable_id,
                           name, status, meta_version, prev_meta_sig_hash_hex,
                           author_user_id, chain_head_hash_hex, chain_head_seq)

env_meta_signed_bytes = LP("maruhi/v1/env-meta-sig",
                           project_id, environment_id,
                           name, status, meta_version, prev_meta_sig_hash_hex,
                           author_user_id, chain_head_hash_hex, chain_head_seq)
```

- エンコーディングは §2.1(§4.1 と同一規約): 数値(`meta_version`・`chain_head_seq`)は 10 進文字列化、バイナリ(ハッシュ)は hex 小文字文字列として LP に載せる
- `status` は `"active"` | `"deleted"`(**変数のレイアウト v2 では `"declared"` を加えた 3 値** — 本節末尾の「レイアウト v2」。環境メタと変数の v1 レイアウトは従来どおり 2 値)。`meta_version` は 1 始まりの連番(作成 = 1。rename・削除 = +1)。`prev_meta_sig_hash_hex` は直前ステートメントの signed_bytes の SHA-256(hex 小文字。meta_version 1 では空文字列)— §4.1 と同じ連鎖規約
- `name` は UTF-8 バイト列として**そのまま**束縛する(署名検証は byte-exact)。Unicode 正規化(NFC)は**署名前のクライアント**が行い、サーバー・検証者は正規化しない(正規化を検証規則・受理後処理に入れると、署名済みバイト列との乖離または実装間の正規化差異がそのまま検証分裂になる)。非正規形の拒否・名前の一意性・文字種制限は API 受理ポリシー(AUTH_SPEC §12-1)
- rename は meta_version をインクリメントする新ステートメント。削除は `status = "deleted"` のステートメント(`name` には直前の active 名をそのまま保持する — 名前フィールドを削除で空にしない)とし、**削除後の再 active 化は禁止**(ID 再利用禁止 — AUTH_SPEC §12-1 — のステートメント層での対応物。tombstone の署名化により、サーバーによる削除済み変数の無断復活は「削除ステートメントの隠蔽」= 巻き戻しに帰着し、§6.3 のローカル床・連鎖検証の対象になる)
- author の必要 role(宣言ヘッド時点 — 検証規則は §6.3): 変数の作成・rename・削除と環境の作成(meta_version 1)・rename = member 以上、環境の削除 = admin 以上(AUTH_SPEC §12-3 のデータプレーン表と同水準。本改訂は認可水準を変更しない)
- **メタステートメント自体はエポックに相当する鮮度アンカーを持たない**: 値(§4.1)のエポック単調性に対応する検査が構造的に存在せず、削除済みメンバーの鍵による「前進 meta_version への偽ステートメント注入」(在籍区間内の宣言ヘッド)は、ステートメント単体の署名・連鎖検証を通る。この穴は**環境マニフェスト(§4.3 — 2026-08-18。旧未決 #12 の解消)がエポック焼き込みで塞ぐ**: 検証済みマニフェストとのダイジェスト整合を要求することで、ステートメントの検証はマニフェストのエポックアンカーを継承する(残余は §14.3-5 — 値と対称の形に縮む)。fork 証拠化(prev 連鎖)は独立の防衛層として不変
- 値(§4.1)は variable_id へ束縛され、名前には束縛されない。名前 → variable_id の解決(CLI の push・`maruhi run` の環境変数名)は、検証済みステートメントを経由しなければならない。同一環境内で同名の active ステートメントが複数検証に通る場合(サーバーの equivocation)、クライアントは解決を拒否して警告する
- 環境の作成はチェーン op(§6.2 `create_environment`)であり、env メタステートメント(meta_version 1)は作成の複合リクエスト(AUTH_SPEC §12-4)に同梱される。環境の削除はデータプレーンの admin 操作 + `status = "deleted"` ステートメント
- テストベクター: `test-vectors/metadata-signature.json`(正例 + 改竄・名前入替・座標移植・署名者付け替え・ヘッド差し替え・連鎖不整合・分岐・削除後 rename・suite 不一致の負例)

**変数メタステートメントのレイアウト v2 — スキーマ欄と `declared` 状態(2026-08-30 セッション 46 起草 — S0。裁定 CR・CS・CT は docs/notes/session-46.md)**

値なしスキーマ(ADR-0014 Phase 3 ① — 名前・型・説明・必須のみをエージェントへ開示する)のスキーマ欄を、変数メタステートメントの第 2 レイアウトとして定義する。並置(独立スキーマステートメント種)ではなく拡張を採る理由: §4.3 の entry は `meta_sig_hash` を束縛するため、ステートメント本体に載せたスキーマ欄はマニフェスト被覆(完全性・エポック鮮度・チェックポイント束縛・equivocation 証拠化)を**マニフェスト層の変更なしに自動継承する**(設計比較・棄却案は session-46 裁定 CR)。

```
var_meta_signed_bytes_v2 = LP("maruhi/v1/var-meta-sig-v2",
                              project_id, environment_id, variable_id,
                              name, status, var_type, required, description,
                              meta_version, prev_meta_sig_hash_hex,
                              author_user_id, chain_head_hash_hex, chain_head_seq)
```

- **エンコーディングは §2.1(v1 と同一規約)**。ドメイン分離文字列は `maruhi/v1/var-meta-sig-v2` — レイアウトの版は**ステートメント種ローカル**であり、suite(`maruhi/v1`)は据え置く(suite はアルゴリズム束の識別子で、`maruhi/v2` は PQ ハイブリッドに予約済み — §2・未決 #5。AUTH_SPEC §12-2 の「v2 まで先取りしない」保留はアルゴリズム版に係るものであり、本レイアウト版はそれに抵触しない)。v1 と v2 の相互解釈は署名不一致で構造的に失敗する(§1 原則 6)
- **スキーマ欄**: `var_type` ∈ `"" | "string" | "number" | "boolean" | "url"`(`""` = 未指定。**閉集合** — 検証 DSL・enum・デフォルト値は導入しない。enum の見送り理由は session-46 裁定 CT)。`required` ∈ `"true" | "false"`(**v2 では明示必須** — 空文字列を許さない。省略時の既定値解釈をクライアント実装に分散させない fail-closed)。`description` は UTF-8 自由文字列(name と同じく byte-exact 束縛・検証者は正規化しない。長さ上限・文字種はサーバー受理ポリシー — AUTH_SPEC §12-8。表示側の中和義務は独立 — 同 §12-8・設計文書)
- **`status` の第 3 の値 `"declared"`(v2 限定)**: 「宣言済み・値未設定」。遷移規則(受理検査は AUTH_SPEC §12-5): 作成(meta_version 1)は active(値同梱)または declared(値なし)。declared → active は最初の値 push との複合(activation — meta_version + 1)。declared → deleted は可。**active → declared は禁止**(値の存在の巻き戻し表現を作らない — 値を取り除く唯一の経路は削除)。deleted 後の再 active 化禁止(既存)は declared への遷移にも適用する。declared を v1 レイアウトに許さない理由は session-46 裁定 CS(「v1 は不変」という移行の核を守る)
- **検証側のレイアウト選択と旧検証者の破壊様式(裁定 CR)**: どのレイアウトの signed_bytes を再計算するかは、ワイヤの `layoutVersion`(AUTH_SPEC §12-2 — 省略 = 1)が選択する。検証者は**署名検証より前に** layoutVersion のサポート範囲を検査し、超過は「未対応レイアウト(クライアント更新が必要)」の**型付きエラー**で拒否する — 署名不正(改ざんと区別のつかない警告)として現れさせない誠実な破壊様式。layoutVersion は署名対象の外(運搬フィールド)だが、虚偽申告は別レイアウトでの signed_bytes 再計算 = 署名不一致に退化する(§1 原則 6 の既知の残余「検証モード選択」と同型 — 攻撃者が得るのはエラーメッセージの品質のみで、検証は破れない)
- **v1 レイアウトは有効なまま**: 既存ステートメントの移行は不要(一括移行なし)。スキーマ欄・declared を使わないステートメントは v2 導入後も v1 で発行してよい(v1 変数のまま運用を続けられる)。再発行の自然な機会(rename・スキーマ設定)に v2 へ移る。削除ステートメントは name と同じ規約でスキーマ欄とレイアウトを直前ステートメントからそのまま保持する
- **変数単位のレイアウト単調性(2026-08-30 — PR #112 pullfrog レビュー対応)**: 直前ステートメントが v2 の変数の後続ステートメント(rename・スキーマ再発行・削除・activation)は **layoutVersion 2 でなければならない**(v1 への後退禁止)。後退を許すと rename 1 回でスキーマ欄が黙って消え、presence 保証(§14.2-8)の前提 — 「required = true の宣言は署名済みの明示操作なしに消えない」— が崩れ、schema-locked(AUTH_SPEC §12-11)も「作成は v2 → rename で v1 へ落とす」で迂回できる。スキーマ欄の**値**自体は後続の v2 ステートメントで明示的に変更してよい(スキーマ再発行・rename との複合 — required を false へ下げる正当な操作はこの形。削除ステートメントのみ直前の値の完全保持を要求する — name の規約と同型)。受理検査は AUTH_SPEC §12-5、クライアント検証は prev を知る検証者(§6.3 の 6 の連鎖整合と同じ既知範囲)が行う
- **書き込みの有効化ゲート(発見 F — 旧検証者保護)**: v2 の**新規採用** — metaVersion 1 の v2 作成と、v1 変数への v2 再発行(正確な線引きは AUTH_SPEC §12-5)— の受理はプロジェクト単位のスキーマポリシー(AUTH_SPEC §12-11 — 既定 disabled)が遮断する。**直前ステートメントが既に v2 の変数の継続ステートメントはポリシーに依らず受理される**(2026-08-30 PR #112 レビュー対応: ゲートの目的 = 未更新クライアントが読めない新しい v2 ステートメントの出現防止は、v2 配布済みの変数には既に達成不能であり、継続まで止めても保護は増えず、ポリシー降格が既存 v2 変数のライフサイクル — 削除・activation — を凍結する形だけが残る)。アップグレード済みメンバー 1 人の書き込みが未更新メンバーの検証を割る形を、有効化の明示操作(サーバー → 全メンバー CLI → 有効化の順序 — SELF_HOSTING "Updates" への追記は実装 PR 側)で防ぐ。v1 → v2 の導入自体は公開前(適用済み外部ステートメントなし)であり後方互換条項を持たない(§6.2 の先例)— 以後のレイアウト版上げ(v3〜)は上記のレイアウト選択規則により旧クライアントで decode 段の明示エラーとして現れる(layoutVersion のワイヤ型は上限を固定しない整数 — AUTH_SPEC §12-2)
- **required の意味論**: required は「**環境の契約**」(この環境はこの変数の値を持つべきだ)であり、充足 = 当該変数の status が active であること。ステートメントは (environment, variable) 単位なので環境別の required は構造がそのまま与える。充足の検証可能性(サーバー申告に依存しない硬い保証)は §14.2、型宣言が advisory であること(overclaim の禁止)は §14.3。コード側の要求宣言はスキーマの責務にしない(コード自身が正 — `maruhi schema lint`。設計文書)
- **author の必要 role は v1 と同一**(変数の作成・スキーマ設定・rename・削除 = member 以上。本改訂は認可水準を変更しない)。環境メタステートメント(`env_meta_signed_bytes`)は本改訂の対象外(v1 のまま)
- テストベクター: `test-vectors/metadata-signature.json` の追記拡張(§11 の 0.8-draft 項)

### 4.3 環境マニフェスト(2026-08-18 セッション 27 起草 — 未決事項 #12 の解消)

§4.2 のメタステートメントは「エポックに相当する鮮度アンカーを持たない」ため、削除済みメンバー・漏洩鍵による前進 meta_version の注入が床を持つクライアントに対しても検出されない(§14.3-5 — 値との保証の非対称)。また変数集合の欠落(配布からステートメントを丸ごと落とす — G6)は床を持たないクライアントに検出されない。これらを塞ぐため、**環境単位の署名付きマニフェスト**を導入する: 環境のメタ状態(全変数ステートメント + 環境メタステートメントのダイジェスト)を、メタ状態を変えるすべての操作の実行者が、**その時点の現エポックを焼き込んで**再署名する。既存部品(Ed25519 + SHA-256 + §2.1 LP)のみで構成し、新しいプリミティブは導入しない。

- **署名対象の正規化バイト列**(§2.1 のエンコーディング):

  ```
  env_manifest_signed_bytes = LP("maruhi/v1/env-manifest-sig",
                                 project_id, environment_id,
                                 epoch, manifest_version,
                                 variables_digest_hex,
                                 env_meta_version, env_meta_sig_hash_hex,
                                 prev_manifest_sig_hash_hex,
                                 issuer_user_id, chain_head_hash_hex, chain_head_seq)

  variables_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/env-manifest-vars",
                                              entry_1, …, entry_n)))
  entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)
  ```

  - エンコーディング規約は §4.1 / §4.2 と同一(数値は 10 進文字列化、バイナリは hex 小文字。ドメイン分離文字列がスイートを束縛)。entry の列は当該環境の**全**メタステートメントの最新形 — `status = "deleted"` の tombstone を含む — を **variable_id のバイト昇順**で並べる(順序はダイジェストの正規形の一部)。変数ゼロの環境では要素 0 の LP(空集合も有効なダイジェストを持つ)
  - `manifest_version` は 1 始まりの連番(環境作成 = 1)。`prev_manifest_sig_hash_hex` は直前マニフェストの signed_bytes の SHA-256(manifest_version 1 では空文字列)— §4.1 / §4.2 と同じ連鎖規約(分岐の証拠化)
  - `epoch` は**発行時点(宣言ヘッド時点)の当該環境の現エポック**。この焼き込みが本機構の核である: メタステートメント自体に欠けていた鮮度アンカー(値の §4.1 エポック整合に対応するもの)をマニフェスト層が供給する
- **発行契機(すべて複合受理 — AUTH_SPEC §12-4 / §12-5)**: 環境の作成(manifest_version 1、変数空集合)、変数の作成・rename・削除、環境の rename、`rotate_epoch`(新エポックの焼き込み — メタ集合は不変でもエポック前進を反映する)。**環境の作成・`rotate_epoch` の複合は、発行したマニフェストを束縛する境界 `checkpoint` エントリを必須で同梱する(2026-08-19 セッション 32 — §6.3 の発行規則・AUTH_SPEC §12-4)**。**値の push では発行しない**(マニフェストは値 version を含めない — 全 push がマニフェスト CAS を通るホットパスの直列化を避ける。セッション 12 案 C-2 の却下理由 (i) の回避。値の巻き戻し検出はチェックポイント — §6.2 / §6.3 — の責務)。環境の削除ではマニフェストを再発行しない(配下メタはカスケード削除され配布チャネルが消える — AUTH_SPEC §12-4。環境自身の deleted ステートメントが終端の検出材料)
- **発行者(issuer)= その操作の実行者**。必要 role は操作自体と同じ(§4.2 / AUTH_SPEC §12-3 の表を変更しない)。`issuer_user_id` の焼き込み・鍵選択・宣言ヘッド束縛の意味論は §4.1 / §4.2 と同一
- **検証規則(クライアント — §6.3 に統合)**: (1) §6.3 の 1〜3・5〜6 と同型の署名・ヘッド束縛・認可時点・座標・prev 連鎖(床がある場合)の検証、(2) **エポック整合(2026-08-19 セッション 32 改訂 — session-31 M1-A6 の解消。設計比較は session-32 §4〜§5)**: 検証済みチェーン上に当該 (environment_id, manifest_version) のタプルを含む `checkpoint` エントリが存在する場合、そのタプルの (epoch, manifest_sig_hash_hex) と**完全一致しなければならない**(境界チェックポイント束縛 — 宣言ヘッド時点との一致はこの場合の代替経路に**ならない**。環境作成・ローテーション複合が発行するマニフェストは、複合が必須同梱する境界チェックポイント — §6.3 / AUTH_SPEC §12-4 — のこの経路で検証される。同一 (environment_id, manifest_version) に異なる manifest_sig_hash のタプルが検証済みチェーン上に併存する場合は、マニフェスト equivocation の硬い証拠として当該環境の配布を拒否し警告する)。タプルが存在しない場合、マニフェストの epoch が**宣言ヘッド時点**の当該環境の現エポックと一致すること(strict — §6.3 の 4 のマニフェスト版。削除・member 未満への降格・scope の縮小は対象の scope の全環境のローテーションを伴う — §7、2026-09-14 ES — ため、write 資格を失った鍵では現エポックのマニフェストを署名できない。**旧 H+1 例外 — 宣言ヘッドの次エントリでエポックが成立する複合形の無条件許容 — は本改訂で廃止し、チェックポイント束縛のみが strict の例外となる**)、(3) **ダイジェスト再計算**: 配布された全ステートメント(tombstone 含む — AUTH_SPEC §12-7)を個別検証した上で variables_digest を再計算し、マニフェストと一致すること。不一致はステートメントの欠落・注入の検出であり拒否する、(4) **チェックポイント整合**(§6.3): 当該環境を含む最新のチェックポイントに対する manifest_version・エポックの非後退(境界チェックポイントが供給する下限は、タプルを持つ版への (2) の照合を下方回避できなくする役割を兼ねる)
- **サーバー検証(受理時 — AUTH_SPEC §12-5)**: メタは平文であり、サーバーは署名・ヘッド・認可時点・prev 連鎖・エポック整合に加えて**ダイジェストの再計算一致まで**検証できる(値の AAD と異なり E2EE の制約がない)。不正クライアントの偽マニフェスト持ち込みは受理段で全部落ちる
- **意味論**: 「issuer が、このチェーン位置・この現エポックの下で、この環境のメタ状態の全体像はこれだと宣言した」。平文の正しさ(G9)・チェーンヘッド自体の鮮度(G5)は証明しない — 後者は床・帯域外アンカー・チェックポイント(§6.3)との合成が担う。prev 連鎖は分岐(同一 manifest_version への異なる有効署名)を否認不能な証拠に変換する(§14.2-5)。**検証は最新マニフェスト 1 通で成立する**(中間マニフェストの配布・連鎖検証を要しない — 後続性の検証は manifest_version の単調性 + エポック整合で足りる。設計比較はセッション 27 ノート §5-1)
- **スキーマ欄の被覆(2026-08-30 セッション 46 — S0 の確認。本節は無変更)**: entry_i は `meta_sig_hash_hex`(ステートメント signed_bytes の SHA-256)を束縛するため、§4.2 レイアウト v2 のスキーマ欄(型・必須・説明)と `declared` 状態は、本節の被覆(完全性 = 欠落・注入の検出、エポック鮮度、チェックポイント束縛、equivocation の証拠化)を**マニフェスト層の変更なしに自動継承する**(v2 ステートメントの meta_sig_hash は v2 の signed_bytes から計算される — entry の構造・ダイジェストのエンコーダは不変)。entry の `status` フィールドに `"declared"` が新しい文字列値として現れるだけで、正規形(variable_id バイト昇順・tombstone 含む全列挙)に変更はない。並置ルート(独立スキーマステートメント種)がこの被覆の外に落ちることとの比較は docs/notes/value-free-schema.md §4・session-46 裁定 CR
- テストベクター: `test-vectors/env-manifest.json`(§11)

## 5. 鍵ラップ(HPKE)

- DEK の各受信者へのラップは HPKE Base mode の単発 Seal で行う
- `info`(必須): `"maruhi/v1/dek-wrap" || project_id || environment_id || epoch || recipient_user_id`
- 受信者はサーバーが配布するラップ済み DEK を自分の秘密鍵で Open して DEK を得る
- info の不一致(別プロジェクト・別エポック・別受信者への移植)は復号失敗となる。これが移植攻撃対策の中核である

### 5.1 DEK ラップの登録署名(2026-08-02 セッション 07 所有者裁定 2-E。セッション 09 起草)

ラップの中身はサーバーに検証不能(E2EE)であり、復号不能な毒ラップの登録者の帰属をサーバー管理データ(監査ログ)だけに頼るとサーバー不信の下で偽造可能になる。これを塞ぐため、**すべての DEK ラップは、ラップ実行者(§7)のチェーン署名鍵(Ed25519)による「ラップごと」の登録署名を伴う**。既存部品(Ed25519 + §2.1 エンコーディング)のみで構成し、新しいプリミティブは導入しない。

- **署名単位はラップごと**(1 受信者宛の 1 ラップに 1 署名)。配布時に受信者が自分宛のラップを単体で検証できる(集合単位の署名では、修復経路 — AUTH_SPEC §12-6 — による個別削除・再登録で署名対象の集合が変わり検証が壊れる)
- **署名対象の正規化バイト列**(§2.1 のエンコーディング):

  ```
  signed_bytes = LP("maruhi/v1/dek-wrap-sig",
                    project_id, environment_id, epoch, recipient_user_id,
                    recipient_enc_pub_hex, enc_hex, ciphertext_hex,
                    signer_user_id)
  ```

  - ドメイン分離文字列は `<suite>/dek-wrap-sig`(§5 の HPKE info と同じく、スイート識別子の束縛はドメイン文字列が担う)。suite が異なれば signed_bytes が異なり、スイート間の署名移植は検証失敗となる
  - バイナリ列(受信者 enc 公開鍵 32B、HPKE encapsulated key 32B、ラップ暗号文 48B)は §6.2 grant_server の先例に倣い **hex 小文字文字列**として LP に載せる(生バイトではない)
  - `recipient_enc_pub_hex` を署名対象に含めるのは裁定列挙(suite・project・env・epoch・受信者・enc・ct)への追加提案: これによりワイヤ上の WrappedDek(AUTH_SPEC §12-2)の全フィールドが署名で束縛され、未束縛フィールドが残らない。受信者は自分の公開鍵を知っているため、配布時の単体検証可能性は損なわれない
  - `signer_user_id`(署名者自身の内部 user_id)を署名対象に含めるのも裁定列挙への追加提案(セッション 09 レビューループ 1): 署名だけでは「鍵 K の保持者が署名した」ことしか固定されない。起草時点のチェーンは同一公開鍵を持つ複数メンバー(当時の add_member は鍵の重複を拒否しなかった)を許容していたため、鍵を流用した別 user_id への**帰属の付け替え**(削除済みスロットへ、同一鍵の別メンバーとして他人の署名済みラップを再投入する)が成立してしまう。署名者 user_id を署名に焼き込むことでこれを塞ぐ。署名者は自分の user_id を知っており、受信者は配布される署名者情報(AUTH_SPEC §12-2)から検証時に再構成できるため、単体検証可能性は損なわれない。なお 2026-08-03 に §6.2 のメンバー鍵の一意性(合意規則)が鍵重複メンバーの成立自体を禁止したが、本束縛は独立の防衛層としてそのまま維持する(§6.2 の規則が実装バグ・将来改訂で破れても署名層単独で帰属付け替えを拒否できる)
- **署名の意味論は帰属であり、鮮度証明ではない**: 署名は文脈(プロジェクト・環境・エポック・受信者・暗号文・署名者)に束縛され、文脈外への移植は検証失敗となる。一方、同一文脈への再登録(修復経路の削除後に同一内容を再登録する場合)は同一署名のまま有効である。これは意図された性質であり、タイムスタンプ・ノンスは署名対象に含めない(スロットの上書き禁止 — AUTH_SPEC §12-6 — により、同一文脈の再登録は「同じ署名者による同じ内容の復元」以上の効果を持たない)
- **サーバー検証(受理時)**: 登録 API の呼び出し主体(認証済み内部 user_id)= 署名者であることを受理条件とし、**受理時点のチェーン導出現メンバー集合**におけるその主体の sig 公開鍵で全ラップの署名を検証する(= 「登録時点の鍵」。受理はプロジェクト DO の直列化の下で行われるため、受理時点のチェーン状態が登録時点の状態である)。他人が署名したラップの持ち込み(削除済みスロットへの第三者による再投入を含む)は署名者不一致として拒否される。この規則は v1 の全登録経路(環境作成の同梱・ローテーション後の一括登録・新メンバー宛バックフィル・修復経路の再登録)と両立する — いずれも「DEK を保持するクライアントが自らラップして自ら登録する」(§7)ため
- **クライアント検証(配布時)**: サーバーはラップとともに署名・署名者(user_id + 鍵フィンガープリント)を配布する。受信者は、検証済みチェーン履歴でその user_id に束縛された sig 公開鍵のうち**署名者フィンガープリントが一致するもの**(genesis / add_member の payload に記録された鍵)で署名を検証する。署名者がその後 `remove_member` で削除されていても、過去に登録されたラップの署名は当時の鍵で検証できる(チェーンは append-only であり鍵の履歴を保持する)。v1 のクライアント検証ロジックの実装は CLI / Web 実装時(§6.3 のクライアント同期と同時)とし、本仕様はワイヤ・保存がそれを可能にする形であることを規定する
- サーバーの保存行はラップごとに署名と署名者(user_id + 鍵フィンガープリント)を持ち、監査イベント `dek.registered` は署名者フィンガープリントを写す(AUDIT_SPEC §3.3。監査行とチェーン外署名の突合を可能にする)
- テストベクター: `test-vectors/dek-wrap-signature.json`(正例 + 改竄・座標移植・鍵不一致・suite 不一致の負例)

### 5.2 エポック DEK のコミットメント(チェーンによる真正性の束縛。2026-08-03 セッション 12 起草)

§5.1 の登録署名は「誰がこのラップを持ち込んだか」の帰属であり、「そのラップが当該エポックの**正規の** DEK を含むか」は証明しない。悪意あるサーバーとチェーン履歴上の鍵保持者が共謀すると、実在エポックに対する自作 DEK のラップを §5.1 検証を通る形で配布でき、(1) 偽 DEK で暗号化した偽値を復号させる、(2) 受信者に偽 DEK で新しい値を暗号化・push させて攻撃者が読む、の両方が成立する(セッション 11 の既知残余)。これを塞ぐため、**エポック DEK の SHA-256 コミットメントをメンバーシップチェーンに載せ、受信者は開封した DEK をコミットメントと照合するまで、その DEK をいかなる暗号操作にも使用してはならない**。

- **コミットメントの計算**(§2.1 のエンコーディング。`dek_hex` は DEK 32 バイトの hex 小文字):

  ```
  dek_commitment_hex = lower_hex(SHA-256(LP("maruhi/v1/dek-commit",
                                            project_id, environment_id, epoch, dek_hex)))
  ```

  - ドメイン分離文字列は `<suite>/dek-commit`。座標(project / environment / epoch)を原像に含めることで、同一 DEK を誤って別文脈に流用した場合もコミットメントが一致せず、コミットメント値同士の比較から文脈間の DEK 一致が漏れることもない
- **掲載場所**: 環境作成のチェーン op `create_environment`(§6.2 で新設)がエポック 1 のコミットメントを、`rotate_epoch` が新エポックのコミットメントを payload に持つ。チェーンエントリは作成者 / ローテーション実行者(= DEK を生成したクライアント — §7)の署名で覆われるため、コミットメントは「その時点のチェーン導出状態で必要 role を持つメンバーが認可した DEK」へ帰属付きで束縛される。**エポックとコミットメントの対応はチェーン検証(§6.3 / §6.4)の一部として全クライアント・サーバーで一意に導出される**
- **クライアント検証(必須)**: ラップを Open して得た DEK からコミットメントを再計算し、検証済みチェーンの当該 (environment_id, epoch) のコミットメントと**一致するまで、その DEK を復号にも暗号化にも使用してはならない**。不一致のラップは毒ラップとして扱い(修復経路 — AUTH_SPEC §12-6 — の対象)、警告する。特に **push 前の照合**が (2) の機密性攻撃(攻撃者が鍵を知る偽 DEK での暗号化の誘導)を遮断する
- **秘匿性**: コミットメントは公開値(チェーン上)だが、DEK は一様ランダム 256-bit であり、SHA-256 の原像計算困難性によりコミットメントから DEK の情報は得られない(§8 の「高エントロピー乱数のため」と同じ前提)。**この構成の秘匿性は入力のエントロピーに依存するため、低エントロピー値のコミットメントへの流用は禁止**(§12)
- これは新しいプリミティブではない: SHA-256 + §2.1 LP のみで構成され、§3 の鍵フィンガープリントと同じ「公開ハッシュによる同定」の適用である(独自プロトコルの発明にあたらないことの確認はセッション 12 ノート)
- **受信者集合に依存しない**: コミットメント対象は DEK そのものであり、ラップ集合・HPKE 暗号文は含まない。よって (a) add_member 後の過去エポックのバックフィル(招待者が同じ DEK を新メンバーへラップ)、(b) 修復経路の削除 → 再登録、(c) HPKE のランダム性による同一 DEK のラップ暗号文の変動、(d) add_member による受信者集合の事後拡大 — のいずれもコミットメントの生成・検証に影響しない(ラップ集合へのコミットメント案がこれら全てで壊れることとの比較はセッション 12 ノート)
- **§5.1 との責務分離**: コミットメントは「何が正規 DEK か」(真正性)、登録署名は「誰がこのラップを持ち込んだか」(帰属)。§5.1 は帰属・修復の監査層としてそのまま維持する
- テストベクター: `test-vectors/dek-commitment.json` + `chain-entries.json` の拡張(§11)

## 6. メンバーシップログ(署名付きハッシュチェーン)

プロジェクトごとに append-only の署名チェーンを持つ。サーバーはチェーンを保存・配布するが、改竄・偽造はできない(署名できないため)。

### 6.1 エントリ形式

```
{
  suite: "maruhi/v1",
  seq: <連番>,
  prev_hash: <SHA-256(直前エントリの正規化バイト列)>,
  op: <操作種別>,
  actor: { user_id, key_fingerprint },
  payload: <操作ごとのデータ>,
  timestamp,
  signature: <actor の Ed25519 署名(上記全フィールドの正規化バイト列に対する)>
}
```

- **アイデンティティ規則(絶対)**: エントリ内の主体識別は内部 user_id と鍵フィンガープリントのみ。GitHub ID 等のプロバイダ情報・メールアドレスを含めてはならない(この構造は書き換え不能であり、認証プロバイダから独立していなければならない)
- 正規化: 決定論的シリアライズ(フィールド順固定の canonical 形式)。実装はテストベクターで固定する
- **フィールドサイズ上限(2026-08-02 決定)**: エントリ内の自由文字列フィールド(user_id、environment_id、reason 等)は **UTF-8 で 1024 バイト以下**、`grant_server` の scope_environments は **256 要素以下**とする。超過エントリは無効。この上限はチェーン有効性の合意規則であり、全実装(クライアント検証 §6.3・サーバー検証 §6.4)で一致させる(巨大 payload による検証クライアントの資源消費対策。固定長の hex フィールドには個別の長さ検査がある。エントリ全体・チェーン全体のサイズ上限は §6.4 のサーバー受理ポリシーとして規定済み — 合意規則はこのフィールド上限のみである)

### 6.2 role と操作種別(認可モデル。2026-08-01 決定・旧未決事項 #7)

チェーン上の role は **owner / admin / member / reader** の 4 段とする:

| role | できること |
|---|---|
| `reader` | scope 内の環境の値の取得・復号のみ(DEK ラップは scope 内の環境について受け取る)。チェーン追記不可 |
| `member` | + scope 内の環境の値の更新(新バージョンの push)、`rotate_epoch`、`checkpoint`。scope = all なら `create_environment` |
| `admin` | + reader / member を対象とする `add_member` / `remove_member` / `change_role` — ただし**その操作が権限を変える環境集合**(add = 新 scope、change_role = role が変わるなら旧 scope ∪ 新 scope・scope だけが変わるなら対称差、remove = 現 scope — 原則 1)が自分の scope に包含される範囲に限る |
| `owner` | + admin の管理、`grant_server` / `revoke_server`、`set_approval_policy`、プロジェクト削除。**scope は常に all**。最後の owner は削除・降格不可 |

- **org ロール(AUTH_SPEC)はプロジェクトアクセスに一切関与しない**(真実源はチェーンのみ。§6.4)
- サーバーは push / pull 等のデータ操作もチェーン導出の role で認可する(reader の push は拒否等)
- **grant_server の scope_environments の正規化(2026-08-02 決定)**: 対象環境の environment_id リストを §2.1 のエンコーディングで LP 化し、その **hex 小文字文字列**を payload の 1 フィールドとして正規化バイト列に載せる(入れ子 LP)。リストの順序は署名対象バイト列の一部である。生成時はコードポイント昇順・重複なしで並べることを推奨する(SHOULD。検証はスコープを集合として扱う)
- **環境スコープ(2026-09-14 ES 改訂 — 旧未決事項 #11)**: `genesis` / `add_member` / `change_role` はメンバーの **scope** を確立する。scope の正規化は payload の 2 フィールド `scope_kind`(`"all"` | `"listed"`)と `scope_environments_lp_hex`(environment_id リストを §2.1 で LP 化した hex 小文字文字列 — `grant_server` の `scope_environments` と同じ入れ子 LP。リストの順序は署名対象バイト列の一部。生成時はコードポイント昇順・重複なしで並べることを推奨〔SHOULD〕し、検証は集合として扱う)。`genesis` は payload に scope を持たず、作成者の scope は構造的に `all` である。合意規則:
  - **構造(payload 構造検査の段 — 認可判定に先行)**: `scope_kind = "all"` のとき `scope_environments` は空リストでなければならない(非空は `invalid-payload`)。リストは 256 要素以下(§6.1 の `grant_server` と同じ上限)。**重複 environment_id を含むリストは無効**(`invalid-payload` — `checkpoint` と同じ「非決定性の芽を構造段で摘む」線)。`scope_kind = "listed"` の**空リストは有効**(= どの環境の DEK も受け取らないメンバー。平文メタは §6.3 のとおり見える)
  - **環境の存在(認可段)**: `listed` の各 environment_id は、そのエントリ時点でチェーン上に `create_environment` が先行していなければならない(拒否理由 `unknown-environment` — `rotate_epoch` / `checkpoint` と同じ理由コード。typo を fail-closed にし、未存在環境への事前スコープは持たない)。削除済み環境はチェーンが削除を観測しないため列挙してよい(害はない)
  - **owner は all(認可段)**: `role = owner` を確立する `add_member` / `change_role` は `scope_kind = "all"` でなければ無効(拒否理由 `scope-role-mismatch`)。owner は「最後の owner」保護・`grant_server`(全環境の開示)・全環境の rotate 義務の履行者であり、scope を持てない。admin / member / reader は `listed` を持てる(dev 専任の admin が書ける — 設計録 裁定 C)
  - **原則 1 — 権限の変更可能性(認可段。2026-09-14 — 設計録 3-ter・pullfrog 第 9 巡改訂)**: エントリが環境 E におけるメンバーの権限(値の読み / 書き / `rotate_epoch` / `checkpoint` の可否 — role 表)を変えるとき、**actor の scope は E を含む**。すなわち actor の scope は op の**権限変化の環境集合**を包含していなければならない(拒否理由 `scope-not-contained`。`all` は全てを包含し、`listed` は `listed` の部分集合のみを包含する — `listed` は `all` を包含しない)。権限変化の環境集合は role 表から導出する(列挙ではない): `add_member` = 新 scope / `change_role` = 新 role ≠ 旧 role なら 旧 scope ∪ 新 scope(role が変わる環境の全体)、新 role = 旧 role なら (新 \ 旧) ∪ (旧 \ 新)(scope の出入りだけが権限を変える)/ `remove_member` = 現 scope。**集合代数(`all` の扱い — 2026-09-14 Cursor Bugbot 指摘対応)**: 包含判定において `all` は**全環境の集合 U(将来作成される環境を含む)**として扱い、`listed{X}` は有限集合 X として扱う。したがって `all ⊇ 任意` は真、`listed{X} ⊇ all` は偽、`listed{X} ⊇ listed{Y}` は Y ⊆ X。`all ∪ listed{X} = all`、`all \ listed{X} = U \ X`(未作成の環境を含むため `listed` の actor は包含できない)、`listed{X} \ all = ∅`、`all △ listed{X} = U \ X`。帰結として、**旧 scope または新 scope が `all` である `change_role`、および `all` を付与する `add_member` は、権限変化の環境集合が U \ X(または U)を含むため scope = all の actor しか行えない**(`listed` の admin は対象を `all` にできず、`all` の対象を `listed` にもできない — 将来環境の DEK を渡す・回収する義務を負えないため)。**系 — 義務の履行可能性**: §7 / AUTH_SPEC §12-6 の義務(バックフィル・rotate)は権限が変わる環境にしか生じないため、義務の環境集合(`add_member` = 新 scope〔バックフィル〕/ `change_role` = (新 \ 旧)〔バックフィル〕∪ (旧 \ 新)〔rotate〕∪(member 未満への降格なら新 scope)〔rotate〕/ `remove_member` = 現 scope〔rotate〕)は権限変化の環境集合の部分集合であり、義務を負う actor は常にその環境の DEK を持つ(DEK のラップは DEK 保持者が行う〔§7〕— 環境 E へ人を入れるのも E から外すのも E の DEK を持つ者だけ、という暗号的必然と一致する)。義務の環境集合だけを包含対象にする形(2026-09-14 の一時的な定式)は認可の必要条件に過ぎず、義務が生じない scope 不変の昇格(dev 専任 admin が prod の reader を member に上げる)を通してしまうため採らない。dev 専任 admin は scope だけを変える `change_role` を対称差の範囲で行える。owner は all のため常に通る
  - **環境対象 op**: `rotate_epoch` の対象 environment_id、`checkpoint` の全タプルの environment_id は actor の scope に含まれていなければならない(拒否理由 `environment-out-of-scope`)。`create_environment` の新 environment_id も同じ述語で判定する — `listed` の scope に未存在の環境は含まれえないため、**環境の作成は scope = all の actor のみ**ができる(作成者が受け取れない環境を作る形・署名対象にない暗黙の scope 変化を作らない)
  - **検査順序(理由コードごとテストベクターで固定。scope 系の検査は既存の検査列の後ろに置き、既存負例の期待理由を温存する)**: `add_member` = role 規則 → `duplicate-member` → `duplicate-member-key` → `unknown-environment`(scope の各 id)→ `scope-role-mismatch` → `scope-not-contained`。`change_role` = role 規則 → `approval-required`(直接追記のみ — 下記)→ `unknown-target` → `last-owner-protected` → `unknown-environment` → `scope-role-mismatch` → `scope-not-contained` → `approval-quorum-unreachable`(四眼有効時 — 下記)。`remove_member` = role 規則 → `approval-required` → `unknown-target` → `last-owner-protected` → `scope-not-contained` → `approval-quorum-unreachable`。`add_member` / `grant_server` / `revoke_server` の `approval-required` も同じ位置(role 規則の直後)。`rotate_epoch` = role 規則 → `unknown-environment` → `environment-out-of-scope` → エポック順序。`create_environment` = role 規則 → `duplicate-environment` → `environment-out-of-scope`。`checkpoint` = role 規則 → 非空監査ヘッドの admin role → `unknown-environment` → `environment-out-of-scope` → `checkpoint-epoch-mismatch` → `checkpoint-regression`(段ごとに全タプルを走査 — stage-wise)
  - **検証状態**は現メンバーごとの scope を導出する(§6.3 のラップ先一致検査・宣言ヘッド時点の scope 検査・AUTH_SPEC §12-3 の認可の入力)。履歴索引はメンバーの在籍区間ごとに (role, scope) の変化点(seq)を保持する
  - **受信者集合 R(E)**(§6.3 / §7 / AUTH_SPEC §12-4 / §12-6 の 1 定義): 環境 E の DEK ラップの宛先の完全集合 = { 現メンバー m | E ∈ scope(m) } ∪ { 有効 `grant_server` g | E ∈ scope_environments(g) }。`grant_server` のサーバー鍵は自前の `scope_environments` を持つため ES の対象外であり、判定は受信者クラスを跨いで同一に適用する
  - **縮小は remove 相当(§7)**: `change_role` で旧 scope \ 新 scope が非空のとき、縮小分の各環境について `remove_member` と同じ `rotate_epoch` 義務を負う(合意規則ではなく §7 の義務 — `grant_server` の再 grant がスコープ縮小を合意規則で拒否するのと対照的に、メンバーの縮小は受理して義務を課す。招待のやり直し・在籍区間の分断を避けるため — 設計録 裁定 F)。拡大分は actor が全エポックの DEK をバックフィルする(AUTH_SPEC §12-6)
  - 本規則の導入(2026-09-14)は `add_member` / `change_role` の payload 形式変更であり、**導入前に受理された既存チェーンは新規則で無効になる**(互換条項を持たない — 2026-09-14 所有者裁定「利用者がいないうちは古い実装をすべて削除してよい」。既存プロジェクトは再作成する — 移行手順は docs/SELF_HOSTING.md "Updates" に K2〔設計録 §4 — 再作成が必要になる K2 のデプロイと同じ PR〕で追記する)。`chain-entries.json` は全再生成する(§11)

| op | payload | 権限 |
|---|---|---|
| `genesis` | プロジェクト作成者の公開鍵一式 | 作成者自身(owner・scope = all となる) |
| `add_member` | 対象 user_id、対象の enc/sig 公開鍵、role、**scope_kind、scope_environments_lp_hex** | admin 以上(admin / owner の付与は owner のみ)。対象 scope ⊆ actor scope |
| `remove_member` | 対象 user_id | admin 以上(admin / owner の削除は owner のみ)。対象の現 scope ⊆ actor scope。**対象の現 scope の全環境**の `rotate_epoch` を伴う(§7) |
| `change_role` | 対象 user_id、新 role、**scope_kind、scope_environments_lp_hex**(新 (role, scope) の全置換) | admin 以上(admin / owner が関わる変更は owner のみ)。権限変化の環境集合(role が変わるなら 旧 scope ∪ 新 scope、scope だけなら対称差 — 原則 1)⊆ actor scope。member 未満への降格は対象 scope の全環境の、scope の縮小は縮小分の環境の `rotate_epoch` を伴う(§7) |
| `create_environment` | 対象 environment_id、エポック 1 の dek_commitment_hex(§5.2) | member 以上・scope = all |
| `rotate_epoch` | 対象 environment_id、新エポック番号、理由、新エポックの dek_commitment_hex(§5.2) | member 以上・対象環境 ∈ scope |
| `grant_server` | サーバー鍵の公開鍵・フィンガープリント、許可スコープ(対象環境の部分集合を含む)、リースポリシー | owner のみ(明示操作) |
| `revoke_server` | 失効対象 | owner のみ |
| `checkpoint` | 環境ごとの (environment_id, epoch, manifest_version, manifest_sig_hash, values_digest) + 監査ヘッド累積ハッシュ(省略 = 空文字列。§6.2 の合意規則参照) | member 以上(非空の監査ヘッドを公証する actor は admin 以上)・全タプルの環境 ∈ scope |
| **`set_approval_policy`** | **対象 op 集合(ops_lp_hex)、必要承認数(required_approvals)** | **owner のみ。現方針が有効なら四眼の対象(下記)** |
| **`propose`** | **内側 op 名、内側 payload(inner_payload_lp_hex — 当該 op の正規化 payload_bytes)、期限(expires_at_ms)** | **内側 op を実行できる role(内側 op の規則で判定)** |
| **`approve`** | **提案エントリのハッシュ(proposal_hash_hex)** | **owner のみ(提案者と distinct。owner の提案は 1 票に数える)** |
| **`withdraw`** | **提案エントリのハッシュ(proposal_hash_hex)** | **提案者または owner** |

- **ES / PF1 の payload 正規化フィールド順(2026-09-14 — チェーン正規化ベクターで固定)**: `add_member` = `[target_user_id, enc_pub_hex, sig_pub_hex, role, scope_kind, scope_environments_lp_hex]`、`change_role` = `[target_user_id, new_role, scope_kind, scope_environments_lp_hex]`(いずれも既存フィールドの**末尾**に追加)、`set_approval_policy` = `[ops_lp_hex, required_approvals]`(`ops_lp_hex` = op 名リストの入れ子 LP の hex。順序は署名対象。生成はコードポイント昇順 SHOULD・検証は集合)、`propose` = `[inner_op, inner_payload_lp_hex, expires_at_ms]`(`inner_payload_lp_hex` = 内側 op の `payload_bytes` — §6.1 の入れ子 LP — の hex 小文字)、`approve` = `[proposal_hash_hex]`、`withdraw` = `[proposal_hash_hex]`(いずれも hex 小文字 64 = 提案エントリの entry_hash)
- **四眼(2026-09-14 PF1 — 複数署名承認。設計録 docs/notes/es-design.md §3)**: 危険操作を「提案 → 承認」の 2 段エントリで受理し、**distinct な owner の署名が必要承認数に達したときにだけ**内側 op が適用される。閾値署名・集約署名は導入しない(既存の Ed25519 署名を 2 エントリで数えるだけ)。合意規則:
  - **方針**: `set_approval_policy` は方針 { ops, required_approvals } を確立する。方針が一度も確立されていない(または `required_approvals = 0`)状態は**オフ**(既定 — 単独 owner のプロジェクトは何も変わらない)。`required_approvals` は 0(オフ)または 2 以上。**有効化・変更は、その時点の現 owner 数 ≥ required_approvals でなければ無効**(拒否理由 `approval-quorum-unreachable`)。`ops` は次の集合の部分集合でなければならない(構造検査 — `invalid-payload`): `grant_server` / `revoke_server` / `remove_member` / `change_role` / `add_member` / `set_approval_policy`。`create_environment` / `rotate_epoch` / `checkpoint`(データ・安全側の操作を止めない — rotate はインシデント対応であり遅らせてはならない)、`genesis` / `propose` / `approve` / `withdraw` は対象にできない。**方針が有効な間、`set_approval_policy` 自身と、owner role を確立する `add_member` / `change_role` は `ops` の列挙に依らず常に対象**(オフにするにも四眼が要る — でなければ四眼が無意味。owner を増やす op を四眼の外に残すと、owner 1 名が自分の第 2 の鍵対を owner として直接追記し、自作の 2 人目 owner で定足数を満たせる — 2026-09-14 pullfrog レビュー対応。`distinct` はチェーン上の身元であって人格ではないため、身元の追加経路そのものを四眼に入れる)
  - **到達可能性の不変条件**: 方針が有効な間、現 owner 数を `required_approvals` 未満にする op(owner の `remove_member`・owner から他 role への `change_role`)は無効(`approval-quorum-unreachable` — `last-owner-protected` の一般化。検査順序は各 op の末尾)
  - **原則 2 — 署名者集合による認可(2026-09-14 — 設計録 3-ter)**: すべてのエントリは**署名者集合 S** で認可される。直接追記では S = {actor}、提案経由では S = {提案者} ∪ {`approve` の actor 全員}。op に必要な承認数 `required(op)` は、方針が有効かつ op が対象なら `required_approvals`、それ以外は 1。エントリ(直接追記)または提案の適用は、`required(op) ≥ 2` のとき **適用時点で owner である S の distinct な要素数 ≥ required(op)** でなければ無効(原則 2 は `required(op) ≥ 2` のときに掛かる追加条件であり、`required = 1` の op は通常の role 規則〔S = {actor} が op の role を持つ〕のみで判定する — 非 owner の member / admin による直接追記を否定しない)。**不変条件(方針の単調性 — 2 つの帰結)**: 方針が有効な間、(a) 方針を変える op(`set_approval_policy`)と owner 身元を増やす op(owner role を確立する `add_member` / `change_role`)は `ops` の列挙に依らず常に対象、(b) owner 数を `required_approvals` 未満にする op(上記「到達可能性」)は無効 — 定足数未満の署名者で方針を弱める・迂回する経路を持たない。owner を減らす op は (b) で扱い、常時対象にはしない(`ops` に含めなければ直接追記できる — 上記「方針」・§14.2-10 と同じ集合)。以下の個別規則はこの原則と不変条件からの導出である
  - **対象 op の直接追記の拒否(導出)**: 方針が有効で対象の op を**直接**追記したエントリは S = {actor} で |S ∩ owners| ≤ 1 < required のため無効(拒否理由 `approval-required`。検査は role 規則の**直後**)。`propose` / `approve` が内側 op を評価する文脈では、内側 op は S を集めている最中なので本検査は**発生しない**(原則 2 の同一判定であり、例外規定ではない)
  - **`propose`**: actor は内側 op を通常の規則で実行できる role を持ち、内側 op はその時点の状態で合意規則(構造・認可・包含・最後の owner・到達可能性 … — ただし `approval-required` を除く)を満たさなければならない(満たさない提案は無効 — pending に積まない。理由コードは内側 op の理由をそのまま用いる)。`inner_op` は方針の対象(`ops` + 常時対象の op)でなければならない(`approval-not-required` — 対象外の op を提案しても意味を持たない)。`expires_at_ms` は非負の安全整数。提案は pending として検証状態に載る(識別子 = 提案エントリの entry_hash)。**方針がオフのときの `propose` は無効**(`approval-not-required`)
  - **`approve`**: actor はその時点の owner であること(`insufficient-role`)。参照先が pending の提案であること(`unknown-proposal` — 適用済み・撤回済み・未存在)。actor が当該提案に未投票であること(提案者が owner なら提案が 1 票 — `duplicate-approval`)。**`approve` エントリの `timestamp_ms` が提案の `expires_at_ms` 以下であること(`proposal-expired`)** — 本仕様で timestamp を合意規則に用いる**唯一の箇所**。`timestamp_ms` は承認者の自己申告(チェーンに単調性も上界もない)であるため、**期限は正直な承認者を文脈を失った承認から守る UX 上の安全装置であり、悪意の承認者に対する保証ではない**: 承認者が過去方向に時刻を詐称すれば期限切れの提案を承認できる(その承認者は owner として四眼の 1 票を正当に持つ主体であり、期限が守る対象ではない。2026-09-14 pullfrog レビュー対応 — 旧「拒否方向のみ = fail-closed」の主張は撤回)。§14.2-10 の保証は期限に依存しない。票数 = |S ∩ 適用時点の owners|(原則 2 の導出): **この `approve` エントリの actor 自身**(owner — role 規則で検査済み)に、**この `approve` エントリの時点でも owner である**過去の投票者(過去の `approve` の actor と、owner として提案した提案者)を加えた distinct な数。提案後に降格・削除された過去の投票者の票は数えない(過去の投票者の owner 資格を判定する状態は「今の `approve` エントリの適用前状態」— 2026-09-14 Cursor Bugbot 指摘対応: 投票者の owner 資格を投票時にだけ検査すると、残る owner 1 名が離脱済み投票者の票を使って完成できてしまう。owner 2 名・`required_approvals = 2` では「owner の提案 + 別 owner の approve」または「非 owner の提案 + owner 2 名の approve」で完成する)。票数が `required_approvals` に達したとき、**この `approve` エントリの seq で内側 op を適用する**(inclusive 規約 — `remove_member` の在籍終了・`change_role` の新 role / scope はこの seq で有効。§7 の rotate 義務・要ローテーション検出の起点もこの seq)。適用時は内側 op の合意規則を**適用時点の状態**で再検査し、加えて**提案者がその時点の現メンバーで、提案時と同じ鍵 FP を持ち、内側 op に必要な role を持つ**こと(拒否理由 `proposal-void` — 提案後に提案者が削除・降格・鍵変更された提案は完成できない)。適用時の検査に失敗する `approve` エントリは無効エントリであり、提案は pending のまま残る(`withdraw` で閉じる — 承認署名に「閉じる」効果を持たせない)。適用した内側 op の actor は**提案者**として扱う(在籍・帰属の記録)。**原則 1 との関係**: 内側 op の義務(rotate / バックフィル)の履行者は適用を完成させた承認者(owner = all)であり、原則 1 は構造的に満たされる。提案時・適用時に提案者の scope で行う原則 1 の検査は「提案者が直接追記できる op であること」の確認であり、履行可能性の担保ではない(提案後に提案者の scope が縮小していれば `scope-not-contained` で適用に失敗し、提案は pending に残る — `withdraw` で閉じる)
  - **方針変更と pending 提案の関係(2026-09-14 pullfrog レビュー対応)**: pending 提案は提案時の方針をスナップショットせず、**各 `approve` エントリの時点の現方針**で判定する — 必要承認数は現方針の `required_approvals`、内側 op が現方針の**対象**(`ops` + 常時対象の op — `propose` / 直接追記の拒否と同一の述語。常時対象の op は方針が有効な限り対象から外れない)でなくなっていれば(方針オフ、または常時対象でない op の `ops` からの除外)その `approve` は `approval-not-required` で無効となり、提案は pending のまま残る(`withdraw` で閉じる。対象外になった op は直接追記で実行できる — 常時対象の op にはこの経路はない。2026-09-14 Cursor Bugbot 指摘対応)。`required_approvals` の引き下げは pending 提案にも即時に効く(既に足りている票数で次の `approve` が完成させる)
  - **`withdraw`**: actor は提案者または owner。参照先が pending であること(`unknown-proposal`)。提案を closed にする(状態変化なし)
  - **検査順序**(理由コードごとベクターで固定): `set_approval_policy` = role 規則(owner)→ `approval-required`(現方針が有効なら直接追記は不可)→ `approval-quorum-unreachable`。`propose` = role 規則(内側 op の規則で判定)→ `approval-not-required` → 内側 op の合意規則(`approval-required` を除く — 内側 op の理由コード)。`approve` = role 規則 → `unknown-proposal` → `duplicate-approval` → `approval-not-required`(方針変更後の対象外 — 上記)→ `proposal-expired` → (定足数到達時)`proposal-void` → 内側 op の合意規則。`withdraw` = role 規則 → `unknown-proposal`
  - 検証状態は方針(ops・required)と pending 提案の集合(提案 hash → 提案者・内側 op・期限・投票者集合)を導出する。**pending 提案の件数上限は合意規則に置かない**(サーバー受理ポリシー — §6.4 / AUTH_SPEC §12-8)
  - 4 op の導入は「未知 op = チェーン無効」の下で全実装の同時更新を要するが、既存 op の payload 形式には触れない(ES の add_member / change_role 変更とは独立)。テストベクターは ES と同じ再生成に束ねる(§11)
- **メンバー鍵の一意性(2026-08-03 決定 — セッション 09 申し送りの検討結果)**: `add_member` は、対象の enc / sig 公開鍵の**いずれか**が現メンバー集合(genesis 由来の owner を含む、その時点の検証済み状態)のいずれかのメンバーの**同種**公開鍵と一致する場合、無効とする(拒否理由 `duplicate-member-key`)。規則の性質:
  - **判定単位は enc / sig の個別鍵**(鍵フィンガープリント = enc‖sig の一致ではない)。片方の鍵だけを流用したメンバーにも正当なユースケースがなく(v1 はデバイス鍵分離を持たず 1 ユーザー = 1 master keypair — §3)、sig 鍵の共有は「署名検証が通る主体が複数いる」多義性を、enc 鍵の共有は「同一鍵への複数ラップ」と削除・ローテーション意味論の濁りを生むため、強い側を採る。enc と sig の種類を跨いだ比較は行わない(X25519 と Ed25519 は用途が交わらず、混同による攻撃を構成できない)
  - **禁止範囲は現メンバー集合のみ**(チェーン履歴全体ではない)。`remove_member` 済みメンバーを同一 user_id・同一鍵で再追加すること(同一人物の復帰)は禁止しない。削除済みメンバーの鍵を別 user_id で再登録することも禁止しない — これは admin / owner が持つ「任意の公開鍵のメンバーを追加できる」権限の範囲内の行為と等価であり、鍵フィンガープリントがチェーンに残るため機械的に追跡可能で、ラップの帰属は §5.1 の signer_user_id 束縛が独立に守る
  - **検査順序**: role 規則(admin 以上・admin/owner 付与は owner のみ)→ 対象 user_id の重複(`duplicate-member`)→ 鍵の重複(`duplicate-member-key`)(2026-09-14 ES: この後ろに scope 系の検査 `unknown-environment` → `scope-role-mismatch` → `scope-not-contained` が続く — 上記「環境スコープ」の検査順序)。理由コードは合意規則の一部であり、順序は複合違反エントリのベクター(role → 鍵は negative `authz-add-member-role-precedes-duplicate-key`、user_id → 鍵は negative `authz-add-member-duplicate-user-precedes-key`)で固定する
  - これはチェーン有効性の**合意規則**であり、全実装(クライアント検証 §6.3・サーバー検証 §6.4)で一致させる。§5.1 の signer_user_id 束縛が塞いだ帰属付け替え(鍵流用ソック垢)の根本原因をチェーン層でも解消する防衛の多層化であり、「鍵 → 主体」の逆引きの一意性(§5.1 のクライアント検証・監査 UI・§6.3 のラップ先一致検査が依存する)を不変条件にする
  - 本規則の導入(2026-08-03)前に受理された既存チェーンは存在しない(公開前・適用済みチェーンなしの前提での導入)ため、後方互換の例外規定を持たない
  - `genesis` は最初のメンバーでありメンバー集合が空のため、重複は構造上生じない(規則は「現メンバー集合に対する検査」として全鍵登録経路で一貫し、genesis 由来の owner 鍵も以後の add_member の比較対象になる)。`grant_server` のサーバー enc 鍵とメンバー鍵の衝突は本規則の対象外(受信者クラスとフィンガープリント定義が別 — §9。owner 限定操作かつサーバー宛ラップは Phase 2 まで未実装)。**注意**: grant_server 自体は稼働済みの合意規則であるため、Phase 2 でこの衝突を合意規則として禁止する場合、それまでに受理されたチェーンへの後方互換条項(grandfathering)を要する — 本規則が「導入前に受理されたチェーンは存在しない」根拠で例外規定を省けたのと同じ論法は使えない(先送りのコストとして明記。2026-08-03)
- **環境ライフサイクルのチェーン束縛(2026-08-03 セッション 12 起草 — 合意規則)**: 環境の作成はチェーン op `create_environment` で行う(従来の「環境作成はチェーン op ではない」を改める。§5.2 のエポック 1 コミットメントの掲載場所を確保し、環境の存在自体をチェーン導出にするため)。合意規則:
  - `create_environment` の environment_id は**チェーン履歴全体で一意**とする(拒否理由 `duplicate-environment`)。削除済み環境の ID 再利用禁止(AUTH_SPEC §12-1)が、サーバー tombstone による受理ポリシーから**クライアントも検証できる合意規則へ昇格**する(環境の削除自体はデータプレーン操作のままであり、チェーンは削除を観測しない — 履歴全体一意ならそれで足りる)
  - `rotate_epoch` は当該 environment_id の `create_environment` がチェーン上で**先行していなければ無効**とする(拒否理由 `unknown-environment`)。従来の「チェーン受理は環境メタデータと突合しない」規則(AUTH_SPEC §12-4)は、環境の存在が可変のサーバーローカル状態からチェーン導出値に変わったことで、client-verifiable なまま置き換えられる(存在しない ID への rotate_epoch が ID を焼却するだけの従来挙動は廃止)
  - `create_environment` / `rotate_epoch` の `dek_commitment_hex` は hex 小文字 64 文字(形式検査は合意規則。コミットメントの**内容**はチェーン検証では検証不能であり、受信者の照合 — §5.2 — が担う)。形式検査は既存の payload 構造検査の段(固定長 hex フィールドの個別検査 — §6.1 の先例)に属し、**認可判定に先行する**(既存実装・ベクターの検証段順「構造 → actor → 署名 → 認可」を変更しない)
  - payload の正規化フィールド順(チェーン正規化ベクターで固定): `create_environment` = `[environment_id, dek_commitment_hex]`、`rotate_epoch` = `[environment_id, new_epoch, reason, dek_commitment_hex]`(既存 3 フィールドの**末尾**に追加)
  - 認可段の検査順序: role 規則 → `duplicate-environment` / `unknown-environment` → `environment-out-of-scope`(2026-09-14 ES — 上記「環境スコープ」)→ エポック順序(§6.3)。順序は理由コードごとテストベクターで固定する
  - 環境の**表示名・削除はチェーンに載せない**(名前は §4.2 の署名付きステートメント、削除はデータプレーンの admin 操作)。チェーンは鍵の真正性・認可の台帳であり、可変メタデータの台帳にしない(チェーン肥大の抑制。名前の rename をチェーン op にすると §6.4 のエントリ上限を表示編集が消費する)
  - チェーン容量への影響: `create_environment` は環境ごとに 1 エントリ(環境数上限は AUTH_SPEC §12-8 で tombstone 込み 1,000)、`rotate_epoch` への追加は 1 エントリ +64 バイト。§6.4 の 10,000 エントリ / 32 MiB に対して十分小さい
  - 本規則の導入前に受理された既存チェーンは存在しない(公開前・適用済みチェーンなし)ため、後方互換の例外規定を持たない(§6.2 メンバー鍵一意性と同じ前提)。初期エポック = 1・`rotate_epoch` の +1 規則(§3 / §6.3)は不変であり、エポック 1 の開始点が `create_environment` の seq として観測可能になる
- **grant_server payload のリースポリシー拡張(2026-08-12 起草 — §9.1 ワークロードリースの認可の真実源)**: `grant_server` の payload の正規化フィールド順を `[server_enc_pub_hex, server_key_fingerprint_hex, scope_environments_lp_hex, lease_policy_lp_hex]` とする。`lease_policy` は **issuer 汎用**のワークロード ID フェデレーション制約のリスト — 各要素 = `(issuer_url, audience, claim_constraints)`、`claim_constraints` = `(claim_name, claim_value)` の完全一致制約のリスト。正規化は scope_environments と同じ入れ子 LP(§2.1。リスト順は署名対象バイト列の一部。生成はコードポイント昇順・重複なしを推奨 — SHOULD)。空リスト(要素 0)は「リース経路なし」を意味する(grant はサーバー鍵宛ラップの登録のみを許す)
  - **合意規則が固定するのは構造のみ**: フィールド順・サイズ上限(issuer 要素 8 以下、issuer あたり claim 制約 8 以下、各文字列は §6.1 の 1024 バイト上限。要素数上限は、仕様適合 `grant_server` エントリの正規化サイズが §6.4 の受理ポリシー上限 1 MiB を数学的に下回り続けるように選ぶ — 同節のサイズ束縛の前提)。制約の**評価意味論**(v1 = 完全一致のみ、有効化 issuer = GitHub Actions のみ)は AUTH_SPEC §14 に置き、評価規則・対応 issuer の将来拡張はチェーン形式の変更を伴わない(= grandfathering を要しない)。ポリシー言語を合意規則へ持ち込まない
  - **アイデンティティ規則(§6.1)との関係**: claim_value に外部ネームスペースの識別子(例: `owner/repo`)が現れるのは**主体識別ではなく認可対象の記述**であり、「アクター = 内部 user_id + 鍵 FP のみ」の規則に抵触しない(アクターの識別は不変)
  - 本拡張は grant_server エントリを含む受理済みチェーンが存在しない公開前に行う(§6.2 メンバー鍵一意性と同じ前提で後方互換条項を持たない)。2026-08-03 に明記した「Phase 2 での改訂は grandfathering を要する」の先送りコストを、公開前に payload 形式を確定することで支払わずに解消する。既存の grant_server / revoke_server テストベクターは本改訂で全再生成する(§11)
- **サーバー鍵の一意性(2026-08-12 起草 — 2026-08-03 の先送り事項の解消)**: `grant_server` は、payload のサーバー enc 公開鍵が現メンバー集合のいずれかのメンバーの enc 公開鍵と一致する場合、無効とする(拒否理由 `duplicate-server-key`)。§6.2 メンバー鍵一意性と同じ動機(「鍵 → 主体」逆引きの一意性)の受信者クラス横断版。検査順序は role 規則 → 再 grant 規則(§6.3)→ 鍵重複とし、理由コードごとテストベクターで固定する。公開前導入のため後方互換条項を持たない
- **`checkpoint` op(2026-08-18 セッション 27 起草 — 未決事項 #4・#12 の解消、AUDIT_SPEC 未決 #2 と統合)**: クライアント(member 以上)が自分の検証済みビューのデータ状態ダイジェストをチェーンへ公証する op。実効権限 admin の発行者だけが、同じエントリでサーバー申告の監査ヘッドも公証する(それ以外は空文字列)。チェーンは既に「全員が検証する認証済みブロードキャスト」であり(§5.2 の掲載場所判断と同じ論法)、チェックポイントの最新性はチェーンヘッドの鮮度(床・帯域外アンカー・ヘッド申告 — §6.3 / §6.6)に還元される — これにより「巻き戻し検出機構自体が巻き戻される」再帰が止まる(検証連鎖の全体像はセッション 27 ノート §6)。合意規則:
  - payload の正規化フィールド順: `[environments_lp_hex, audit_head_hash_hex]`。`environments_lp_hex` は環境エントリのリストを §2.1 でネスト LP 化した hex 小文字文字列(scope_environments と同じ入れ子 LP)。各エントリ = `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex, values_digest_hex)`。**重複 environment_id を含む payload は無効(MUST — 下の合意規則の payload 構造検査)**: scope_environments(要素 = ID 単体で重複が情報を持たない)と異なり、本エントリはタプルを運ぶため、同一環境の 2 エントリを許すと §6.3 の基準・`checkpoint-regression` の比較対象が非決定になる(2026-08-18 pullfrog レビュー対応 — 重複を SHOULD に置かない)。リストの並びは environment_id のバイト昇順で生成する(SHOULD — 検証は順序を規範にしない)。要素 0(環境ゼロのプロジェクト)も有効
  - `values_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/env-values-digest", v_1, …, v_m)))`、`v_j = LP(variable_id, version, value_sig_hash_hex)`(variable_id のバイト昇順。**active 変数のみ** — tombstone はマニフェスト側 — §4.3 — が捕捉する。**status = declared の変数 — §4.2 レイアウト v2・値未設定 — も対象外とする(2026-08-30)**: 値が存在せず公証する座標がない。ステートメント自体はマニフェスト側が捕捉し、「declared に値が配布されないことは正当」の検証規則は §6.3)。`value_sig_hash_hex` = 当該 version の `value_signed_bytes`(§4.1)の SHA-256
  - `audit_head_hash_hex` = サーバー申告の監査ログ累積ハッシュ(定義は AUDIT_SPEC §5.1)、または**空文字列 = 監査ヘッドの公証なし**(発行者の実効権限〔min(トークンスコープ, チェーン role) — AUTH_SPEC §9-2〕が admin でなく監査ヘッド申告を取得できない場合 — AUTH_SPEC §16-2 のタイミングサイドチャネル対応 — と、監査行ゼロの場合を包含する。データ層の公証 — environments — は監査ヘッドと独立に有効)。**監査行数(seq)は payload に含めてはならない**: チェーンは reader を含む全メンバーへ配布され、監査 seq は無欠番の共有採番であるため、載せると admin 未満が可視性クラス 2(AUDIT_SPEC §6)の行数・活動量を確定推論できる(同 §7 の「件数にも漏らさない」規律との衝突)。累積ハッシュは乱数的で序数を運ばず、照合(AUDIT_SPEC §6)にも seq を要しない
  - 合意規則が検証するのは**形式・actor のチェーン role・座標整合**: payload 構造(hex 長・要素数・重複 environment_id の拒否)、**audit_head_hash が非空なら actor が当該エントリ時点で admin 以上であること**(拒否理由 `checkpoint-audit-role-insufficient`。API 受理面はさらにトークンスコープ admin を要求 — AUTH_SPEC §16-2)、各 environment_id の `create_environment` の先行(拒否理由 `unknown-environment` — rotate_epoch と同じ)、各環境エントリの epoch が**エントリ時点(自エントリ適用前)のチェーン導出現エポックと厳密一致**すること(拒否理由 `checkpoint-epoch-mismatch`。並行 rotate との競合は追記 CAS — §6.4 — が排除するため、正当な発行は常にこれを満たす)、**各環境エントリの manifest_version が、同一環境を含む直近の先行 `checkpoint` エントリの値以上であること**(拒否理由 `checkpoint-regression` — 悪意・過失のある member が古い状態を公証して床なしクライアントの検出基準を巻き戻す形をチェーン層で遮断する。manifest_version は payload の公開値でありチェーン検証だけで照合可能。epoch の非後退は上の厳密一致規則から自動的に従う。**発行クライアントはこの規則を満たすため、チェックポイント発行前にデータ層のビューを最新化する** — 直近チェックポイントより古いマニフェストしか持たない検証済みビューからの発行は無効エントリになる)。**環境集合は部分集合でよい**(全 active 環境のカバーを合意規則にしない — 環境作成との競合を作らず、環境単位の発行も有効。基準の解釈は §6.3)。`manifest_sig_hash_hex` / `values_digest_hex` / `audit_head_hash_hex` の**内容**はチェーン検証では検証不能であり(マニフェスト・値・監査行はチェーン外)、内容の検証はサーバー受理検証(§6.4)とクライアントの配布時照合(§6.3)が担う — §5.2 の「形式は合意規則、内容は照合側」と同じ線引き
  - 認可段の検査順序: role 規則(member 以上)→ 非空監査ヘッドの admin role(`checkpoint-audit-role-insufficient`)→ `unknown-environment` → `environment-out-of-scope`(2026-09-14 ES — 上記「環境スコープ」)→ `checkpoint-epoch-mismatch` → `checkpoint-regression`。順序は理由コードごとテストベクターで固定する
  - **境界チェックポイント(2026-08-19 セッション 32 — 環境作成・ローテーション複合への必須同梱。AUTH_SPEC §12-4)は本合意規則に例外を要しない**: 同梱 checkpoint は複合エントリ(create / rotate)の直後 seq に置かれ、エポック厳密一致は「エントリ時点(自エントリ適用前)」基準により同梱エントリ適用後の現エポック(create = 1 / rotate = new_epoch)と自然に一致する。`unknown-environment` も create の先行(直前 seq)で満たされる。合意規則面は M2 の周期チェックポイントと完全に同一
  - 検証状態は**最新チェックポイント**(seq・環境ごとの (epoch, manifest_version, manifest_sig_hash, values_digest)・audit_head_hash)を導出する(§6.3 のチェックポイント整合検証の入力)
  - サイズ上限: 仕様適合サーバーは削除済み環境のエントリを拒否し(§6.4)、アクティブ環境数を 100 以下に制限する(AUTH_SPEC §12-8)。したがって**サーバー受理ポリシーを通る** checkpoint の環境エントリ数は最大 100、最大形は約 50 KiB / エントリ(環境 100 × 約 450 バイト + 監査ヘッド 64 バイト。入れ子 LP の hex 化込み)で §6.4 の 1 MiB 上限を大きく下回る。推奨契機(§6.3 — 7 日ごと + rotate と再暗号化の完了後)に従う想定では、年間約 50〜100 エントリ、最大形でも約 2.5〜5 MiB/年であり、§6.4 の 32 MiB / 10,000 エントリに対して十分小さい(数値見積もりはセッション 27 ノート §8)。これはハード上限ではなく運用見積もりである。環境の削除はチェーンから導出できないため、「アクティブ 100」は合意規則の要素数上限ではなくサーバー受理ポリシー上の束縛である
  - **発行者はクライアントのみ(構造的必然)**: チェーン op は actor の Ed25519 署名を要し、サーバーは署名できない。「定期」チェックポイントはサーバー cron ではなくクライアント駆動である(発行契機は §6.3)
  - 本 op の導入は「未知 op = チェーン無効」の合意規則の下で全実装の同時更新を要する破壊的変更だが、公開前のため後方互換条項を持たない(§6.2 の先例と同じ前提)。**既存 op の payload 形式には触れないため、既存テストベクターの正規チェーンは有効なまま追記で拡張できる**(grant_server のリースポリシー拡張 — payload 形式変更 = 全再生成 — との違い。§11)

### 6.3 クライアント検証規則

- クライアントは同期時にチェーン全体(または検証済み位置からの差分)を検証する: prev_hash 連続性、署名、操作権限
- **エポック順序規則(2026-08-02 決定。2026-08-03 の環境ライフサイクル束縛 — §6.2 — に追随)**: `rotate_epoch` の `new_epoch` は「その環境の現エポック(`create_environment` 直後の初期値 1)+ 1」と厳密に一致しなければならない。巻き戻し(削除済みメンバーが保持する旧エポック DEK で新しい値が暗号化される)・重複・ジャンプ(member 権限の 1 署名でエポック空間を上限まで消費し以後のローテーションを不能にする DoS)をすべて拒否する。検証状態はエポックの現在値に加えて**各エポックの有効区間(開始 seq)**を導出する(§4.1 の値検証の入力になる)
- **再 grant 規則(2026-08-02 決定。2026-08-12 二層化)**: 有効な `grant_server` と同一サーバー鍵への `grant_server` は、**開示スコープ(scope_environments)については拡大(旧 ⊆ 新)のみ**受理する。縮小は `revoke_server`(§7 の全環境ローテーション義務を伴う)を経由しなければならない — ローテーションなしの縮小は、サーバーが既に知る DEK を「開示されていない」ように見せる見せかけの縮小になるため。一方、**リースポリシー(lease_policy — §6.2)は再 grant で自由に改訂できる(縮小・全削除を含む)**: ポリシーはリース経路(§9.1)の ACL であり、サーバーの既知 DEK 集合を変えない。締め付けに全環境ローテーションを課すと、誤設定の是正・リポジトリ移転などの正当なポリシー修正のコストが不当に高くなり、修正しない方向へ倒れる。二層の判定はフィールドごとに独立して行う
- **DEK のラップ先はチェーン導出の受信者集合 R(E)(§6.2 — scope 内の現メンバー + 開示スコープ内の有効な grant_server)と厳密に一致しなければならない(2026-09-14 ES 改訂 — 旧「チェーン上の現メンバー(+ 有効な grant_server)」の環境軸版)**。チェーンにない公開鍵へのラップの生成・受理は禁止(ゴーストメンバー攻撃対策)。scope 外のメンバー宛のラップの生成・受理は禁止(ゴーストメンバー対策の環境軸版)。**受信側**: 自分宛のラップで環境 ∉ 自分の scope のものは、開封できても**使用せず警告する**(サーバーが AUTH_SPEC §12-6 の受理規則を執行していない証拠。当該環境への書き込みは scope 外として全検証者が拒否するため実害は「読める」に限られるが、規範として使わない)。サーバー鍵宛ラップの登録経路・完全一致判定は AUTH_SPEC §12-4 / §12-6(2026-08-12 改訂 — 旧「v1 は登録経路を持たない」線引きの解消。完全一致の対象は現メンバー集合 + 開示スコープ内の有効な grant_server のサーバー鍵)。応答スコープのリースラップは本規則の対象外(§9.1 の線引き)
- **DEK コミットメント照合(2026-08-03 — §5.2)**: ラップの Open 後・DEK の使用前に、チェーン導出の (environment_id, epoch) コミットメントと照合する(必須)
- **値・メタデータステートメントの検証(2026-08-03 — §4.1 / §4.2)**: クライアントは配布された値・メタデータステートメントについて以下を検証する。「宣言ヘッド時点の状態」とは、seq = `chain_head_seq` のエントリまで**適用済み**(inclusive)のチェーン導出状態を指す(`create_environment` / `rotate_epoch` エントリ自身を宣言ヘッドとする直後の push は正当フローとして必然的に発生する — off-by-one の実装差は正当データへの検証分裂になるため、ベクターで固定する。メンバー在籍区間の境界 — add / remove エントリ自身をヘッドにする署名 — にも同じ inclusive 規約を適用する):
  1. **署名**: 配布された writer / author の user_id と鍵フィンガープリントから、検証済みチェーン履歴でその user_id に束縛された sig 公開鍵のうち、フィンガープリントが一致し**かつ宣言ヘッド時点でその user_id に有効に束縛されていた**(宣言ヘッドを含む在籍区間の鍵である)ものを選択して署名を検証する(remove → 別鍵で re-add された user_id における、区間を跨いだ鍵とヘッドの組合せを拒否する。§5.1 の選択規則にヘッド時点の束縛条件を加えたもの)。署名者がその後削除されていても、過去の正規な書き込みは当時の鍵で検証できる
  2. **ヘッド束縛**: `chain_head_hash_hex` が、自分の検証済みチェーンの seq = `chain_head_seq` のエントリハッシュと一致すること。不一致は 2 種を区別する(チェーン fork 時の挙動の規定): (a) `chain_head_seq` が自分のヘッド以下なのにハッシュ不一致 = **チェーン分岐(equivocation)または偽造の硬い証拠** — 即時拒否 + 警告。(b) `chain_head_seq` が自分のヘッドより先 = 自分のチェーンが古いだけの可能性がある(正直サーバーでも同期と取得の間に他メンバーの追記が挟まれば起きる)— まずチェーンを再同期・再検証し、自チェーンの延長として一致すれば正常受理、再同期しても一致しなければ (a) と同じ扱い
  3. **認可時点**: 宣言ヘッド時点のチェーン導出状態で、writer / author が当該操作の必要 role(§4.2 / AUTH_SPEC §12-3 の表)を持つこと。削除済みメンバーの鍵による署名は、宣言ヘッドが在籍区間内にある場合のみ通る — これが「登録時点の在籍」をクライアントが検証できる根拠である(残余は §14.3)
  4. **エポック整合(値のみ)**: 署名対象の epoch が、宣言ヘッド時点の当該環境の現エポックと一致すること(push は現エポックのみ受理 — AUTH_SPEC §12-5 — のため、正規の書き込みは常にこれを満たす。削除済みメンバーの鍵で現エポックの値を偽造する経路を塞ぐ: 削除は対象の scope の全環境のローテーションを伴う — §7。scope 外の環境には対象の署名座標がそもそも存在しない〔3′〕— ため、削除済みメンバーの在籍区間に、現在の現エポックが当時の現エポックだったヘッドは存在しない)。宣言ヘッド seq が当該環境の `create_environment` の seq より**前**である値署名は無効(環境未存在でエポックが定義されない — 既定値へのフォールバック実装を禁止する)
  5. **座標整合**: 署名対象の座標(project / environment / variable / version / epoch、値は nonce / ciphertext も)が、要求文脈・申告 AAD・受信ペイロードと一致すること(サーバー申告値の再構成ではなく、期待座標からの再計算 — セッション 11 の CLI 検証と同じ姿勢)
  6. **連鎖整合**: `prev_*_hash` が、既知の直前 version / meta_version の signed_bytes ハッシュと一致し、値については epoch が直前 version から**非減少**であること(§4.1 のエポック単調性)。直前を保持しない初回同期・latest-only 取得では検査対象が存在しない(その場合に何が保証されないかは §14.3)
- **スコープの認可時点検査(2026-09-14 ES)**: 値・メタデータステートメント・マニフェストの検証(1〜6)に **scope の認可時点検査**を加える: **3′. スコープ(環境対象の署名)**: 宣言ヘッド時点のチェーン導出状態で、writer / author / issuer の scope が当該 environment_id を含むこと(拒否理由 `writer-environment-out-of-scope-at-head` / `author-environment-out-of-scope-at-head` / `issuer-environment-out-of-scope-at-head` — 3 の role 検査の直後)。環境メタステートメント(rename / delete)・変数メタステートメント・マニフェストはすべて環境対象であり対象になる。環境作成複合の同梱ステートメント / マニフェストは、宣言ヘッドが追記前ヘッド(AUTH_SPEC §12-4)で環境未存在だが、作成者は scope = all(§6.2)であるため空虚に成立する
- **スコープ外環境の扱い(2026-09-14 ES 改訂 — 設計録 裁定 G)**: メンバーは scope 外の環境について、チェーン(全エントリ — 当該環境の `checkpoint` タプルを含む)・環境の存在・表示名・変数名・スキーマ欄・マニフェスト・tombstone(平文メタ = 未決 #3 の線)を受け取り検証できる(メタのみ pull — AUTH_SPEC §12-7)。暗号文・自分宛 DEK ラップは受け取らず、書き込み・rotate・checkpoint はできない。**環境横断の検証**: (i) `checkpoint` の scope 外環境のタプルは合意規則(§6.2)として検証するが、チェックポイント整合の**基準には用いない** — 基準は自分が値付き pull する環境にしか要らない、(ii) マニフェスト検証は pull した環境のみ(不変)、(iii) ヘッド申告・招待リンクアンカーは環境を持たず不変。リポジトリアンカーの環境ごとのエポックはチェーン導出値であり scope 外環境についても書ける(不変)、(iv) ローカル床は「検証に成功した事実の join」であり scope 外環境の床は確立されないだけ(拒否・警告の対象にならない)
- **検証状態の四眼(2026-09-14 PF1)**: 検証状態に四眼の方針と pending 提案を含める(§6.2)。クライアントは自分の scope・方針を検証済みチェーンから導出し、操作の前に scope 外・提案要の操作を型付きエラー / 提案の作成として扱う(サーバーの 403 を待たない)
- **active ステートメントの値配布要求(2026-08-30 セッション 46 — §4.2 レイアウト v2 の `declared` 導入と同時の明文化)**: 値付き配布(一括 pull・リース応答)において、`status = "active"` の検証済みステートメントを持つ変数の値(最新バージョン)が配布されないことは、値の欠落(G6)として拒否する。**`status = "declared"` のステートメントに値が配布されないことは正当**(値未設定の唯一の表現 — 値・バージョンは存在しない)。従来この検査は「値のない変数は存在しない」(AUTH_SPEC §12-5)の含意として暗黙だったが、declared の導入で「値がない」が正当になりうるため、明示の検証規則へ昇格する — これにより「required だが未設定」の判定(§14.2)は署名済みステートメント + マニフェスト被覆だけから行え、サーバー申告に依存しない
- **環境マニフェストの検証(2026-08-18 — §4.3。2026-08-19 セッション 32 でエポック整合を改訂)**: クライアントは配布された環境マニフェストについて、上記 1〜3・5 と同型の署名・ヘッド束縛・認可時点・座標の検証、エポック整合(§4.3 検証規則 (2) — 当該 (environment_id, manifest_version) の `checkpoint` タプルが検証済みチェーン上に存在すればその (epoch, manifest_sig_hash) と完全一致必須、存在しなければ宣言ヘッド時点の現エポックとの strict 一致)、および配布された全ステートメント(tombstone 含む)からの variables_digest 再計算一致を検証する。**ダイジェスト不一致・マニフェスト欠落(サーバーがマニフェストを配布しない)は、ステートメントの欠落・注入・マニフェスト隠しとして一律に拒否する** — 「未初期化」の警告格下げ分岐は置かない(2026-08-18 pullfrog レビュー対応: クライアントは「本当に未初期化」と「サーバーが握り潰した」を区別できず、分岐は攻撃者が選べる緩和経路になる。環境作成複合が manifest_version 1 を必須同梱する — AUTH_SPEC §12-4 — ため仕様適合の環境に未初期化状態は構造的に存在せず、公開前導入〔後方互換条項なし — §6.2 の前提〕により分岐が守る対象も存在しない。導入前に作成された内部ドッグフーディング環境の初期化は実装 PR の移行手順 — セッション 27 ノート §14。**移行の明示初期化操作(2026-08-18 明確化 — PR-M1)**: 初期化はメンバーの明示操作 `maruhi env rotate --init-manifest` によるローテーション複合で manifest_version 1 を発行する — AUTH_SPEC §12-5 (6) の CAS 初期値。このフラグが緩めるのは**欠落の許容のみ**であり、マニフェストが配布された場合の検証は一切緩和しない。またローカル床にマニフェスト記録が確立済みの環境に対する欠落は、移行操作下でも握り潰しの証拠として拒否する — 初期化済みマニフェストが消える正当な経路は存在しない)
- **チェックポイント整合(2026-08-18 — §6.2 `checkpoint`)**: 環境ごとの基準は、検証済みチェーン上で**その環境のエントリを含む最新の `checkpoint`**(チェックポイントは環境の部分集合を公証できる — §6.2)。基準を持たない環境(一度もチェックポイントされていない・チェックポイント後に作成された)は本検証の対象外である(その環境の保証は床・マニフェストのエポック整合のみ)— ただし**床を持たないクライアント(特にワークロード — §9.1)は、値付き配布を受けた環境に基準が存在しないことを検出したら警告する(SHOULD。2026-08-18 pullfrog レビュー対応)**: 基準の有無は検証済みチェーンからサーバー非依存に判定でき、不在の黙認はこのクラスの主要保証(本検証)が働いていないことの不可視化になる。基準の常在はカバー範囲の発行規範(下の発行 SHOULD)が担う。基準に対してクライアントは以下を検証する:
  1. **マニフェストの非後退**: 配布された環境マニフェストの manifest_version が基準の値以上であり、等しい場合は signed_bytes ハッシュが一致し、**かつマニフェストの epoch が基準の epoch 以上**であること。version の後退・同版でのハッシュ不一致・エポックの基準割れは、チェックポイント済み状態からの巻き戻し・分岐・旧エポック鍵による前進注入として拒否する(チェーン自体の鮮度が床・アンカーで担保されている限り、床を持たないクライアントにもチェックポイント時点までのメタ状態の完全性 + エポック基準による前進注入検出が届く — これが #12 の眼目)
  2. **値の非後退**: 値付き配布(一括 pull・リース応答)に同梱される「チェックポイント時点の値スナップショット列挙(variable_id, version, value_sig_hash — AUTH_SPEC §12-7)」のダイジェストがチェーン上の values_digest と一致することを照合した上で、**基準チェックポイントを持つ環境の値付き配布がスナップショット列挙を欠く場合は拒否する**(2026-08-18 pullfrog レビュー対応 — 基準の存在は検証済みチェーン上のエントリからサーバー非依存に判定でき、列挙の省略を「規則 2 のスキップ」に落とす読みは本検査の無効化経路になる)。配布された各変数について: version がスナップショット以上・等号なら value_signed_bytes ハッシュが一致し、**スナップショットより新しい version の epoch が基準の epoch 以上**であること(§6.3 床規則 (c) のチェックポイント版 — 基準時点が「最後に成功した pull」でなく「チェックポイント発行」になった形。床を持たないクライアントへの前進注入検出はこれが担う。基準時点の正当性の論証は床規則 (c) と同じ: チェックポイント受理後に受理される正規 push は当時の現エポック = 基準 epoch 以上でしか起きない)。スナップショットに存在して配布に存在しない変数は、検証済み tombstone(マニフェスト整合込み)で削除が説明されない限り欠落として拒否する。スナップショットに存在しない配布変数はチェックポイント後の正当な作成でありうる(マニフェスト整合とエポック基準 — 床規則 (c) の「version 0 相当」と同型 — で検証する)
  3. audit_head_hash はクライアント同期では検証しない(監査行はこの経路で配布されない。照合は監査全行を読める admin の突合 — AUDIT_SPEC §6)
- **境界チェックポイントの必須同梱(MUST。2026-08-19 セッション 32 — session-31 M1-A6 の解消)**: 環境の作成・`rotate_epoch` の複合(AUTH_SPEC §12-4)は、**当該環境 1 タプルのみ**をカバーする `checkpoint` エントリを複合エントリの直後 seq に必須で同梱する。タプルは同梱マニフェストの (epoch, manifest_version, manifest_sig_hash) を束縛し、values_digest は作成では変数空集合、ローテーションでは受理時点の現在値(未再暗号化 = 旧エポックの値 — AUTH_SPEC §12-7 の正当な状態)から構成する。カバーを当該環境に限るのは監査規律による: rotate 実行者は再暗号化義務(§7)により当該環境の全現在値を必ず実読する(その `var.read` は真実の記録)が、他環境の値は読まないため、全環境カバーをここに課すと読んでいない値の取得を強制する。周期チェックポイント(下記 SHOULD)の全環境カバー推奨は従来どおり。MUST 同梱を緩める退避(checkpoint なし複合)は設けない — §4.3 検証規則 (2) の束縛経路が空くため(session-32 §5-1 の liveness 評価も参照)
- **チェックポイントの発行(SHOULD — 周期チェックポイント。境界チェックポイント〔上記 MUST — 複合の必須同梱〕とは別区分。2026-08-19 セッション 32 で 2 区分へ改訂)**: member 以上のクライアントは、(i) `rotate_epoch` **とそれに伴う現在値の再暗号化(§7)の完了後**(本 (i) は**再暗号化完了後のデータ状態〔新エポックの値〕を公証する周期分**にのみ係る — 境界分は複合に同梱済みで、突合基準が複合の適用後状態 — §6.4 — のため受理時点一致検査との自己競合は生じない。周期分を再暗号化 push の集中区間中に発行すると受理時点一致検査 — §6.4 — と自己競合するため完了後に発行する。再暗号化の writer はローテーション実行者自身 — §4.1 — なので、同一クライアントが rotate〔境界分同梱〕→ 再暗号化 → 周期 checkpoint を直列化すれば衝突しない。2026-08-18 pullfrog レビュー対応)、(ii) 明示操作、(iii) push / pull 成功時に「基準チェックポイントから 7 日超経過または未発行」を検出した場合の提案、を契機に `checkpoint` エントリを発行する(頻度の起草値。§6.2 のサイズ束縛の前提)。**(iii) の基準は発行者の実効権限(min(トークンスコープ, チェーン role) — AUTH_SPEC §9-2)で分かれる(2026-08-18 レビュー第 5 ラウンド対応)**: 実効権限 admin のクライアントは「最新の**公証あり**(audit_head_hash 非空)チェックポイント」、それ以外は「最新のチェックポイント」を基準に評価する — 分けないと、member の発行(公証なし)が admin 側の契機を潰し続け、公証済み接頭辞が前進しなくなる(AUDIT_SPEC §6 の残余明記も参照)。発行者は**発行の直前にデータ層のビューを最新化した上で**、自分の検証済みビューからマニフェスト参照・values_digest を組み立てる(サーバー申告値をそのまま署名しない。ビューが古ければ合意規則 `checkpoint-regression` — §6.2 — と受理検証 — §6.4 — が拒否する。競合による 422 の再試行は**〔監査ヘッドを公証する場合は申告の取り直しを含めて〕**有界とする — 上限・バックオフは実装の裁量。SHOULD を無限再試行に読み替えない。**有界再試行を使い切った場合は、受理時点一致が確認できた環境の部分集合で発行してよい** — §6.2 は部分集合を有効とし、部分基準は基準ゼロより厳密に強い。2026-08-18 pullfrog レビュー対応)。**カバー範囲は検証済みビュー内の全環境とする(SHOULD。2026-08-18 pullfrog レビュー対応)**: §6.2 の部分集合許容は環境作成との競合を合意規則にしないための線であって、発行者が操作した環境だけを公証してよいという意味ではない — 対話的同期が定期的に走らない環境(ワークロード専用等)のカバレッジは、他環境の操作に相乗りする全環境公証でしか確保されない。ただし**検証済み削除ステートメント(§4.2 の status = deleted)のある環境は含めない**(削除済み環境のマニフェスト・値・スナップショットは存在せず — AUTH_SPEC §12-4 のカスケード — 公証する状態がない。受理面は §6.4)。audit_head_hash は、**発行者の実効権限が admin の場合に**サーバー申告値を「発行時未検証の公証」として写す(SHOULD。意味論は §6.4。虚偽申告の固定が事後改竄の検出材料になる — AUDIT_SPEC §6。**申告の取得はチェーンヘッド〔CAS 親〕の確定より後に行う** — 先に取得すると、間に着地した他者の checkpoint により受理段の位置下限〔audit-head-stale〕へ落ちる。後に取得すれば競合は CAS 409 が先に吸収し、audit-head-stale は正直なクライアントに事実上到達しない = サーバー不正の signal に純化される。2026-08-18 pullfrog レビュー対応)。実効権限が admin でない発行者は空文字列(公証なし)とする — 監査ヘッド申告の取得は実効権限 admin 限定である(AUTH_SPEC §16-2 のタイミングサイドチャネル対応)
- **ローカル床(SHOULD。2026-08-19 セッション 32 改訂 — session-31 裁定 3: 定義を「検証済み観測の単調 join」へ一般化し、保存形を追記専用ログにする。設計比較は session-31 §7 裁定 3 / session-32 §4-3・§5-3)**: 永続状態を持てるクライアントは、**これまでに検証へ成功した事実の単調 join(結合半束)**を床として**非機密ローカル状態**に保持する —「最後に成功した pull のスナップショット」ではない。対象の事実: 検証したチェーンヘッド(hash + seq)、変数ごとの最新 (version, **その version の epoch**, meta_version, 最新 version の signed_bytes ハッシュ, **最新 meta_version の signed_bytes ハッシュ**)、環境ごとの環境メタステートメントの最新 (meta_version, signed_bytes ハッシュ)と環境マニフェストの最新 (manifest_version, その epoch, signed_bytes ハッシュ)(2026-08-18 — §4.3)、および環境ごとの値規則 (c) の pull 基準(下記)。記録規則はただ 1 つ: **検証に成功した事実は必ず join する。値床は値を実際に検証した場合のみ記録する(捏造しない)** — 契機は列挙ではなく、metadata-only pull(AUTH_SPEC §12-7 — 環境水準の事実のみ)、環境作成・ローテーション複合の受理確認(チェーン同期 — AUTH_SPEC §12-10 (3)。同梱エントリ + 境界チェックポイントが manifest_version + ハッシュの床コミット材料を運ぶ)、値付き pull のすべてが同じ規則で join する。エポック観測は**型付きの 2 座標**として分けて join する: (i) **値規則 (c) の pull 基準** — 値床カバレッジと原子的に確立された観測のみが前進させる(規範 — 下記)、(ii) **環境水準のエポック観測** — マニフェスト規則 (c) baseline・巻き戻し / equivocation 検出に使い、出所を問わず join する(こちらは値を誤拒否する経路を持たない)。同座標で比較不能な事実(同一版・異ハッシュ)には join が定義されない = typed conflict として証拠化する(下の規則 (b) がマージ意味論そのものになる)。この床に対して、次を検出したら拒否・警告する(SHOULD): (a) チェーンの短縮、version / meta_version(変数・環境)/ **manifest_version** / エポックの後退、削除の無断取り消し、(b) 床と同一 version / **同一 meta_version(変数・環境)/ 同一 manifest_version** に対する signed_bytes の相違(内容差し替え・分岐の証拠。メタ側ハッシュの保存は本規則のメタ適用に必要 — 2026-08-04 セッション 16)、(c) **床の version より新しい version の epoch が、当該環境の pull 時点エポック床より小さい**こと(その pull 以降に受理された正規 push は当時の現エポック以上でしか起きない — 削除済みメンバーの鍵による「前進 version への旧エポック注入」の検出。§14.3-5。**床にない変数は version 0 相当として本規則を適用する**: 床の存在する環境で床にない変数の配布が pull 時点エポック床未満の epoch を持つ場合も拒否する — 前回成功 pull 以降の正当な作成の epoch は作成時点の現エポック ≥ 基準であり、基準未満の「新規」は旧エポック鍵による backdated 作成の形である。2026-08-04 セッション 16。**床の manifest_version より新しいマニフェストの epoch が pull 時点エポック床より小さい配布にも同型に適用する** — メタ層の前進注入の床検出。2026-08-18 §4.3。**マニフェスト適用の基準は「pull 時点エポック床」と「床マニフェスト自身の epoch」の大きい方とする(2026-08-18 明確化 — PR-M1 レビュー)**: マニフェスト連鎖のエポックは非減少(§4.3 の epoch-regressed 検証)なので、床が検証済みの epoch E のマニフェストを持つ以上、より新しい manifest_version の正当な配布の epoch は E 以上でしかありえない(推移形 — 誤検出を生まない)。pull 時点エポック床だけを基準にすると、rotate 複合の受理直後(受理マニフェストの床昇格は行うが pull 基準は次の pull まで動かない)や有界再同期の形(基準は応答取得前ビュー)で、床が知っている epoch より古い焼き込みの前進 manifest_version が素通りする)。**規則 (c) の基準はチェーン同期単独で前進させてはならない**: チェーン同期で知った新エポックを pull を経ずに基準へ昇格させると、「ローテーション後・再暗号化完了前」の正当な最新値(旧エポックのまま — AUTH_SPEC §12-7)を誤拒否する。逆に基準の定義を持たない実装は永続床の読み違いで検出を失う — この基準時点は規範である(セッション 12 ノート §12 ループ 2)。更新順序: pull で受信した値は**前回成功 pull の基準**で検証し、pull 基準の前進(今回のチェーン導出現エポックへ)は検証成功後に値床と原子的に join する。**保存形(2026-08-19 — 追記専用観測ログ)**: 床は「検証済み観測の追記専用ログ(1 観測 = 1 レコード)と、その fold として導出する join」で保持し、上書き更新の保存形(読み・merge・書き戻し)を用いない。追記は追記モード(O_APPEND 相当)のみで行い、破損した末尾レコードは fold が無視する(自己回復)。並行プロセスの観測は両方ログに残り、同座標 conflict は fold 時に typed conflict として顕在化する — **上書きによる証拠喪失を「禁止」から「表現不能」へ格上げする**(メンバーシップチェーン・監査ログに続く append-only 構造の 3 例目。プロセス間ロックを証拠保全のクリティカルパスに置かない)。コンパクションは「現在の fold 結果 + 畳んだ接頭辞の終端位置」を**スナップショットレコードとして追記**する形でのみ行い(契機 = 最新スナップショットレコード以降に積まれた相対量の閾値超過。fold = 最新スナップショット ⊔ それ以降の全レコード。位置情報の欠損・破損時は全レコード fold へフォールバックしても join の冪等性・可換性により正しさは変わらない)、書き直し・切り詰め・物理回収は行わない(物理回収はチェックポイント基準への接続 — §6.2 — と同時に設計する)。同座標 conflict の証拠レコードはスナップショットに畳まれても消えない。**記録規律(journal-before-release / journal-before-send)**: (i) 検証済み事実の追記(永続化 = fsync 相当まで)を、値・DEK の解放・床検査合格の使用・成功報告のすべてに先行させる(SHOULD —「検証したのに記録前に中断した」窓を閉じ、記録漏れの失敗方向を「観測が残りすぎる」安全側に固定する)。(ii) security-critical mutation(AUTH_SPEC §12-10)の**送信前**に intent レコード(op 種別・environment_id・manifest_version + signed_bytes ハッシュ・宣言ヘッド — 非機密のみ)を追記し、効果確認(AUTH_SPEC §12-10 (3))の成功で resolution レコードを追記して閉じる(SHOULD)。intent は検証済み事実ではないため join の格子に入れない(記録クラスを分け、fold は未解決 intent を「要照合」として表面化する)。未解決 intent を持つクライアントは、同一環境への次の mutation・成功報告の前に照合(チェーン同期 / metadata-only pull)で解決する — クラッシュ・応答消失で失われるのは「成功したという思い込み」ではなく「確認義務の記録」になる。保存するのはハッシュ・連番・op 種別のみで、平文値・鍵素材を含まない(CLI のディスクレス不変条件と両立する。CLI 実装は PR #33 = セッション 16 — 本改訂の join・追記専用ログへの移行は実装 PR〔session-31 §6 PR-F2〕の対象。メタの床は巻き戻し・同一 meta_version の相違検出のみで、前進注入は検出されない — §14.3-5。マニフェスト層の前進注入検出は §4.3 が担う)
- **帯域外アンカー(SHOULD。2026-08-12 起草)**: 床を持たない初回同期クライアント(§14.3-3 の支配的残余)のうち、**既存の帯域外チャネルを持つ 2 クラス**に、チェーンアンカーの運搬を規定する:
  - **(a) 招待リンクアンカー(2026-09-13 IV 改訂)**: 招待リンク(AUTH_SPEC §15)は、リンク鍵の種(§6.5)に加えて genesis ハッシュ(= project_id)・招待作成時点の招待者の検証済みヘッド(hash + seq)・付与予定 role・**scope**(2026-09-14 ES — §6.5)・招待者の user_id と **enc / sig 公開鍵**を、**クライアント側エンコード(URL フラグメント)**で運び、これら全体に対する招待者の**発行署名**(§6.5)を併載する。リンクは招待者から相手へ人対人チャネルで渡り、サーバーはフラグメントを観測も改変もできない。受諾クライアントは発行署名を招待者の sig 公開鍵で検証してから(失敗 = 受諾しない)、アンカーを非機密ローカル状態(ローカル床と同じクラス)へピン留めし、初回同期では genesis が一致し、**ピン留めヘッドを当該 seq に含み、かつ当該 seq 時点のチェーン上で招待者 user_id に束縛された sig 公開鍵がリンクの `is` と一致する**チェーンのみを受理する(SHOULD)。招待者 FP(`ie` ‖ `is` から §3 のとおり導出)は相互確認(§6.5)の照合材料になる。発行署名により、リンク経路上の改竄(ヘッド・role・scope・招待者鍵の差し替え)と、第三者が招待者の**公開**鍵を自分のチェーンへ追加して招待者名義のリンクを作る形(ゴースト追加)は、いずれも受諾前に検出される
  - **(b) リポジトリアンカー**: プロジェクトのソースリポジトリへコミットする非機密アンカーファイル(genesis ハッシュ・検証済みヘッド hash + seq・環境ごとの「その時点のチェーン導出現エポック」)。ワークロードリース(§9.1)の受信クライアントは、チェーン検証に加えて「アンカーのヘッドを含み、環境エポックがアンカー以上」のビューのみを受理する(SHOULD)。CLI は `rotate_epoch` / push の成功時にアンカーファイルの更新を提案する。内容はハッシュ・連番・エポック番号のみで平文値・鍵素材を含まない(CLI のディスクレス不変条件と両立)。CI という「床なし・自動・無人」の最弱クライアントに対する巻き戻し配布(例: インシデントローテーション後に旧ビューを配布し、漏洩済み credential を再デプロイさせ続ける)を検出可能にする
  - 位置づけ: 旧未決 #4(チェーンヘッドの外部チェックポイント)の部分的実現(2026-08-12)であり、§14.3-3 の残余を「帯域外チャネルが既に存在する経路」から順に狭める。**データ層の網羅的な検出は `checkpoint`(§6.2)とチェックポイント整合(本節)が担う(2026-08-18 — 旧未決 #4/#12 の解消)**: アンカーがチェーンヘッドの鮮度を、チェックポイントがそのヘッドの下のデータ状態を固定する分担(検証連鎖の全体像はセッション 27 ノート §6)
- **ヘッドゴシップ(分岐攻撃対策。2026-08-18 セッション 27 で具体化 — 申告の形式・検証は §6.6)**: 書き込みについては §4.1 / §4.2 のヘッド束縛が申告ヘッドの受動的な運搬役を兼ねる(書き込みに埋め込まれたヘッドは他メンバーの検証で照合される)。これに加えて、全メンバー(reader を含む — 認可モデル導入により書き込みをしないメンバーが常在するため。2026-08-01 追記)はチェーン同期 + 検証の成功後、検証済みヘッドが前回申告より前進していれば署名付きヘッド申告(§6.6)を提出し(SHOULD)、サーバーは現メンバーの最新申告集合をチェーン取得応答で相互配布する。クライアントは配布された各申告を検証(§6.6)した上で自ビューと照合し、矛盾は 2 種を区別する(上記 2 のヘッド束縛照合と同型): (a) 申告 seq が自ヘッド以下でハッシュ不一致 = **分岐(equivocation)または偽造の硬い証拠** — 当該同期の成果物の使用を中断して警告し、証拠(申告 + 自ビューのチェーンダイジェスト)を非機密ローカル状態へ保存する(§14.2-5 の証拠化)。(b) 申告 seq が自ヘッドより先 = 自分のチェーンが古いだけの可能性 — 再同期・再検証して自チェーンの延長として解決すれば正常、解決しなければ (a)。**検出の限界(規範的な非保証)**: サーバーは申告の配布を選択的に省略・停滞できる(omission は G8 に帰着し防止不能)ため、能動的な悪意サーバーに対する保証付きの split view 検出ではない — 得られるのは検出可能性(攻撃者に継続的・完全な omission を強いる)と、交差配布された矛盾申告の否認不能な証拠化である(§14.3-4。帯域外アンカー・チェックポイントとの合成でこの残余を狭める — セッション 27 ノート §2 / §6)
- ~~将来オプション: チェーンヘッドの外部チェックポイント(ユーザーの GitHub リポジトリ等への定期書き出し)~~(2026-08-18 解消: 帯域外アンカー(上記)と `checkpoint` op — §6.2 — で実現。未決事項 #4)

### 6.4 サーバーの役割: 検証・直列化・認可の真実源

- **チェーンはサーバーも検証する**: チェーンは公開データ(署名・ハッシュ)であり、サーバーは追記受理時に prev_hash 連続性・署名・操作権限を検証し、不正なエントリを拒否する。クライアント検証(§6.3)はサーバー不信の防衛、サーバー検証は不正クライアントの防衛であり、両方必須
- **認可の真実源はチェーンとする**: 「誰がこのプロジェクトのデータ(ラップ済み DEK、暗号文)を取得できるか」のサーバー側判定は、チェーンから導出された現メンバー集合(と各メンバーの scope — 2026-09-14 ES。AUTH_SPEC §9-2 / §12-3)に基づく。D1 の memberships(org)とは役割が異なり、プロジェクトアクセスについてチェーンと矛盾する独立の権限テーブルを作らない(2 つの真実源の禁止)
- **並行追記の直列化**: チェーン追記はプロジェクト DO が直列化する。追記リクエストは「親とするヘッドのハッシュ」を含み、現ヘッドと不一致なら拒否(compare-and-swap)。クライアントは最新チェーンを取得・再検証して再試行する
- **サイズ上限(サーバー受理ポリシー。2026-08-02 追加 — §6.1 が先送りした項目)**: サーバーは追記受理時に次の上限を適用する: (1) エントリ全体の正規化バイト列(§6.1 の entry_bytes)は **1 MiB 以下**、(2) チェーン全体は **10,000 エントリ以下**かつ正規化バイト列の**累積 32 MiB 以下**。これらは**チェーン有効性の合意規則ではなく、サーバーの受理ポリシー**である。§6.1 / §6.2 のフィールドサイズ上限(合意規則)が仕様適合エントリの正規化サイズを最大約 810 KiB(`grant_server` の最大形: scope_environments = 1024 バイト環境 ID × 256 要素 ≈ 512 KiB + lease_policy = 8 要素 × 8 claim 制約 × 1024 バイト文字列 — §6.2 — ≈ 288 KiB。いずれも入れ子 LP の hex 化込み)に数学的に束縛するため、本ポリシーが仕様適合エントリを拒否することはなく、実装間の食い違いによるチェーン分裂も生じない。累積上限は、追記時の全チェーン再検証(本節)と全クライアントの同期・検証コスト(§6.3)を、member 権限での追記連打(`rotate_epoch` 等)によるチェーン肥大 DoS から守る資源保護である。受理ポリシーであるため、値の引き上げは過去チェーンの有効性に影響せず、セルフホスト側での調整も合意を破らない。超過は型付きエラーで拒否する(HTTP 境界の生ボディ上限などの前段防御は実装詳細とし、本仕様は正規化バイト列基準の値のみを規定する)
- **プロジェクト ID = genesis エントリハッシュ(2026-08-02 追加)**: プロジェクトの識別子は genesis エントリのエントリハッシュ(§6.1 の entry_hash、hex 小文字 64 文字)とし、サーバーはこの ID でプロジェクト DO を解決する。チェーン初期化はサーバーが genesis を検証・ハッシュ化して ID を採番する(クライアントも同じ計算で ID を予見できる)。この束縛により、サーバーが「別のチェーンを同じプロジェクト ID で配布する」差し替えは、クライアントの genesis ハッシュ再計算(§6.3 の同期検証の一部)で機械的に検出できる。同一 genesis の再投入は同一 ID に解決されるため、初期化済みプロジェクトへの genesis 重複投入として拒否する
- **値・メタデータ署名のサーバー検証(2026-08-03 — §4.1 / §4.2)**: push・変数/環境メタ操作の受理条件に署名検証を加える(受理条件の具体化は AUTH_SPEC §12): API 呼び出し主体 = writer / author の厳密一致(§5.1 と同じ規則 — 他人が署名した値・ステートメントの持ち込みは拒否)、受理時点のチェーン導出現メンバーの sig 鍵での署名検証、宣言ヘッドが自チェーン上に存在すること、宣言ヘッド時点の role と鍵束縛の一致(§6.3 の 1・3 と同じ判定 — 受理時点の鍵が宣言ヘッド時点にも同じ user_id へ束縛されていたこと。remove → 別鍵 re-add の主体による旧在籍区間ヘッドの宣言を、クライアントが全拒否するデータとして受理段階で排除する)、**値のみ**エポック整合(§6.3 の 4 — メタステートメントは epoch を持たないため対象外)。サーバー検証は不正クライアント・誤実装への防衛であり、サーバー不信下の保証はクライアント検証(§6.3)が担う(本節冒頭の両輪と同じ構図)
- **複合受理(2026-08-03。2026-08-18 マニフェスト同梱を追加 — §4.3)**: 環境作成は「`create_environment` エントリ + env メタステートメント(meta_version 1)+ エポック 1 のラップ完全集合 + 環境マニフェスト(manifest_version 1)」、ローテーションは「`rotate_epoch` エントリ + 新エポックのラップ完全集合 + 新エポックを焼き込んだ環境マニフェスト」を 1 リクエストとしてプロジェクト DO が原子的に受理する(AUTH_SPEC §12-4)。チェーン追記(CAS)とデータ登録が分離した「エポックはあるがラップがない」中間状態を作らない
- **`checkpoint` の受理検証(2026-08-18 — §6.2)**: 合意規則(形式・非空監査ヘッドの actor role admin・unknown-environment・エポック厳密一致・checkpoint-regression)に加えて、受理ポリシーとして payload の内容を**受理時点のサーバー保存状態**と突合する。**複合同梱の境界チェックポイント(2026-08-19 セッション 32 — AUTH_SPEC §12-4)の突合基準は「複合の適用後の保存状態」とする**: 束縛するマニフェストは同一トランザクションの同梱分が登録し、環境作成では環境自体が事前に存在しないため、受理「前」の状態には突合対象が存在しない(standalone チェックポイントは従来どおり受理時点 = 適用前の保存状態。同一リクエスト内の同梱物どうしの座標・ハッシュ一致検査は AUTH_SPEC §12-4 の整合検査が担い、本突合と重複しない範囲を実装 PR で一意化する):
  - **マニフェスト参照**: 各環境エントリの (manifest_version, manifest_sig_hash) が、受理時点の当該環境の**最新**マニフェストと一致すること
  - **値スナップショット**: 各環境エントリの values_digest が、受理時点の保存状態(全 active 変数の最新 version とその保存済み value_signed_bytes ハッシュ)から再計算した値と一致すること。**ダイジェストの原像はワイヤで運ばない**(サーバーが受理時点状態から一意に再構成できる — 一致検査のみで足りる)
  - この 2 検査は「発行者の検証済みビュー = 受理時点のデータ状態」を要求する。発行とデータ層の並行書き込み(push・メタ操作)が挟まれた場合は型付きエラーで拒否し、クライアントはビューを再取得・再検証して再署名・再試行する(チェーン追記 CAS の 409 と同じ再試行構造)。競合確率を支配するのは**発行所要時間 × プロジェクト全体の書き込み頻度**である(カバー範囲が全環境 — §6.3 — のため、どの環境への書き込みも in-flight のチェックポイントを無効化する。secrets の書き込みは低頻度であり実用上は稀。収束しない場合の退避経路は §6.3 の部分集合発行)。過去状態の公証は受理しない(受理時点一致に単純化することで、per-variable の基準単調性が状態の時間単調性から自動的に従う)
  - **監査ヘッド(audit_head_hash が非空の場合のみ — 空 = 公証なしは検査対象外)**: API 呼び出し主体の実効権限が admin であること(AUTH_SPEC §16-2。チェーン role admin は §6.2 の合意規則でも検証)、audit_head_hash が保存済みの累積ハッシュ列(AUDIT_SPEC §5.1)に**存在し**、かつ**その出現位置が、直前の `checkpoint` エントリのミラー行(`chain.checkpointed` — AUDIT_SPEC §3.4)の位置以上である**こと(**直前の `checkpoint` エントリが存在しない場合 — プロジェクト初のチェックポイント — は位置下限を課さない〔空虚に真〕**。受理検査と admin 突合〔AUDIT_SPEC §6〕は同一述語であることが健全性の根拠であり、基底ケースの扱いも両者で一致させる — 2026-08-18 pullfrog レビュー対応)(2026-08-18 pullfrog / Bugbot レビュー対応 — 位置の下限がないと、CAS 競合に敗れた正直な発行者が古い監査ヘッド申告のまま再署名・受理される経路が残り、admin 突合の位置検査〔AUDIT_SPEC §6〕が良性の競合を改竄告発と誤読する。**この受理検査により、正直なサーバーの下では突合の位置検査が構造的に必ず成立する**)。最新一致は要求**しない**(監査ヘッドは発行者の取得から追記受理までの間にも前進し — チェーン追記自体がミラー行を書く — 最新一致の要求は自己競合する)。実効権限不足は 403、位置下限を満たさない申告は他の突合失敗と同じ型付きエラーで拒否し、クライアントは監査ヘッド申告も取得し直して再試行する(§6.3)
  - **削除済み(tombstone)環境のエントリは拒否する(受理ポリシー — 2026-08-18 pullfrog レビュー対応)**: 削除済み環境はマニフェスト・値が存在せず(AUTH_SPEC §12-4 のカスケード)、「受理時点状態との一致」が定義できない。**これを合意規則にはできない**(チェーンは環境の削除を観測しない — §6.2 の環境ライフサイクル束縛のとおり削除はデータプレーン操作であり、チェーン検証だけでは active / deleted を判定できない)ため、`unknown-environment` とは別の受理段拒否(型付きエラー — AUTH_SPEC §16-2)とする。正当な発行者は検証済み削除ステートメントのある環境を含めない(§6.3)
  - **虚偽の状態への公証(存在しない状態・改変ダイジェスト・偽の監査ヘッド)の持ち込みを受理段で排除する**(不正クライアントへの防衛 — 本節冒頭の両輪。サーバーと共謀する攻撃者はこの受理検証を無視できるが、その場合もクライアント側の §6.3 チェックポイント整合と合意規則 `checkpoint-regression` が独立に働く。**values_digest の中身の per-variable 非後退はチェーン検証では照合できない** — ダイジェストは不透明なため、共謀サーバー + 現 member による値基準の引き下げは残余になる。ただしそのクラスは正規 push の権限を持ち、基準を下げるまでもなく正規の書き込みができる = G9 に帰着する)
  - **値スナップショットの原子保存**: 受理と同じ project DO トランザクションで、payload に含まれる環境ごとに「checkpoint 時点の値スナップショット列挙」(受理時点状態そのもの)+ 対応 checkpoint seq / hash を最新包含 checkpoint として保存(upsert)し、payload に含まれない環境の既存スナップショットは変更しない。これにより A / B の基準を持つ状態で A のみを再 checkpoint しても B の基準は失われず、AUTH_SPEC §12-7 は各環境のチェーン導出「その環境を含む最新 checkpoint」と対応する列挙を配布できる
- **ヘッド申告の受理・配布(2026-08-18 — §6.6)**: サーバーはメンバーごとの最新申告 1 行を保存し(チェーンに載せない — 申告は同期のたびに更新される可変データであり、チェーン op にするとエントリ上限を同期活動が消費する。§6.2 の「チェーンは可変メタデータの台帳にしない」と同じ線)、受理時に検証する: 呼び出し主体 = attester の厳密一致、受理時点の現メンバー(reader 以上)の sig 鍵での署名検証、申告ヘッドが自チェーンの当該 seq のエントリハッシュと一致すること、保存済み申告からの seq 単調前進(後退は型付きエラーで拒否 — 黙って成功させない)。`remove_member` の受理時に対象メンバーの申告行を削除する(現メンバーのみ配布 — チェーン導出真実へのストレージ収束。AUTH_SPEC §12-6 の旧鍵ラップ掃除と同型)
- **スコープと四眼の受理(2026-09-14)**: §6.2 の合意規則(scope の構造・包含・環境対象 op・四眼の提案 / 承認 / 方針)はチェーン受理時に verifyChain が検証する(受理 4 手順は不変)。**四眼の適用完了**(定足数に達した `approve` エントリ)の受理副作用(要ローテーション検出・申告行の削除・旧鍵ラップ掃除・招待の completed 化)は、内側 op を直接受理した場合と同一に、当該 `approve` エントリの受理タスク内で走らせる(AUDIT_SPEC §3.4 のミラーも同様)。**受理ポリシー**: pending 提案はプロジェクトあたり **32** 件以下(超過は型付きエラー — AUTH_SPEC §12-8。合意規則ではない)。**期限切れの提案は数えない**(サーバー時計で `expires_at_ms` を過ぎた pending 提案は上限の計算から除く)。**`expires_at_ms` の上界**(受理ポリシー — 2026-09-14 pullfrog 第 9 巡対応): `propose` の受理時、`expires_at_ms` が受理時点のサーバー時計 + **30 日**を超える提案は受理しない(型付きエラー — AUTH_SPEC §12-8。合意規則ではない: `expires_at_ms` は提案者が選ぶ値で §6.2 の構造検査は非負の安全整数しか課さないため、上界なしでは遠い未来の期限を入れた提案で上限を占有でき、期限切れの除外が効かない)。効果範囲を正確に述べると: 期限切れの除外は**放置された提案**(善意の提案者が完成も撤回もしなかったもの)を `withdraw` を待たずに解き、上界はそれを全提案に及ぼす — 意図的な占有は最長 30 日で解け、即時に解く手当は owner の `withdraw`(CLI の一括撤回)である。合意規則ではなく受理ポリシーなのでサーバー時計でよい。提案者単位の副次上限は置かない(K5 で必要になれば受理ポリシーとして加法的に追加できる)。`propose` / `approve` / `withdraw` / `set_approval_policy` は汎用チェーン追記 API(AUTH_SPEC §11)で受理する
- **DEK ラップ受理の受信者集合**は §6.2 の R(E)(AUTH_SPEC §12-6 — 完全一致・受信者判定とも scope を含む)

### 6.5 招待の暗号面: リンク鍵・発行署名・受諾の共同署名・相互確認(2026-08-12 起草 — 未決事項 #9 の解消。2026-09-13 IV 改訂)

未登録ユーザーの招待(および登録済みユーザーの追加 — 両者は同一機構)の暗号面。リソース・API 面は AUTH_SPEC §15。設計原則: **招待は master 鍵素材・DEK を運ばない**(招待リンクの漏洩が鍵の漏洩にならない — リンクが運ぶ秘密は当該招待だけに効く**リンク鍵の種**であり、漏洩の半径は招待 1 件)。相手鍵の真正性は (1) リンク鍵による受諾の共同署名(本節 — **IV1**)、(2) 発行署名(本節 — IV1)、(3) 裏付け元による鍵の照合(本節 — **IV2**)、(4) 招待リンクアンカー(§6.3)、(5) フォールバックとしての鍵 FP の帯域外相互確認(ワード表示 — §3)が担う。グローバルな公開鍵ディレクトリは**作らない** — user_id を知るだけで相手の合意なく add_member できる構造(同意なき追加)と、ディレクトリという新しい信頼オブジェクトの両方を避け、鍵は常に「この招待への受諾」として文脈付きで運ぶ。裏付け元(IdP の公開鍵一覧)はディレクトリではない: 受諾はリンクの保持と受諾者の能動的な署名を要し、裏付け元は**その受諾の鍵を事後に照合するだけ**で、鍵の取得元にも add_member の入力にもならない。

- **リンク鍵**: 招待者クライアントは招待ごとに招待 id(ULID)を採番し、32 バイトの一様乱数 `k`(種)を生成して Ed25519 鍵ペア `(K_priv, K_pub)` を導出する(§3 の署名鍵と同じ導出 — 種 = 秘密鍵の seed)。`K_pub` は発行文(下記)の一部として発行 API へ渡し(AUTH_SPEC §15-2)、`k` はリンクのフラグメントにのみ載せる。**サーバーは `k` / `K_priv` を一度も受け取らない**。招待者クライアントは `k` を永続化しない(表示 = リンクの組み立て直後に参照を捨てる)
- **発行文と発行署名**: 招待者は発行文(招待 id・リンク公開鍵・検証済みヘッド・role・**scope**・自分の同一性)にチェーン署名鍵(Ed25519)で署名し、**サーバー行とリンクの両方**に載せる:

  ```
  invite_issue_signed_bytes = LP("maruhi/v1/invite-issue",
                                 invite_id, project_id, link_pub_hex, head_hash_hex, head_seq, role,
                                 inviter_user_id, inviter_enc_pub_hex, inviter_sig_pub_hex,
                                 scope_kind, scope_environments_lp_hex)
  ```

  - **scope(2026-09-14 ES 改訂)**: 付与予定の scope(§6.2 と同じ符号化)を発行文の**末尾**に加える。role と同じく改竄検出の対象であり、受諾者は「どの環境に入るか」を受諾前に読む。`add_member` は招待行の role / scope で署名する(AUTH_SPEC §15-2 — 招待者が受諾後に別の scope を付けることはできない: 同意の範囲を発行時に固定する)。`invite-link.json` は再生成する(§11)
  - エンコーディングは §2.1(バイナリは hex 小文字、数値は 10 進文字列)。検証鍵は署名対象内の `inviter_sig_pub_hex`(自己束縛 — §5.1 / 旧 §6.5 の受諾署名と同型)であり、検証の成立は「`inviter_sig_pub` の秘密鍵の保持者がこの招待(この id・この link_pub・このヘッド・この role・この scope)を発行した」ことの帰属。招待者が**誰か**は裏付け元(下記)または帯域外照合が示す
  - 意味論(受諾者側): リンク経路上の改竄(アンカー・role・scope・招待者鍵の差し替え)を検証失敗に落とす。招待者の公開鍵を自分のチェーンへゴースト追加した第三者は招待者名義のリンクを作れない(逆方向フィッシングの機械的な遮断 — 補足 21 裁定 E)。受諾クライアントは発行署名の検証失敗を**受諾しない**理由とする(帯域外照合で上書きしない)
  - 意味論(招待者側): サーバー行の発行文 + 発行署名を**自分の sig 公開鍵**で検証できることが、「この行(この link_pub)は自分が発行した」ことの真実源になる。サーバーは発行署名を偽造できず、別の行へ移植すると `invite_id` / `link_pub_hex` の束縛で落ちる。これにより招待者は**発行ピンに依存せず**(別端末でも)受諾を検証できる(補足 21 裁定 A ⑦)。発行ピン(AUTH_SPEC §15-3)は追加の突合と宛先 login の保持を担う SHOULD 水準の材料に留まる
  - サーバーは発行署名を検証しない(検証者は招待者自身と受諾者 — 二重の真実源を作らない)
- **受諾の共同署名**: 招待の受諾は、受諾者のチェーン署名鍵(Ed25519)による**受諾署名**と、リンク鍵 `K_priv` による**リンク署名**の 2 署名を、**同一のバイト列**に対して伴う:

  ```
  invite_accept_signed_bytes = LP("maruhi/v1/invite-accept-v2",
                                  project_id, link_pub_hex,
                                  invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)
  accept_signature = Ed25519(invitee_sig_priv, invite_accept_signed_bytes)
  link_signature   = Ed25519(K_priv,           invite_accept_signed_bytes)
  ```

  - ドメイン文字列は `-v2`(旧 `invite-accept` は `invite_token_hash_hex` を束縛した — 旧形式は受け付けない。AUTH_SPEC §12-10 (2) の「旧実装が構造的に拒否する形」)。エンコーディングは §2.1。受諾署名の検証鍵は署名対象内の `invitee_sig_pub_hex`、リンク署名の検証鍵は署名対象内の `link_pub_hex`(いずれも自己束縛)
  - 意味論: 受諾署名 = 「この鍵ペアの保持者が、この招待に対してこの鍵で参加する意思を表明した」の帰属・文脈束縛(不変)。リンク署名 = 「**リンクを持つ者**がこの鍵での受諾を承認した」。サーバーは `K_priv` を持たないため、**受諾ブロックの鍵を別の鍵に差し替えて有効なリンク署名を作ることが暗号的に不可能**になる。招待は**単回使用**(AUTH_SPEC §15)であるため、リンクを横取りした攻撃者が自分の鍵で先に受諾すると(攻撃者はリンク署名を作れる)、正規の相手の受諾が同一招待上で衝突して**顕在化**する — この残余(リンク経路の読み取り + 先着)は裏付け元の照合(IV2)が事前に閉じ、裏付け元が無い場合は帯域外相互確認が閉じる
  - サーバーは受諾時に両署名を検証する(AUTH_SPEC §15-2)。招待者クライアントは `add_member` の前に、一覧行の発行文 + 発行署名を自分の sig 公開鍵で検証し(失敗 = 自分の発行ではない / 行のすり替え → 拒否)、発行ピンがあれば `link_pub_hex` / role を突合した上で、両署名を独立に再検証する
- **裏付け元(IV2 — クライアント仕様)**: 受諾鍵(招待者側)/ 招待者鍵(受諾者側)が「名指しした相手」のものかを、IdP が公開する鍵一覧で機械照合する出所。差し替え可能な抽象として `github-signing-keys` / `org-directory`(予約 — 組織の鍵台帳。SSO 導入時の同等物)/ `none`(照合しない = 儀式)を持ち、v1 の実装は `github-signing-keys` のみ:
  - 各ユーザーは自分の maruhi **sig 公開鍵(Ed25519)**を GitHub の **SSH 署名鍵**(コミット署名用の種別。SSH 認証には使えない)として登録する(`maruhi key publish`)。表現は OpenSSH 公開鍵行 `ssh-ed25519 <base64(SSH ワイヤ形式: uint32-BE 長さ ‖ "ssh-ed25519" ‖ uint32-BE 長さ ‖ 32 バイト鍵)>`(RFC 4253 §6.6 / RFC 8709)。**これは相互運用の符号化であり新しい暗号プリミティブではない**(§3 の FP ワード・§8.4 のハンドオフコードと同じ位置づけ。符号化・解析は `packages/crypto` に 1 実装を置きテストベクターで固定する)
  - 照合するクライアントは GitHub の公開 API(`GET /users/{login}/ssh_signing_keys`、認証不要)で当該 login の署名鍵一覧を取得し、`ssh-ed25519` 種別の鍵に対象の sig 公開鍵が**バイト一致**で含まれるかを見る。照合するのは **sig 鍵のみ**で足りる: enc 鍵は受諾署名 / 発行署名の署名対象に含まれ、sig 鍵の保持者が束縛している
  - 裏付け元へ送る情報は **login のみ**(プロジェクト・鍵・値・利用状況を送らない)。ホストは固定(`api.github.com`)。応答は公開情報として扱い、照合に**失敗**(鍵が無い)しても**不能**(取得できない・上限・オフライン)でも、下記の充足形 1〜3 へ戻る(fail-closed: 裏付け元は儀式を**省く**根拠にしかならず、儀式を**免除しない**方向へは働かない)。鍵が無い場合、クライアントは儀式へ入る前に「相手に登録(`maruhi key publish`)を頼んで再実行する」選択を提示してよい(儀式の代替ではなく延期 — 補足 21 裁定 D ④)
  - 登録の導線(クライアント仕様): 受諾クライアントは受諾の完了時に登録を案内し、鍵の生成・再生成・復元の直後に登録(または再登録)を提案する(補足 21 裁定 G ⑥)。登録は利用者の明示の同意(yes)を要し、無断で行わない
  - 将来の裏付け元候補: 利用者が既に IdP に登録している SSH **認証**鍵で受諾文に SSHSIG 署名する形(`github-ssh-keys` — 登録手順が不要になる)は、SSH 公開鍵と SSHSIG の解析・検証を本仕様に足す改訂として別途提示する(補足 21 裁定 G ⑦)
  - 同じ鍵でコミット署名もできる副産物は許容する(用途は SSHSIG の名前空間と本仕様の LP ドメイン文字列で分離される)
- **相互確認(必須 UX)**: 確認は**双方向**とする。招待者側: `add_member` の実行前。受諾者側: 受諾の実行前。片方向の確認だけでは、偽招待で被害者を攻撃者所有のプロジェクトへ参加させ、本物のシークレットを push させる**逆方向フィッシング**が残る(攻撃者は自プロジェクトの正当な owner であり、チェーン検証は警報を出さない)ため、相互を必須とする
- **明示確認の充足形(2026-09-12 改訂 — 検証済み指紋帳の解釈の規範化。2026-09-13 IV 改訂 — 第 4 形の追加と既定化)**: 前項の確認は、招待者側・受諾者側とも次のいずれかで充足する。**既定は 4.**、4. が成立しない場合に 1.〜3. へ戻る:
  1. **読み上げ儀式**: その実行で FP ワード列を帯域外(通話等)で照合し、最終語を再入力する
  2. **フラグによる機械照合**(`--expect-fingerprint` / `--inviter-fingerprint`): 帯域外で控えた FP の実行時の明示指定。この受諾 1 件への明示的作為であるため、帯域外の記録を照合済みとして扱う(裏付け元を使わない非対話環境で許される形)
  3. **検証済み指紋帳のヒット + 受諾単位の明示確認**: 同一 (origin, user_id, FP) を過去に 1. または 2. で確認済み(CLI が非機密設定として記録)であれば、読み上げ照合の**再実施**のみを免除する。対象(相手・role / プロジェクト)を名指しする明示確認(yes 入力)は免除しない。この形を使えるのは stdin / stdout が対話端末のときだけであり、AI エージェント環境では使わない(ADR-0016 決定 7 の一次境界と同じ allow-list)
  4. **リンク束縛 + 裏付け元の照合(既定 — IV1 + IV2)**:
     - 招待者側: (i) 一覧行の発行文 + 発行署名が自分の sig 公開鍵で検証でき(発行ピンがあれば `link_pub` / role の突合も成立し)、(ii) リンク署名・受諾署名の検証に成功し、(iii) 裏付け元が「受諾の sig 鍵は、発行時に名指しした相手(`invite create --github <login>` — 発行ピンに保持。無ければ実行時の `--github <login>`。対話入力は設けない — AUTH_SPEC §15-3)の鍵である」と照合できた — このとき **確認入力なしに** `add_member` へ進んでよい。名指しは招待の発行時に行われた明示的作為であり、受諾単位の同意はそこで表明済みである
     - 受諾者側: (i) 発行署名の検証に成功し、(ii) 裏付け元が「招待者の sig 鍵(リンクの `is`)はリンクが名指す login(`il`)の鍵である」と照合できた — このとき読み上げ照合は不要で、**受諾者が「その login からの招待を期待していた」ことの表明**(非対話: `--from <login>` の一致 / 対話: login を名指しする yes 入力)で充足する。受諾は受諾者の能動的な参加意思の表明であり、この 1 回の表明は省かない(経路で差し替えられた**有効な**別人のリンクを見分ける最後の防衛が「login を読む」ことだから)
     - (i)(ii) の暗号検証の**失敗**(発行署名・リンク署名・受諾署名の失敗、ピンとの不一致)は充足形 1.〜3. へ**戻さず拒否**する(壊れた署名を人間の読み上げで上書きしない)。(iii) の**不能**(裏付け元 `none`・宛先 login が無い・未登録・取得不能)は 1.〜3. へ戻る
  - **帳のヒットのみによる無確認の自動通過は認めない**(不変): 招待リンクは受諾者の同一性を運ばず、帳は過去の別文脈の検証記録にすぎないため、この付与 / 受諾への人間の同意を代替できない。第 4 形の無確認は、暗号検証(リンク束縛)と発行時の名指し(裏付け元照合)の**両方**が成立する場合に限る
- `add_member` エントリ(§6.2)の形式・意味論は本節(IV 改訂)では不変(scope フィールドの追加は §6.2 の ES 改訂 — 2026-09-14): チェーンに載る公開鍵は招待者が確認したものであり、以後の真正性はチェーン署名が担う。発行署名・受諾署名・リンク署名はチェーン外の追加証跡(サーバー検証 + 招待者 / 受諾者クライアント検証 — AUTH_SPEC §15)であり、チェーン有効性の合意規則には含めない
- **禁止事項(本節の範囲)**: リンク鍵の種 `k` / `K_priv` をディスク・ログ・エラーメッセージ・監査に出さない(表示はリンクとして 1 回)。サーバーが `k` / `K_priv` を受け取る形の API を作らない。裏付け元の照合結果をサーバーへ報告しない(照合はクライアント内で完結)。裏付け元の login をチェーン・監査・サーバー保存の招待行・署名済み構造に書かない(リンクのフラグメントと招待者のローカルピンにのみ置く)
- テストベクター: `test-vectors/invite-accept-signature.json`(v2 — 再生成)/ `test-vectors/invite-link.json`(新規 — §11)

### 6.6 ヘッド申告(2026-08-18 セッション 27 起草 — §6.3 ヘッドゴシップの申告形式)

読み取り側クライアントが「自分はこのチェーンヘッドまで検証した」を署名付きで宣言するチェーン外データ。既存部品(Ed25519 + §2.1 LP)のみで構成する。

- **署名対象の正規化バイト列**(§2.1 のエンコーディング):

  ```
  head_attestation_signed_bytes = LP("maruhi/v1/head-attestation",
                                     project_id, attester_user_id,
                                     chain_head_hash_hex, chain_head_seq)
  ```

  - `attester_user_id` の焼き込みは §5.1 の signer_user_id と同じ帰属付け替え対策。project_id が文脈を束縛し、別プロジェクトへの申告の移植は検証失敗となる
  - **署名は必須**: 無署名の申告はサーバーが合成でき、警告誘発 DoS(偽の矛盾申告)と偽の安心(偽の一致申告)の両方向に使える。署名付きの申告は、自ビューと矛盾した時点で「サーバーの equivocation または attester の鍵漏洩」の**否認不能な証拠**になる(§14.2-5 と同じ地位)
  - **タイムスタンプ・ノンスは含めない**: 署名の意味論は「このヘッドまで検証した」の帰属であり、鮮度証明ではない(§5.1 の意味論と同じ線)。申告の新旧は chain_head_seq が順序付け、古い申告の再配布はサーバーの omission(申告を古く見せる)と等価で暗号では防げない(G8)。タイムスタンプは「いつ同期したか」という行動情報を増やすだけで検出能力を足さない(プライバシー検討はセッション 27 ノート §7)
- **クライアント検証(配布された申告の受信時)**: (1) attester(user_id + 鍵 FP)が自ビューの現メンバーであり、申告ヘッド時点(inclusive — §6.3 の規約)にも在籍していること、(2) 署名を、チェーン履歴でその user_id に束縛された sig 公開鍵のうち FP が一致し申告ヘッド時点で有効だったもので検証すること(§6.3 の 1 と同じ鍵選択)、(3) 申告ヘッドの自ビューとの照合(§6.3 のヘッドゴシップ段落の 2 種区別)。検証に失敗した申告は照合材料にしない(偽申告による警告誘発を排除する)
- **意味論**: 「attester_user_id が、このプロジェクトのチェーンをこの位置まで検証済みとして受理した」。チェーンヘッドの真正性は証明しない(検証は受信側が自ビューと照合して行う — §6.3)。**平文値・変数へのアクセスの有無を一切運ばない**(申告が開示する行動情報は「チェーン同期の到達点」のみ — 全操作・全 actor を全メンバーへ配布・検証させるチェーン自体の開示に対して増分は小さく、split view 検出は reader を含む全メンバーの利害であるため、申告の配布は全メンバー宛とする。監査イベント化はしない — AUDIT_SPEC §6)
- ワイヤ・保存・受理・配布の規定は AUTH_SPEC §16、サーバー検証は §6.4。クライアントの提出契機・照合規則・検出時の挙動は §6.3 のヘッドゴシップ段落
- **ワークロード(§9.1)は申告に参加しない**: ワークロードは Ed25519 署名鍵を持たず(一時 X25519 のみ)、偽造可能な無署名申告に証拠価値がない。リース応答へ他メンバーの申告は同梱しない — 悪意サーバーは古い整合ビューに当時の申告を添えて配れるため検出を足さず、「検証済み」の誤認だけが増える。ワークロードの防衛はリポジトリアンカー(§6.3 (b))とチェックポイント整合(§6.3)が担う
- テストベクター: `test-vectors/head-attestation.json`(§11)

## 7. エポックとメンバーシップ変更

- メンバー削除・サーバー失効時は必ず `rotate_epoch` を伴う。**対象環境の集合(2026-09-14 ES 改訂)**: `remove_member` は**対象の現 scope の環境**(scope = all なら全環境)、`revoke_server` は全環境(不変 — 改訂は ES の対象外・設計録 §6)。環境ごとに新 DEK を生成し、現在値を新 DEK で再暗号化し、新 DEK を受信者集合 R(E)(§6.2)へラップする。**scope 外の環境を rotate の対象に含めてはならない**(対象は DEK を持たず、義務は存在しない — 実行者も scope 外なら rotate できない。包含規則 — §6.2 — により、remove の actor は対象の scope を包含するため履行可能)。「全環境」の定義と 404 時の中断規律は不変: `rotate_epoch` エントリには新 DEK のコミットメント(§5.2)を含め、再暗号化された各値には実行者が writer として署名する(§4.1)。**「全環境」とは、チェーン導出の環境集合(`create_environment` — §6.2)のうち、検証済み削除ステートメント(§4.2 の status = deleted)で削除済みになっていないもの**を指す(削除済み環境は暗号文もラップも消えており rotate に守るものがない。サーバーは削除済み環境への rotate を受理しない — AUTH_SPEC §12-4)。active と信じる環境への rotate が 404 で拒否された場合、検証済み削除ステートメントを確認できない限り**黙ってスキップせず**中断して警告する(悪意サーバーによる選択的なローテーション阻止を不可視にしない)
- **member 未満への降格(`change_role` で reader 化)は対象の scope の環境の `rotate_epoch` を伴う(2026-08-03 セッション 12 起草。2026-09-14 ES 改訂 — 動機はエポックアンカーの健全性で不変、範囲だけが scope に縮む)**: 削除時の義務(上記)の動機は機密性(既知 DEK の失効)だが、降格時の義務の動機は**エポックアンカーの健全性**である — 降格者は reader として新 DEK を受け取り続けるため機密性上の効果はないが、ローテーションを挟まないと「降格者の member 在籍区間のヘッド × 現エポック」が有効な署名座標として**次のローテーションまで無期限に**残り、悪意サーバーとの共謀で現エポック宛の前進注入(§14.3-5)が成立し続ける。ローテーションがエポックを進めれば、降格者の偽造可能座標は削除済みメンバーと同じ「当時のエポックのみ」に縮む。再暗号化・再ラップの手順は削除時と同一
- **scope の縮小(2026-09-14 ES 改訂)**: `change_role` で旧 scope \ 新 scope が非空のとき、縮小分の各環境について `remove_member` と同じ `rotate_epoch` 義務を負う(機密性 — 対象が保持する縮小分の DEK の失効)。義務の起点は当該 `change_role` の seq。要ローテーション検出は縮小分の環境に限って走る(AUDIT_SPEC §4.1)。**scope の拡大**は actor(包含規則により DEK 保持者)が拡大分の環境について全エポックの DEK を対象へラップして登録する(AUTH_SPEC §12-6 の追記経路 — add_member 後のバックフィルと同型。複合化しない)
- **ラップの実行者**: DEK のラップは常に「DEK を保持しているクライアント」が行う(不変)。メンバー追加時は招待者のクライアントが**対象の scope の**全環境の全エポック DEK を新メンバーの公開鍵へラップする。ローテーション時は実行者のクライアントが新 DEK を R(E) へラップする(2026-09-14 ES 改訂)
- **grant_server が有効なプロジェクトのローテーション**: ローテーション実行者は新エポック DEK をサーバー公開鍵へも再ラップする(再ラップしなければリース経路 — §9.1 — は停止する。UI はこれを明示する)。登録経路は複合リクエストのラップ完全集合(サーバー鍵を含む)と grant 直後のバックフィル — AUTH_SPEC §12-4 / §12-6(2026-08-12 改訂 — 旧「v1 は登録経路を持たない」線引きの解消)
- 過去バージョンの値は当時のエポック DEK のまま保持する。**scope 内の各環境の全エポック DEK** を R(E) へラップする(2026-09-14 ES 改訂 — 旧「全環境の全エポック DEK を現メンバーへ」。新規メンバーは scope 内の履歴も読める。secrets はメッセージと異なり履歴の秘匿を目的としない)
- 削除されたメンバーは新エポック以降の値を復号できない
- **四眼の下の義務の起点と履行者(2026-09-14 PF1)**: 提案経由の `remove_member` / 降格 / 縮小 / `revoke_server` の rotate 義務、および `add_member` / scope 拡大のメンバー宛バックフィル義務・`grant_server` のサーバー宛バックフィル義務(開示スコープ内全環境 × 全エポック — AUTH_SPEC §12-6)は、いずれも**適用時点**(定足数に達した `approve` エントリの seq)から始まる。提案時には対象は在籍しており失効する DEK はなく、適用前の対象にラップを登録することもできない(受信者集合 R(E) に未だ含まれない — AUTH_SPEC §12-6 は拒否する)。**履行者は適用を完成させた承認者**(owner — scope = all なので全環境の DEK を持ち、包含規則により履行可能)であり、承認クライアントは適用後に sweep(rotate 義務)とバックフィル(メンバー宛 / サーバー宛の全エポックのラップ登録 — AUTH_SPEC §12-6 の 5 番目の経路)を実行する。「ラップの実行者 = 招待者 / 拡大を署名した actor / grant 実行者」の規定は直接追記の場合のものであり、四眼経由では**内側 op の種類を問わず**承認者に移る(2026-09-14 pullfrog / Cursor Bugbot レビュー対応)。未履行のまま放置された状態は既存と同じ「メンバーはいるがラップがない」(AUTH_SPEC §12-4 の非対称)であり、`project verify` の未収束義務の警告(rotation-sweep の常時警告)にバックフィル未了も含めて表示する
- **要ローテーション検出(製品機能)**: メンバー削除時、監査ログからそのメンバーが閲覧可能だった変数を算出し「上流 credential のローテーション推奨」フラグを立てて UI / CLI に表示する。暗号は既読の値を取り消せないという限界を、ワークフローで補う

## 8. master 鍵ラップ台帳(リカバリーコード・パスキー PRF・保護者・ハンドオフ)

**2026-09-12 改訂(KL3)**: 旧 §8「リカバリーコード」を、同一の master 鍵ブロブに対する**受信者ごとのラップの集合(台帳)**として一般化する。リカバリーコード経路の構造・バイト列・テストベクター(`recovery-wrap.json`)は**不変**であり、本改訂は経路を足すだけである(既存ブロブの再ラップ・移行は無い)。設計録は docs/notes/integration-options.md 補足 19。

### 8.1 共通規定

- **ラップ対象 B**: user master 秘密鍵(enc / sig)の不透明ブロブ。直列化形式はクライアント(CLI)の契約であり、サーバーは関知しない(現行 = キーチェーンレコードの JSON。復元側は自己検証を通してから保存する)
- **受信者クラス**: (S) 対称 KEK — `recovery-code` / `passkey-prf`。(G) 保護者グループ — `guardian`。(H) ハンドオフ — 一時受信者(台帳に永続行を持たない。§9.1 リースラップと同じ応答スコープ)
- **ラップ**(クラス S / G / H の端末移行に共通): AES-256-GCM、96-bit ランダム nonce(暗号文と併置)。AAD は §2.1 のエンコーディングで

  ```
  master_wrap_aad = LP("maruhi/v1/master-wrap", user_id, kind, wrap_ref, mode)
  ```

  `kind` ∈ {`passkey-prf`, `guardian`, `device`}。`wrap_ref` = passkey-prf: `wrap_id` / guardian: `group_id` / device: `request_id`(8.4)。`mode` = guardian のみ `any` | `all`、それ以外は空文字列。**例外: `recovery-code` は旧 §8 の AAD `LP("maruhi/v1/recovery-wrap", user_id)` のまま**(バイト互換の維持。新経路には用いない)
- すべてのラップ・分片はサーバーから見て不透明であり、KEK の素材(リカバリーコード・PRF 出力・分片の平文・一時秘密鍵)はいかなる API ペイロードにも含まれない。他ユーザー・他文脈への移植は AAD / info の束縛により復号失敗となる(設計原則 3)
- **取得の前提**: いずれのクラスも、ラップ・分片の取得は認証済みの本人(またはハンドオフの承認者)に限る(認証 + 鍵素材の二重防御 — 旧 §8 と同じ)。取得エンドポイントはレート制限を持つ(AUTH_SPEC §13-8)

### 8.2 対称 KEK 受信者(クラス S)

- **recovery-code**(旧 §8 のまま): サインアップ時に生成する 256-bit ランダム値。表示形式は Base32 をグループ化した人間可読文字列で、ユーザーが安全に保管する。`KEK = HKDF-SHA256(recovery_secret, salt = 空(長さ 0), info = "maruhi/v1/recovery")`。salt 空の根拠(RFC 5869 §3.1 — IKM が既に一様ランダムな場合、salt は省略可。用途分離は info が担う)・高エントロピー乱数のためストレッチング不要・Argon2id 条項(パスフレーズ由来の鍵を導入する場合は Argon2id 必須 = 本仕様の改訂を要する)・再発行 = 新コード生成 → 再ラップ → 旧ラップの削除、はすべて不変。デバイス追加・鍵喪失時のフローも不変: **まず GitHub 認証で新デバイスにセッションを確立し**、その認証済みセッション上でラップ済み master 秘密鍵を取得 → リカバリーコード入力 → KEK 導出 → 復号。**パスフレーズ由来 KEK は KL3 でも導入しない**(補足 12 L4-a)
- **passkey-prf**(新設): WebAuthn PRF 拡張(CTAP2 hmac-secret)の出力 `prf_out`(32 バイト。認証器の HMAC-SHA-256 出力で一様ランダム)を IKM とする:

  ```
  prf_out = PRF(credential, eval.first = prf_salt)
  KEK     = HKDF-SHA256(prf_out, salt = 空(長さ 0), info = "maruhi/v1/passkey-prf")
  ```

  - `prf_salt` は**登録ごとに生成する 32 バイトの乱数**で、公開パラメータとして台帳行に併置する(credential_id・rpId と同じ扱い)。固定文字列にしない理由: 固定だと KEK が credential の固定関数になり、一度漏れた KEK が再登録後のラップも開く。乱数なら再登録 = 新 KEK となり、recovery-code の「再発行 → 旧ラップ削除」と同じ意味論が成立する
  - salt 空の根拠は recovery-code と同じ(prf_out は一様ランダム 256-bit)。用途分離は info が担う。ストレッチング不要
  - PRF は**ブラウザでしか取得できない**。取得は CLI が配布する localhost ページ(`127.0.0.1`、rpId = `localhost`)で行い、PRF 出力はループバックの 1 POST で CLI プロセスへ渡す(ADR-0018: hosted Web は鍵・ラップのコードパスを持たない)。運営配信の Web で PRF を取得してはならない。ページと CLI 間の認証(ワンタイムトークン + Origin 検査)は ADR-0018 決定 2 の要件に従う
  - 1 ユーザーが複数の passkey-prf ラップ(複数の認証器)を持ってよい。各行は独立(wrap_id で識別)

### 8.3 保護者グループ(クラス G)

ward(本人)が指名した保護者の公開鍵へ B を包む。「鍵とリカバリーコードを両方失っても、保護者 + 本人のアカウント認証で復元できる」経路。

- **グループ**: `group_id`(乱数 ULID)、`mode` ∈ {`any`(1-of-n: 誰か 1 人で足りる), `all`(n-of-n: 全員が要る)}、グループ KEK = 256-bit 乱数。B は 8.1 の AES-GCM で `kind = "guardian"`, `wrap_ref = group_id`, `mode` を AAD に束縛してラップする
- **分片**(share_index = 1..n):
  - `mode = any`: すべての `s_i = KEK`
  - `mode = all`(n ≥ 2): `s_1 … s_{n-1}` を独立な 32 バイト乱数とし、`s_n = KEK ⊕ s_1 ⊕ … ⊕ s_{n-1}`。復元は全片の XOR。任意の n−1 片は KEK と独立(情報理論的 n-of-n 秘密分散の標準形)。**k-of-n(Shamir 等)は導入しない**(新プリミティブ)。HPKE の入れ子(A で包んだものを B で包む)は逐次依存で承認が並列にできないため採らない
- **分片の封印**: HPKE Base mode 単発 Seal(§5 と同一プリミティブ)。受信者 = 保護者の master enc 公開鍵(DEK ラップを受ける鍵と同じ)。平文 = `s_i`(32 バイト)。aad は空、info は

  ```
  guardian_wrap_info = LP("maruhi/v1/guardian-wrap", user_id, group_id, mode, share_index, guardian_user_id)
  ```

  ドメイン文字列により §5 `dek-wrap` / §9.1 `lease-wrap` / 8.4 `handoff-wrap` と相互に移植できない。`mode` を AAD と info の両方に含めるのは、サーバーによる `any` ↔ `all` の付け替え(要求者に n 片の XOR を求める / 1 片で足りると誤らせる)を復号失敗に落とすため
- **保護者の鍵の真正性**: 保護者は ward と共有プロジェクトを持つ**チェーン導出の現メンバー**から選び、その enc 公開鍵はチェーン(add_member / genesis の payload)から取る。鍵の確認は §6.5「明示確認の充足形」(読み上げ儀式 / フラグ / 検証済み指紋帳のヒット + yes)に従う。グローバル公開鍵ディレクトリは作らない(§6.5)。台帳は保護者の鍵 FP を併置し、クライアントは保護者の現鍵(チェーン導出)と突合して不一致(保護者の鍵更新)を警告する — `all` では 1 人の不一致でグループが復元不能になる
- **保護者の同意手続きは v1 で持たない**: 指名は ward の単独操作。復元には保護者の能動的な承認(8.4)が要るため、同意なき指名で保護者に生じる面は「自分の台帳に ward が表示される」だけである。同意の署名(招待型の握手)は将来の改訂候補
- グループの削除 = ward の単独操作(行の削除。旧分片は消える)。保護者の入れ替えは削除 → 再作成

### 8.4 ハンドオフ(クラス H — 端末移行と保護者承認の共通機構)

「B(または分片)を要求者の一時公開鍵へ再封印して渡す」応答スコープの機構。**端末移行**(旧端末が承認)と**保護者リカバリー**(保護者が承認)は同じ要求・同じ承認 payload を使い、要求者の手順は承認者の種別に依らない。

- **一時鍵 E**: 要求者(新端末)がメモリ内で生成する X25519 keypair。永続化しない。要求者プロセスの終了とともに消える
- **request_id**: `lower_hex(SHA-256(LP("maruhi/v1/handoff-id", E_pub_hex)))`。要求者・承認者が独立に同じ値を計算できる
- **ハンドオフコード(クライアント仕様)**: `E_pub(32 バイト) ‖ SHA-256(E_pub) の先頭 4 バイト` を Base32(RFC 4648 アルファベット・パディング無し)で符号化した文字列(グループ化表示。表示形はテストベクターで固定)。**コードは人が運ぶ**(同一人物の端末間はコピー&ペースト、保護者へは帯域外)。**サーバーは E.pub を中継せず保存もしない**: 承認者は運ばれたコードから E.pub と request_id を得る。これにより、サーバーによる受信鍵のすり替えが構造的に成立せず、12 語型の照合儀式を要しない(§3 の「短縮コードへの切り詰めは行わない」— 一方の鍵を攻撃者が選べる状況 — が発生しない)。コードは公開情報(公開鍵)であり、鍵素材ではない
- **承認**: 承認者は 32 バイト値 `v` を E.pub へ HPKE Base mode 単発 Seal する(aad 空、info は下記)。**同一の request_id に対する承認は、承認者・source ごとに 1 つ**

  ```
  handoff_wrap_info = LP("maruhi/v1/handoff-wrap", user_id, request_id, source, share_index, approver_user_id)
  ```

  - **保護者の承認**: `v = s_i`(台帳から自分宛の分片を取得 → 自分の master enc 鍵で Open → **その場で** E.pub へ Seal。分片・B を保存しない)。`source = group_id`、`share_index` = 自分の分片番号、`approver_user_id` = 保護者の user_id
  - **旧端末の承認(端末移行)**: 承認者 = ward 本人(B を保持する端末)。`KEK_h` を 256-bit 乱数として生成し、`v = KEK_h`、`source = "device"`、`share_index = 0`、`approver_user_id = user_id`。同時に B を 8.1 の AES-GCM で `kind = "device"`, `wrap_ref = request_id`, `mode = ""` として `KEK_h` でラップし、承認に同送する
- **要求者の組み立て**: 届いた承認を `source` で分ける。`device` があれば `KEK = v`、同送されたラップを開く。`group_id` なら当該グループの `mode` に従い(any: 任意の 1 片、all: 全 n 片の XOR)KEK を得て、台帳から取得したグループのラップを開く。得た B は自己検証(鍵の整合)を通してからキーチェーン(または agent メモリ)へ保存する
- **承認前の本人確認(規範)**: 保護者は承認前に、要求者が ward 本人であることを**帯域外**(通話等)で確かめる。サーバーは承認者へ要求の ward(user_id と表示用スナップショット)を示すが、それは表示であって証明ではない(サーバーが偽った ward を示しても、info の user_id 束縛により正規の要求者以外は開けず、fail-closed)。承認・PRF 取得・復元は儀式であり、AI エージェント環境・非対話端末では拒否する(ADR-0016 決定 7 の既存ゲート)
- **有効期間**: 要求は起草値 15 分で失効し、承認は要求とともにサーバーから消える(応答スコープ — 永続台帳に入らない)。要求者は成功後に要求を削除してよい

### 8.5 禁止事項(本節の範囲)

- KEK・分片・一時秘密鍵・B の平文をディスク・ログ・エラーメッセージに出さない
- パスフレーズ由来の KEK(Argon2id 条項 — 8.2)
- k-of-n 閾値分散、独自の鍵合意・確認プロトコル(SAS 短縮を含む)
- ハンドオフの E.pub をサーバー経由で承認者へ配布する実装(コードは人が運ぶ)

## 9. 選択的開示(サーバー鍵)

- サーバー(デプロイメント)は自身の X25519 keypair を持つ。秘密鍵は Workers Secret に保存(セルフホストではユーザー自身のアカウント内)
- **サーバー鍵フィンガープリント(2026-08-02 決定)**: `SHA-256(サーバー enc 公開鍵(32B))` の先頭 16 バイト。サーバーは enc 鍵のみを保持するため、§3 のユーザー FP 定義(enc ‖ sig)は適用しない。チェーン検証はこの FP と payload 内の公開鍵の整合を検査する
- デフォルトではいかなるプロジェクトの DEK もサーバーへラップされない(= 純粋 E2EE)
- プロジェクト owner がサーバー主導機能(例: GitHub Actions 同期)を有効化すると、クライアントが `grant_server` をチェーンに記録し、許可スコープ(対象環境の部分集合を含みうる)に応じた必要エポック DEK をサーバー公開鍵へラップする
- 無効化は `revoke_server` + `rotate_epoch`
- UI / CLI は「このプロジェクトはサーバーに開示されています」を常時明示する
- **grant 実行時のサーバー鍵確認(2026-08-12 起草)**: grant_server の実行 UI / CLI は、サーバーが配布する enc 公開鍵のフィンガープリントをワード表示(§3)し、デプロイメントの公開設定(AUTH_SPEC §4 — `/auth/config` の `serverKeyFingerprintHex`)との照合の明示確認を要求する。メンバー鍵に課している真正性確認(§6.5)をサーバー鍵にだけ免除しない — grant はサーバーを「メンバー N+1」にする操作である
- **サーバー宛ラップの HPKE info(2026-08-12 起草)**: サーバーを受信者とする永続ラップ(§7 のローテーション・grant 直後のバックフィル)では、§5 の info の recipient_user_id 位置に**サーバー鍵フィンガープリント(hex 小文字)**を用いる(サーバーは user_id を持たない。§11 のベクターで固定)
- MVP(Phase 1)ではこの機能自体を実装しない(データ構造のみ仕様として確保)— **Phase 2 で §9.1 とともに実装する(2026-08-12 起草。受理面は AUTH_SPEC §12-4 / §12-6 / §14)**

### 9.1 ワークロードリース(2026-08-12 セッション 22 起草)

grant_server 済みプロジェクトの DEK を、長期資格情報を持たないワークロード(v1 = GitHub Actions の CI ジョブ)へ、**応答スコープの一時鍵ラップ**として配布する機構。API 面・OIDC 検証規則は AUTH_SPEC §14。**サーバーの役割は「値の復号者」ではなく「DEK の仲介者」**であり、リース経路においてサーバーは変数値を復号しない(自分宛ラップの開封と再ラップのみ)。

- **リースラップ**: HPKE Base mode の単発 Seal(§5 と同じプリミティブ)。受信者はワークロードがメモリ内で生成し、ジョブ終了とともに破棄する一時 X25519 公開鍵
- `info`(必須): `"maruhi/v1/lease-wrap" || project_id || environment_id || epoch || claims_digest_hex`(§2.1 のエンコーディング)
- `claims_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/lease-claims", issuer_url, subject, audience)))` — 検証済み OIDC トークンの issuer / sub / aud。サーバーとワークロードが独立に同じ値を計算でき、リース応答の別ワークロード文脈への転用は復号失敗となる(設計原則 3 の一貫適用)
- **リースラップは永続化しない**: dek_wraps(AUTH_SPEC §12-6)には入らず、リース応答の中にのみ存在する。§6.3 の「DEK のラップ先はチェーン上の現メンバー + 有効な grant_server と厳密に一致」(ゴーストメンバー禁止)は**永続ラップストアとクライアント生成ラップに対する規則**であり、リースラップ(サーバー生成・応答スコープ・grant の範囲内)はその対象外である — この線引きにより両規則は矛盾なく並立する
- **認可の真実源はチェーン**: どのワークロードがリースを受けられるか(issuer / audience / claim 制約)は grant_server payload の lease_policy(§6.2)であり、owner 署名・append-only・全メンバー検証可能。サーバー可変の設定にしない
- **受信ワークロードの検証義務(必須)**: リース応答の使用前に (1) チェーン検証(§6.3。project_id = genesis ハッシュはワークロード設定に事前固定)、(2) リポジトリアンカーの包含・非後退検査(§6.3 帯域外アンカー (b) — SHOULD)、(3) DEK コミットメント照合(§5.2)、(4) 値署名・メタステートメント検証(§4.1 / §4.2 / §6.3)、(5) **環境マニフェストとチェックポイント整合の検証(§4.3 / §6.3 — 2026-08-18)**: マニフェストのダイジェスト再計算・エポック整合と、チェーン導出の最新チェックポイントに対するマニフェスト・値スナップショットの非後退検査。ワークロードは床を持たない初回同期クラス(§14.3-3)であり、(2) がチェーンヘッドの鮮度を、(5) がそのヘッドの下でのデータ層の完全性・最新性(チェックポイント時点まで)を担う
- **有効期間内の OIDC トークンのリプレイ(2026-08-15 追記、同日所有者裁定 — 設計比較・却下案は docs/notes/session-24.md)**。`claims_digest` が束縛するのは issuer / subject / audience であり、ワークロードの一時公開鍵も nonce も含まない。したがって暗号層だけを見れば、**まだ有効な OIDC トークンのコピーを入手した者**(ネットワーク捕捉・悪意あるワークフローステップ・ログ流出)は、**自分の一時鍵で**リースを要求し、正当に再ラップされた DEK を受け取れる — リースラップ自体に「正規のジョブ」と「トークンのコピー保持者」を区別する手段はない(本節が保証するのは「リース応答を**別のワークロード同一性へ転用できない**」ことであって、同一同一性でのベアラーリプレイの防止ではない)。この残余は**サーバーの先着束縛**(AUTH_SPEC §14-1: 発行時に「束縛キー → 一時公開鍵」を記録し、同一トークン + 別鍵の再要求を拒否する)が塞ぐ — 暗号構成(リースラップ・claims_digest)は変更しない。**束縛キーは JWS signing input(`header.payload`)のハッシュであって生トークンのハッシュではない**: 生トークンの署名セグメントは署名の保護外で可鍛(base64url 末尾ビット / ES256 s-malleability)であり、生トークンをキーにすると署名検証・claims_digest を変えずにハッシュだけ変える 1 文字編集で束縛を回避できてしまう(2026-08-15 pullfrog レビュー。詳細は AUTH_SPEC §14-1)。なお束縛はトークン単位でプロジェクト内の全環境を跨ぐため、1 トークンで複数環境をリースするワークロードは全リクエストで同一の一時鍵を用いる義務がある(AUTH_SPEC §14-1)。裁定で採らなかった所持証明(要求する `aud` に一時公開鍵のハッシュを混ぜる形。IETF WIMSE の WIT/WPT が標準化中の同型)は、audience を発行時に固定する issuer(GitLab 等)で構造的に成立しないため見送った(issuer 汎用性 — session-22 §2 R1 — の維持。issuer 側が鍵束縛トークンを発行できるようになった時点で追加裁定する)。**縮小後の非保証(v1)**: (1) **初回使用前**に窃取されたトークンの先着使用(正規ジョブ側は `token-replayed` の失敗として検出する — 露出は「初回使用まで」であり `exp - iat` 全幅ではない)、(2) 束縛状態がプロジェクト単位であることによる、**同一ワークロード同一性を複数プロジェクトの lease_policy が許可している場合**のクロスプロジェクト先着。§14.3 の非保証一覧と同じ性格の記載
- **保証の含意**: リース経路の導入後も §14.2 の保証は不変 — 侵害・悪意のサーバーは grant スコープ内の**機密性**を失わせられる(grant の定義そのもの)が、ワークロードへ**偽値を注入することはできない**(値署名の writer はチェーン上のメンバーであり、サーバーは署名できない)。「CI へ平文 secrets を複製する」型の同期と比べ、書き込み方向(CI 環境の汚染)の攻撃面が存在しない
- 変数粒度のリース(「この変数だけ」)は v1 の鍵階層(環境 × エポック単位の DEK)では表現できず、Phase 3 の課題として据え置く(ROADMAP: DO ベースのリース)
- テストベクター: `test-vectors/lease-wrap.json`(§11)

## 10. API 境界の不変条件

- 平文のシークレット値・DEK・master 秘密鍵はいかなる API ペイロードにも含まれない
- API スキーマ上、シークレット値は `EncryptedPayload` 型(フィールドの正規定義は AUTH_SPEC §12-2。suite・aad 構成要素・nonce・ciphertext に加え、2026-08-03 以降は §4.1 の署名ブロックを含む)としてのみ表現する
- サーバーは暗号文の保存・配布・アクセス制御・チェーン保存のみを行う(grant_server 済みプロジェクトの同期処理を除く)

## 11. テストベクター

- `packages/crypto/test-vectors/` に JSON として保持: 固定鍵・固定 nonce による各操作(変数暗号化、値の書き込み署名、メタデータステートメント署名、DEK ラップ、DEK ラップ登録署名、DEK コミットメント、チェーンエントリ正規化・署名、リカバリーラップ)の入力と期待出力
- 本改訂(0.4-draft)で追加・改訂されるベクター(**所有者承認後の実装 PR で、実装より先にコミットする** — 計画の詳細と negative 一覧は docs/notes/session-12.md §8): `value-signature.json`(新規)、`metadata-signature.json`(新規)、`dek-commitment.json`(新規)、`chain-entries.json` の**改訂**(単なる追記ではない: 既存正規チェーンは `create_environment` 非先行の `rotate_epoch` を含み新合意規則で無効になるため、create 先行 + rotate payload への commitment 追加で全再生成する。既存負例の期待理由・expected_head_states の意味論の変更を含む — 影響一覧は session-12.md §8-4)
- 0.5-draft で追加・改訂されるベクター(**所有者承認後の実装 PR で、実装より先にコミットする**): `lease-wrap.json`(新規 — §9.1。正例 + info 不一致〔別プロジェクト・別環境・別エポック・別 claims_digest〕の負例)、`invite-accept-signature.json`(新規 — §6.5)、`dek-wrap.json` / `dek-wrap-signature.json` の**拡張**(受信者クラス server — サーバー鍵 FP を info に用いる正例・移植負例)、`chain-entries.json` の**再生成**(grant_server payload のリースポリシー拡張 — §6.2 — により既存の grant_server / revoke_server 系正例・負例を新 payload 形式で再生成。`duplicate-server-key`・再 grant 二層規則〔開示スコープ縮小の拒否 / lease_policy 縮小の受理〕の正負例を追加)
- 0.6-draft で追加・改訂されるベクター(**所有者承認後の実装 PR で、実装より先にコミットする** — 計画の詳細と negative 一覧は docs/notes/session-27.md §13): `env-manifest.json`(新規 — §4.3。正例 + 改竄・座標移植・issuer 付け替え・ヘッド差し替え・prev 連鎖不整合・エポック後退・ダイジェスト不一致〔ステートメント欠落 / tombstone 隠し〕・分岐・suite 不一致の負例)、`head-attestation.json`(新規 — §6.6)、`checkpoint-digest.json`(新規 — variables_digest / values_digest / 監査累積ハッシュの LP 正規形の固定)、`chain-entries.json` の**追記**(§6.2 `checkpoint` op の正例・認可系負例と expected_head_states の最新チェックポイント導出への拡張。**全再生成は不要** — 新 op の追加は既存 op の payload 形式に触れず、既存正規チェーンのバイト列・ハッシュ・既存負例は不変。grant_server 拡張〔payload 形式変更 = 全再生成〕との違い)
- 0.8-draft で追加・改訂されるベクター(**所有者承認後の実装 PR〔S1 — 実装分割は docs/notes/value-free-schema-design.md §3〕で、実装より先にコミットする**): `metadata-signature.json` の**追記拡張**(§4.2 レイアウト v2。正例 = スキーマ欄あり active・`""` 型・declared 作成・declared → active 遷移〔activation〕・v2 削除のスキーマ欄保持。負例 = レイアウト混同〔v2 ステートメントの v1 ドメイン文字列解釈とその逆〕・スキーマ欄改竄〔var_type / required / description の各差し替え〕・required 空文字列・active → declared 遷移・deleted → declared 遷移・v1 レイアウトの declared・**v2 変数への v1 後続ステートメント〔レイアウト後退 — rename 形〕**・suite 不一致)、`env-manifest.json` / `checkpoint-digest.json` の**追記**(declared entry を含むダイジェスト正例と「declared は values_digest に現れない」正例 — entry・ダイジェストのエンコーダは不変)。**既存 v1 正例・負例は不変**(レイアウト v2 は新ドメイン文字列の追加であり、既存ステートメントのバイト列・ハッシュに触れない — §6.2 `checkpoint` op 追加時と同じ「追記で拡張」の型)。`chain-entries.json` は変更なし(チェーン形式に触れない)
- 0.9-draft(KL3)で追加されるベクター(**所有者承認後の実装 PR〔K2 — 実装分割は docs/notes/integration-options.md 補足 19〕で、実装より先にコミットする**): `master-key-wrap.json`(新規 — §8)。正例 = `passkey-prf-basic`(prf_out → KEK → AES-GCM・AAD バイト列)/ `guardian-any-2` / `guardian-all-3`(XOR 分片・固定一時鍵での HPKE Seal・info バイト列)/ `handoff-guardian-share` / `handoff-device`(KEK_h + device 形 AAD)/ `handoff-id` / `handoff-code`(表示形の符号化・復号)。負例 = AAD の kind / wrap_ref / mode 差し替え(`any` ↔ `all` の付け替え)・user_id 移植・guardian-wrap の share_index / guardian_user_id / group_id 移植・handoff-wrap の request_id / approver / source 移植・分片欠落(n−1 片の XOR)・チェックサム不一致のハンドオフコード・prf_salt 差し替え・suite 不一致。**`recovery-wrap.json` は不変**(バイト互換 — README 規約 25 として明記)
- 0.10-draft(IV)で改訂・追加されるベクター(**所有者承認後の実装 PR〔IV-K2 — 実装分割は docs/notes/integration-options.md 補足 21〕で、実装より先にコミットする**): `invite-accept-signature.json` の**再生成**(v2 — §6.5: `invite_token_hash_hex` → `link_pub_hex`、ドメイン `invite-accept-v2`。正例は同一 signed_bytes に対する受諾署名とリンク署名の 2 本を併記。負例 = 改竄・別招待〔別 link_pub〕・別プロジェクト・invitee 差し替え・enc / sig 鍵不一致・署名者不一致・**リンク鍵不一致**〔別のリンク鍵で作ったリンク署名 = サーバー偽造の形〕・suite 不一致)。**旧形式(token_hash 束縛)のベクターは残さない** — 互換経路を作らない裁定(2026-09-13)の写しであり、README 規約「既存ベクターは不変」の意図的な例外(規約 26 として明記)。`invite-link.json`(新規 — §6.5): 種 `k` からのリンク鍵導出(`k` → `K_pub`)、発行署名(正例 + 負例 = 改竄・**invite_id 移植**・head 差し替え・role 差し替え・link_pub 移植・inviter 鍵差し替え・署名者不一致・suite 不一致)、OpenSSH 公開鍵行の符号化と解析(正例 = 受諾者 sig 鍵の `ssh-ed25519 …` 行と GitHub 応答形〔`key` フィールドにコメント無し / あり〕の解析。負例 = 種別違い〔`ssh-rsa` / `sk-ssh-ed25519@openssh.com`〕・鍵長違い・base64 破損・種別文字列の大文字)。`chain-entries.json` は変更なし(チェーン形式に触れない)
- 0.11-draft(ES + PF1)で改訂・追加されるベクター(**所有者承認後の実装 PR〔K2 — 実装分割は docs/notes/es-design.md §4〕で、実装より先にコミットする**): `chain-entries.json` の**全再生成**(`add_member` / `change_role` の payload 形式変更 — §6.2。正規チェーンは scope = all / listed の両方のメンバーと、`set_approval_policy` → `propose` → `approve` の完成列を含む。`expected_head_states` に scope・方針・pending 提案を追加。負例 = `scope-role-mismatch`〔owner に listed〕・`scope-not-contained`〔add / change_role / remove の各形〕・`unknown-environment`〔scope の typo〕・`environment-out-of-scope`〔listed actor の create / scope 外 rotate / scope 外タプルの checkpoint〕・all に非空リスト・重複 id・`approval-required`〔方針下の直接追記〕・`approval-not-required`〔方針オフの propose / 対象外 op の propose / 方針変更後に対象外となった提案への approve〕・`approval-quorum-unreachable`〔owner 1 名での有効化 / owner を required 未満にする remove〕・`unknown-proposal`・`duplicate-approval`〔提案者 owner の自己承認〕・`proposal-expired`・`proposal-void`〔提案者の削除後の完成〕・内側 op の適用時失敗・フィールド順の入替・scope LP の平坦連結 — と各検査順序の固定形)、`invite-link.json` の**再生成**(発行文に scope — §6.5。負例に scope の差し替えを追加)、`value-signature.json` / `metadata-signature.json` / `env-manifest.json` の**再生成**(正規チェーンを読み込むため。正例の意味は不変。負例に `*-environment-out-of-scope-at-head` を追加)。**他のベクターは不変**(README 規約 27 として明記)
- ベクターは人間(+ 対話でのレビュー)が定義し、実装より先にコミットする
- ラウンドトリップテストはブラウザ / Bun / workerd の 3 環境すべてで CI 実行する
- nonce 一意性・AAD 検証・チェーン検証失敗系(改竄、順序入替、移植)の negative テストを必須とする

## 12. 禁止事項

- 独自暗号プロトコル・独自モードの発明
- ECB、CBC(unauthenticated)、静的 nonce、鍵の使い回し(用途間)
- 秘密鍵・DEK・平文値のログ出力(エラーメッセージ含む)
- プロバイダ ID・メールアドレスのチェーン / 監査ログへの記録
- 低エントロピー値への §5.2 型ハッシュコミットメントの適用(秘匿性が入力エントロピーに依存するため。コミットメントの対象は一様ランダム 256-bit の鍵素材のみ)

## 13. 未決事項

1. ~~HPKE ライブラリ選定~~ **決定済み(2026-08-01)**: `hpke`(panva)を採用(§2 参照)
2. デバイス鍵分離・パスキー PRF(WebAuthn PRF 拡張)対応(Phase 2 以降)**— 2026-09-12 追記: パスキー PRF は KL3 で「封印バックアップの KEK 素材」として §8.2 に導入した。デバイス鍵分離(端末単位の失効)は本項のまま未決**
3. 変数名の秘匿オプション
4. ~~チェーンヘッドの外部チェックポイント機構~~ **解消(2026-08-18 起草 — 本改訂 PR のマージをもって確定)**: 帯域外アンカー(§6.3 — 2026-08-12 の部分的実現)+ `checkpoint` op(§6.2 — #12 と統合した定期・網羅的チェックポイント)として設計。実装は Phase 2 Wave 3 の後続 PR(設計比較は docs/notes/session-27.md)
5. `maruhi/v2` ハイブリッド PQ スイートの詳細
6. ~~環境(environment)モデル~~ **決定済み(2026-08-01)**: DEK 粒度 = プロジェクト × 環境 × エポック(§3〜§5、§7 に反映)。環境別の閲覧制限は #11(2026-09-14 解消 — ES)
7. ~~プロジェクト内認可モデル~~ **決定済み(2026-08-01)**: チェーン上の 4 role(owner / admin / member / reader、§6.2)。org ロールとは完全分離(AUTH_SPEC §9)
8. SOPS 互換エクスポート / インポート(ロックイン懸念への回答。温存オプション、Phase 2 以降)
9. ~~未登録ユーザーの招待(pending invitation)~~ **解消(2026-08-12 起草 — 本改訂 PR のマージをもって確定)**: 招待一本化(登録済み・未登録とも同一機構)+ 受諾署名 + FP 相互確認 + 招待リンクアンカーとして設計(§6.3 / §6.5、AUTH_SPEC §15)。グローバル公開鍵ディレクトリは「同意なき追加」を許す構造になるため採用しない。実装は Phase 2 チーム共有 PR(設計比較は docs/notes/session-22.md) **— 2026-09-13 追記: 招待者側の 12 語儀式の既定廃止(IV1 リンク束縛 + IV2 裏付け元)を §6.5 の改訂として起草。設計録は docs/notes/integration-options.md 補足 21**
10. サーバー鍵(デプロイメント keypair)自体のローテーション手順
11. ~~環境スコープの role~~ **解消(2026-09-14 起草 — 本改訂 PR のマージをもって確定)**: `add_member` / `change_role` の payload に scope(`all` / `listed`)を追加し、DEK ラップの受信者集合を scope で限定(§3 / §6.2 / §6.3 / §7、AUTH_SPEC §9-2 / §12、AUDIT_SPEC §4.1)。設計録は docs/notes/es-design.md
12. ~~認証済みデータ履歴の強化(環境マニフェスト・チェックポイント)~~ **解消(2026-08-18 起草 — 本改訂 PR のマージをもって確定)**: 環境マニフェスト(§4.3 — 変数集合の欠落検出 + メタ層の鮮度アンカー)、`checkpoint` op(§6.2 — 値・マニフェスト・監査ヘッドのチェーンへの公証。#4・AUDIT_SPEC 未決 #2 と統合)、ヘッド申告(§6.6)として設計。実装は Phase 2 Wave 3 の後続 PR(設計探索・残余対応表・却下案は docs/notes/session-27.md)

## 14. データ真正性の保証と非保証(2026-08-03 セッション 12 起草)

§4.1 / §4.2 / §5.1 / §5.2 / §6 の各機構が「何を証明し、何を証明しないか」の規範的まとめ。詳細な脅威分析・設計比較・却下案は docs/notes/session-12.md。Phase 2 の公開前脅威モデル文書(ROADMAP)は本節を基礎とする。

### 14.1 セキュリティ目標の分解

以下の性質は独立であり、混同してはならない:

| # | 目標 | 意味 | 担う機構 |
|---|---|---|---|
| G1 | 帰属 | 誰の鍵がこのデータに署名したか | §4.1 / §4.2 / §5.1 の署名 + user_id 焼き込み |
| G2 | 認可時点 | 署名者がどのチェーン状態で必要 role を持っていたか | §4.1 / §4.2 のヘッド束縛 + §6.3 の宣言ヘッド時点 role 検証 |
| G3 | 内容真正性 | ciphertext / DEK / metadata が署名(コミットメント)後に改変されていないか | §4.1 / §4.2 の署名対象全列挙、§5.2 コミットメント |
| G4 | 文脈束縛 | project / environment / epoch / variable / version / recipient の外への移植不能性 | AAD(§4)・HPKE info(§5)・全署名対象の座標列挙・§5.2 の座標入り原像 |
| G5 | 最新性 | 古い正規データへの巻き戻しの検出 | §6.3 ローカル床(SHOULD)+ 帯域外アンカー(チェーンヘッド)+ チェックポイント整合(§6.2 / §6.3 — データ層。2026-08-18)。アンカーも床も持たないクライアントには機構的保証なし(14.3-3) |
| G6 | 完全性 | 値・更新・チェーンエントリの欠落の検出 | チェーン: prev_hash + seq 連続性。値・メタ: prev 連鎖(既知範囲)+ ローカル床 + **環境マニフェストのダイジェスト(§4.3 — 集合の欠落検出)+ チェックポイントの値スナップショット(§6.3。2026-08-18)** |
| G7 | 分岐耐性 | メンバーごとに別の「正規」履歴を配布する split view の検出 | 証拠化(prev 連鎖・ヘッド束縛・**署名付きヘッド申告 §6.6**)+ ヘッドゴシップの相互照合(§6.3 — サーバーの omission で回避可能なため**保証なし**。2026-08-18)。帯域外アンカー(外部の合意点)との合成で残余を狭める(14.3-4) |
| G8 | 可用性 | サーバーの応答拒否・削除・遅延への耐性 | **保証しない**(検出可能な場合も防止はできない) |
| G9 | 平文の正しさ | writer が「正しい」値を書いたこと | **保証しない**。証明できるのは「正規権限を持つ writer がこの暗号文を書いた」まで |

### 14.2 保証(クライアントが §5.2 / §6.3 の全検証を実施する前提)

すべて「クライアントが検証したチェーンビュー」に相対的である(そのビュー自体の鮮度は G5/G7 の領分):

1. **偽 DEK 注入の不能性**: 検証済みチェーンに載る (environment, epoch) のコミットメントと一致しない DEK は使用前に拒否される。サーバーとチェーン履歴上の任意の鍵保持者が共謀しても、実在エポックへ自作 DEK を注入できない(SHA-256 の衝突困難性)。ラップ改竄・毒ラップは可用性問題(G8)に退化する
2. **値・メタデータの偽造の限定と帰属**: 検証を通る値は、「チェーン上のいずれかの時点で必要 role を持っていたメンバーの sig 鍵」の保持者が、その鍵の在籍区間内の宣言ヘッド・当時の現エポック座標に対して署名したものに限られる。検証を通るメタデータステートメントは、同じく在籍区間内の宣言ヘッドへの署名に限られる(エポック座標を持たない — §4.2)。いずれも帰属(user_id + 鍵 FP)が偽装不能に固定される。サーバー単独では値・名前・DEK のいずれも偽造できない
3. **現エポックの健全性**: メンバー削除・member 未満への降格・scope の縮小が対象の scope の全環境のローテーション(§7 — 2026-09-14 ES 改訂)を伴う運用の下で、write 資格を失った鍵(削除済みメンバー・降格済みメンバー・漏洩した旧鍵)では現エポック宛の値・現エポックの DEK を偽造できない(G2 + エポック整合 §6.3-4 + §5.2)
4. **名前 ↔ ID 対応の真正性**: 名前と variable_id / environment_id の対応の書き換えは、必要 role を持つ(または過去に持っていた)鍵保持者の署名済みステートメントの範囲でしか行えず、帰属が残る。サーバーによる対応の付け替え・無署名の改名は検証で拒否される。**メタ層の鮮度は環境マニフェスト(§4.3)のエポック焼き込みが供給する(2026-08-18)**: write 資格を失った鍵(削除済み・降格済み・漏洩した旧鍵)では現エポックのマニフェストを署名できず(§7 のローテーション義務〔対象の scope の全環境 — 2026-09-14 ES〕+ マニフェストのエポック整合検証)、メタの前進注入の残余は値(14.2-3)と対称の形 — 14.3-5 の (i)(ii)(iii) — に縮む(旧「メタはエポックアンカーを持たない」非対称の解消)
5. **分岐・差し替えの証拠化**: 同一座標(variable × version、meta_version、または manifest_version)に対する内容の異なる 2 つの有効署名、自ビューに存在しないヘッドへの束縛、および自ビューと矛盾する署名付きヘッド申告(§6.6)は、サーバーの equivocation または鍵漏洩の暗号学的証拠となる(否認不能)
6. **チェックポイント時点までのデータ層の完全性・最新性(2026-08-18 — §6.2 / §6.3)**: 検証済みチェーンに `checkpoint` が存在する場合、チェックポイント整合検証を通過した配布は、チェックポイント発行時点のメタ状態(マニフェスト)・値状態(スナップショット)から巻き戻っていない。**この保証は「クライアントが検証したチェーンビュー」に相対的である**(本節冒頭のとおり): チェーンヘッド自体の鮮度は床・帯域外アンカーが担い、それらを持たないクライアントには 14.3-3 が残る
7. **監査ログの事後改竄の検出材料(2026-08-18 — §6.2、AUDIT_SPEC §6)**: チェックポイントに公証された監査累積ハッシュは、公証済み接頭辞の監査行の事後改竄・削除を、全行を読める admin の再計算との矛盾(署名済み・チェーン上のため否認不能)として検出可能にする。admin の突合は所属に加えて**公証点の位置の単調前進**(直前チェックポイントのミラー行以上 — AUDIT_SPEC §6)を検査し、実在する古い累積ハッシュを返し続ける陳腐化リプレイ(保護接頭辞の凍結)も検出する。記録時点の虚偽(サーバーが最初から偽の行を書く・書かない)は従来どおり非保証(監査ログはサーバー管理データ — AUDIT_SPEC §6 の脅威モデルは不変)
8. **required 充足(presence)の検証可能性(2026-08-30 セッション 46 — §4.2 レイアウト v2)**: スキーマ欄(型・必須・説明)と `declared` 状態は署名済みステートメントに載り、マニフェスト被覆(§4.3)に自動継承されるため、「この環境の required 変数はすべて設定済み(active)か」は、検証済みステートメント集合だけから、**サーバー申告に依存せず**全検証者 — 値を復号できないクライアントを含む — が判定できる。サーバーが「値がある」と偽る余地は active の値配布要求(§6.3)が、「値がない」と偽る余地は欠落検出(マニフェストのダイジェスト + チェックポイント)が挟む
9. **環境スコープの鍵配布保証(2026-09-14 — ES)**: 検証済みチェーン上でメンバー m の scope に含まれない環境 E について、m 宛の E の DEK ラップは仕様適合クライアントによって生成されず、仕様適合サーバーによって受理されない(§6.3 / AUTH_SPEC §12-6)。サーバーが侵害されても E の DEK を m へ渡す材料が存在しない。**保証しないもの**: scope に入っていた期間に取得した DEK・平文の取り消し(§1 原則 5 — 縮小・削除時の rotate 義務と要ローテーション検出が補う)、および平文メタ(存在・名前・スキーマ欄)の秘匿(未決 #3)
10. **四眼の適用保証(2026-09-14 — PF1)**: 方針が有効なプロジェクトで対象 op が適用されるのは、distinct な owner の署名(提案 + 承認)が必要承認数に達したエントリ列のみ(§6.2)。owner 1 名の鍵の漏洩・暴走では対象 op は適用されない。**保証しないもの**: 必要承認数以上の owner の共謀、方針オフ状態のプロジェクト(既定)、対象外の op。owner 身元の追加(`add_member` / `change_role` で owner を確立する op)と方針の変更は `ops` の列挙に依らず常に四眼の対象であり(§6.2)、単独 owner が身元を増やして定足数を満たす経路は閉じている — ただし方針を有効化する前から存在する owner 身元の同一人物性は検証しない(有効化時点で既に 2 身元を持つ人物は四眼の外)。**可用性(2026-09-14 pullfrog レビュー対応)**: 方針が有効な間、チェーン上の現 owner 数は到達可能性の不変条件(§6.2)により `required_approvals` 未満にはならないが、**署名できる owner**(鍵を保持し協力する owner)が `required_approvals` 未満になった場合(owner の鍵の恒久的な喪失・離職 — チェーン上は owner のまま)、残る owner は owner の追加・欠けた owner の削除 / 降格・方針の変更のいずれも単独では完成できず、**対象 op と方針の変更は復帰不能**になる(データ面 — push / rotate / create_environment — は動き続ける。break-glass の時間錠は原則 6 と timestamp の扱いに抵触するため置かない)。緩和は運用前提: 有効化は現 owner 数 ≥ `required_approvals` **+ 1**(予備 owner)を推奨し、CLI は有効化時にこの条件と各 owner のリカバリー登録(§8)を案内する(合意規則の有効化条件は ≥ のまま — 承認項目 17 で所有者裁定)

### 14.3 明示的な非保証(v1)

1. **可用性(G8)**: 悪意あるサーバーは応答拒否・データ削除・選択的遅延ができる。修復経路・警告はあるが防止はできない
2. **平文の正しさ(G9)**: 悪意ある(または誤った)正規 writer の不正値は防げない。E2EE でサーバーは値を検証できず、これは設計上の帰結である
3. **床もアンカーも持たない初回同期クライアントへの最新性・完全性(G5/G6。2026-08-18 に残余クラスを縮小)**: ローカル床を持たないクライアントに対し、サーバーは「内部整合する古いビュー」(短縮したチェーン + 当時の値・ステートメント・マニフェスト・チェックポイント一式)を配布できる。**チェーンごと巻き戻したビューでは削除済みメンバーが現メンバーに見える**ため、14.2 の保証はそのビューの時点の意味でしか成立しない。帯域外アンカー(§6.3 — 招待リンク = 新メンバー、リポジトリアンカー = ワークロード)がチェーンヘッドの鮮度を、チェックポイント整合(§6.3)がそのヘッドの下でのデータ層の完全性・最新性(**チェックポイント時点まで** — 14.2-6)を与えるため、**残余は「床も帯域外アンカーも持たないクライアント」に縮む** — このクラスにはトラストアンカーが存在せず、鮮度の機構的保証は原理的に不可能である(ヘッドゴシップの申告照合は検出可能性を足すが、サーバーの omission で回避可能 — 14.3-4)。緩和の全体像と検証連鎖はセッション 27 ノート §2 / §6
4. **split view(G7)**: メンバーごとに異なる内部整合ビューの配布は、**保証付きには検出されない**(2026-08-18 更新): ヘッドゴシップ(§6.3 / §6.6)は申告の相互照合による検出可能性と否認不能な証拠化を与えるが、サーバーは申告の配布を選択的に省略・停滞できる(omission は G8 に帰着)ため、能動的な悪意サーバーはビューごとに「分岐前の共通接頭辞の申告のみ」を配布して照合を空振りさせられる。残余の縮小は帯域外の合意点(リポジトリアンカー — 全メンバー・ワークロードが同一の git 履歴を見る)とチェックポイントの合成が担い、完全な閉包は v1 の目標にしない
5. **共謀の残余**: 「member 以上の role を持つ在籍区間」がチェーン履歴上に存在する鍵の保持者(削除済み元メンバー・member 未満へ降格されたメンバー・漏洩した旧署名鍵)+ サーバーは、**その区間内の座標(値: 当時のエポック × 当時のヘッド。メタ: 当時のヘッド)に限り**、帰属付きの偽値・偽ステートメントを注入できる。注入の向きは 2 つあり、検出可能性が異なる:
   - **後退方向**(既存座標の差し替え・巻き戻しとの併用): ローカル床に version / meta_version / エポックの後退、または同一 version の signed_bytes 相違として検出される
   - **前進方向**(実最新の次の version / meta_version / manifest_version を旧座標で偽造する「追記」注入): 巻き戻し・欠落を必要とせず、**署名・連鎖検証と素朴な床(連番の単調性)だけでは検出されない**。値については、エポック単調性(§4.1)+ 床の拡張規則(§6.3 の (c))により床を持つクライアントに検出される。**メタについても、環境マニフェスト(§4.3 — 2026-08-18)のエポック焼き込み + エポック整合検証 + 床のマニフェスト版規則により、床を持つクライアントに検出される**(偽メタステートメント単体はマニフェストのダイジェスト不整合で落ち、偽マニフェスト込みの注入は旧エポックしか名乗れない): 旧「メタはエポックアンカーを持たず床でも検出されない」非対称は解消され、メタの残余は値と対称の以下 3 つに縮む — (i) 床を持たない初回同期クライアント(非保証 3 に帰着。帯域外アンカーを持つ場合はチェックポイント整合 — §6.3 — のエポック基準検査〔床規則 (c) のチェックポイント版〕が前進注入の検出まで与える: 基準がチェックポイント時点である分、返却クライアントの床より粗いだけで形は同じ)、(ii) remove / 降格から全環境 rotate 完了までの窓(§7 が義務付けるため短いが機構保証ではない — 機構化の候補はセッション 12 ノート §10-7。独立タスクとして維持 — セッション 27 ノート §11)、(iii) **当該環境のエポック床が攻撃者の在籍区間より古い(= 在籍区間終了後に一度も当該環境を pull していない)返却クライアント**(規則 (c) の基準が攻撃座標のエポック以下のため発火しない — マニフェスト版規則にも同型に成立する)
   - なお **DEK を知らない鍵保持者(署名鍵のみの漏洩)は復号可能な偽値を作れない**(AES-GCM のタグ偽造不能性により、値の注入は復号失敗 = 可用性問題に退化する)。メタステートメント・マニフェストの偽造には DEK が不要であり、このクラスにもメタの前進注入は可能である — 検出可能性は上記(マニフェストのエポック整合 + 床)と同じ
6. **漏洩・取り消し**: メンバー(reader 含む)は保持する DEK・平文を漏らせる。暗号は既読の値を取り消せない(§1 原則 5 の再掲)
7. **宣言型と値の一致(type / format。2026-08-30 セッション 46 — §4.2 レイアウト v2)**: スキーマ欄の var_type / description と実際の値の一致は保証しない — E2EE のためサーバーは原理的に検証できず、検証は値を平文で扱う文脈のクライアント(push 時・`maruhi run` 時)の **advisory な検査**のみである。G9(平文の正しさ)の亜種であり、署名が証明するのは「author がこの型を宣言した」ことまで。**表示規律(規範)**: UI / CLI は型を「宣言(declared type)」として表示し、型検証を実施した主体以外の文脈で「検証済み(verified)」と表示してはならない — required の充足(presence — 14.2-8)は「署名済みステートメントから検証済み」と表示してよく、この非対称こそが保証の分割である(検討メモ発見 B・session-46 裁定 CU)
8. **保護者リカバリーとハンドオフの共謀(2026-09-12 — §8.3 / §8.4)**: `mode = any` の保護者 1 人(`all` なら全員)と、ward のアカウント認証を得た者が共謀すれば、ward の master 鍵を復元できる。保護者は「その相手」として ward が信頼する人物であり、暗号はこれを防がない(保護者を指名しないことも選べる)。ward のアカウント奪取者が保護者へなりすまして承認を得る攻撃は、保護者の帯域外の本人確認だけが防ぐ(サーバーは証明できない)。ハンドオフコードを運ぶ経路が能動的に改竄された場合、承認は攻撃者の一時鍵へ向くが、承認・ラップの取得には ward のアカウント認証が要る(コード改竄 + アカウント奪取の複合が条件)
9. **招待リンク経路の残余(2026-09-13 — §6.5 IV 改訂)**: リンク鍵によりサーバーは受諾鍵をすり替えられないが、**リンクを渡す経路**(Slack DM 等)を読める攻撃者は正規の相手より先に自分の鍵で受諾できる(受諾衝突として正規の相手側には顕在化する)。裏付け元(`github-signing-keys`)がこれを事前に閉じるが、攻撃者が相手の GitHub アカウントに自分の鍵を置ける(アカウント奪取)場合、または招待者が宛先 login を誤って名指しした場合は閉じない。裏付け元 `none` ではフォールバックの帯域外相互確認が閉じる。経路が**能動的に**差し替えられた場合(攻撃者自身のプロジェクトへの有効なリンク)、受諾者側の防衛は裏付け元が示す招待者 login を受諾者が読むこと(`--from` / yes)である。**招待リンクは信頼できる人対人チャネルで渡す**(規範 — AUTH_SPEC §15-3)。本項は H5 で脅威モデル文書へ移す
