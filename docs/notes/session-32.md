# セッション 32 メモ(session-31 裁定 1 の仕様起草と strict 受理経路の実証)

日付: 2026-08-19。対象: session-31(PR-M1 マージ後監査)§7 の所有者裁定 3 件のうち
裁定 1 の仕様起草。形式: 仕様改訂 + 技術検証の記録。実装(PR-F1〜F4)は
仕様承認後の別 PR で行う。

## 1. 本 PR で起草したもの(裁定 1 = session-31 の最終推奨をそのまま採用)

- AUTH_SPEC §12-10: security-critical 受理スキーマの厳格性(1-E)・
  wire 非互換変更の設計規範・mutation 成功の定義(1-E′)
- CRYPTO_SPEC §1 原則 6: 意味論は署名バイト列の中に置く(既存アーキテクチャの
  明文化。残余 = 受理側の検証モード選択は裁定 2 の帰結に従うことを明記)

裁定 2(H+1 例外 — 2-F / 2-E / 2-D のはしご)と裁定 3(床 — 3-D + 3-E + 3-E′)は
本 PR に含めない。裁定 2 は一時コスト(2-F = re-genesis + データ層全再構築)の
受け入れが所有者にしか決められず、裁定 3 の §6.3 床節の書き直しは裁定 2 の帰結
(2-F なら床のマニフェスト記録材料がチェーン導出になる — session-31 §7 裁定 1
第 4 次の相乗効果)と文言が絡むため、裁定確定後にまとめて起草する。

## 2. strict 受理の実装経路の実証(session-31 が「PR-F1 の最初の作業」とした確認)

環境: effect 4.0.0-rc.109(リポジトリの厳密ピン)。検証スクリプトは使い捨て
(コミットしない)。

### 2-1. 結論: スキーマ AST 注釈だけで到達できる(HttpApiBuilder の変更不要)

session-31 は「`onExcessProperty` は decode 呼び出しの `ParseOptions` であって
スキーマ注釈ではなく、現行の `HttpApiBuilder` は payload デコーダを
ParseOptions なしで組み立てる」ため、エンドポイント定義でのオプション指定・
手動 decode 層・upstream 対応のいずれかが要ると見込んでいた。実測の結果、
**第 4 の経路(スキーマ自身への焼き込み)が存在し、それだけで足りる**:

- `SchemaParser.makeParser`(dist/SchemaParser.js)は AST 注釈
  `annotations["parseOptions"]` を読み取り、parse 時に
  `mergeParseOptions(options, astOptions)` で合成する
- 合成は **AST 注釈が呼び出し側 ParseOptions に勝つ**(第 2 引数が後勝ち)。
  HttpApiBuilder が options なしで decode しても、将来緩い options を渡す
  実装になっても、スキーマに焼き込んだ strict は維持される

### 2-2. 実測結果(bun + effect rc.109)

`Schema.Struct({...}).annotate({ parseOptions: { onExcessProperty: "error" } })`
に対して、HttpApiBuilder と同一の組み立て
(`Schema.decodeUnknownEffect(Schema.Union([schema]))`、options なし)で:

| ケース | 結果 |
|---|---|
| 素の Struct + 未知フィールド | 黙って除去して成功(M1-A2 の既定挙動の再現) |
| 注釈付き + 未知フィールド | `Expected no excess property at ["manifest"]` で拒否 |
| 注釈付き + 正常入力 | 成功 |
| 親にのみ注釈 + ネスト内の未知フィールド | 拒否(**子へ伝播する**) |
| 注釈付き + 呼び出し側が `onExcessProperty: "ignore"` を明示 | 拒否(**注釈が勝つ**) |
| `Schema.Union` ラップ越し(HttpApiBuilder 実経路と同型) | 拒否 |

### 2-3. PR-F1 実装への含意

- 適用点は `packages/api-schema` の security-critical payload schema のみ
  (トップレベル 1 注釈で全ネストに効く)。共有ラッパー(例:
  `strictPayload(...)`)1 つで単一実装点にできる
- HttpApiBuilder のフォーク・手動 decode 層・upstream issue は不要。
  AUTH_SPEC §12-10 (1) の実装注記に反映済み
- エラーは既存の Schema 検証エラー(400)として表面化する(HttpApiSchemaError
  経由)— 新しいエラー面を増やさない
- **適用順の制約(2026-08-19 pullfrog レビュー指摘 — 実測で確認)**:
  `SchemaParser.makeParser` は AST に checks があると `parseOptions` を
  **最後の check の annotations** から読む(dist/SchemaParser.js:892)。
  `SchemaAST.annotate` も checks があると最後の check へ注釈を付けるため、
  **注釈の後に `.check(...)` を合成すると strict が無警告で失効する**
  (rc.109 実測: annotate のみ → 拒否 / check → annotate → 拒否 /
  annotate → check → **受理・未知フィールドは黙って除去**)。
  fail-closed 機構の失敗が silent なので、PR-F1 では
  (1) `strictPayload(...)` を**最後に適用する**規約(check を全て
  済ませたスキーマにのみ被せる)とし、
  (2) 全対象エンドポイントについて「未知フィールドが実際に 400 で
  拒否される」ことを受理経路の固定テストで保証する(注釈の存在では
  なく拒否の実効性をテストする — 適用順バグ・upstream の読み取り位置
  変更の両方を検出する)

## 3. 裁定待ちの状態(所有者へ)

- 裁定 1: 本 PR のマージ = 承認
- 裁定 2: はしごは §4-2 で改訂(新案 2-H の追加)。推奨 = 2-H。
  公開前限定の選択肢は 2-F / 2-H / 2-E(session-31 §7 裁定 2 + 本ノート §4)
- 裁定 3: session-31 の最終推奨(意味論 = 3-D 単調 join、保存形 = 3-E
  追記専用ログ、記録規律 = 3-E′ journal-before-release、コンパクション =
  M1 はスナップショット行方式)に §4-3 の 3-F(intent journaling)を
  加えた形の確認待ち。承認されれば裁定 2 の確定と合わせて §6.3 床節の
  改訂を起草する

## 4. 裁定 2・3 の上位互換探索(2026-08-19 第 5 次 — 所有者依頼)

session-31 §7 の各最終推奨に対して、さらなる上位互換がないかを再点検した。

### 4-1. 検討して棄却した案(裁定 2)

- **案 2-G: `checkpoint` op(§6.2 — 既起草・未実装)を複合へ原子同梱する**:
  2-F の「チェーンがマニフェストハッシュを運ぶ」を、既存起草の op の再利用で
  合意規則の**追加のみ**(既存 op payload 不変 = re-genesis 不要)により
  実現する着想。棄却理由: checkpoint payload は values_digest_hex を必須で
  運び、受理検証(§6.4)が受理時点のサーバー保存状態との突合を要求するため、
  発行者は最新の値レベルビュー(variable_id / version / value_sig_hash)が
  必要になる。metadata-only pull はこれを運ばない(AUTH_SPEC §12-7 —
  実測で確認)ため full pull が要り、rotate / create のたびに `var.read` を
  変数ごとに記録する監査汚染が発生する — 案 3-B の棄却根拠と同じ循環
- **案 2-I: checkpoint の values_digest を空許容にする(manifest-only
  checkpoint)**: §6.3 チェックポイント整合の規則 2 は「基準チェックポイントを
  持つ環境の値付き配布がスナップショット列挙を欠く場合は拒否する」を
  不変条件とする(2026-08-18 pullfrog レビューで固めた線)。値公証なしの
  checkpoint はそこへ「基準あり・列挙なし」の第 3 状態を持ち込み、攻撃者が
  選べる規則 2 スキップ経路になる。棄却

### 4-2. 案 2-H: 専用アンカー op の複合原子同梱(2-F の強度を re-genesis なしで)

**着想: 2-F のコストの源泉は「既存 op(create / rotate)の payload を変える」
ことにあり、束縛を「新 op の追加」で運べば加法的になる**(checkpoint op が
§6.2 で「既存 op payload に触れない」を利点として明記した、その形の再利用)。

- 新 op `anchor_manifest`(名称は起草時に確定): payload =
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex)` —
  checkpoint の環境エントリから values_digest を除いた同型。
  「チェーンはハッシュを運び、内容の検証はデータ層が担う」クラス(§6.2 の
  先例に載る)
- 複合(create / rotate)は同一リクエストで **H+1 = create / rotate、
  H+2 = anchor_manifest の 2 エントリを原子追記**する(単一 DO
  トランザクション — 部分受理は構造的に起きない)
- 合意規則(いずれも新 op に閉じる = 既存チェーンへ影響しない):
  (i) 隣接規則 — anchor は直前エントリが同一環境の create / rotate かつ
  同一 actor の場合のみ有効(standalone アンカーの排除)、
  (ii) epoch はエントリ時点(自エントリ適用前)の現エポックと厳密一致
  (checkpoint と同型)。**H+2 時点では H+1 が適用済みなので new_epoch が
  厳密一致する — anchor 自身に H+1 例外は不要**、
  (iii) manifest_version の単調増加 — 同一環境の先行 anchor の値より
  大きいこと(checkpoint-regression と同型。payload の公開値のみで
  チェーン検証可能)。これにより有効チェーン上で (environment_id,
  manifest_version) の anchor は高々 1 つになり、下の検証規則の照合先が
  決定的になる
- マニフェスト検証(**選言にしない — 2026-08-19 pullfrog レビュー反映**。
  当初の「strict または anchor 一致」の形は、anchor が存在しても strict
  経路が生きたままなので、同一 issuer が同じ (environment_id, epoch,
  manifest_version) で別内容のマニフェストに宣言ヘッド H+2 以降を
  焼き込めば strict 側で通ってしまい、equivocation 優位が消える):
  1. 検証済みチェーン上に当該 (environment_id, manifest_version) の
     anchor が**存在するなら、manifest_sig_hash の完全一致を MUST とする**
     (strict はこの場合の代替経路にならない)。epoch も anchor の値と
     一致すること
  2. anchor が存在しない場合のみ strict(epoch = 宣言ヘッド時点の
     現エポック)を適用する
  3. 配布されたマニフェストの manifest_version は、検証済みチェーン上の
     当該環境の**最新 anchor の値以上**、epoch は同 anchor の epoch 以上で
     なければならない(チェーン導出の下限。manifestVersion はエポックを
     跨いで単調 — §12-5 CAS — なので、境界より前の版はすべて最新 anchor の
     値未満になり、正当な配布への誤検出はない)
  - actor = issuer 規則は不要(2-F と同じ論法: 投機的相乗りは hash を
    予知できず、事後の相乗りは自分のマニフェストの hash がアンカーに
    載っていない)。なお 2-F を採る場合も、session-31 §7 の規則文
    (「例外は…場合のみ」)は同じ選言形なので、起草時に本 MUST 形
    (エントリが manifest ハッシュを運ぶ create / rotate に対応する
    manifest_version は、その hash と一致しなければならない)へ
    書き直すこと
- 2-F の波及効果を全て保持する: エポック境界の発行時チェーンアンカー、
  M1-A4(受理確認 = チェーン同期だけで床コミット材料が揃う)、M1-A3
  (env create 直後の床のマニフェスト記録がチェーン導出で確立)、1-E′
  (複合の成功確認がチェーン同期で完結)
- **2-E に対する検出差(2026-08-19 pullfrog レビュー反映 — 当初の
  「equivocation が全クライアントに検出可能」は過大主張であり縮小する)**:
  アンカーが載るのはエポック境界(create / rotate 複合)の版のみで、
  同一エポック内の後続版(メタ操作ごとの manifestVersion = 最新 + 1 —
  AUTH_SPEC §12-5)は構造的に未アンカーのまま規則 2(strict)に落ちる。
  よって 2-H / 2-F が閉じるのは **(i) アンカーを持つ版(= 境界
  マニフェスト)の equivocation** と、**(ii) 規則 3 による境界跨ぎの
  巻き戻し配布の検出**(最新 anchor 未満の版・エポックの拒否)であり、
  いずれも「床を持たないが帯域外アンカーでチェーン鮮度を持つクライアント
  (§9.1 ワークロードのリポジトリアンカー等 — §14.3-3)」にも効く。
  **最新 anchor より先の未アンカー版を名乗る前進注入は、issuer の正規
  発行能力そのものであり、2-E / 2-D と同じ残余として残る**
  (CRYPTO_SPEC §14.3-5 の残余 (i) に記録済みの非保証と同じクラス。
  周期的な非後退カバーは M2 checkpoint の領分で、anchor はその境界即時版
  という分担)。床・基準を持つクライアントは 2-E でも §6.3 床規則 (b) /
  チェックポイント整合規則 1 で同等の検出ができる。なおマニフェストの
  prev 連鎖(prevManifestSigHashHex)が最新 anchor へ到達することを
  要求すれば未アンカー版も推移的に束縛できるが、サーバーの保持が
  最新 1 通のみ(§12-5)で中間版が配布されないため、保持・配布規則の
  改訂を伴う — 本探索では 2-H のコストに含めず採らない(2-H の眼目は
  検出差ではなく「2-F の強度を re-genesis なしで」に置く)
- **コストが加法的**: 既存チェーンは新規則の下でも有効(旧エントリに新 op は
  含まれない)→ **re-genesis 不要・データ層再構築不要**。chain-entries.json
  は追加のみ(既存ベクター・expected_head_states の再生成なし)。
  マニフェストのワイヤ形式は不変 → env-manifest.json は負例追加のみ。
  移行 = 環境ごと 1 回の rotate / メタ操作(2-E と同水準)。crypto の
  人間レビューも加法ベクターで済む(2-F は全再生成のレビュー)
- 2-F が恒久的に勝る点(正直な差分): op が 1 つ少ない・隣接規則が不要・
  エポック境界あたり 1 エントリで済む。2-H はこの 3 点を恒久コストとして
  払い、引き換えに一時コスト(データ層全再構築)を消す
- **更新順序(2026-08-19 pullfrog レビュー反映 — session-28 §2-2 の順序が
  一部逆転する)**: 最初の移行 rotate がアンカーエントリを載せた時点で、
  旧 CLI は「未知 op = チェーン無効」により**プロジェクト全体の**チェーン
  検証に失敗する(未移行環境の CI ジョブも含む)。したがって順序は
  ① サーバー → ② **CI / CLI の更新** → ③ 全環境の移行 rotate とし、
  session-28 §2-2 の「② 移行 → ③ CLI」を入れ替える。②〜③ の間に
  旧クライアントが残っていればプロジェクトが読めなくなる窓があり、
  これは 2-E / 2-D にはない移行コストとしてはしごの比較に含める
  (fail-closed 方向の失敗であり無言の劣化ではない点は変わらない)

**はしごの改訂(第 5 次)**: 2-F ⇔ **2-H** ⇔ 2-E ⇔ 2-D。
推奨 = **2-H**: 2-F の一時コストの大半(re-genesis = projectId 更新 →
全署名データの検証不能化 → データ層全再構築)が消え、恒久差分は
op 1 個 + 隣接規則 1 本 + 境界 1 エントリに縮む。「公開前に払って恒久に
単純へ」の先例(grant_server 拡張・rotate への commitment)はいずれも
**既存データの作り直しを伴わない**形式確定だった — データ層全再構築まで
踏み込む先例はなく、2-H は先例の水準で 2-F の強度に到達する。

### 4-3. 案 3-F: intent journaling(3-E′ の上位互換 — journal-before-send)

3-E′(journal-before-release)は「検証済み事実の記録が使用・報告に先行する」
規律だが、**mutation の送信そのものは覆わない**。M1-A4 の応答消失・
post-accept failure の窓(session-31 §8 運用ガード 5 が手動で塞いでいるもの)は
「送信したが受理を観測できていない」状態が非永続であることに由来する。

- **3-F**: security-critical mutation の**送信前**に intent record
  (op 種別・environment_id・manifest_version + sig hash・宣言ヘッド —
  非機密のみ。ディスクレス不変条件と両立)を床ログへ追記する。
  受理確認(§12-10 (3) の効果確認)の成功で resolution record を追記して
  閉じる。未解決 intent を持つクライアントは、同一環境への次の mutation・
  成功報告の前に照合(チェーン同期 / metadata-only pull)で解決する(SHOULD)
- join との関係: intent は検証済み事実ではないため **join の格子には
  入れない**(観測とは記録クラスを分ける)。fold は未解決 intent を
  「要照合」として表面化する — 3-D の意味論を汚さない
- 失敗方向: クラッシュ・応答消失で失われるのは「成功したという思い込み」では
  なく「確認義務の記録」— 記録漏れの方向が安全側に固定される(3-E′ と同じ
  性質を送信側へ拡張した形)
- §12-10 (3)(1-E′)との相乗: 1-E′ が「確認するまで成功と言わない」を
  規範化し、3-F がその未確認状態をクラッシュ耐性にする。裁定 2 で 2-H / 2-F を
  採る場合、rotate / create intent の解決はチェーン同期のみで完結する
- 3-E′ の精密化(同時に規定する): journal-before-release / before-send の
  「記録」は write の成功ではなく**永続化(fsync 相当)**を基準とする。
  床ログの追記頻度は低くコストは無視できる

**推奨(第 5 次)**: 裁定 3 = 3-D + 3-E + 3-E′ + **3-F**(コンパクションは
session-31 の M1 スナップショット行方式のまま)。
