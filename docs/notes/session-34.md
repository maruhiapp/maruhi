# セッション 34 メモ(PR-F4 実装 — test hardening / cross-layer 回帰)

日付: 2026-08-28。対象: session-31 §6 の PR-F4(M1-T1 / M1-T2 の残り /
F1×F2×F3 の cross-layer 回帰)。前提: PR-F1(#87)・F2(#88)・F3(#96 / #97)は
main へマージ済みで、main は 2-G′ の「境界 checkpoint 必須」世代
(実装裁定は docs/notes/session-33.md)。本 PR はテストの修正・追加が本分で、
プロダクションコードの挙動変更は含まない(テストが実装バグを露呈した場合のみ
最小修正可 — 結果として今回は 0 件)。裁定プロセスは goal の指示どおり
「複数案 → 上位互換探索 → 3 周の比較 → 自律選択」で行い、各周の棄却理由を記録する。

## 1. 裁定 G: M1-T2 の固定手段の分担(JSON ベクター vs ハーネス invalid-input)

M1-T2 の残り 3 点 — (i) BMP × astral の UTF-8 バイト順、(ii) 非整数(1.5)と
`Number.MAX_SAFE_INTEGER + 1` の数値入力、(iii) 同じ長さの大文字 hex — を
どこで固定するか。

### 第 1 周

- **案 G-a: すべて JSON ベクター化** — 1.5 も 2^53 も JSON では表現可能
  (float64 で正確)。利点: 全部が「実装より先にコミットされる固定物」になる。
  欠点: 拒否ケースには参照生成器(generate_reference.py)が算出する期待暗号値が
  **存在しない**(期待値が「拒否」だけ)— 独立実装間の突合という
  ベクターの存在理由が立たない
- **案 G-b: すべてハーネス側** — 欠点: 順序ケース(i)は期待ダイジェストという
  暗号値を持ち、Python 参照生成との突合が本質的(UTF-16 順の実装は JS 側の
  自己整合テストだけでは落とせても、独立実装との固定にならない)。ベクターに
  できるものをハーネスへ落とす理由がない
- **案 G-c: 分担** — 順序(i)= JSON ベクター(参照生成器の期待値と突合)、
  拒否(ii)(iii)= ハーネスの invalid-input チェック(4 実行環境で走る)

### 第 2 周(上位互換探索)

- **案 G-d: negative セクションへ新 kind(例: "invalid-input")を導入し、
  拒否も JSON で運ぶ** — 棄却: (1) 参照生成器に生成物がなく、JSON が運ぶのは
  入力の列挙だけ(ハーネス定数と等価)。(2) env-manifest.json の kind 語彙は
  signature / authorization の 2 値で網羅チェックされており(session-13 の教訓)、
  第 3 の値の導入は既存の分担線 —「暗号検証・検証規則の拒否 = ベクター、
  InvalidInput(構造不正)= ハーネス」— を崩す拡張で、加法価値に見合わない。
  (3) 数値フィールドに非整数が混ざる JSON は、oxfmt・パーサ間の数値往復という
  新しいリスク面をゼロ利得で作る

### 第 3 周(再点検)

- F3a が checkpoint の values_digest に対して既に同じ分担を敷いている先例を確認:
  正規形の期待値は `values_digests` セクション(ベクター)、fractional /
  uppercase の拒否は `test/checks/checkpoint.ts` の invalid-input チェック
  (ハーネス)。G-c はこの既存線の延長であり新しい規約を作らない
- 順序ケースの判別力を再点検: 既存の byte-ascending ケースは ASCII / BMP
  低位止まりで、**UTF-16 コード単位比較(JS の素の文字列比較)と UTF-8 バイト
  比較が食い違う対**を含まない。食い違いはサロゲート境界にのみ現れる —
  BMP 高位 U+E000〜U+FFFF(UTF-8 リード 0xEE/0xEF)× astral(0xF0〜。UTF-16 では
  サロゲート 0xD800〜0xDBFF)。U+FFE5(EF BF A5)< U+1F511(F0 9F 94 91)が
  バイト昇順、UTF-16 では逆転する — この対を両ダイジェスト(§4.3
  variables_digest / §6.2 values_digest)の JSON ベクターに固定する

**選択: 案 G-c**。実装:

- ベクター(加法のみ — 先行コミット): `env-manifest.json` digests
  `surrogate-boundary-order`(ASCII / BMP 低位 / BMP 高位 / astral の 4 本立て、
  tombstone 1 本混在)+ `chain-entries.json` values_digests
  `surrogate-boundary-order`(同型)。生成は generate_reference.py の拡張
  (独立 venv)、oxfmt 後の git diff で挿入のみを確認、verify_reference.mjs
  全 PASS(663 件)。規約は test-vectors/README.md の 21 に記録
- ハーネス(4 実行環境): `test/checks/encoding.ts` — §2.1 の最下層で
  1.5 / MAX_SAFE_INTEGER + 1 / 負数の TypeError と MAX_SAFE_INTEGER 自身の受理
  (上界の内側)を固定。`env-manifest.ts` — ダイジェストエントリ(fractional /
  unsafe integer metaVersion・大文字 metaSigHashHex)と署名 context(fractional
  epoch・unsafe integer manifestVersion・大文字 digest / head hash)の
  InvalidInput。`checkpoint.ts` — unsafe integer version を既存の fractional /
  uppercase 系へ追加
- UTF-16 判別性のメタチェック(「ベクターが本当に判別対か」)は env-manifest 側に
  1 箇所だけ置く: 正規形実装は sorted-digest.ts の 1 実装で、両 JSON ベクターが
  両呼び出し面(§4.3 / §6.2)のダイジェスト値を独立に固定しているため、
  メタチェックの重複は不要

## 2. 裁定 I: §2.1 数値境界の最小仕様追記

§2.1 は「数値フィールドは 10 進文字列化」とだけ規定し、非整数・2^53 以上の
入力の扱いが明文化されていない(実装は一貫して `Number.isSafeInteger` で拒否)。

- 第 1 周: 案 I-1 = 追記しない(テストだけで固定)。案 I-2 = 最小 1 項の追記
  (「非負の安全整数のみ。非整数・2^53 以上は拒否」)
- 第 2 周(上位互換探索): 案 I-3 = 任意精度整数(BigInt / 文字列運搬)を許す
  方向の一般化 — 棄却: 現行の全数値フィールド(epoch / version / seq)は実運用で
  2^53 に近づくことがなく、ワイヤ・実装・他言語実装の複雑化だけが増える。
  公開前に「安全整数のみ」で確定する方が §12-10 の構造的 fail-closed と整合
- 第 3 周: 拒否の**根拠**を仕様に置く価値を確認 — float64 の精度喪失域では
  10 進文字列化が値と一対一にならず(9007199254740993 が表現不能)、同一
  「値」に対する signed bytes の一意性という §2.1 の眼目そのものが壊れる。
  これは実装詳細ではなく仕様の帰結であり、1 項の追記が適切

**選択: 案 I-2**(CRYPTO_SPEC §2.1 へ 1 項追記。goal の事前承認に基づき本 PR に
同梱 — 承認は PR レビューで行う)。挙動の変更はない(既存実装の明文化)。

## 3. 裁定 H: cross-layer 回帰で何を固定するか

F1(strict 受理 + 受理後照合 1-E′)× F2(manifest floor / intent 3-F)×
F3(境界 checkpoint 2-G′)の層間相互作用のうち、既存テストが固定していない
交点を列挙して選ぶ。

### 第 1 周(候補の列挙)

- **H-1: F1 strict × F3 checkpoint フィールド** — 複合 payload の `checkpoint`
  は F1 の strict テスト(#87)より後に F3b が追加したネスト構造で、strict の
  伝播(checkpoint エントリ root / payload / 環境タプル内の未知フィールド =
  400)が未固定
- **H-2: F3 checkpoint 配布の握り潰し × F1-E′ 受理後照合(CLI)** — 受理した
  境界 checkpoint を配布チェーンへ追記しないサーバー(チェーン合意規則上は
  有効なまま §4.3 (2) の束縛タプルだけが消える)。session-33 F-7 は「モックが
  2 エントリを追記**しないと**受理後の再 pull 検証が strict で落ちる」ことを
  観測しながら、その fail-closed 自体はテスト化していない — 旧 H+1 例外の廃止の
  end-to-end 固定として本質
- **H-3: F3 有界再試行(F-2)× F2 intent 規律(3-F)** — CheckpointStateMismatch
  の再試行は試行ごとに intent を積む。422 = 確定拒否(isServerRejection)が
  各 intent を閉じることで、打ち切り後に未解決 intent が残らない(次の実行へ
  照合義務を漏らさない)ことが未固定
- **H-4: F3 チェーン基準線 × F2 床規則 (a) の粒度** — メタ操作は checkpoint を
  発行しないため、チェーン基準線(mv1)は床(v3)より遅れて進む。基準線以上・
  床未満の v2 配布を checkpoint-regressed が素通しし、床規則 (a) が落とすこと
  (粗い共有基準が細かいローカル基準を短絡しない)が未固定
- **H-5: checkpoint 欠落複合の 400** — 旧 CLI(checkpoint を知らない)の
  create / rotate が Schema 段で fail-closed になるという session-33 裁定 E-3 の
  承認済み帰結が未固定
- H-6: checkpoint-regressed と床規則 (a) の優先順(両層が同時に武装した場合) —
  **棄却(重複)**: F-7 の 2 テスト(manifest.test.ts「rotate 受理後の巻き戻し
  検出」)が固定済み
- H-7: 移行経路(stripTrailingCheckpoint)× 床 — **棄却(重複)**: CLI 側は
  「床にマニフェスト記録がある環境の欠落は --init-manifest でも拒否」等、
  サーバー側は data-manifest の移行経路 2 テストが固定済み

### 第 2 周(上位互換探索)

- **H-8: workerd 実サーバー × 実 CLI の直結 full-stack 回帰** — 棄却:
  テスト基盤が別系統(vitest-pool-workers の SELF と CLI の MockServer)で、
  接続には HTTP ブリッジの新設が要る。各交点は既に両側からピン留めできており
  (サーバー側 = 受理面、CLI 側 = 配布検証面)、基盤新設のコストに対する増分が
  ない。将来の統合テスト基盤の提案としてのみ記録
- **H-9: property-based(fast-check 等)の層間状態空間探索** — 棄却: 新規依存
  最小の規律(CLAUDE.md)に反し、固定すべき交点は既知の具体形で列挙できている。
  ランダム探索が要る規模の状態空間ではない

### 第 3 周(再点検)

- H-2 の期待理由コードを再点検: 検出は検証順 D-2(prev → チェックポイント束縛
  エポック整合 → 内容 → 基準線)の strict 経路で `epoch-not-current-at-head`。
  タプル不在の複合形マニフェストは他のどの検査でも救済されない(それが 2-G′ の
  眼目)ため、理由コードまで固定してよい。あわせて「受理の確認(チェーン上の
  自 commitment 一致)は checkpoint の有無と独立に成立する」ため、床の
  自己発行マニフェスト昇格(M1-A4)は起きる — これも固定点に含める
  (握り潰しサーバーでも自分の受理の証拠は床に残る)
- H-3 の成功側(2 試行目で受理)も固定対象に含める: 1 試行目の intent が
  rejected で閉じ、2 試行目が受理確認で閉じる — 成功経路でも積み残しゼロ
- H-4 のフィクスチャ形を再点検: チェーンの checkpoint タプルは実マニフェスト
  ハッシュ(manifestHashOf(v1))と結線する(F-6 と同じ規律 — ダミーだと
  「タプル内容はどうせ照合されない」という誤前提をテストに持ち込む)。
  values_digest はチェーン合意規則が形式のみ検査する位置なのでダミー 64-hex

**選択: H-1 + H-2 + H-3 + H-4 + H-5**。実装:

- H-1 / H-5 → `apps/server/test/strict-payload.test.ts`(create へ checkpoint
  root プローブ、rotate へ payload / 環境タプルプローブ、checkpoint 欠落 400 の
  独立テスト)
- H-2 / H-3 → `apps/cli/test/env-rotate.test.ts`(makeServer へ
  `dropCheckpointFromChain` を追加。既存の有界再試行 2 テストへ intent / 床の
  assertion を追加)
- H-4 → `apps/cli/test/manifest.test.ts`(checkpoint エントリ入りチェーンの
  2 フェーズ床テスト。期待 = `environment-manifest rollback` が出て
  `checkpoint-regressed` が出ない)

## 4. M1-T1 の実装と横断確認の結果

### 4-1. 移行経路正例の修正(主対象)

`apps/server/test/data-manifest.test.ts` の移行経路正例は wrapDekForAll と
commitmentOf に**別々の** makeDek() を渡していた — サーバーは member 宛ラップの
平文を開けないため受理するが、「配布される新エポック DEK がチェーンの
コミットメントと一致せず peer CLI が拒否する」状態を正例が固定していた。修正:

- 単一の `nextDek` をラップとコミットメントの両方に使用
- サーバーの 200 で終わらせず、受信者(READER)として配布ラップを Open →
  §5.2 のコミットメント再計算 → **チェーンが配布した rotate_epoch エントリの
  dek_commitment_hex** との一致まで検証(data-crypto.ts へ
  `unwrapDistributedDek` を追加 — unwrapAndDecrypt の前半の切り出し)

### 4-2. 同型パターンの横断確認

全サーバーテストの makeDek() 使用箇所を走査した結果:

- **修正した正例(受理 200/204 まで進み、ラップ集合とコミットメントの不一致が
  受理後状態として残るもの)**:
  - data-environment「creates an environment atomically」(createEnvironmentWith
    の使い捨てコミットメント)
  - data-environment「retries a composite creation after a head CAS conflict」
    (ダミー "ab"×32 — 再試行の 200)
  - data-environment「enforces display-name uniqueness」(second の 200)
  - data-environment エポックライフサイクルの複合ローテーション 200
    (ダミー "ab"×32)
  - data-dek「accepts the original signer re-registering the identical wrap」
    (createEnvironmentWith の 200)
- **ヘルパの変更**: `createEnvironmentWith` に省略可能な `dekCommitmentHex` を
  追加(既定 = 使い捨て DEK — negative 用の従来挙動)。doc コメントに
  「受理まで進める正例はラップした DEK 自身のコミットメントを渡す」を明記
- **対象外と裁定したもの**:
  - negative(4xx で受理されない)全般 — data-fixture.ts の既存コメントどおり、
    使い捨ては受理判定に影響しない
  - data-dek の削除意味論テスト(cross-class 404)内の server 宛ラップ登録
    (makeDek 使い捨て)— 登録は削除 API の対象を作るためだけの配管で、
    ラップ内容はテストの固定対象でなく、コミットメントとの照合面も持たない
  - data-scenario の `wrapsFor`(ダミー DEK の完全ラップ集合)— negative /
    配管用ヘルパで、正例では使われない(境界 checkpoint 整合テスト等の
    422 系のみ)

## 5. 実装内容の要約

- ベクター(先行コミット): §1 裁定 G のとおり(surrogate-boundary-order ×2、
  加法のみ、verify_reference.mjs 全 PASS)
- crypto ハーネス: encoding / env-manifest / checkpoint の invalid-input
  チェック追加(§1)。4 実行環境(node / Bun / workerd / Chromium)で実行
- CRYPTO_SPEC §2.1: 数値境界の 1 項追記(§2 裁定 I — 挙動変更なし)
- M1-T1: §4 のとおり(プロダクション変更なし — サーバーの受理挙動は不変で、
  テストが固定する状態だけが「peer CLI が受理できる整合形」へ変わった)
- cross-layer 回帰: §3 のとおり 5 本(server 2 面 + CLI 3 面)
- スコープ外(M2 本体・standalone checkpoint 受理・先行 manifest_version 公証の
  negative)は session-33 §5「M2 への申し送り」のまま持ち越し
