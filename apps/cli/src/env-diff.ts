// 環境間のパリティチェック(`maruhi env diff`)。
//
// 同一プロジェクト内の 2 環境について**変数名の集合**と**スキーマ契約
// (required・set / declared の状態 — 設計文書 §1-5 の required 軸)**を比較し、
// 片方にしか無い名前と、両方にあるが契約の食い違う名前を報告する(「prod に
// 入れ忘れた」「staging には required の宣言がない」を値を一切見ずに検出する)。
// description は diff 出力に出さない(§2 の消費点規律 — fail-fast・lint と同じ線)。
//
// 値も DEK も取得しない: 入力は §12-7 のメタデータのみ pull だけで、平文値を
// メモリに作らない。サーバーはこのエンドポイントで `var.read` を記録しない
// (AUDIT_SPEC §3.3)— これは AUDIT_SPEC §4 の要ローテーション検出の入力純度を
// 守るための規律なので、diff でも記録を増やさない。
//
// 比較は**検証済みステートメントの name** で行う(§6.3 を通ったものだけを
// 信用する — §12-2)。照合規則は AUTH_SPEC §12-1 の byte-exact・大文字小文字
// 区別(POSIX 環境変数名の意味論)で、環境間の変数名照合を平文メタデータの
// 変数名で行うのは CRYPTO_SPEC §4 のとおり。削除済み(tombstone)は対象外で、
// active な最新ステートメントだけを見る。
//
// **両方にある名前は「名前が一致する」以上のことを意味しない**。値が一致するか
// どうかは復号しなければ分からず、この機構は原理的にそこへ触れない — 報告でも
// そう明示する(「同期している」と読まれると、検出できていない不一致を
// 検出済みと誤解させる)。
//
// **標本のずれ(検査済みと偽らない)**: 2 環境は 2 回の pull で**順に**読む。
// 2 環境を同時に読む API は無いため、1 つ目と 2 つ目の間に他メンバーの push が
// 挟まると、その変数は一時的に片側だけに見える = **偽の差分**になる。逆向きも
// ある: 1 つ目を読んだ後に片側から変数が削除されると、両方にあると報告されて
// 差分ゼロで終わる = **実在する差分の見落とし**になる。ここで
// 揃えているのは検証に使うチェーンビューであって、変数集合の同時性ではない
// (前者は §6.3 の検証が別々の履歴に対して行われるのを防ぐためのもので、
// 後者は保証できない)。偽の差分を真に受けた利用者の「修正」は push であり、
// チェーンへの取り消せない追記 — かつ新しい値を古い値で上書きしうる — であり、
// 見落としの側は「揃っている」と読ませる。どちらの結論も覆されうるので、
// 注意書きは**差分の有無によらず常に**添える(reportEnvironmentDiff)。
//
// AI エージェント検出(agent.ts)は掛けない: agent.ts の線引きは「値を端末に
// 表示する操作」であり、変数名は**設計上の平文メタデータ**(CRYPTO_SPEC §4 —
// 名前の秘匿は未決 #3)なので値ではない。`--show` なしの `maruhi pull` が
// 同じ一覧を既に表示している(エージェント判定は `--show` のときだけ)。
//
// ただし「pull より開示が狭い」とは言えない — master 鍵を要求しない以上、
// キーチェーンの無い端末(MARUHI_TOKEN 経由 — session.ts)では pull が
// loadMasterKeys で落ちる一方、このコマンドは両環境の変数名一覧を出す。
// **その資格情報で変数名を出す最初のコマンド**である。線引きそのものは
// 変わらない(開示の境界はトークンで、サーバーは read 権限があれば
// pullMetadata を返す — ローカル鍵の有無は関与しない)が、名前を値と同じ
// 扱いにするなら agent.ts の線引きごと見直す話になるので、ここで判断を
// 握り潰さずに記す。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import type { CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** 比較対象の 1 環境。床は §6.3 のメタ水準検査に使う(コミットはしない)。 */
export interface DiffTarget {
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
}

/**
 * 1 変数の required 契約(検証済みステートメントの schema 欄のみから導出 —
 * サーバー申告を使わない §14.2-8)。`none` = スキーマ欄なし(レイアウト v1)。
 */
export type RequiredContract = "required" | "optional" | "none";

/** 片側にしかない 1 変数(名前・状態・required — description は運ばない §2)。 */
export interface DiffSideEntry {
  readonly name: string;
  /** true = declared(値なし — S3 申し送りの注記)。 */
  readonly declared: boolean;
  readonly required: RequiredContract;
}

/** 両側にある名前のうち、宣言された契約(required / 状態)が食い違うもの。 */
export interface ContractMismatch {
  readonly name: string;
  readonly first: { readonly declared: boolean; readonly required: RequiredContract };
  readonly second: { readonly declared: boolean; readonly required: RequiredContract };
}

/** 変数名の集合比較の結果(名前でソート済みの差分と件数)。 */
export interface EnvironmentDiff {
  readonly firstEnvironmentId: EnvironmentId;
  readonly secondEnvironmentId: EnvironmentId;
  /** 1 つ目にしか無い変数(名前でソート済み)。 */
  readonly onlyInFirst: readonly DiffSideEntry[];
  /** 2 つ目にしか無い変数(名前でソート済み)。 */
  readonly onlyInSecond: readonly DiffSideEntry[];
  /**
   * 両方にある名前のうち required 契約・状態(set / declared)が食い違うもの
   * (§1-5 の required 軸 — 判定材料は両環境の検証済みステートメントのみ)。
   */
  readonly contractMismatches: readonly ContractMismatch[];
  /** 両方にある名前の数。**値が一致することは含意しない**(復号しないため)。 */
  readonly shared: number;
}

/**
 * 名前の並びは **UTF-16 コード単位**の昇順(既定の比較)。localeCompare は
 * 実行環境のロケールで並びが変わるため使わない — 同じ 2 環境を比べた出力が
 * 端末によって別の順に出ると、出力そのものの差分を取れなくなる。
 */
function sortedByName<T extends { readonly name: string }>(entries: Iterable<T>): readonly T[] {
  return [...entries].toSorted((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function requiredOf(statement: VerifiedVariableStatement): RequiredContract {
  if (statement.schema === null) {
    return "none";
  }
  return statement.schema.required ? "required" : "optional";
}

function sideEntryOf(statement: VerifiedVariableStatement): DiffSideEntry {
  return {
    name: statement.name,
    declared: statement.status === "declared",
    required: requiredOf(statement),
  };
}

/**
 * 検証済み変数ステートメント(active + declared の混在 — §12-7)→ 名前 →
 * ステートメントの表。declared も「存在する変数名」として比較に含める(S3 の
 * 裁定 — declared は第一級の変数 §4.2。値の有無は注記で示す)。同一環境内の
 * 同名は §6.3 の検証(values.ts の checkVerifiedNames)が既に拒否しているので、
 * ここで表に潰しても事実は落ちない。
 */
function statementsByName(
  variables: readonly VerifiedVariableStatement[],
): ReadonlyMap<string, VerifiedVariableStatement> {
  return new Map(variables.map((variable) => [variable.name, variable]));
}

/**
 * Emits one environment's §12-1 SHOULD warnings to stderr, labelled with the
 * environment id.
 *
 * **pull ごとに即時に吐く**: 2 つ目の pull が落ちた実行で 1 つ目の警告を
 * 捨てないため(env-rotate の「収集した警告は失敗経路でも必ず吐く」と同じ規律)。
 *
 * 2 環境ぶんの警告は同じ行になりうる(variable_id は**環境内**で一意なので、
 * 別環境の別変数について文面まで同一の警告が立つ)。集合で畳むと片方の事実が
 * 黙って消えるため、重複排除ではなく環境 ID でラベルする。
 *
 * 組み立てた行は丸ごと displayText を通す — 環境 ID は `EnvironmentId` が
 * ブランド付きでないため検証済みとは限らず、警告本文も将来の産出元が中和済み
 * とは限らない(displayText は冪等なので二重適用しても壊れない)。
 */
export function reportEnvironmentWarnings(
  environmentId: EnvironmentId,
  warnings: readonly string[],
): Effect.Effect<void, CliError, CliIo> {
  return logWarnings(
    warnings.map((warning) => displayText(`environment ${environmentId}: ${warning}`)),
  );
}

/**
 * Compares the variable **names** of two environments in one project, using
 * only metadata pulls (no values, no DEKs, no `var.read`).
 *
 * 2 つ目の pull には **1 つ目が返したビュー**を渡す: メタデータ pull は future
 * head 時に有界再同期でビューを前進させることがあり(§6.3-2b)、元のビューを
 * 使い回すと 2 環境を**別々の履歴**に対して検証したまま比較することになる。
 */
export function envDiffOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  /** future head 時の有界再同期(各 pull が 1 回ずつ使う)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly first: DiffTarget;
  readonly second: DiffTarget;
  /**
   * 検証済みチェーンヘッドの記録。**pull ごとに**呼ぶ: 最後にまとめて呼ぶと、
   * 2 つ目の pull が失敗した実行で 1 つ目の有界再同期が確立した前進を落とす
   * (pull / push は応答ごとの accept の中で同じヘッドを書いている)。
   */
  readonly commitHead: (verified: VerifiedProject) => Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<EnvironmentDiff, CliError, CliServices> {
  return Effect.gen(function* () {
    const first = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      verified: input.verified,
      environmentId: input.first.environmentId,
      resync: input.resync,
      floor: input.first.floor,
    });
    // 警告 → ヘッド記録の順(どちらも 2 つ目の pull の成否に依存させない)
    yield* reportEnvironmentWarnings(input.first.environmentId, first.warnings);
    yield* input.commitHead(first.verified);
    const second = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      // 1 つ目の検証に使ったビュー(前進していることがある)を引き継ぐ
      verified: first.verified,
      environmentId: input.second.environmentId,
      resync: input.resync,
      floor: input.second.floor,
    });
    yield* reportEnvironmentWarnings(input.second.environmentId, second.warnings);
    yield* input.commitHead(second.verified);
    const firstByName = statementsByName(first.variables);
    const secondByName = statementsByName(second.variables);
    const contractMismatches: ContractMismatch[] = [];
    for (const [name, firstStatement] of firstByName) {
      const secondStatement = secondByName.get(name);
      if (secondStatement === undefined) {
        continue;
      }
      const firstSide = sideEntryOf(firstStatement);
      const secondSide = sideEntryOf(secondStatement);
      if (
        firstSide.declared !== secondSide.declared ||
        firstSide.required !== secondSide.required
      ) {
        contractMismatches.push({
          name,
          first: { declared: firstSide.declared, required: firstSide.required },
          second: { declared: secondSide.declared, required: secondSide.required },
        });
      }
    }
    return {
      firstEnvironmentId: input.first.environmentId,
      secondEnvironmentId: input.second.environmentId,
      onlyInFirst: sortedByName(
        [...firstByName.values()].filter((v) => !secondByName.has(v.name)).map(sideEntryOf),
      ),
      onlyInSecond: sortedByName(
        [...secondByName.values()].filter((v) => !firstByName.has(v.name)).map(sideEntryOf),
      ),
      contractMismatches: sortedByName(contractMismatches),
      shared: [...firstByName.keys()].filter((name) => secondByName.has(name)).length,
    };
  });
}

/**
 * 片側にしかない 1 変数の表示注記(§1-5 の required 軸 + declared 注記)。
 * 出力は名前・状態・required のみ — **description は出さない**(§2 の消費点
 * 規律: fail-fast エラー・lint レポートと同じ線。diff 出力もログ・CI へ流れる)。
 * required の充足・宣言は署名済みステートメント由来だが、表示は宣言として扱い
 * 「verified」の語を使わない(§14.3 の表示規律)。
 */
function sideEntryLine(entry: DiffSideEntry): string {
  const notes = [
    ...(entry.required === "none" ? [] : [entry.required]),
    ...(entry.declared ? ["declared — no value set"] : []),
  ];
  const suffix = notes.length === 0 ? "" : ` (${notes.join(", ")})`;
  return `  ${displayText(entry.name)}${suffix}`;
}

/** 契約食い違いの片側の表示(required / optional / no schema + declared 注記)。 */
function contractText(side: ContractMismatch["first"]): string {
  const required = side.required === "none" ? "no schema (layout v1)" : side.required;
  return side.declared ? `${required}, declared — no value set` : required;
}

/**
 * 差分の報告。一覧は stdout(コマンドの出力)、警告は stderr(logWarnings)へ
 * 分ける — 「stdout はコマンドの出力だけ」の規律。
 *
 * 端末へ出す文字列は**この関数が中和する**(警告は reportEnvironmentWarnings が
 * 同じ規律で受け持つ)。変数名は他メンバーが書いた平文メタデータで ANSI / BEL を
 * 仕込まれうるし(pull の formatPulledLine と同じ扱い)、環境 ID も
 * `EnvironmentId` がブランド付きではない以上、型では検証済みを保証できない。
 */
export function reportEnvironmentDiff(diff: EnvironmentDiff): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const first = displayText(diff.firstEnvironmentId);
    const second = displayText(diff.secondEnvironmentId);
    yield* io.log(
      `Synced and verified: environment ${first} = ${countNoun(diff.onlyInFirst.length + diff.shared, "variable")} / environment ${second} = ${countNoun(diff.onlyInSecond.length + diff.shared, "variable")}`,
    );
    const sides = [
      { environmentId: first, entries: diff.onlyInFirst },
      { environmentId: second, entries: diff.onlyInSecond },
    ];
    for (const side of sides) {
      // 件数は名前が 0 件でも必ず出す(出力の形を実行ごとに変えない)
      yield* io.log(`Variables only in environment ${side.environmentId}: ${side.entries.length}`);
      for (const entry of side.entries) {
        yield* io.log(sideEntryLine(entry));
      }
    }
    // required 軸(§1-5): 両方にある名前でも、宣言された契約(required /
    // set・declared)が食い違えば表示する。件数行は 0 件でも必ず出す(上と同じ
    // 「出力の形を実行ごとに変えない」規律)
    yield* io.log(
      `Variables in both with a differing schema contract: ${diff.contractMismatches.length}`,
    );
    for (const mismatch of diff.contractMismatches) {
      yield* io.log(
        `  ${displayText(mismatch.name)} — ${first}: ${contractText(mismatch.first)} / ${second}: ${contractText(mismatch.second)}`,
      );
    }
    yield* io.log(
      `Variables in both: ${diff.shared} (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)`,
    );
    // 標本のずれの注意書きは**常に**出す(stderr — 助言であってコマンドの出力
    // ではないので stdout の差分一覧には混ぜない)。差分ゼロのときに黙ると、
    // **skew が最も危険な向き**を隠すことになる: 1 つ目を読んだ後に片側から
    // 変数が削除されると、両方にあると報告されて差分ゼロで終わる = 実在する
    // 差分を「揃っている」と読ませる。助言だけを結論に合わせて変える
    const advice =
      diff.onlyInFirst.length + diff.onlyInSecond.length > 0
        ? "For differences you cannot explain, run this again to confirm before filling them in with a push (a push is an irreversible chain append and may overwrite a newer value with an older one)"
        : "Before treating zero differences as proof the environments are in sync, run this again to confirm";
    yield* io.logError(
      `Note: the two environments are read sequentially, not atomically (there is no API that reads two environments at once). If another member pushes or deletes during the run, differences may appear that do not exist, and real differences may not appear — ${advice}`,
    );
  });
}
