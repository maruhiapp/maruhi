// 環境間のパリティチェック(`maruhi env diff`)。
//
// 同一プロジェクト内の 2 環境について**変数名の集合だけ**を比較し、片方にしか
// 無い名前を報告する(「prod に入れ忘れた」を値を一切見ずに検出する)。
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
// 表示する操作」であり、変数名は平文メタデータで、`--show` なしの `maruhi pull`
// が既に表示している(エージェント判定は `--show` のときだけ)。diff は値を
// 取得すらしないので、pull のメタデータ一覧より開示は狭い。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { displayText, logWarnings } from "./display.ts";
import type { CliError } from "./errors.ts";
import type { FloorHandle, VerifiedActiveStatement } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** 比較対象の 1 環境。床は §6.3 のメタ水準検査に使う(コミットはしない)。 */
export interface DiffTarget {
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
}

/** 変数名の集合比較の結果(名前でソート済みの差分と件数)。 */
export interface EnvironmentDiff {
  readonly firstEnvironmentId: EnvironmentId;
  readonly secondEnvironmentId: EnvironmentId;
  /** 1 つ目にしか無い変数名(名前でソート済み)。 */
  readonly onlyInFirst: readonly string[];
  /** 2 つ目にしか無い変数名(名前でソート済み)。 */
  readonly onlyInSecond: readonly string[];
  /** 両方にある名前の数。**値が一致することは含意しない**(復号しないため)。 */
  readonly shared: number;
  /**
   * 環境ごとの SHOULD 警告。**ラベル付けと端末中和は報告側**が行う(組み立て
   * 済みの文字列を持つと、中和済みかどうかが呼び出し元ごとに変わる)。
   */
  readonly firstWarnings: readonly string[];
  readonly secondWarnings: readonly string[];
}

/**
 * 名前の並びは **UTF-16 コード単位**の昇順(既定の比較)。localeCompare は
 * 実行環境のロケールで並びが変わるため使わない — 同じ 2 環境を比べた出力が
 * 端末によって別の順に出ると、出力そのものの差分を取れなくなる。
 */
function sortedNames(names: Iterable<string>): readonly string[] {
  return [...names].toSorted();
}

/**
 * 検証済み active ステートメント → 名前の集合。同一環境内の同名 active は
 * §6.3 の検証(values.ts の checkVerifiedNames)が既に拒否しているので、
 * ここで集合に潰しても事実は落ちない。
 */
function namesOf(variables: readonly VerifiedActiveStatement[]): ReadonlySet<string> {
  return new Set(variables.map((variable) => variable.name));
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
    yield* input.commitHead(first.verified);
    const second = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      // 1 つ目の検証に使ったビュー(前進していることがある)を引き継ぐ
      verified: first.verified,
      environmentId: input.second.environmentId,
      resync: input.resync,
      floor: input.second.floor,
    });
    yield* input.commitHead(second.verified);
    const firstNames = namesOf(first.variables);
    const secondNames = namesOf(second.variables);
    return {
      firstEnvironmentId: input.first.environmentId,
      secondEnvironmentId: input.second.environmentId,
      onlyInFirst: sortedNames([...firstNames].filter((name) => !secondNames.has(name))),
      onlyInSecond: sortedNames([...secondNames].filter((name) => !firstNames.has(name))),
      shared: [...firstNames].filter((name) => secondNames.has(name)).length,
      firstWarnings: first.warnings,
      secondWarnings: second.warnings,
    };
  });
}

/**
 * 差分の報告。一覧は stdout(コマンドの出力)、警告は stderr(logWarnings)へ
 * 分ける — 「stdout はコマンドの出力だけ」の規律。
 *
 * 端末へ出す文字列の中和は**この関数に集約する**。変数名は他メンバーが書いた
 * 平文メタデータで ANSI / BEL を仕込まれうるし(pull の formatPulledLine と
 * 同じ扱い)、環境 ID も `EnvironmentId` がブランド付きではない以上、型では
 * 検証済みを保証できない — 警告のラベル付けをここで行うのもそのため。
 */
export function reportEnvironmentDiff(diff: EnvironmentDiff): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const first = displayText(diff.firstEnvironmentId);
    const second = displayText(diff.secondEnvironmentId);
    // 2 環境ぶんの警告は同じ行になりうる(variable_id は**環境内**で一意なので、
    // 別環境の別変数について文面まで同一の警告が立つ)。集合で畳むと片方の
    // 事実が黙って消えるため、重複排除ではなく環境 ID でラベルする
    yield* logWarnings([
      ...diff.firstWarnings.map((warning) => `環境 ${first}: ${warning}`),
      ...diff.secondWarnings.map((warning) => `環境 ${second}: ${warning}`),
    ]);
    yield* io.log(
      `同期・検証 OK: 環境 ${first} = ${diff.onlyInFirst.length + diff.shared} 変数 / 環境 ${second} = ${diff.onlyInSecond.length + diff.shared} 変数`,
    );
    const sides = [
      { environmentId: first, names: diff.onlyInFirst },
      { environmentId: second, names: diff.onlyInSecond },
    ];
    for (const side of sides) {
      // 件数は名前が 0 件でも必ず出す(出力の形を実行ごとに変えない)
      yield* io.log(`環境 ${side.environmentId} のみにある変数: ${side.names.length}`);
      for (const name of side.names) {
        yield* io.log(`  ${displayText(name)}`);
      }
    }
    yield* io.log(
      `両方にある変数: ${diff.shared}(名前が一致するだけです — 値を取得も復号もしていないため、値が同じかどうかは比較していません)`,
    );
    // 標本のずれの注意書きは**常に**出す(stderr — 助言であってコマンドの出力
    // ではないので stdout の差分一覧には混ぜない)。差分ゼロのときに黙ると、
    // **skew が最も危険な向き**を隠すことになる: 1 つ目を読んだ後に片側から
    // 変数が削除されると、両方にあると報告されて差分ゼロで終わる = 実在する
    // 差分を「揃っている」と読ませる。助言だけを結論に合わせて変える
    const advice =
      diff.onlyInFirst.length + diff.onlyInSecond.length > 0
        ? "心当たりのない差分は、push で埋める前にもう一度実行して確かめてください(push はチェーンへの追記で取り消せず、新しい値を古い値で上書きしうるため)"
        : "差分ゼロを「揃っている」の根拠にする場合は、もう一度実行して確かめてください";
    yield* io.logError(
      `注意: 2 つの環境は同時ではなく順に読んでいます(2 環境を同時に読む API はありません)。実行中に他のメンバーが push / 削除を行うと、実在しない差分が出ることも、実在する差分が出ないこともあります — ${advice}`,
    );
  });
}
