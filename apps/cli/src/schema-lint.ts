// `maruhi schema lint`(発見 G — 設計文書 §1-7)。
//
// ソースの env 参照(`process.env.X` 等)を静的走査し、検証済みストア側
// スキーマ(live 変数名の集合 — active + declared)と突合する: 「コードは FOO
// を読むがスキーマに宣言がない / 逆」。
//
// **best-effort・善意のドリフト検出**(BG トリップワイヤと同じ位置づけ):
// 動的アクセス(`process.env[name]`)・未対応言語・文字列組み立ては拾えない。
// 検査の欠落を保証の欠落と混同させない注意書きを常に出力へ含める(§1-7)。
//
// 走査器は**自前の正規表現ベース**(仕様が固定するのは位置づけのみ — コード
// パーサの新規依存を追加しない)。対応する読み取り形(実装裁定 — 主要
// ランタイムの静的な逐語形のみ):
//   JS/TS: process.env.X / process.env["X"] / import.meta.env.X / Bun.env.X /
//          Deno.env.get("X")
//   Python: os.environ["X"] / os.environ.get("X") / os.getenv("X")
//   Go:     os.Getenv("X") / os.LookupEnv("X")
//   Ruby:   ENV["X"] / ENV.fetch("X")
//   Rust:   env::var("X") / env::var_os("X")(std:: 接頭辞あり・なし)
// シェルの `$X` は対応しない(シェル変数と env 参照を静的に区別できず
// 誤検出が支配的になる — best-effort の線)。
//
// **レポートは変数名のみ**(description を含めない — §1-7 / §2 の消費点規律。
// レポートはログ・CI へ流れる)。名前は displayText で中和する(コード由来・
// ストア由来とも、端末インジェクションの中和は表示側の独立義務 — 裁定 CW)。
//
// **終了コードの裁定(実装裁定 — PR 本文に記録)**: 「コードが読むが宣言が
// ない」は exit 1(fail-loud — 走査が**見つけた**証拠で、run の presence
// fail-fast の予兆)。「宣言済みだがコードで読まれない」は報告のみ(exit 0)
// — 動的アクセス・別リポジトリの消費・run 経由の子プロセスの読みで正当に
// 発生し、best-effort 走査の欠落を CI 失敗に直結させると「検査の欠落」を
// 「保証の欠落」と混同させる方向になる。env diff の「差分があっても 0」との
// 線引き: diff は環境間の**報告**(どちらが正か機械には決められない)、lint は
// コード契約の**検査**(コードが正 — 発見 G)。

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** 環境変数名として拾う識別子形(POSIX 環境変数名の慣用形)。 */
const NAME = "([A-Za-z_][A-Za-z0-9_]*)";

/** 静的な逐語 env 参照のパターン(`${NAME}` の位置 = 変数名のキャプチャ)。 */
const REFERENCE_SOURCES: readonly string[] = [
  String.raw`process\.env\.${NAME}`,
  String.raw`process\.env\[["']${NAME}["']\]`,
  String.raw`import\.meta\.env\.${NAME}`,
  String.raw`Bun\.env\.${NAME}`,
  String.raw`Bun\.env\[["']${NAME}["']\]`,
  String.raw`Deno\.env\.get\(\s*["']${NAME}["']\s*\)`,
  String.raw`os\.environ\[["']${NAME}["']\]`,
  String.raw`os\.environ\.get\(\s*["']${NAME}["']`,
  String.raw`os\.getenv\(\s*["']${NAME}["']`,
  String.raw`os\.(?:Getenv|LookupEnv)\(\s*"${NAME}"\s*\)`,
  String.raw`ENV(?:\.fetch\(\s*|\[)["']${NAME}["']`,
  String.raw`(?:std::)?env::var(?:_os)?\(\s*"${NAME}"\s*\)`,
];

const REFERENCE_PATTERNS: readonly RegExp[] = REFERENCE_SOURCES.map(
  (source) => new RegExp(source, "g"),
);

/** Scans one file's text for literal environment-variable references. */
export function scanEnvReferences(content: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const pattern of REFERENCE_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      const name = match[1];
      if (name !== undefined) {
        names.add(name);
      }
    }
  }
  return names;
}

/** 走査対象の拡張子(対応パターンのある言語のソースのみ — 誤検出を抑える)。 */
const SOURCE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".py",
  ".rb",
  ".go",
  ".rs",
]);

/** 生成物・依存のディレクトリは走査しない(ソースの契約だけを見る)。 */
const SKIPPED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
  "coverage",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
]);

/** 1 ファイルの走査上限(生成物・データファイルの巻き込みを抑える)。 */
const MAX_FILE_BYTES = 1024 * 1024;

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot);
}

/** Recursively collects scannable source files under one path (best effort). */
async function collectSourceFiles(path: string, into: string[]): Promise<void> {
  const info = await stat(path);
  if (info.isFile()) {
    // 明示指定されたファイルは拡張子で弾かない(利用者の指定を黙って無視しない)
    into.push(path);
    return;
  }
  if (!info.isDirectory()) {
    return;
  }
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      // シンボリックリンクは辿らない(循環・リポジトリ外への逸脱を作らない)
      continue;
    }
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        await collectSourceFiles(join(path, entry.name), into);
      }
      continue;
    }
    if (entry.isFile() && SOURCE_EXTENSIONS.has(extensionOf(entry.name))) {
      into.push(join(path, entry.name));
    }
  }
}

/** 走査の結果(突合前の生データ)。 */
export interface LintScan {
  readonly scannedFiles: number;
  readonly references: ReadonlySet<string>;
}

/** Walks the given paths and scans every supported source file. */
export function scanPaths(paths: readonly string[]): Effect.Effect<LintScan, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const files: string[] = [];
      for (const path of paths) {
        await collectSourceFiles(path, files);
      }
      const references = new Set<string>();
      let scannedFiles = 0;
      for (const file of files) {
        const info = await stat(file);
        if (info.size > MAX_FILE_BYTES) {
          continue;
        }
        const content = await readFile(file, "utf8");
        // バイナリの巻き込みは NUL で検出してスキップ(拡張子は偽装できる)
        if (content.includes("\u0000")) {
          continue;
        }
        scannedFiles += 1;
        for (const name of scanEnvReferences(content)) {
          references.add(name);
        }
      }
      return { scannedFiles, references };
    },
    // パスは利用者の入力なのでエラーへ出してよい(値ではない)が、OS エラーの
    // 詳細は運ばない(schema import のファイル読み込みと同じ規律)
    catch: () =>
      cliError("Could not scan the given paths (check that they exist and are readable)"),
  });
}

const BEST_EFFORT_NOTE =
  "Note: this is a best-effort static scan of literal references — dynamic access " +
  "(e.g. process.env[name]), unsupported languages and generated code are not seen, " +
  "so an empty report is not a guarantee that code and schema agree. Variables " +
  "declared but not read here may be consumed dynamically or by another repository";

/**
 * Cross-checks scanned environment-variable references against the
 * environment's verified live variable names (発見 G — §1-7). The scan is
 * the caller's input (`scanPaths` — run before any network access so a bad
 * path fails without a round trip). Reports carry variable names only. Exit
 * is non-zero only for the hard direction (code reads a name the store does
 * not declare).
 */
export function schemaLintOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly scan: LintScan;
  /** undeclared 側から除外する名前(NODE_ENV 等の maruhi 管理外 — 明示指定)。 */
  readonly ignore: readonly string[];
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const scan = input.scan;
    const metadata = yield* pullVerifiedEnvironmentMetadata(input);
    yield* logWarnings(metadata.warnings);
    // 突合の対象は検証済み live 集合の名前(v1 変数も名前は第一級 — スキーマ欄の
    // 有無に依らず「ストアに存在する変数」として数える。捏造するのは名前ではない)
    const declaredNames = new Set(metadata.variables.map((statement) => statement.name));
    const ignored = new Set(input.ignore);
    const undeclared = [...scan.references]
      .filter((name) => !declaredNames.has(name) && !ignored.has(name))
      .toSorted();
    const unread = [...declaredNames].filter((name) => !scan.references.has(name)).toSorted();
    const environment = displayText(input.environmentId);
    yield* io.log(
      `Scanned ${countNoun(scan.scannedFiles, "source file")} (${countNoun(scan.references.size, "distinct environment-variable reference")})`,
    );
    // 件数行は 0 件でも必ず出す(出力の形を実行ごとに変えない — env diff の規律)
    yield* io.log(
      `Read by the scanned code but not declared in environment ${environment}: ${undeclared.length}`,
    );
    for (const name of undeclared) {
      yield* io.log(`  ${displayText(name)}`);
    }
    yield* io.log(
      `Declared in environment ${environment} but not read by the scanned code: ${unread.length}`,
    );
    for (const name of unread) {
      yield* io.log(`  ${displayText(name)}`);
    }
    // best-effort の注意書きは結論に依らず常に出す(検査の欠落 ≠ 保証の欠落 —
    // stderr: 助言でありコマンドの出力ではない)
    yield* io.logError(BEST_EFFORT_NOTE);
    if (undeclared.length > 0) {
      return yield* Effect.fail(
        cliError(
          `The scanned code reads ${countNoun(undeclared.length, "environment variable")} not declared in environment ${environment} (listed on stdout). Declare them with \`maruhi schema set <NAME>\` (or \`maruhi schema import\`), or exclude non-maruhi runtime variables with --ignore <NAME>`,
        ),
      );
    }
  });
}
