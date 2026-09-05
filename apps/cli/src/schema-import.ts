// `maruhi schema import <file>`(ブートストラップ — 設計文書 §1-3・発見 A)。
//
// 儀式の形(4 段):
//   (1) 明示の位置引数で指定された .env / .env.example をクライアント側でのみ
//       読む(env-file.ts — 値は読み取り直後に Redacted。型推論 = 形の観察のみ)
//   (2) 変数ごとの対話承認(編集可)。名前・型候補・required(作成既定 true)・
//       description 候補を提示し、承認 / 編集 / スキップを選べる
//   (3) 承認分を declared として登録(schemaSetOp の宣言作成部品を再利用 —
//       requireCreation)。値が実値と判断され、利用者が変数ごとに明示選択した
//       場合のみ値 push = activation まで同時に行う(既存 pushVariable の再利用。
//       既定は値を送信しない)
//   (4) 完了時に元ファイルの削除を提案する(明示確認の上でのみ削除。既定は
//       削除しない — 「.env.example の最後の仕事は、署名付きスキーマになること」)
//
// **対話承認が儀式の核**なので、一括 --yes は作らない。非対話環境(stdin /
// stdout が端末でない)と既知エージェント検出時は型付きエラーで拒否する —
// invite / recovery と同じ儀式系 deny の類型(ADR-0016 決定 7)。判定材料は
// Stdio / AgentProfileRef サービス経由で取り、process.* を直に読まない。
//
// 登録は変数ごとの複合 × マニフェスト CAS の直列実行(O(N) 往復 — 発見 F′。
// 一括複合受理の要否は S4 の実測報告 — 本 PR 本文 — を材料にオーナーが判断
// する。先取りしない)。競合は schemaSetOp / pushVariable の既存リトライ規律
// (retryOnConflict)をそのまま再利用する。

import { unlink } from "node:fs/promises";

import type { EnvironmentId } from "@maruhi/core";
import type { MetaVarType } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import { AgentProfileRef } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import type { DekRecipient } from "./deks.ts";
import { countNoun, displayText, escapeText, logWarnings } from "./display.ts";
import { findHighEntropySubstring } from "./entropy.ts";
import {
  type EnvFileEntry,
  type EnvFileSkippedLine,
  MAX_NAME_LENGTH,
  observeValue,
  parseEnvFile,
} from "./env-file.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedSchemaFields } from "./floor-check.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { pushVariable } from "./push.ts";
import { schemaSetOp } from "./schema.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** description のサーバー受理上限(AUTH_SPEC §12-8 — 事前絞り込みにのみ使う)。 */
const MAX_DESCRIPTION_LENGTH = 1024;

/**
 * Refuses the import ceremony outside an interactive human terminal: the
 * per-variable approval **is** the ritual, so there is no --yes and no
 * non-interactive path (ADR-0016 決定 7 — the invite / recovery deny class).
 *
 * 境界は stdin + stdout の 2 チャネル(値表示・儀式系の一次境界と同じ)であり、
 * recovery コード・招待リンク生値の **3 チャネル**(stderr も TTY)ゲートには
 * 揃えない(意図的な線引き): あちらは「他の経路ではディスクに存在しない
 * capability / 鍵素材」が stderr へ流れるため `2>` での永続化が新しい露出
 * クラスになるが、import が stderr へ出すもの(候補の提示 — description 候補を
 * 含む)は**利用者自身のローカルファイルに既に書かれている内容**で、
 * リダイレクトしても新しい露出は生じない。値そのものはどのチャネルにも
 * 出さない(観察のみ — env-file.ts)。
 */
export const ensureImportCeremonyAllowed: Effect.Effect<void, CliError, Stdio.Stdio> = Effect.gen(
  function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      const detected = agent.name === undefined ? "" : ` (${agent.name})`;
      return yield* Effect.fail(
        cliError(
          `Refused to run schema import: an AI agent environment was detected${detected}. The per-variable approval is the core of this ceremony, so a person must run it in a terminal (agents can read the resulting schema with \`maruhi schema\`)`,
        ),
      );
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      return yield* Effect.fail(
        cliError(
          "Refused to run schema import: stdin and stdout are not both an interactive terminal (pipes, redirects, CI, and AI agents are refused; the per-variable approval is the core of the ceremony and there is no --yes bypass). Run it yourself in a terminal",
        ),
      );
    }
  },
);

/** import の入力(effect-cli.ts が EnvironmentContext から組む)。 */
export interface SchemaImportInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
  /** activation の値 push(明示選択時のみ)に使う受信者材料。 */
  readonly recipient: DekRecipient;
  /** 表示用のファイルパス(読み込みは呼び出し側 — content で受ける)。 */
  readonly filePath: string;
  /** ファイル内容(呼び出し側がクライアント側でのみ読む)。 */
  readonly content: string;
}

/** 1 変数の承認結果(編集後の確定値)。 */
interface ApprovedCandidate {
  readonly name: string;
  readonly schema: VerifiedSchemaFields;
  /** true = 値 push(activation)まで行う(利用者の明示選択)。 */
  readonly pushValue: boolean;
}

/** 承認ループの 1 変数分の状態(編集で上書きされる)。 */
interface CandidateDraft {
  name: string;
  varType: MetaVarType;
  required: boolean;
  description: string;
}

const SCHEMA_TYPES: readonly MetaVarType[] = ["string", "number", "boolean", "url"];

function skipReasonText(skipped: EnvFileSkippedLine): string {
  switch (skipped.reason) {
    case "not-an-assignment":
      return "not a KEY=VALUE assignment (content not shown — it may be a value)";
    case "invalid-name":
      return "the name is not a valid environment variable name (letters, digits and _ only, not starting with a digit; content not shown)";
    case "duplicate-name":
      return `duplicate of ${displayText(skipped.name ?? "")} (only the first occurrence is offered)`;
  }
}

/** 候補の提示行(値そのものは出さない — 型候補と実値らしさの観察結果のみ)。 */
function describeCandidate(draft: CandidateDraft, line: number, valueNote: string): string {
  const typeShown = draft.varType === "" ? "-" : draft.varType;
  const description = draft.description === "" ? "-" : `"${escapeText(draft.description)}"`;
  return `Line ${line}: ${displayText(draft.name)} — type=${typeShown}, required=${draft.required}, description=${description}, value=${valueNote}`;
}

/** yes/no プロンプトの解釈(y / yes のみ肯定 — 既定は否定側)。 */
function isYes(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

/** 編集: 名前(空 = 現状維持。形式・重複は警告して現状維持)。 */
function editName(
  io: CliIoShape,
  draft: CandidateDraft,
  isNameTaken: (name: string) => boolean,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const answer = (yield* io.promptLine({
      prompt: `  Name (blank = keep ${displayText(draft.name)}): `,
    })).trim();
    if (answer === "") {
      return;
    }
    const name = answer.normalize("NFC");
    // 形式・長さの検査はパーサ(env-file.ts)と同じ受理集合 — 編集経由だけが
    // サーバー 400 の遅い失敗点(import ごと停止)へ素通りする形を作らない
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name.length > MAX_NAME_LENGTH) {
      return yield* io.logError(
        `  Not a valid environment variable name (letters, digits and _ only, not starting with a digit, at most ${MAX_NAME_LENGTH} characters) — keeping the current name`,
      );
    }
    if (isNameTaken(name)) {
      return yield* io.logError(
        "  That name already exists in the environment or in this import — keeping the current name",
      );
    }
    draft.name = name;
  });
}

/** 編集: 型(空 = 現状維持・none = 未指定。閉集合外は警告して現状維持)。 */
function editType(io: CliIoShape, draft: CandidateDraft): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const answer = (yield* io.promptLine({
      prompt: `  Type (${SCHEMA_TYPES.join(" | ")}; blank = keep ${draft.varType === "" ? "unspecified" : draft.varType}, "none" = unspecified): `,
    }))
      .trim()
      .toLowerCase();
    if (answer === "") {
      return;
    }
    if (answer === "none") {
      draft.varType = "";
      return;
    }
    if ((SCHEMA_TYPES as readonly string[]).includes(answer)) {
      draft.varType = answer as MetaVarType;
      return;
    }
    yield* io.logError(
      `  Unknown type (${SCHEMA_TYPES.join(" | ")} or "none") — keeping the current type`,
    );
  });
}

/** 編集: required(y/n。空 = 現状維持、それ以外は警告して現状維持)。 */
function editRequired(io: CliIoShape, draft: CandidateDraft): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const answer = (yield* io.promptLine({
      prompt: `  Required? (y/n; blank = keep ${draft.required}): `,
    }))
      .trim()
      .toLowerCase();
    if (answer === "y" || answer === "yes") {
      draft.required = true;
    } else if (answer === "n" || answer === "no") {
      draft.required = false;
    } else if (answer !== "") {
      yield* io.logError("  Answer y or n — keeping the current value");
    }
  });
}

/** 編集: description(空 = 現状維持・"-" = クリア)。 */
function editDescription(io: CliIoShape, draft: CandidateDraft): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const answer = yield* io.promptLine({
      prompt:
        '  Description (blank = keep; "-" = clear; plaintext metadata visible to the server — never put secret values here): ',
    });
    const trimmed = answer.trim();
    if (trimmed === "-") {
      draft.description = "";
    } else if (trimmed !== "") {
      draft.description = trimmed;
    }
  });
}

/** 編集サブプロンプト(空 = 現状維持。不正入力は警告して現状維持)。 */
function editDraft(
  io: CliIoShape,
  draft: CandidateDraft,
  isNameTaken: (name: string) => boolean,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    yield* editName(io, draft, isNameTaken);
    yield* editType(io, draft);
    yield* editRequired(io, draft);
    yield* editDescription(io, draft);
  });
}

/** 承認ループの結果。 */
type ApprovalOutcome =
  | { readonly kind: "approved"; readonly approved: ApprovedCandidate }
  | { readonly kind: "skipped" }
  | { readonly kind: "stopped" };

/** 承認ループの 1 周の結果(approve = y の確定。retry = 提示からやり直し)。 */
type ApprovalStep = ApprovalOutcome | { readonly kind: "retry" };

/** 承認プロンプトへの応答の解釈(表示・副作用を持たない純関数)。 */
function interpretApprovalAnswer(raw: string): "approve" | "edit" | "skip" | "stop" | "invalid" {
  const answer = raw.trim().toLowerCase();
  if (answer === "s" || answer === "") {
    return "skip";
  }
  if (answer === "q") {
    return "stop";
  }
  if (answer === "e") {
    return "edit";
  }
  return answer === "y" || answer === "yes" ? "approve" : "invalid";
}

/**
 * エントロピー検出時の専用の明示確認(fail-closed — 裁定 CW の対話形。
 * 非対話経路が存在しないため --allow-high-entropy 相当は不要)。
 */
function confirmHighEntropy(io: CliIoShape): Effect.Effect<boolean, CliError> {
  return Effect.gen(function* () {
    const confirmed = yield* io.promptLine({
      prompt: "  Keep the high-entropy text anyway? Type 'yes' to proceed: ",
    });
    if (confirmed.trim() === "yes") {
      return true;
    }
    yield* io.logError("  Not confirmed — edit the candidate or skip it");
    return false;
  });
}

/**
 * 候補の提示 + エントロピー警告(裁定 CW)+ 1 回分の応答の解釈。検出時に
 * そのまま承認するには専用の明示確認("yes")を要求する。
 */
function approvalStep(
  io: CliIoShape,
  entry: EnvFileEntry,
  draft: CandidateDraft,
  valueNote: string,
  isNameTaken: (name: string) => boolean,
): Effect.Effect<ApprovalStep, CliError, CliIo> {
  return Effect.gen(function* () {
    yield* io.logError(describeCandidate(draft, entry.line, valueNote));
    const finding =
      findHighEntropySubstring(draft.description) ?? findHighEntropySubstring(draft.name);
    if (finding !== null) {
      // 警告は検出値そのものを運ばない(秘密でありうる — entropy.ts の規律)
      yield* logWarning(
        `the candidate looks like it contains a secret-like high-entropy string (a ${finding.length}-character ${finding.kind} run). Schema metadata is stored in plaintext and is visible to the server — edit it out with "e", or approving will ask for an explicit confirmation`,
      );
    }
    const answer = interpretApprovalAnswer(
      yield* io.promptLine({
        prompt: `Declare ${displayText(draft.name)}? [y = declare / e = edit / s = skip / q = stop]: `,
      }),
    );
    if (answer === "skip") {
      return { kind: "skipped" } as const;
    }
    if (answer === "stop") {
      return { kind: "stopped" } as const;
    }
    if (answer === "edit") {
      yield* editDraft(io, draft, isNameTaken);
      return { kind: "retry" } as const;
    }
    if (answer === "invalid") {
      yield* io.logError("  Answer y, e, s or q");
      return { kind: "retry" } as const;
    }
    if (finding !== null && !(yield* confirmHighEntropy(io))) {
      return { kind: "retry" } as const;
    }
    return {
      kind: "approved",
      approved: {
        name: draft.name,
        schema: {
          varType: draft.varType,
          required: draft.required,
          description: draft.description,
        },
        pushValue: false,
      },
    } as const;
  });
}

/**
 * 1 変数の対話承認(編集可 — 設計文書 §1-3 (2))。承認が確定したら、実値らしい
 * 値に限り「値 push = activation まで行うか」の変数ごとの明示選択を続けて聞く
 * (既定 = 送信しない)。
 */
function approveCandidate(
  io: CliIoShape,
  entry: EnvFileEntry,
  isNameTaken: (name: string) => boolean,
): Effect.Effect<ApprovalOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    // 忠実に解釈できたと言えない値(閉じない引用符・引用値内のエスケープ —
    // env-file.ts)は観察にも掛けず、push の提案も出さない(fail-closed —
    // 誤読した値を暗号化して黙って保存する経路を作らない)
    const observed = entry.valueFaithful
      ? observeValue(entry.value)
      : ({ varType: "", looksReal: false } as const);
    const valueNote = entry.valueFaithful
      ? observed.looksReal
        ? "looks like a real value (not shown)"
        : "empty or a placeholder"
      : "could not be parsed faithfully by the line-based parser (unclosed quote or escapes) — pushing it will not be offered";
    const draft: CandidateDraft = {
      name: entry.name,
      varType: observed.varType,
      required: true,
      description: entry.descriptionCandidate,
    };
    if (draft.description.length > MAX_DESCRIPTION_LENGTH) {
      yield* logNote(
        `the comment above line ${entry.line} exceeds the ${MAX_DESCRIPTION_LENGTH}-character description limit and was discarded — add a shorter one with "e"`,
      );
      draft.description = "";
    }
    for (;;) {
      const step = yield* approvalStep(io, entry, draft, valueNote, isNameTaken);
      if (step.kind === "retry") {
        continue;
      }
      if (step.kind !== "approved" || !observed.looksReal) {
        return step;
      }
      // 値の送信は常に利用者の変数ごとの明示選択(既定 = 送信しない)。送信は
      // 宣言登録の後の pushVariable = activation 複合で行われ、値は E2EE の
      // まま(平文はサーバー API を通らない)
      const pushAnswer = yield* io.promptLine({
        prompt: `  Also push the value from the file (end-to-end encrypted; activates ${displayText(draft.name)})? [y/N]: `,
      });
      return {
        kind: "approved",
        approved: { ...step.approved, pushValue: isYes(pushAnswer) },
      } as const;
    }
  });
}

/** import の結果(表示は本関数内 — stdout は結果の要約のみ)。 */
export interface SchemaImportSummary {
  readonly declared: number;
  readonly activated: number;
  readonly skipped: number;
  /** 削除提案まで到達したか(q での中断・候補ゼロでは提案しない)。 */
  readonly deletionOffered: boolean;
  readonly deleted: boolean;
}

/**
 * 承認済み 1 変数の宣言登録(schemaSetOp の宣言作成部品の再利用 —
 * requireCreation で既存変数への再発行に切り替わらない)。
 */
function declareApproved(
  input: SchemaImportInput,
  approved: ApprovedCandidate,
): Effect.Effect<void, CliError, CliIo> {
  return schemaSetOp({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    name: approved.name,
    updates: {
      varType: { kind: "set", value: approved.schema.varType },
      required: { kind: "set", value: approved.schema.required },
      description: { kind: "set", value: approved.schema.description },
    },
    resync: input.resync,
    floor: input.floor,
    authorUserId: input.authorUserId,
    signingKey: input.signingKey,
    requireCreation: true,
    quietDisabledAdvisory: true,
  }).pipe(
    Effect.asVoid,
    Effect.mapError((error) =>
      cliError(
        `Import stopped at ${displayText(approved.name)}: ${error.message}. Variables declared before this point remain declared`,
      ),
    ),
  );
}

/**
 * 明示選択された値 push(activation — 既存 pushVariable の再利用: declared に
 * 解決され activation 複合を組む)。値はここで初めて Redacted<string> →
 * Redacted<Uint8Array> に写す。
 */
function pushApprovedValue(
  input: SchemaImportInput,
  entry: EnvFileEntry,
  approved: ApprovedCandidate,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 剥がす理由: エンコードの入力。産物は再び Redacted で、平文はこの式の
    // 外へ出ない(暗号化は push.ts の既存境界)
    const value = Redacted.make(new TextEncoder().encode(Redacted.value(entry.value)), {
      label: "variable-value",
    });
    const pushed = yield* pushVariable({
      client: input.client,
      environmentId: input.environmentId,
      recipient: input.recipient,
      name: approved.name,
      value,
      verified: input.verified,
      resync: input.resync,
      writerUserId: input.authorUserId,
      signingKey: input.signingKey,
      floor: input.floor,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `Import stopped while pushing the value of ${displayText(approved.name)}: ${error.message}. The variable stays declared — set its value later with \`maruhi push ${displayText(approved.name)}\``,
        ),
      ),
    );
    yield* logWarnings(pushed.warnings);
    yield* io.log(
      `Pushed the value of ${displayText(approved.name)} (version=${pushed.version}, epoch=${pushed.epoch})`,
    );
  });
}

/**
 * 完了時の元ファイル削除の提案(設計文書 §1-3 (4) — 明示確認の上でのみ削除。
 * 既定は削除しない)。呼び出し側が「全候補が今回宣言された」ことを確認済み —
 * プロンプトの文言はその事実を主張する。
 */
function offerSourceDeletion(
  input: SchemaImportInput,
  declared: number,
): Effect.Effect<{ readonly deleted: boolean }, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const answer = yield* io.promptLine({
      prompt: `All ${countNoun(declared, "variable")} in ${displayText(input.filePath)} are now declared as a signed schema — its last job is done. Delete the file? [y/N]: `,
    });
    if (!isYes(answer)) {
      return { deleted: false };
    }
    yield* Effect.tryPromise({
      try: () => unlink(input.filePath),
      catch: () => cliError(`Could not delete ${displayText(input.filePath)} — delete it manually`),
    });
    yield* io.log(`Deleted ${displayText(input.filePath)}`);
    return { deleted: true };
  });
}

/**
 * Imports schema candidates from a parsed .env / .env.example file (設計文書
 * §1-3): per-variable interactive approval, declared-only registration through
 * `schemaSetOp` (one composite × manifest CAS per variable, executed serially
 * — O(N) round trips, 発見 F′), optional per-variable value push (activation)
 * and, on completion, an explicit offer to delete the source file.
 */
/** 承認 → 登録の直列ループ(変数ごとの複合 × マニフェスト CAS — O(N)。発見 F′)。 */
function runApprovalLoop(
  input: SchemaImportInput,
  entries: readonly EnvFileEntry[],
  existingNames: ReadonlySet<string>,
): Effect.Effect<
  { declared: number; activated: number; skipped: number; stopped: boolean },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const importedNames = new Set<string>();
    // 編集(e)での改名は、ファイル内の**未処理の候補**の名前とも衝突させない
    // (後続の候補が requireCreation の「already exists」で import ごと止まる
    // ローカル衝突を、編集時点の警告で防ぐ — pullfrog レビュー対応)
    const fileNames = new Set(entries.map((candidate) => candidate.name));
    const counts = { declared: 0, activated: 0, skipped: 0, stopped: false };
    for (const entry of entries) {
      const isNameTaken = (name: string) =>
        existingNames.has(name) ||
        importedNames.has(name) ||
        (fileNames.has(name) && name !== entry.name);
      if (existingNames.has(entry.name)) {
        // 既存の active / declared と同名の候補は既定でスキップして表示する —
        // 再発行は `schema set` の領分(設計文書 §1-3 の線引き)
        yield* io.logError(
          `Skipped ${displayText(entry.name)} (line ${entry.line}): a variable with this name already exists — reissue its schema with \`maruhi schema set\``,
        );
        counts.skipped += 1;
        continue;
      }
      const outcome = yield* approveCandidate(io, entry, isNameTaken);
      if (outcome.kind === "stopped") {
        counts.stopped = true;
        break;
      }
      if (outcome.kind === "skipped") {
        counts.skipped += 1;
        continue;
      }
      yield* declareApproved(input, outcome.approved);
      counts.declared += 1;
      importedNames.add(outcome.approved.name);
      yield* io.log(`Declared ${displayText(outcome.approved.name)}`);
      if (outcome.approved.pushValue) {
        yield* pushApprovedValue(input, entry, outcome.approved);
        counts.activated += 1;
      }
    }
    return counts;
  });
}

export function schemaImportOp(
  input: SchemaImportInput,
): Effect.Effect<SchemaImportSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const parsed = parseEnvFile(input.content);
    for (const skipped of parsed.skipped) {
      yield* io.logError(`Skipped line ${skipped.line}: ${skipReasonText(skipped)}`);
    }
    if (parsed.entries.length === 0) {
      yield* io.log("No importable variables found in the file");
      return { declared: 0, activated: 0, skipped: 0, deletionOffered: false, deleted: false };
    }
    // 既存名の照合材料(検証済みステートメントのみ — §12-2。active / declared の
    // 両方が variables に混在する §12-7)と disabled advisory の一度きりの案内
    const metadata = yield* pullVerifiedEnvironmentMetadata(input);
    yield* logWarnings(metadata.warnings);
    if (metadata.advisorySchemaPolicy === "disabled") {
      yield* logNote(
        "the server reports this project's schema policy as disabled, so it will likely reject new declarations (422 schema-policy-disabled). An admin can enable it via PUT /projects/:projectId/schema-policy (see docs/SELF_HOSTING.md)",
      );
    }
    const existingNames = new Set(metadata.variables.map((statement) => statement.name));
    const { declared, activated, skipped, stopped } = yield* runApprovalLoop(
      input,
      parsed.entries,
      existingNames,
    );
    yield* io.log(
      `Import finished: ${countNoun(declared, "variable")} declared (${activated} with a value pushed), ${countNoun(skipped, "candidate")} skipped${stopped ? " — stopped before the end" : ""}`,
    );
    // 完了時の削除提案(設計文書 §1-3 (4))は「ファイルの全候補が今回宣言
    // された」実行に限る: q での中断・スキップした候補(s / 既存名)・解釈
    // できなかった行が 1 つでも残るなら、ファイルの「最後の仕事」はまだ
    // 終わっていない(pullfrog レビュー対応 — 全スキップの実行に「宣言済み」を
    // 主張する提案を出さない)
    const everyCandidateDeclared =
      !stopped && declared > 0 && skipped === 0 && parsed.skipped.length === 0;
    if (!everyCandidateDeclared) {
      return { declared, activated, skipped, deletionOffered: false, deleted: false };
    }
    const deletion = yield* offerSourceDeletion(input, declared);
    return { declared, activated, skipped, deletionOffered: true, deleted: deletion.deleted };
  });
}
