// `maruhi schema import <file>` (bootstrap — design doc §1-3, finding A).
//
// The ceremony's shape (4 stages):
//   (1) Read the .env / .env.example named by the explicit positional
//       argument on the client side only (env-file.ts — the value is
//       Redacted right after reading. Type inference = shape observation
//       only)
//   (2) Per-variable interactive approval (editable). Present the name,
//       type candidate, required (creation default true), and
//       description candidate; approve / edit / skip can be chosen
//   (3) Register the approved ones as declared (reusing schemaSetOp's
//       declaration-creation piece — requireCreation). Only when the
//       value is judged a real value and the user explicitly opts in per
//       variable does it also push the value = activation (reusing the
//       existing pushVariable. The default is to send no value)
//   (4) On completion, offer to delete the source file (deleted only on
//       explicit confirmation. The default is not to delete — "a
//       .env.example's last job is to become a signed schema")
//
// **The interactive approval is the ceremony's core**, so no blanket
// --yes is built. A non-interactive environment (stdin / stdout not a
// terminal) or a detected known agent is refused with a typed error —
// the same ceremony-family deny class as invite / recovery (ADR-0016
// decision 7). The judgment material comes via the Stdio /
// AgentProfileRef services; process.* is never read directly.
//
// Registration is a serial run of per-variable composites × manifest
// CAS (O(N) round trips — finding F'. Whether a bulk composite
// acceptance is warranted is the owner's call on the evidence of a
// measured report — not anticipated). Conflicts reuse schemaSetOp /
// pushVariable's existing retry discipline (retryOnConflict) as-is.

import { unlink } from "node:fs/promises";

import type { EnvironmentId } from "@maruhi/core";
import type { MetaVarType } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import { ensureHumanCeremonyAllowed } from "../agent-gate.ts";
import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { countNoun, displayText, escapeText, logWarnings } from "../display.ts";
import { findHighEntropySubstring } from "../entropy.ts";
import {
  type EnvFileEntry,
  type EnvFileSkippedLine,
  MAX_NAME_LENGTH,
  observeValue,
  parseEnvFile,
} from "../env-file.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle, VerifiedSchemaFields } from "../floor-check.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { pushVariable } from "../push.ts";
import { pullVerifiedEnvironmentMetadata } from "../values.ts";
import { schemaSetOp } from "./schema.ts";

/** The server's description acceptance cap (AUTH_SPEC §12-8 — used only for pre-filtering). */
const MAX_DESCRIPTION_LENGTH = 1024;

/**
 * Refuses the import ceremony outside an interactive human terminal: the
 * per-variable approval **is** the ritual, so there is no --yes and no
 * non-interactive path (ADR-0016 decision 7 — the invite / recovery deny class).
 *
 * The boundary is the 2 channels stdin + stdout (the same first boundary
 * as value display / the ceremony family); it deliberately does NOT
 * match the **3-channel** gate (stderr also TTY) of recovery codes /
 * invite link raw values: there, a "capability / key material that
 * exists on disk via no other path" flows to stderr, so persisting it
 * via `2>` becomes a new exposure class — whereas what import emits to
 * stderr (the candidate presentation, including the description
 * candidate) is **content already written in the user's own local
 * file**, so redirecting it creates no new exposure. The value itself
 * goes out on no channel (observation only — env-file.ts).
 */
export const ensureImportCeremonyAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to run schema import: an AI agent environment was detected${detected}. The per-variable approval is the core of this ceremony, so a person must run it in a terminal (agents can read the resulting schema with \`maruhi schema\`)`,
    terminalRefusal: (reason) =>
      `Refused to run schema import: ${reason} (pipes, redirects, CI, and AI agents are refused; the per-variable approval is the core of the ceremony and there is no --yes bypass). Run it yourself in a terminal`,
  });

/** The import's input (schema.package/command.ts assembles it from EnvironmentContext). */
interface SchemaImportInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
  /** The recipient material for the activation value push (only on explicit opt-in). */
  readonly recipient: DekRecipient;
  /** The file path for display (the caller does the reading — received as content). */
  readonly filePath: string;
  /** The file content (read by the caller on the client side only). */
  readonly content: string;
}

/** One variable's approval result (the settled values after editing). */
interface ApprovedCandidate {
  readonly name: string;
  readonly schema: VerifiedSchemaFields;
  /** true = also perform the value push (activation) (the user's explicit choice). */
  readonly pushValue: boolean;
}

/** One variable's state in the approval loop (overwritten by edits). */
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

/** The candidate's presentation line (never shows the value itself — only the type candidate and the real-value-ness observation). */
function describeCandidate(draft: CandidateDraft, line: number, valueNote: string): string {
  const typeShown = draft.varType === "" ? "-" : draft.varType;
  const description = draft.description === "" ? "-" : `"${escapeText(draft.description)}"`;
  return `Line ${line}: ${displayText(draft.name)} — type=${typeShown}, required=${draft.required}, description=${description}, value=${valueNote}`;
}

/** Interpreting a yes/no prompt (only y / yes affirm — the default is the negative). */
function isYes(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

/** Edit: the name (blank = keep as-is. Format / duplicates warn and keep as-is). */
const editName = Effect.fn("schema-import.editName")(function* (
  io: CliIoShape,
  draft: CandidateDraft,
  isNameTaken: (name: string) => boolean,
): Effect.fn.Return<void, CliError> {
  const answer = (yield* io.promptLine({
    prompt: `  Name (blank = keep ${displayText(draft.name)}): `,
  })).trim();
  if (answer === "") {
    return;
  }
  const name = answer.normalize("NFC");
  // The format / length check accepts the same set as the parser
  // (env-file.ts) — never build a shape where only the edit route
  // passes through to the server's slow 400 failure point (stops the
  // whole import)
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

/** Edit: the type (blank = keep as-is, none = unspecified. Outside the closed set warns and keeps as-is). */
const editType = Effect.fn("schema-import.editType")(function* (
  io: CliIoShape,
  draft: CandidateDraft,
): Effect.fn.Return<void, CliError> {
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

/** Edit: required (y/n. blank = keep as-is; anything else warns and keeps as-is). */
const editRequired = Effect.fn("schema-import.editRequired")(function* (
  io: CliIoShape,
  draft: CandidateDraft,
): Effect.fn.Return<void, CliError> {
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

/** Edit: description (blank = keep as-is, "-" = clear). */
const editDescription = Effect.fn("schema-import.editDescription")(function* (
  io: CliIoShape,
  draft: CandidateDraft,
): Effect.fn.Return<void, CliError> {
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

/** The edit sub-prompts (blank = keep as-is. Invalid input warns and keeps as-is). */
const editDraft = Effect.fn("schema-import.editDraft")(function* (
  io: CliIoShape,
  draft: CandidateDraft,
  isNameTaken: (name: string) => boolean,
): Effect.fn.Return<void, CliError> {
  yield* editName(io, draft, isNameTaken);
  yield* editType(io, draft);
  yield* editRequired(io, draft);
  yield* editDescription(io, draft);
});

/** The approval loop's outcome. */
type ApprovalOutcome =
  | { readonly kind: "approved"; readonly approved: ApprovedCandidate }
  | { readonly kind: "skipped" }
  | { readonly kind: "stopped" };

/** One turn of the approval loop's outcome (approve = the y confirmation. retry = restart from the presentation). */
type ApprovalStep = ApprovalOutcome | { readonly kind: "retry" };

/** Interpreting the approval prompt's answer (a pure function with no display or side effects). */
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
 * The dedicated explicit confirmation on an entropy finding (fail-closed
 * — ruling CW's interactive form. Since no non-interactive path exists,
 * no --allow-high-entropy equivalent is needed).
 */
const confirmHighEntropy = Effect.fn("schema-import.confirmHighEntropy")(function* (
  io: CliIoShape,
): Effect.fn.Return<boolean, CliError> {
  const confirmed = yield* io.promptLine({
    prompt: "  Keep the high-entropy text anyway? Type 'yes' to proceed: ",
  });
  if (confirmed.trim() === "yes") {
    return true;
  }
  yield* io.logError("  Not confirmed — edit the candidate or skip it");
  return false;
});

/**
 * The candidate presentation + the entropy warning (ruling CW) + one
 * round of answer interpretation. Approving as-is on a finding requires
 * the dedicated explicit confirmation ("yes").
 */
const approvalStep = Effect.fn("schema-import.approvalStep")(function* (
  io: CliIoShape,
  entry: EnvFileEntry,
  draft: CandidateDraft,
  valueNote: string,
  isNameTaken: (name: string) => boolean,
): Effect.fn.Return<ApprovalStep, CliError, CliIo> {
  yield* io.logError(describeCandidate(draft, entry.line, valueNote));
  const finding =
    findHighEntropySubstring(draft.description) ?? findHighEntropySubstring(draft.name);
  if (finding !== null) {
    // The warning never carries the found value itself (it may be a
    // secret — entropy.ts's discipline). Per-candidate warning (emitted
    // every time — on a retry of the same candidate and on another
    // candidate of the same shape — never a ledger-suppressed item).
    // Attached indented directly below the candidate
    yield* logWarning(
      `the candidate looks like it contains a secret-like high-entropy string (a ${finding.length}-character ${finding.kind} run). Schema metadata is stored in plaintext and is visible to the server — edit it out with "e", or approving will ask for an explicit confirmation`,
      { scope: "prompt" },
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
        maxAgeDays: null,
      },
      pushValue: false,
    },
  } as const;
});

/**
 * One variable's interactive approval (editable — design doc §1-3 (2)).
 * Once the approval settles, only for a value that looks real does it
 * continue to ask the per-variable explicit choice "push the value = go
 * as far as activation?" (default = do not send).
 */
const approveCandidate = Effect.fn("schema-import.approveCandidate")(function* (
  io: CliIoShape,
  entry: EnvFileEntry,
  isNameTaken: (name: string) => boolean,
): Effect.fn.Return<ApprovalOutcome, CliError, CliIo> {
  // A value that cannot be said to parse faithfully (unclosed quotes,
  // escapes inside a quoted value — env-file.ts) is neither observed
  // nor offered a push (fail-closed — never build a path that encrypts
  // a misread value and silently stores it)
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
    // Emitted before the candidate's presentation (approvalStep's
    // describeCandidate), so not given the prompt scope that hangs
    // under an item (the indent would attach to the previous item).
    // Since it carries the line number it is unique per candidate and
    // needs no repeating on retry (the discard happened once)
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
    // Sending a value is always the user's per-variable explicit choice
    // (default = do not send). The send happens as the pushVariable =
    // activation composite after the declaration registers, and the
    // value stays E2EE (plaintext never crosses the server API)
    const pushAnswer = yield* io.promptLine({
      prompt: `  Also push the value from the file (end-to-end encrypted; activates ${displayText(draft.name)})? [y/N]: `,
    });
    return {
      kind: "approved",
      approved: { ...step.approved, pushValue: isYes(pushAnswer) },
    } as const;
  }
});

/** The import's result (display lives inside this function — stdout carries only the result's summary). */
interface SchemaImportSummary {
  readonly declared: number;
  readonly activated: number;
  readonly skipped: number;
  /** Whether the deletion offer was reached (never offered on a q interruption or zero candidates). */
  readonly deletionOffered: boolean;
  readonly deleted: boolean;
}

/**
 * Registering one approved variable's declaration (reusing schemaSetOp's
 * declaration-creation piece — requireCreation keeps it from switching
 * into reissuing onto an existing variable).
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
      // An import declares no max age (set it later with `schema set --max-age`)
      maxAgeDays: { kind: "keep" },
    },
    resync: input.resync,
    floor: input.floor,
    authorUserId: input.authorUserId,
    signingKey: input.signingKey,
    requireCreation: true,
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
 * The explicitly-chosen value push (activation — reusing the existing
 * pushVariable: resolves to declared and assembles the activation
 * composite). Here the value is transcribed for the first time:
 * Redacted<string> → Redacted<Uint8Array>.
 */
const pushApprovedValue = Effect.fn("schema-import.pushApprovedValue")(function* (
  input: SchemaImportInput,
  entry: EnvFileEntry,
  approved: ApprovedCandidate,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  // Reason for unwrapping: the encoding's input. The product is again
  // Redacted and the plaintext never leaves this expression (encryption
  // is push.ts's existing boundary)
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

/**
 * The offer to delete the source file on completion (design doc §1-3
 * (4) — deleted only on explicit confirmation. The default is not to
 * delete). The caller has already confirmed "every candidate was
 * declared this run" — the prompt's wording asserts that fact.
 */
const offerSourceDeletion = Effect.fn("schema-import.offerSourceDeletion")(function* (
  input: SchemaImportInput,
  declared: number,
): Effect.fn.Return<{ readonly deleted: boolean }, CliError, CliIo> {
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

/**
 * Imports schema candidates from a parsed .env / .env.example file
 * (design doc §1-3): per-variable interactive approval, declared-only
 * registration through `schemaSetOp` (one composite × manifest CAS per
 * variable, executed serially — O(N) round trips, finding F'), optional
 * per-variable value push (activation) and, on completion, an explicit
 * offer to delete the source file.
 */
/** The serial approve → register loop (per-variable composite × manifest CAS — O(N). Finding F'). */
const runApprovalLoop = Effect.fn("schema-import.runApprovalLoop")(function* (
  input: SchemaImportInput,
  entries: readonly EnvFileEntry[],
  existingNames: ReadonlySet<string>,
): Effect.fn.Return<
  { declared: number; activated: number; skipped: number; stopped: boolean },
  CliError,
  CliIo
> {
  const io = yield* CliIo;
  const importedNames = new Set<string>();
  // A rename via edit (e) may collide with no name — not even an
  // **unprocessed candidate** in the file (a local collision that would
  // stop the whole import on a later candidate's requireCreation
  // "already exists" is prevented by a warning at edit time)
  const fileNames = new Set(entries.map((candidate) => candidate.name));
  const counts = { declared: 0, activated: 0, skipped: 0, stopped: false };
  for (const entry of entries) {
    const isNameTaken = (name: string) =>
      existingNames.has(name) ||
      importedNames.has(name) ||
      (fileNames.has(name) && name !== entry.name);
    if (existingNames.has(entry.name)) {
      // A candidate named like an existing active / declared is skipped
      // by default and shown — reissuing is `schema set`'s domain (the
      // design doc §1-3's boundary)
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

export const schemaImportOp = Effect.fn("schema-import.schemaImportOp")(function* (
  input: SchemaImportInput,
): Effect.fn.Return<SchemaImportSummary, CliError, CliIo> {
  const io = yield* CliIo;
  const parsed = parseEnvFile(input.content);
  for (const skipped of parsed.skipped) {
    yield* io.logError(`Skipped line ${skipped.line}: ${skipReasonText(skipped)}`);
  }
  if (parsed.entries.length === 0) {
    yield* io.log("No importable variables found in the file");
    return { declared: 0, activated: 0, skipped: 0, deletionOffered: false, deleted: false };
  }
  // The matching material for existing names (verified statements only
  // — §12-2. Both active and declared are mixed into variables §12-7)
  const metadata = yield* pullVerifiedEnvironmentMetadata(input);
  yield* logWarnings(metadata.warnings);
  const existingNames = new Set(metadata.variables.map((statement) => statement.name));
  const { declared, activated, skipped, stopped } = yield* runApprovalLoop(
    input,
    parsed.entries,
    existingNames,
  );
  yield* io.log(
    `Import finished: ${countNoun(declared, "variable")} declared (${activated} with a value pushed), ${countNoun(skipped, "candidate")} skipped${stopped ? " — stopped before the end" : ""}`,
  );
  // The completion-time deletion offer (design doc §1-3 (4)) is limited
  // to a run where "every candidate in the file was declared this
  // time": if an interruption via q, a skipped candidate (s / existing
  // name), or an uninterpretable line remains, the file's "last job" is
  // not done (never emit an offer that asserts "declared" on an
  // all-skipped run)
  const everyCandidateDeclared =
    !stopped && declared > 0 && skipped === 0 && parsed.skipped.length === 0;
  if (!everyCandidateDeclared) {
    return { declared, activated, skipped, deletionOffered: false, deleted: false };
  }
  const deletion = yield* offerSourceDeletion(input, declared);
  return { declared, activated, skipped, deletionOffered: true, deleted: deletion.deleted };
});
