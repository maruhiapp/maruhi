import { unlink } from "node:fs/promises";

import { type EnvironmentId, type UserId } from "@maruhi/core";
import type { MetaVarType } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import { ensureHumanCeremonyAllowed } from "../agent-gate.ts";
import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { countNoun, displayText, escapeText, logWarnings } from "../display.ts";
import { findHighEntropySubstring } from "../entropy.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle, VerifiedSchemaFields } from "../floor-check.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { pushVariable } from "../push.package/index.ts";
import { pullVerifiedEnvironmentMetadata } from "../values.ts";
import {
  type EnvFileEntry,
  type EnvFileSkippedLine,
  MAX_NAME_LENGTH,
  observeValue,
  parseEnvFile,
} from "./env-file.ts";
import { schemaSetOp } from "./schema.ts";

const MAX_DESCRIPTION_LENGTH = 1024;

export const ensureImportCeremonyAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to run schema import: an AI agent environment was detected${detected}. The per-variable approval is the core of this ceremony, so a person must run it in a terminal (agents can read the resulting schema with \`maruhi schema\`)`,
    terminalRefusal: (reason) =>
      `Refused to run schema import: ${reason} (pipes, redirects, CI, and AI agents are refused; the per-variable approval is the core of the ceremony and there is no --yes bypass). Run it yourself in a terminal`,
  });

interface SchemaImportInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
  readonly recipient: DekRecipient;
  readonly filePath: string;
  readonly content: string;
}

interface ApprovedCandidate {
  readonly name: string;
  readonly schema: VerifiedSchemaFields;
  readonly pushValue: boolean;
}

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

function describeCandidate(draft: CandidateDraft, line: number, valueNote: string): string {
  const typeShown = draft.varType === "" ? "-" : draft.varType;
  const description = draft.description === "" ? "-" : `"${escapeText(draft.description)}"`;
  return `Line ${line}: ${displayText(draft.name)} — type=${typeShown}, required=${draft.required}, description=${description}, value=${valueNote}`;
}

function isYes(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

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

type ApprovalOutcome =
  | { readonly kind: "approved"; readonly approved: ApprovedCandidate }
  | { readonly kind: "skipped" }
  | { readonly kind: "stopped" };

type ApprovalStep = ApprovalOutcome | { readonly kind: "retry" };

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

const approveCandidate = Effect.fn("schema-import.approveCandidate")(function* (
  io: CliIoShape,
  entry: EnvFileEntry,
  isNameTaken: (name: string) => boolean,
): Effect.fn.Return<ApprovalOutcome, CliError, CliIo> {
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
    const pushAnswer = yield* io.promptLine({
      prompt: `  Also push the value from the file (end-to-end encrypted; activates ${displayText(draft.name)})? [y/N]: `,
    });
    return {
      kind: "approved",
      approved: { ...step.approved, pushValue: isYes(pushAnswer) },
    } as const;
  }
});

interface SchemaImportSummary {
  readonly declared: number;
  readonly activated: number;
  readonly skipped: number;
  readonly deletionOffered: boolean;
  readonly deleted: boolean;
}

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

const pushApprovedValue = Effect.fn("schema-import.pushApprovedValue")(function* (
  input: SchemaImportInput,
  entry: EnvFileEntry,
  approved: ApprovedCandidate,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
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
  const fileNames = new Set(entries.map((candidate) => candidate.name));
  const counts = { declared: 0, activated: 0, skipped: 0, stopped: false };
  for (const entry of entries) {
    const isNameTaken = (name: string) =>
      existingNames.has(name) ||
      importedNames.has(name) ||
      (fileNames.has(name) && name !== entry.name);
    if (existingNames.has(entry.name)) {
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
  const everyCandidateDeclared =
    !stopped && declared > 0 && skipped === 0 && parsed.skipped.length === 0;
  if (!everyCandidateDeclared) {
    return { declared, activated, skipped, deletionOffered: false, deleted: false };
  }
  const deletion = yield* offerSourceDeletion(input, declared);
  return { declared, activated, skipped, deletionOffered: true, deleted: deletion.deleted };
});
