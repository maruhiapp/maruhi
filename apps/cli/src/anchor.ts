import {
  decodeEnvironmentId,
  decodeProjectId,
  isEnvironmentId,
  isProjectId,
  type ProjectId,
} from "@maruhi/core";
import { Effect, Schema } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { cliError, type CliError } from "./errors.ts";
import {
  Hex64,
  JsonRecord,
  parseJsonRecord,
  PositiveInt,
  readNamedFile,
  recordKeysMatch,
} from "./json-record.ts";

export interface RepositoryAnchor {
  readonly version: 1;
  readonly projectId: ProjectId;
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly environments: Readonly<Record<string, number>>;
}

export function buildRepositoryAnchor(verified: VerifiedProject): RepositoryAnchor {
  const environments: Record<string, number> = {};
  for (const environmentId of [...verified.state.environments.keys()].toSorted()) {
    const environment = verified.state.environments.get(environmentId);
    if (environment !== undefined) {
      environments[environmentId] = environment.currentEpoch;
    }
  }
  return {
    version: 1,
    projectId: verified.projectId,
    headSeq: verified.state.headSeq,
    headHashHex: verified.state.headHashHex,
    environments,
  };
}

export function formatRepositoryAnchor(anchor: RepositoryAnchor): string {
  return `${JSON.stringify(anchor, null, 2)}\n`;
}

const AnchorEnvironments = Schema.Record(Schema.String, PositiveInt).check(
  recordKeysMatch(isEnvironmentId),
);

function anchorRecordOf(content: string): Record<string, unknown> | string {
  const record = parseJsonRecord(content);
  if (typeof record === "string") {
    return record;
  }
  if (record["version"] !== 1) {
    return "unsupported anchor version (expected 1)";
  }
  return record;
}

function parseRepositoryAnchor(content: string): RepositoryAnchor | string {
  const record = anchorRecordOf(content);
  if (typeof record === "string") {
    return record;
  }
  const projectId = record["projectId"];
  if (!(typeof projectId === "string" && isProjectId(projectId))) {
    return "projectId must be the genesis hash (64 hex digits)";
  }
  const headSeq = record["headSeq"];
  if (!Schema.is(PositiveInt)(headSeq)) {
    return "headSeq must be a positive integer";
  }
  const headHashHex = record["headHashHex"];
  if (!Schema.is(Hex64)(headHashHex)) {
    return "headHashHex must be 64 lowercase hex digits";
  }
  const environments = record["environments"];
  if (!Schema.is(JsonRecord)(environments)) {
    return "environments must be an object of { environmentId: epoch }";
  }
  if (!Schema.is(AnchorEnvironments)(environments)) {
    return "environments must map environment IDs to positive integer epochs";
  }
  return {
    version: 1,
    projectId: decodeProjectId(projectId),
    headSeq,
    headHashHex,
    environments,
  };
}

export const loadRepositoryAnchor = Effect.fn("anchor.loadRepositoryAnchor")(function* (
  path: string,
): Effect.fn.Return<RepositoryAnchor, CliError> {
  const content = yield* readNamedFile(
    path,
    cliError("Cannot read the --anchor file (check the path)"),
  );
  const parsed = parseRepositoryAnchor(content);
  if (typeof parsed === "string") {
    return yield* Effect.fail(
      cliError(
        `The --anchor file is invalid: ${parsed}. Regenerate it with \`maruhi project anchor\``,
      ),
    );
  }
  return parsed;
});

export const checkRepositoryAnchor = Effect.fn("anchor.checkRepositoryAnchor")(function* (input: {
  readonly anchor: RepositoryAnchor;
  readonly verified: VerifiedProject;
}): Effect.fn.Return<void, CliError> {
  const { anchor, verified } = input;
  const evidenceHint =
    "The verification material is the committed anchor file plus the distributed chain (CRYPTO_SPEC §6.3 out-of-band anchor (b))";
  if (anchor.projectId !== verified.projectId) {
    return yield* Effect.fail(
      cliError(
        `Repository-anchor check failed: the anchor's genesis hash does not match the pinned project ID. The anchor file belongs to a different project, or the CI configuration is wrong. ${evidenceHint}`,
      ),
    );
  }
  if (verified.history.entryHashAt(anchor.headSeq) !== anchor.headHashHex) {
    return yield* Effect.fail(
      cliError(
        `Repository-anchor check failed: the distributed chain does not contain the anchored head (seq=${anchor.headSeq}). This suggests a server-side rollback or fork distribution — do not trust this response. ${evidenceHint}`,
      ),
    );
  }
  for (const [environmentId, anchoredEpoch] of Object.entries(anchor.environments)) {
    const environment = isEnvironmentId(environmentId)
      ? verified.state.environments.get(decodeEnvironmentId(environmentId))
      : undefined;
    if (environment === undefined) {
      return yield* Effect.fail(
        cliError(
          `Repository-anchor check failed: anchored environment ${environmentId} does not exist on the distributed chain. This suggests a rollback past the environment's creation — do not trust this response. ${evidenceHint}`,
        ),
      );
    }
    if (environment.currentEpoch < anchoredEpoch) {
      return yield* Effect.fail(
        cliError(
          `Repository-anchor check failed: environment ${environmentId} has a chain-derived epoch below the anchored epoch (${anchoredEpoch}). This suggests distribution of a pre-rotation view (a leaked credential could be re-deployed) — do not trust this response. ${evidenceHint}`,
        ),
      );
    }
  }
});
