// `maruhi project policy schema` (AUTH_SPEC §12-11): show or set the
// project's schema policy.
//
// The policy is a server acceptance setting, not a chain entry (§12-11
// "Not on the chain"), so neither path syncs or verifies the chain and
// neither needs the master key. Reading is reader-level; setting is
// admin scope × chain role admin, enforced by the server (the 403 is
// rendered with the role it needs). The value carries no secret, so the
// command is not gated in agent environments.

import { ForbiddenError, type SchemaPolicy, SchemaPolicySchema } from "@maruhi/api-schema";
import { type ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";

/** The tiers, in the spec's order (enabled is the default). */
export const SCHEMA_POLICIES: readonly SchemaPolicy[] = SchemaPolicySchema.literals;

export function isSchemaPolicy(value: string): value is SchemaPolicy {
  return SCHEMA_POLICIES.some((known) => known === value);
}

/** What a tier means for the people writing variables (one line). */
function describeSchemaPolicy(policy: SchemaPolicy): string {
  return policy === "locked"
    ? "creating a variable requires a declared type (`maruhi schema set NAME --type …`)"
    : "creating a variable without a declared type is allowed";
}

const fetchSchemaPolicy = (
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<SchemaPolicy, CliError> =>
  client.schemaPolicy.get({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.schemaPolicy),
  );

/** Prints the current policy (server-reported — the policy is not on the chain). */
export const showSchemaPolicyOp = Effect.fn("project-schema-policy.showSchemaPolicyOp")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly projectId: ProjectId;
  }): Effect.fn.Return<void, CliError, CliIo> {
    const io = yield* CliIo;
    const policy = yield* fetchSchemaPolicy(input.client, input.projectId);
    yield* io.log(`Schema policy: ${policy} — ${describeSchemaPolicy(policy)}`);
  },
);

/**
 * Sets the policy. The PUT is sent even when the read already shows the
 * requested tier (the server treats a same-value PUT as a no-op without an
 * audit row), so the final state is the requested one even if the read
 * raced another change; the read only shapes the message.
 */
export const setSchemaPolicyOp = Effect.fn("project-schema-policy.setSchemaPolicyOp")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly projectId: ProjectId;
    readonly policy: SchemaPolicy;
  }): Effect.fn.Return<void, CliError, CliIo> {
    const io = yield* CliIo;
    const previous = yield* fetchSchemaPolicy(input.client, input.projectId);
    yield* input.client.schemaPolicy
      .set({ params: { projectId: input.projectId }, payload: { schemaPolicy: input.policy } })
      .pipe(
        Effect.mapError((error) =>
          error instanceof ForbiddenError &&
          (error.reason === "insufficient-role" || error.reason === "insufficient-permission")
            ? cliError(
                `Insufficient permission (${error.reason}): changing the schema policy needs the admin role on this project and a token with admin scope`,
              )
            : toCliError(error),
        ),
      );
    yield* io.log(
      previous === input.policy
        ? `Schema policy is already ${input.policy} — ${describeSchemaPolicy(input.policy)}`
        : `Schema policy: ${previous} → ${input.policy} — ${describeSchemaPolicy(input.policy)}`,
    );
  },
);
