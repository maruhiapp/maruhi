// `maruhi ci run -- <cmd>`: workload-lease execution inside a CI job
// (CRYPTO_SPEC §9.1 / AUTH_SPEC §14; design decisions are in
// docs/notes/session-25.md).
//
// Lease acquisition and verification are ci-lease.ts (shared with `maruhi
// ci sync`). This module only hands the material to the same path as
// `run`: decrypted values pass as Redacted to runOp (buildInjectionEnv →
// ProcessRunner) and are consumed solely by memory injection into the
// child process's environment variables (the diskless invariant). Because
// this is "injection" rather than "display" of values, it is outside the
// agent-gate (value-display gate) (the same sanctioned consumption path
// as run — ADR-0016 decision 7). The required-services type (CliIo |
// ProcessRunner | HttpClient) shows the absence of dependencies on
// config, tokens, and the keychain.

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { type CiLeaseInput, leaseEnvironments } from "./ci-lease.ts";
import { logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { enforceDeclaredPresence, ProcessRunner, runOp, typeAdvisoryWarnings } from "./run.ts";

/** Input of `maruhi ci run` (all from explicit flags — session-25 §2). */
export interface CiRunInput extends CiLeaseInput {
  readonly environmentId: EnvironmentId;
  readonly command: readonly string[];
}

/**
 * Runs one command with the environment's variables leased through OIDC
 * (CRYPTO_SPEC §9.1 / AUTH_SPEC §14), then injects the decrypted values
 * into the child process environment (memory only).
 */
export function ciRunOp(
  input: CiRunInput,
): Effect.Effect<number, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const materials = yield* leaseEnvironments({
      ...input,
      environmentIds: [input.environmentId],
    });
    const material = materials.get(input.environmentId);
    if (material === undefined) {
      return yield* Effect.fail(
        cliError("The lease returned no material (internal inconsistency)"),
      );
    }
    // presence fail-fast (design doc §1-4 — the same rule as run): judged
    // against the verification material bundled in the lease response
    // (statements + manifest — §14-2). If a required = true declared
    // exists, the child process is not started
    yield* enforceDeclaredPresence(material.declared);
    // type is advisory (§14.3-7) — a mismatch only warns; execution continues
    yield* logWarnings(typeAdvisoryWarnings(material.variables));
    return yield* runOp({ command: input.command, variables: material.variables });
  });
}
