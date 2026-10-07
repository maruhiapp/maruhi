// The constant display of server disclosure (CRYPTO_SPEC §9): "this project
// is disclosed to the server" while the verified chain carries an active
// grant whose scope names an environment.
//
// The one derivation every surface reads: the Note (every command that
// opens the project — the prologue in context.ts, plus the views opened
// outside it: `project export`, `mirror sync | status`, and the workload
// lease of `ci run | sync | rotate` in ci-lease.ts), the `env list` column,
// `project verify`'s grant lines, and the workload's lease authorization
// check (lease-client.ts — §9.1 (6): a lease is used only when an active
// grant here names its environment). Chain-derived only: the active grants are
// what §6.3 verification folded (a revoke_server removes one, a
// delete_environment prunes its id from every scope), never the server's
// report. No request is made.

import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { compareCodePoints } from "./scope.ts";

/** One active grant that discloses at least one environment to a server key. */
export interface ServerDisclosure {
  readonly serverKeyFingerprintHex: string;
  /** The grant's scope (ID ascending; never empty — a grant whose scope was emptied by deletions discloses nothing). */
  readonly environmentIds: readonly string[];
  /** The number of lease-policy elements (0 = no lease path — §9.1). */
  readonly leasePolicyCount: number;
  /** Seq of the grant_server entry that established the active grant. */
  readonly grantSeq: number;
}

/** The verified chain's disclosing grants, fingerprint ascending (empty = pure E2EE). */
export function serverDisclosures(verified: VerifiedProject): readonly ServerDisclosure[] {
  return [...verified.state.serverGrants.values()]
    .filter((grant) => grant.scopeEnvironmentIds.length > 0)
    .map((grant) => ({
      serverKeyFingerprintHex: grant.serverKeyFingerprintHex,
      environmentIds: grant.scopeEnvironmentIds.toSorted(compareCodePoints),
      leasePolicyCount: grant.leasePolicy.length,
      grantSeq: grant.grantSeq,
    }))
    .toSorted((a, b) => compareCodePoints(a.serverKeyFingerprintHex, b.serverKeyFingerprintHex));
}

/** The server keys an environment is disclosed to (fingerprint ascending; empty = none). */
export function serverKeysDisclosing(
  disclosures: readonly ServerDisclosure[],
  environmentId: string,
): readonly string[] {
  return disclosures
    .filter((disclosure) => disclosure.environmentIds.includes(environmentId))
    .map((disclosure) => disclosure.serverKeyFingerprintHex);
}

/** "environment prod" / "environments prod, staging" (IDs neutralized). */
function describeEnvironments(environmentIds: readonly string[]): string {
  return `${environmentIds.length === 1 ? "environment" : "environments"} ${environmentIds.map(displayText).join(", ")}`;
}

/** The Note's text for one grant (names the project: a multi-project sweep prints one per project, and the ledger keeps identical lines once). */
function describeServerDisclosure(projectId: string, disclosure: ServerDisclosure): string {
  return `project ${displayText(projectId)} is disclosed to the server (CRYPTO_SPEC §9): server key ${disclosure.serverKeyFingerprintHex} can decrypt the values of ${describeEnvironments(disclosure.environmentIds)}`;
}

/** `project verify`'s row for one grant (fingerprint, scope, lease policy, grant seq). */
export function formatServerDisclosureRow(disclosure: ServerDisclosure): string {
  return `${disclosure.serverKeyFingerprintHex}\tscope=${disclosure.environmentIds.map(displayText).join(", ")}\tlease-policy=${countNoun(disclosure.leasePolicyCount, "element")}\tgranted at seq=${disclosure.grantSeq}`;
}

/**
 * The prologue's standing Note (§9 — one line per disclosing grant; nothing
 * for a project without one). A Note, not a Warning: the grant is an
 * owner-signed configuration on the verified chain, not a degraded state, and
 * a Warning on every run of a deliberately granted project would teach its
 * members to skip warnings.
 */
export const noteServerDisclosure = Effect.fn("server-disclosure.noteServerDisclosure")(function* (
  verified: VerifiedProject,
): Effect.fn.Return<void, never, CliIo> {
  for (const disclosure of serverDisclosures(verified)) {
    yield* logNote(describeServerDisclosure(verified.projectId, disclosure));
  }
});
