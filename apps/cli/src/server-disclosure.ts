import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { compareCodePoints } from "./scope.ts";

export interface ServerDisclosure {
  readonly serverKeyFingerprintHex: string;
  readonly environmentIds: readonly EnvironmentId[];
  readonly leasePolicyCount: number;
  readonly grantSeq: number;
}

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

export function serverKeysDisclosing(
  disclosures: readonly ServerDisclosure[],
  environmentId: EnvironmentId,
): readonly string[] {
  return disclosures
    .filter((disclosure) => disclosure.environmentIds.includes(environmentId))
    .map((disclosure) => disclosure.serverKeyFingerprintHex);
}

function describeEnvironments(environmentIds: readonly EnvironmentId[]): string {
  return `${environmentIds.length === 1 ? "environment" : "environments"} ${environmentIds.map(displayText).join(", ")}`;
}

function describeServerDisclosure(projectId: ProjectId, disclosure: ServerDisclosure): string {
  return `project ${displayText(projectId)} is disclosed to the server (CRYPTO_SPEC §9): server key ${disclosure.serverKeyFingerprintHex} can decrypt the values of ${describeEnvironments(disclosure.environmentIds)}`;
}

export function formatServerDisclosureRow(disclosure: ServerDisclosure): string {
  return `${disclosure.serverKeyFingerprintHex}\tscope=${disclosure.environmentIds.map(displayText).join(", ")}\tlease-policy=${countNoun(disclosure.leasePolicyCount, "element")}\tgranted at seq=${disclosure.grantSeq}`;
}

export const noteServerDisclosure = Effect.fn("server-disclosure.noteServerDisclosure")(function* (
  verified: VerifiedProject,
): Effect.fn.Return<void, never, CliIo> {
  for (const disclosure of serverDisclosures(verified)) {
    yield* logNote(describeServerDisclosure(verified.projectId, disclosure));
  }
});
