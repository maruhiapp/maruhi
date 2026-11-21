import { describe, expect, it } from "vite-plus/test";

import { toWireEntry, vectorAuthzNegatives } from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  registerMembershipScenario,
  replayNegativePrefix,
  submitComposite,
  submitDeletion,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

interface CompositeExpectation {
  readonly status: number;
  readonly reason?: string;
}

const compositeExpectations: Readonly<Record<string, CompositeExpectation>> = {
  "authz-nonmember-actor": { status: 404 },
  "authz-reader-rotate-epoch": { status: 403, reason: "insufficient-role" },
  "authz-rotate-role-precedes-unknown": { status: 403, reason: "insufficient-role" },
  "authz-create-env-reader": { status: 403, reason: "insufficient-role" },
  "authz-create-env-role-precedes-duplicate": { status: 403, reason: "insufficient-role" },
  "authz-rotate-unknown-environment": { status: 404 },
  "authz-rotate-unknown-precedes-epoch": { status: 404 },
  "authz-create-env-duplicate": { status: 422, reason: "duplicate-environment" },
  "authz-epoch-rollback": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-duplicate": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-jump": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-first-jump": { status: 422, reason: "epoch-out-of-sequence" },
  "create-env-commitment-uppercase-hex": { status: 400 },
  "create-env-commitment-bad-length": { status: 400 },
  "rotate-commitment-uppercase-hex": { status: 400 },
  "create-env-commitment-format-precedes-role": { status: 400 },
  "authz-field-too-long": { status: 422, reason: "invalid-payload" },
  "authz-actor-key-mismatch": { status: 422, reason: "actor-key-mismatch" },
  "authz-create-env-listed-admin": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-listed-member": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-unknown-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-out-of-scope-precedes-epoch": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-duplicate-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-by-reader-cap-device": { status: 403, reason: "insufficient-role" },
  "authz-rotate-out-of-device-scope": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-by-listed-device": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-deleted-environment": { status: 404 },
  "authz-rotate-deleted-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-reuse-deleted-id": { status: 422, reason: "duplicate-environment" },
  "authz-delete-env-member": { status: 403, reason: "insufficient-role" },
  "authz-delete-env-reader": { status: 403, reason: "insufficient-role" },
  "authz-delete-env-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-delete-env-before-create": { status: 422, reason: "unknown-environment" },
  "authz-delete-env-unknown": { status: 422, reason: "unknown-environment" },
  "authz-delete-env-role-precedes-unknown": { status: 403, reason: "insufficient-role" },
  "authz-delete-env-unknown-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "delete-env-id-empty": { status: 400 },
  "delete-env-format-precedes-role": { status: 400 },
  "authz-delete-env-twice": { status: 422, reason: "environment-deleted" },
  "authz-delete-env-deleted-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-delete-env-role-precedes-deleted": { status: 403, reason: "insufficient-role" },
};

const DELETION_URL_FALLBACK = "env-prod-0001";

describe("server-side verification (§6.4) — authorization negative vectors (via composite)", () => {
  for (const negative of vectorAuthzNegatives) {
    const op = negative.entry.op;
    if (op !== "create_environment" && op !== "rotate_epoch" && op !== "delete_environment") {
      continue;
    }
    const expectation = compositeExpectations[negative.name];
    if (expectation === undefined) {
      throw new Error(`missing composite expectation for ${negative.name}`);
    }
    it(`rejects ${negative.name} via the composite endpoint with ${expectation.status}${expectation.reason === undefined ? "" : ` (${expectation.reason})`}`, async () => {
      const { members, head } = await replayNegativePrefix(negative);
      const { entry } = await resignEntryAt(
        toWireEntry(negative.entry),
        head.seq + 1,
        head.hashHex,
      );
      if (entry.op === "delete_environment") {
        const response = await submitDeletion(
          entry,
          entry.payload.environmentId === "" ? DELETION_URL_FALLBACK : undefined,
        );
        expect(response.status).toBe(expectation.status);
        if (expectation.reason !== undefined) {
          const body = (await response.json()) as { reason: string };
          expect(body.reason).toBe(expectation.reason);
        }
        return;
      }
      if (entry.op !== "create_environment" && entry.op !== "rotate_epoch") {
        throw new Error("unexpected op");
      }
      const response = await submitComposite(entry, members);
      expect(response.status).toBe(expectation.status);
      if (expectation.reason !== undefined) {
        const body = (await response.json()) as { reason: string };
        expect(body.reason).toBe(expectation.reason);
      }
    });
  }
});
