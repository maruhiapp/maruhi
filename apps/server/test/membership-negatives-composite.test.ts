// Server-side verification (CRYPTO_SPEC §6.4 = verifyChain re-run) —
// rejection tests for the authorization negative vectors that go
// through the composite endpoints (create_environment / rotate_epoch /
// delete_environment).
// Negatives via generic append live in
// membership-negatives-append.test.ts.
// The shared fixture and vector-replay helpers are in
// support/membership-scenario.ts (for the split's motivation see the
// top of the scenario module).

import { describe, expect, it } from "vitest";

import { toWireEntry, vectorAuthzNegatives } from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  registerMembershipScenario,
  replayNegativePrefix,
  submitComposite,
  submitDeletion,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

// A create_environment / rotate_epoch negative goes through the
// composite endpoint, where the server's judgment order (§12-3 /
// §12-4) can act before the consensus rules (verifyChain). The
// vector's expected_reason (a consensus-rule reason code) is pinned
// by the crypto layer's 4-runtime tests; here the expectation on the
// server's acceptance surface (status + kind) is pinned:
// - insufficient role: the DO's requireRole precedes verifyChain (403
//   insufficient-role)
// - rotate on an unknown environment: the absent data row precedes
//   (404 EnvironmentNotFound — the row is created atomically with the
//   chain, so the semantics match unknown-environment)
// - a dek_commitment_hex format violation: api-schema's hex Schema
//   precedes (400)
interface CompositeExpectation {
  readonly status: number;
  readonly reason?: string;
}

const compositeExpectations: Readonly<Record<string, CompositeExpectation>> = {
  // A removed member gets §11-2's existence hiding (the same 404 as
  // the dedicated test in membership-authz.test.ts)
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
  // Environment scope (2026-09-14 ES — CRYPTO_SPEC §6.2's
  // environment-targeted ops): since K3 (2026-09-15) the acceptance
  // surface returns 403 insufficient-scope first (AUTH_SPEC §12-3's
  // judgment order — role 403 → [the parent-head CAS 409 — these vectors
  // are signed over the current head, so it passes] → scope 403 →
  // existence 404 → semantics 422. Design record es-design.md §9 K3-C /
  // K3-G; AUTH_SPEC §12-4 since 2026-10-07). The consensus
  // rule environment-out-of-scope (422) is pinned as defense in depth
  // by the crypto layer's 4-runtime tests. For a listed principal an
  // "uncreated environment" is also out of scope, so 403 precedes 404
  // (an `all` principal still gets 404 —
  // data-environment-rotation.test.ts). The vector names
  // `*-precedes-out-of-scope` refer to the **consensus-rule layer's**
  // (verifyChain's) check order, which is the reverse of the
  // acceptance surface's (scope 403 first). The vectors are untouched
  // in K3 (regeneration is crypto's scope), so the names stay as-is
  "authz-create-env-listed-admin": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-listed-member": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-unknown-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-rotate-out-of-scope-precedes-epoch": { status: 403, reason: "insufficient-scope" },
  // create's scope judgment (403) precedes verifyChain
  // (duplicate-environment 422): the negative's actor is a listed
  // admin, so it falls at scope
  "authz-create-env-duplicate-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  // Device keys (2026-09-19 DK — since K3 the acceptance surface
  // judges by the device's effective permissions. Design record
  // dk-design.md §8 K3-1 stage 2: the effective (role, scope) of the
  // device named by the bundled entry's actor FP returns a 403 before
  // verifyChain. The consensus rules `insufficient-role` /
  // `environment-out-of-scope` (422) are pinned by the crypto layer's
  // 4-runtime tests). A rotate by a reader-cap device = effective role
  // reader; a rotate / create by a listed-cap device = outside the
  // effective scope
  "authz-rotate-by-reader-cap-device": { status: 403, reason: "insufficient-role" },
  "authz-rotate-out-of-device-scope": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-by-listed-device": { status: 403, reason: "insufficient-scope" },
  // Environment deletion on the chain (2026-10-07 — CRYPTO_SPEC §6.2 /
  // AUTH_SPEC §12-4). Signed over the current head, a rotate of a
  // deleted environment passes the CAS and meets the tombstoned row (404,
  // the same as any rotate of a deleted environment); for a listed
  // principal the deletion pruned the id from its scope, so scope 403
  // stands first. Signed over a pre-deletion head it is a 409
  // (scope-authz.test.ts). Reusing a deleted id is the
  // consensus rule's duplicate-environment
  "authz-rotate-deleted-environment": { status: 404 },
  "authz-rotate-deleted-precedes-out-of-scope": { status: 403, reason: "insufficient-scope" },
  "authz-create-env-reuse-deleted-id": { status: 422, reason: "duplicate-environment" },
  // The deletion composite's acceptance surface (§12-4's judgment order:
  // role 403 → the URL / entry match → CAS 409 → scope 403 → verifyChain
  // 422). A wrong role stops at 403; an environment outside a listed
  // admin's scope (unknown, out of scope, or pruned by the deletion) stops
  // at scope 403; existence and deletion themselves are the consensus
  // rules' 422 — never a 404. An empty id fails the wire schema (400)
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

/** The routable path of a deletion negative (an empty id is refused by the payload schema, not the router). */
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
      // The prerequisite chain (device-derived chains included — replayable via generic append since K3)
      const { members, head } = await replayNegativePrefix(negative);
      // Re-sign at the real head (absorbing the seq / prev shift from
      // the inserted boundary checkpoints. The op / payload / actor
      // blocks stay the vector negative's)
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
