// Handlers for the DEK-wrap store / distribute / repair API
// (AUTH_SPEC §12-6).
//
// Recipient validation (non-member recipients, key mismatch, missing,
// duplicate, overwrite) is performed DO-side (programs-dek.ts +
// dek-wraps.ts) against the current member set derived from ChainState.
// The shared path is callProjectData in data-http.ts. The set of
// returnable errors is derived from each endpoint's contract
// declaration (api-schema) — no hand-written enumeration.

import { maruhiApi } from "@maruhi/api-schema";
import type { KeyFingerprintHex, UserId } from "@maruhi/core";
import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData, noContent } from "../data/data-http.ts";
import type { RecipientDekValue } from "../data/data-plane.ts";

/** The recipient position of a wrap: a member's user id for class member, the server key FP for class server (wire-boundary mint — AUTH_SPEC §12-6 / CRYPTO_SPEC §9). */
const recipientOf = (d: {
  readonly recipientClass: "member" | "server";
  readonly recipientUserId: string;
}): UserId | KeyFingerprintHex =>
  d.recipientClass === "server"
    ? decodeKeyFingerprintHex(d.recipientUserId)
    : decodeUserId(d.recipientUserId);

export const deksLive = HttpApiBuilder.group(maruhiApi, "deks", (handlers) =>
  handlers
    .handle("register", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "write",
        invoke: (stub, actor) =>
          stub.registerDekWraps(
            actor,
            params.environmentId,
            payload.deks.map((d) => ({ ...d, recipientUserId: recipientOf(d) })),
          ),
      }).pipe(Effect.as(noContent)),
    )
    .handle("listMine", ({ params, endpoint }) =>
      callProjectData<readonly RecipientDekValue[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listMyDekWraps(actor, params.environmentId),
      }).pipe(Effect.map((deks) => ({ deks }))),
    )
    .handle("remove", ({ params, payload, endpoint }) =>
      // Wrap deletion (the §12-6 repair path) is the same level as
      // environment deletion: admin scope + chain role admin or above
      // (§12-3)
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) =>
          stub.deleteDekWraps(
            actor,
            params.environmentId,
            payload.wraps.map((w) => ({ ...w, recipientUserId: recipientOf(w) })),
          ),
      }).pipe(Effect.as(noContent)),
    ),
);
