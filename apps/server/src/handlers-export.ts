// Handlers for the project export API (AUTH_SPEC §11-6 — PF3).
//
// - page: token scope admin × chain role owner (the role floor, the
//   window, the audit row and the page are the DO's — programs-export.ts).
//   A stateless read apart from the first page's audit row; session
//   principals are refused (outside §5's allowlist)
// - identities: the same authorization (the DO answers the current
//   members' ids under the owner floor); the join with D1's
//   linked_identities happens here. A member without a linked identity
//   on this deployment is reported as unlinked, never invented

import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData } from "./data-http.ts";
import { IdentityRepo } from "./db.package/index.ts";
import type { ExportMembersValue } from "./programs-export.ts";
import type { ExportPageValue } from "./programs-export.ts";

export const exportLive = HttpApiBuilder.group(maruhiApi, "export", (handlers) =>
  handlers
    .handle("page", ({ params, query, endpoint }) =>
      callProjectData<ExportPageValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.exportPage(actor, query.cursor ?? null),
      }).pipe(
        Effect.map((page) => ({
          lines: page.lines,
          ...(page.next === null ? {} : { next: page.next }),
          head: page.head,
        })),
      ),
    )
    .handle("identities", ({ params, endpoint }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const { members, chainHeadSeq, chainHeadHashHex } =
          yield* callProjectData<ExportMembersValue>()({
            endpoint,
            projectId: params.projectId,
            permission: "admin",
            invoke: (stub, actor) => stub.exportMembers(actor),
          });
        const identities = yield* IdentityRepo;
        const linked = yield* identities.identitiesOf(members);
        const known = new Set(linked.map((identity) => identity.userId));
        return {
          exportedBy: principal.userId,
          chainHeadSeq,
          chainHeadHashHex,
          identities: linked.map((identity) => ({
            userId: identity.userId,
            provider: identity.provider,
            providerUserId: identity.providerUserId,
            ...(identity.providerLogin === null ? {} : { providerLogin: identity.providerLogin }),
          })),
          unlinked: members.filter((userId) => !known.has(userId)),
        };
      }),
    ),
);
