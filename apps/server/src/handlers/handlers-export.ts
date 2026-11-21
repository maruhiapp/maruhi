import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData } from "../data.package/index.ts";
import { IdentityRepo } from "../db.package/index.ts";
import type { ExportMembersValue } from "../programs/programs-export.ts";
import type { ExportPageValue } from "../programs/programs-export.ts";

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
    .handle(
      "identities",
      Effect.fn("handlers-export.identities")(function* ({ params, endpoint }) {
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
