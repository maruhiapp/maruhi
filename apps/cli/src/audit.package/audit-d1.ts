import { Effect } from "effect";

import type { CliServices, ProjectContextBase, SessionContext } from "../context.ts";
import type { CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { d1MirrorTrustOf, mirrorWarnings, type WireAuditEvent } from "./audit-mirror.ts";
import {
  type AuditPageOptions,
  continuationHint,
  formatEventLine,
  pageQueryOf,
} from "./audit-page.ts";

interface D1AuditRenderResult {
  readonly events: readonly WireAuditEvent[];
  readonly integrityFailures: number;
}

const fetchAndRenderD1Events = Effect.fn("audit-d1.fetchAndRenderD1Events")(function* <E>(input: {
  readonly request: Effect.Effect<{ readonly events: readonly WireAuditEvent[] }, E>;
  readonly page: AuditPageOptions;
  readonly emptyMessage: string;
  readonly command: string;
}): Effect.fn.Return<D1AuditRenderResult, CliError, CliIo> {
  const io = yield* CliIo;
  const events = yield* input.request.pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.events),
  );
  if (events.length === 0) {
    yield* io.log(input.emptyMessage);
    return { events, integrityFailures: 0 };
  }
  let integrityFailures = 0;
  for (const event of events) {
    const trust = d1MirrorTrustOf(event);
    const warnings = mirrorWarnings(event, trust);
    yield* io.log(formatEventLine(event, null, trust));
    integrityFailures += warnings.length;
    for (const warning of warnings) {
      yield* logWarning(warning);
    }
  }
  const hint = continuationHint(events, input.page.limit, input.command);
  if (hint !== null) {
    yield* io.log(hint);
  }
  return { events, integrityFailures };
});

export function auditInvitesOp(
  context: ProjectContextBase,
  page: AuditPageOptions,
): Effect.Effect<number, CliError, CliServices> {
  return fetchAndRenderD1Events({
    request: context.client.audit.invites({
      params: { projectId: context.projectId },
      query: pageQueryOf(page),
    }),
    page,
    emptyMessage: "No invite audit events",
    command: "maruhi audit invites",
  }).pipe(Effect.map((result) => (result.integrityFailures > 0 ? 1 : 0)));
}

export const auditSelfOp = Effect.fn("audit-d1.auditSelfOp")(function* (
  context: SessionContext,
  page: AuditPageOptions,
): Effect.fn.Return<number, CliError, CliServices> {
  const rendered = yield* fetchAndRenderD1Events({
    request: context.client.audit.self({ query: pageQueryOf(page) }),
    page,
    emptyMessage: "No account audit events",
    command: "maruhi audit self",
  });
  const events = rendered.events;
  if (events.some((event) => event.event === "auth.recovery_blob_fetched")) {
    yield* logNote(
      "auth.recovery_blob_fetched (a fetch of the sealed reserve key) is present. If you do not recognize a fetch, reissue your recovery code (`maruhi key recovery`) and revoke your tokens and sessions",
    );
  }
  return rendered.integrityFailures > 0 ? 1 : 0;
});
