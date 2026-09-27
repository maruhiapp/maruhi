"use client";

// The self axis: GET /auth/audit/events (AUDIT_SPEC §3.1 / §6 — self
// only).
// On the D1 path seq is never on the response (§7) — with
// AuditEventList's response adaptation the column naturally never
// appears.
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { SectionBlock } from "./shared.tsx";
import type { AuditEventsPage } from "./types.ts";

export function AccountAuditScreen(): ReactNode {
  const fetchPage = useCallback(
    (before: string | undefined) => apiGet<AuditEventsPage>(apiPaths.auditSelf(before)),
    [],
  );
  return (
    <DashboardShell
      destination="account"
      title="Account audit"
      intro={
        <Text as="p" type="supporting">
          Events about your own account (sign-ins, tokens, recovery), as reported by the server.
        </Text>
      }
    >
      <SectionBlock>
        <AuditEventList
          fetchPage={fetchPage}
          emptyTitle="No account events"
          testId="audit-list-self"
        />
      </SectionBlock>
    </DashboardShell>
  );
}
