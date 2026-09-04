"use client";

// S6 の本人軸: GET /auth/audit/events(AUDIT_SPEC §3.1 / §6 — 本人のみ)。
// D1 経路のため seq は常に応答に載らない(§7)— AuditEventList の応答適応で
// 列は自然に出ない。
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
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
      <AuditEventList
        fetchPage={fetchPage}
        emptyTitle="No account events"
        testId="audit-list-self"
      />
    </DashboardShell>
  );
}
