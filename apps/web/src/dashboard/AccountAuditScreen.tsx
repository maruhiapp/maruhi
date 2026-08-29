"use client";

// S6 の本人軸: GET /auth/audit/events(AUDIT_SPEC §3.1 / §6 — 本人のみ)。
// D1 経路のため seq は常に応答に載らない(§7)— AuditEventList の応答適応で
// 列は自然に出ない。
import { Card } from "@astryxdesign/core/Card";
import { Layout, LayoutContent, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Heading, Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { ServerReportedNote } from "./shared.tsx";
import type { AuditEventsPage } from "./types.ts";

export function AccountAuditScreen(): ReactNode {
  const fetchPage = useCallback(
    (before: string | undefined) =>
      apiGet<AuditEventsPage>(
        `/auth/audit/events${before === undefined ? "" : `?before=${encodeURIComponent(before)}`}`,
      ),
    [],
  );
  return (
    <Layout
      contentWidth={960}
      padding={6}
      content={
        <LayoutContent>
          <VStack gap={5}>
            <VStack gap={2}>
              <Link href="/dashboard">← Dashboard</Link>
              <Heading level={1}>Account audit</Heading>
              <Text type="supporting">
                Events about your own account (sign-ins, tokens, recovery), as reported by the
                server.
              </Text>
            </VStack>
            <Card padding={5}>
              <VStack gap={4}>
                <AuditEventList
                  fetchPage={fetchPage}
                  emptyTitle="No account events"
                  testId="audit-list-self"
                />
                <ServerReportedNote />
              </VStack>
            </Card>
          </VStack>
        </LayoutContent>
      }
    />
  );
}
