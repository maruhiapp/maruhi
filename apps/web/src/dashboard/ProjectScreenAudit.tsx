"use client";

// The S6 audit tab (the project / invites axes). See
// ProjectScreen.tsx for the screen's tab framework.

import { Code } from "@astryxdesign/core/Code";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { Text } from "@astryxdesign/core/Text";
import { ToggleButton, ToggleButtonGroup } from "@astryxdesign/core/ToggleButton";
import { type ReactNode, useMemo, useState } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { apiPaths } from "./endpoints.ts";
import { SectionBlock } from "./shared.tsx";
import type { AuditEventsPage } from "./types.ts";

// ---------------------------------------------------------------------------
// S6: audit tab (the project / invites axes. The self axis is
// /dashboard/account)
// ---------------------------------------------------------------------------

export function AuditTab({ projectId }: { projectId: string }): ReactNode {
  const [axis, setAxis] = useState("project");
  const fetchProjectEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(apiPaths.auditEvents(projectId, before)),
    [projectId],
  );
  const fetchInviteEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(apiPaths.auditInvites(projectId, before)),
    [projectId],
  );
  return (
    <VStack gap={4}>
      <HStack gap={3} justify="between" align="center" wrap="wrap">
        {/* The prescribed wording (AUDIT_SPEC §7 / design document §4-4): never hints at the existence or count of an invisible class */}
        <Text type="supporting" data-testid="audit-caption">
          Events visible to your role, as reported by the server.
        </Text>
        {/* Axis switching is a ToggleButtonGroup(single). SegmentedControl's unselected-label
            contrast is 4.26:1 (12px) in dark, short of AA (a11y audit — an upstream candidate) */}
        <ToggleButtonGroup
          label="Audit source"
          type="single"
          value={axis}
          onChange={(value: string | null) => {
            if (value !== null) setAxis(value);
          }}
          size="sm"
        >
          <ToggleButton value="project" label="Project events" />
          <ToggleButton value="invites" label="Invites" />
        </ToggleButtonGroup>
      </HStack>
      <SectionBlock>
        {axis === "project" ? (
          <AuditEventList
            fetchPage={fetchProjectEvents}
            emptyTitle="No events"
            testId="audit-list-project"
          />
        ) : (
          <AuditEventList
            fetchPage={fetchInviteEvents}
            emptyTitle="No invite events"
            testId="audit-list-invites"
          />
        )}
      </SectionBlock>
      <Text type="supporting">
        Completeness checks (gap detection, mirror reconciliation) are the CLI's job:{" "}
        <Code>maruhi audit verify</Code> / <Code>maruhi audit reconcile</Code>.
      </Text>
    </VStack>
  );
}
