"use client";

// The S5 overview tab (the chain — members, head, servers — the
// four-eyes approvals, and the environments + variable names
// sections). See ProjectScreen.tsx for the screen's tab framework.
// The sections live in OverviewChain.tsx (with OverviewMembers.tsx's
// members) and OverviewEnvironments.tsx.
import { VStack } from "@astryxdesign/core/Layout";
import type { ReactNode } from "react";

import { apiPaths } from "./endpoints.ts";
import { ChainView } from "./OverviewChain.tsx";
import { EnvironmentsSection } from "./OverviewEnvironments.tsx";
import { FailureNotice, LoadingRow } from "./resource-states.tsx";
import { SECTION_GAP } from "./sections.tsx";
import type { ChainSnapshot } from "./types.ts";
import { useApiResource } from "./use-api-resource.ts";

/**
 * The overview tab. The chain fetch (§11) doubles as the
 * project-existence check and is the leading resource; the
 * environment list is read only once the chain arrives — on a uniform
 * 404 / 403 this avoids the same Banner stacking per section (found
 * when revisiting DP3 ruling B). The one-round-trip serialization is
 * accepted.
 */
export function OverviewTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<ChainSnapshot>(apiPaths.chain(projectId));
  // Replacement form (ruling B-a) — VariablesSection /
  // EnvironmentsSection / RotationTab below are the same
  if (state.kind === "loading") return <LoadingRow label="Loading chain" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <VStack gap={SECTION_GAP}>
      <ChainView snapshot={state.value} />
      <EnvironmentsSection projectId={projectId} />
    </VStack>
  );
}
