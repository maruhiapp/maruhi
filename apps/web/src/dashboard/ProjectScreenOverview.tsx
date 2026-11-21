"use client";

import { VStack } from "@astryxdesign/core/Layout";
import type { ReactNode } from "react";

import { apiPaths } from "./endpoints.ts";
import { ChainView } from "./OverviewChain.tsx";
import { EnvironmentsSection } from "./OverviewEnvironments.tsx";
import { FailureNotice, LoadingRow } from "./resource-states.tsx";
import { SECTION_GAP } from "./sections.tsx";
import type { ChainSnapshot } from "./types.ts";
import { useApiResource } from "./use-api-resource.ts";

export function OverviewTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<ChainSnapshot>(apiPaths.chain(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading chain" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <VStack gap={SECTION_GAP}>
      <ChainView snapshot={state.value} />
      <EnvironmentsSection projectId={projectId} />
    </VStack>
  );
}
