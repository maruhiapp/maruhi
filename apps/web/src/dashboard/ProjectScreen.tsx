"use client";

import { Banner } from "@astryxdesign/core/Banner";
import { VStack } from "@astryxdesign/core/Layout";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { useRouteParams } from "@funstack/router";
import * as stylex from "@stylexjs/stylex";
import { type ReactNode, useState } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { HexText } from "./display.tsx";
import { isProjectId, shortId } from "./ids.ts";
import { InvitesTab } from "./InvitesTab.tsx";
import { AuditTab } from "./ProjectScreenAudit.tsx";
import { OverviewTab } from "./ProjectScreenOverview.tsx";
import { RotationTab } from "./ProjectScreenRotation.tsx";
import { projectRoute, spaPaths } from "./routes.ts";

const PROJECT_TABS = ["overview", "audit", "rotation", "invites"] as const;
type ProjectTab = (typeof PROJECT_TABS)[number];

const PROJECT_TAB_PANELS: Record<ProjectTab, string> = {
  overview: "project-panel-overview",
  audit: "project-panel-audit",
  rotation: "project-panel-rotation",
  invites: "project-panel-invites",
};

const PROJECT_TAB_IDS: Record<ProjectTab, string> = {
  overview: "project-tab-overview",
  audit: "project-tab-audit",
  rotation: "project-tab-rotation",
  invites: "project-tab-invites",
};

const panelStyles = stylex.create({
  hidden: { display: "none" },
});

function isProjectTab(value: string): value is ProjectTab {
  return (PROJECT_TABS as ReadonlyArray<string>).includes(value);
}

function ProjectTabBody({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  if (tab === "audit") return <AuditTab projectId={projectId} />;
  if (tab === "rotation") return <RotationTab projectId={projectId} />;
  if (tab === "invites") return <InvitesTab key={projectId} projectId={projectId} />;
  return <OverviewTab projectId={projectId} />;
}

function ProjectTabList({
  tab,
  onChange,
}: {
  tab: ProjectTab;
  onChange: (tab: ProjectTab) => void;
}): ReactNode {
  return (
    <TabList
      value={tab}
      onChange={(value) => {
        if (isProjectTab(value)) onChange(value);
      }}
      size="md"
      role="tablist"
      aria-label="Project"
      hasDivider
    >
      <Tab
        id={PROJECT_TAB_IDS.overview}
        value="overview"
        label="Overview"
        panelId={PROJECT_TAB_PANELS.overview}
      />
      <Tab
        id={PROJECT_TAB_IDS.audit}
        value="audit"
        label="Audit"
        panelId={PROJECT_TAB_PANELS.audit}
      />
      <Tab
        id={PROJECT_TAB_IDS.rotation}
        value="rotation"
        label="Rotation flags"
        panelId={PROJECT_TAB_PANELS.rotation}
      />
      <Tab
        id={PROJECT_TAB_IDS.invites}
        value="invites"
        label="Invites"
        panelId={PROJECT_TAB_PANELS.invites}
      />
    </TabList>
  );
}

function ProjectTabPanels({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  return PROJECT_TABS.map((id) => (
    <VStack
      key={id}
      id={PROJECT_TAB_PANELS[id]}
      role="tabpanel"
      aria-labelledby={PROJECT_TAB_IDS[id]}
      hidden={tab !== id}
      xstyle={tab === id ? undefined : panelStyles.hidden}
    >
      {tab === id ? <ProjectTabBody tab={id} projectId={projectId} /> : null}
    </VStack>
  ));
}

function ProjectPage({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState<ProjectTab>("overview");
  const label = shortId(projectId);
  return (
    <DashboardShell
      destination="projects"
      project={{ id: projectId, label }}
      backLink={{ label: "Projects", href: spaPaths.dashboard() }}
      title={`Project ${label}`}
      intro={<HexText testId="project-id">{projectId}</HexText>}
      tabs={<ProjectTabList tab={tab} onChange={setTab} />}
    >
      <ProjectTabPanels tab={tab} projectId={projectId} />
    </DashboardShell>
  );
}

function InvalidProjectPage({ projectId }: { projectId: string }): ReactNode {
  return (
    <DashboardShell
      destination="projects"
      backLink={{ label: "Projects", href: spaPaths.dashboard() }}
      title="Project"
      intro={<HexText testId="project-id">{projectId}</HexText>}
    >
      <Banner
        role="alert"
        status="warning"
        title="Not a project ID"
        description="A project ID is 64 lowercase hex characters. Nothing was requested from the server."
      />
    </DashboardShell>
  );
}

export function ProjectScreen(): ReactNode {
  const { projectId } = useRouteParams(projectRoute);
  return isProjectId(projectId) ? (
    <ProjectPage projectId={projectId} />
  ) : (
    <InvalidProjectPage projectId={projectId} />
  );
}
