"use client";

// S5 project overview / S6 audit (project and invites axes) / S7
// rotation-needed flags (design document §3). Read-only; every
// display is server-reported (§4).
//
// - S5: the chain fetch (§11) is folded for display (chain-view.ts —
//   not verification).
//   The environment listing (§12-4) + a pull of the selected
//   environment's metadata only (§12-7 — values and DEKs structurally
//   never appear in a response; no var.read is recorded either)
// - S6: AuditEventList (ruling BQ). The invites axis is limited to
//   chain role admin, and a 403 is displayed as-is with the role
//   wording (no role check that hides the tab in advance)
// - S7: no dismiss here (ADR-0018 amendment 2's boundary principle —
//   erasing a warning). Only static guidance pointing at the CLI
//   `maruhi rotation dismiss`
import { Banner } from "@astryxdesign/core/Banner";
import { VStack } from "@astryxdesign/core/Layout";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { useRouteParams } from "@funstack/router";
import * as stylex from "@stylexjs/stylex";
import { type ReactNode, useState } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { isProjectId, shortId } from "./ids.ts";
import { InvitesTab } from "./InvitesTab.tsx";
import { AuditTab } from "./ProjectScreenAudit.tsx";
import { OverviewTab } from "./ProjectScreenOverview.tsx";
import { RotationTab } from "./ProjectScreenRotation.tsx";
import { projectRoute, spaPaths } from "./routes.ts";
import { HexText } from "./shared.tsx";

// ---------------------------------------------------------------------------
// The screen body
// ---------------------------------------------------------------------------

const PROJECT_TABS = ["overview", "audit", "rotation", "invites"] as const;
type ProjectTab = (typeof PROJECT_TABS)[number];

const PROJECT_TAB_PANELS: Record<ProjectTab, string> = {
  overview: "project-panel-overview",
  audit: "project-panel-audit",
  rotation: "project-panel-rotation",
  invites: "project-panel-invites",
};

// A tabpanel takes its name from the corresponding tab (APG). Astryx
// does not auto-assign ids to Tabs, so an explicit id is placed on
// the tab side and referenced via aria-labelledby
const PROJECT_TAB_IDS: Record<ProjectTab, string> = {
  overview: "project-tab-overview",
  audit: "project-tab-audit",
  rotation: "project-tab-rotation",
  invites: "project-tab-invites",
};

// The `hidden` attribute alone does not hide: VStack's own
// `display:flex` (in `@layer astryx-base`) beats the Astryx reset's
// `:where([hidden]){display:none}` (in `@layer reset`). Between StyleX
// rules the later one wins, so it works (ADR-0013 ②)
const panelStyles = stylex.create({
  hidden: { display: "none" },
});

function isProjectTab(value: string): value is ProjectTab {
  return (PROJECT_TABS as ReadonlyArray<string>).includes(value);
}

function ProjectTabBody({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  if (tab === "audit") return <AuditTab projectId={projectId} />;
  if (tab === "rotation") return <RotationTab projectId={projectId} />;
  // S8 (ruling CP): the project axis's management surface is a tab.
  // Keyed by projectId so a revocation state cannot carry over to
  // another project
  if (tab === "invites") return <InvitesTab key={projectId} projectId={projectId} />;
  return <OverviewTab projectId={projectId} />;
}

/** The TabList for the header slot (it switches panels within one screen, so WAI-ARIA tabs, not a nav landmark). */
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

/** The project screen for a well-formed ID (the `detail-page` template's shape: back link → h1 → ID → tabs). */
function ProjectPage({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState<ProjectTab>("overview");
  // The heading and the sidebar's child item use the shortened form
  // (first and last 6 digits). The full text is shown right under the
  // heading in a HexText
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

/** A path that fails the ID's format (the server is not asked). */
function InvalidProjectPage({ projectId }: { projectId: string }): ReactNode {
  return (
    <DashboardShell
      destination="projects"
      backLink={{ label: "Projects", href: spaPaths.dashboard() }}
      title="Project"
      intro={<HexText testId="project-id">{projectId}</HexText>}
    >
      <Banner
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
