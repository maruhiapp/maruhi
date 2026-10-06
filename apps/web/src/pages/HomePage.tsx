// Server component (baked into the RSC payload at build time).
//
// `my.maruhi.app/` is the top of the product origin (TCB). The LP and
// docs moved to apex `maruhi.app` (apps/site — Blume), so this page
// carries only minimal guidance (logo + a funnel to the dashboard + a
// link to the product site) (DP2 ruling F — docs/notes/web-design-pass.md
// §4). The e2e checks drive `to-dashboard` for SPA navigation and MPA
// degradation.
import { ResumeToDashboard } from "../dashboard/ResumeToDashboard.tsx";
import { spaPaths } from "../dashboard/routes.ts";

export function HomePage() {
  return (
    <main>
      {/* Returns to /dashboard only when the sign-in round-trip marker is present (ruling BU).
          A landing without the marker calls no API */}
      <ResumeToDashboard />
      {/* The brand mark is a bespoke SVG (DP1). The emoji ㊙ is limited to text contexts (CLI / README) */}
      <h1 data-testid="home-heading">
        <img src="/logo.svg" alt="" width="40" height="40" /> maruhi
      </h1>
      <p>
        <a href={spaPaths.dashboard()} data-testid="to-dashboard">
          Open the dashboard
        </a>{" "}
        — your projects' metadata (sign-in required).
      </p>
      <p>
        Docs, installation, and the product overview live at{" "}
        <a href="https://maruhi.app">maruhi.app</a>. Everything else happens in the CLI.
      </p>
    </main>
  );
}
