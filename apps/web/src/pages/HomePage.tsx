import { ResumeToDashboard } from "../dashboard/ResumeToDashboard.tsx";
import { spaPaths } from "../dashboard/routes.ts";

export function HomePage() {
  return (
    <main>
      {}
      <ResumeToDashboard />
      {}
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
