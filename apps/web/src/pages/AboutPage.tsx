// Server component. "About this deployment" — the build time and a
// client-side operation check.
//
// Home of the e2e mechanism-verification hooks (originating in spike A)
// (DP2 ruling F — docs/notes/web-design-pass.md §4):
//   - built-at: build-time RSC (a value the server component embedded
//     appears in the static shell)
//   - counter-button: hydration of the "use client" island and StyleX
//     (xstyle) application under the strict CSP
//   - about-heading / to-home: verification targets for SPA navigation
//     (Navigation API) and MPA degradation
// It doubles as a diagnostics page showing self-host operators "what is
// deployed" and "does the client bundle run under the CSP".
import { CounterCard } from "../components/CounterCard.tsx";
import { spaPaths } from "../dashboard/routes.ts";

const builtAt = new Date().toISOString();

export function AboutPage() {
  return (
    <main>
      <h1 data-testid="about-heading">about maruhi</h1>
      <p>
        This is a maruhi server with its dashboard, which shows metadata and can revoke credentials.
        Values and keys never reach this origin in plaintext; everything else happens in the CLI.
        Source and license:{" "}
        <a href="https://github.com/maruhiapp/maruhi">github.com/maruhiapp/maruhi</a>.
      </p>
      <h2>Diagnostics</h2>
      <p data-testid="built-at">server-rendered at build time: {builtAt}</p>
      <p>Client script check (the button should count when clicked):</p>
      <CounterCard />
      <p>
        <a href={spaPaths.home()} data-testid="to-home">
          back to home
        </a>
      </p>
    </main>
  );
}
