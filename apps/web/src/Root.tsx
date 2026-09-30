// Static shell (build-time RSC). This is a server component and must not
// import client components (they would never hydrate).
import type React from "react";

import "./styles/global.css";

// The OG image requires an absolute URL (some scrapers do not resolve
// relative URLs). Because the static shell is fixed at build time, the
// serving origin arrives as a build-time environment variable, defaulting
// to the hosted origin (docs/notes/hosted-ops.md). Self-hosting can
// point `MARUHI_WEB_ORIGIN` at their own deploy URL
// (docs/SELF_HOSTING.md). Ruling D — docs/notes/web-design-pass.md §3
const publicOrigin = (process.env["MARUHI_WEB_ORIGIN"] ?? "https://my.maruhi.app").replace(
  /\/+$/,
  "",
);
const description =
  "Diskless, end-to-end encrypted secrets manager on Cloudflare. Self-hostable with a single cf deploy.";

export default function Root({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>maruhi</title>
        <meta name="description" content={description} />
        {/* Brand assets are all self-hosted (apps/web/public — TCB rule). The emoji ㊙ is not used */}
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32" />
        <link rel="icon" href="/favicon-192.png" type="image/png" sizes="192x192" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180" />
        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="maruhi" />
        <meta property="og:title" content="maruhi" />
        <meta property="og:description" content={description} />
        <meta property="og:image" content={`${publicOrigin}/og.png`} />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta
          property="og:image:alt"
          content="The maruhi mark (the kanji for 'secret' in a vermilion circle) next to the word maruhi"
        />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="maruhi" />
        <meta name="twitter:description" content={description} />
        <meta name="twitter:image" content={`${publicOrigin}/og.png`} />
      </head>
      <body>
        {/* The framework (funstack-static) mount-point constraint requires a raw div — do not componentize it. children must be the only child of the parent element */}
        <div id="app">{children}</div>
      </body>
    </html>
  );
}
