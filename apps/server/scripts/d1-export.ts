// Exports a remote D1 database to a local SQL file — the polling equivalent
// of the retired `wrangler d1 export <name> --remote --output <file>`
// (operations runbook — docs/notes/hosted-ops.md §2-G and
// .github/workflows/ops-backup.yml).
//
// The export endpoint is a poll protocol: one POST returns either the
// finished export (status "complete" with result.signed_url) or a
// continuation (status "active" with at_bookmark, to be re-sent as
// current_bookmark). The API cancels an export that is not polled, so this
// script owns the poll loop and the signed-URL download, matching wrangler's
// exportRemotely semantics. The requests go through d1-api.ts (cf no longer
// ships a `d1 export` command).
//
// Usage (from apps/server):
//   bun scripts/d1-export.ts [--mode hosted] --output <file.sql>
// Requires CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID. Remote-only by
// definition — nothing is written to local state.

import { cfD1Binding, redactUrls } from "./cf-config.ts";
import { d1ApiPost, pollErrorDetail } from "./d1-api.ts";

const args = process.argv.slice(2);
let mode: string | undefined;
let output: string | undefined;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--mode") mode = args[++i];
  else if (args[i] === "--output") output = args[++i];
}
if (output === undefined) {
  console.error("usage: bun scripts/d1-export.ts [--mode <mode>] --output <file>");
  process.exit(2);
}

const db = cfD1Binding(mode, "d1-export");

const MAX_POLLS = 600; // ~10 minutes at 1s — same order as wrangler's export
let bookmark: string | undefined;
let signedUrl: string | undefined;
for (let poll = 0; poll < MAX_POLLS; poll++) {
  const response = await d1ApiPost("d1-export", db.id, "export", {
    output_format: "polling",
    ...(bookmark === undefined ? {} : { current_bookmark: bookmark }),
  });
  const status = response.status ?? response.result?.status;
  const url = response.result?.signed_url;
  const nextBookmark = response.at_bookmark ?? response.result?.at_bookmark;
  if (url !== undefined || status === "complete") {
    if (url === undefined) {
      throw new Error(
        `D1 export completed without a signed_url: ${redactUrls(JSON.stringify(response))}`,
      );
    }
    signedUrl = url;
    break;
  }
  if (status === "error" || response.success === false) {
    throw new Error(`D1 export failed: ${pollErrorDetail(response, JSON.stringify(response))}`);
  }
  if (nextBookmark === undefined) {
    throw new Error(
      `D1 export returned neither a bookmark nor a result: ${redactUrls(JSON.stringify(response))}`,
    );
  }
  bookmark = nextBookmark;
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
if (signedUrl === undefined) {
  throw new Error(`D1 export did not complete within ${MAX_POLLS} polls`);
}

const download = await fetch(signedUrl);
if (!download.ok) {
  throw new Error(
    `signed_url download failed with HTTP ${download.status} (the URL is valid for one hour)`,
  );
}
await Bun.write(output, await download.text());
console.log(`d1-export: wrote ${output}`);
