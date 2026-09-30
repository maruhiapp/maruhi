// Exports a remote D1 database to a local SQL file via `cf` — the polling
// equivalent of the retired `wrangler d1 export <name> --remote --output
// <file>` (operations runbook — docs/notes/hosted-ops.md §2-G and
// .github/workflows/ops-backup.yml).
//
// `cf d1 export` is a raw API call: one POST returns either the finished
// export (status "complete" with result.signed_url) or a continuation
// (status "active" with at_bookmark, to be re-issued as --current-bookmark).
// The API cancels an unpolluted export, so this script owns the poll loop and
// the signed-URL download, matching wrangler's exportRemotely semantics.
//
// Usage (from apps/server):
//   bun scripts/d1-export.ts [--mode hosted] --output <file.sql>
// Requires CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID (or a `cf auth`
// profile). Remote-only by definition — nothing is written to local state.

import { spawnSync } from "node:child_process";

import { cfD1Binding } from "./cf-config.ts";

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

// cf prints the API response as JSON (its default --output format). The shape
// mirrors wrangler's exportRemotely poll protocol: success/status/at_bookmark
// at the top level and result.signed_url on completion.
interface ExportResponse {
  success?: boolean;
  status?: string;
  error?: string;
  errors?: ReadonlyArray<{ message?: string } | string>;
  messages?: readonly string[];
  at_bookmark?: string;
  result?: { signed_url?: string; status?: string; at_bookmark?: string };
}

function parseExport(stdout: string, stderr: string): ExportResponse {
  try {
    return JSON.parse(stdout) as ExportResponse;
  } catch {
    throw new Error(
      `cf d1 export did not return JSON\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`,
    );
  }
}

const MAX_POLLS = 600; // ~10 minutes at 1s — same order as wrangler's export
let bookmark: string | undefined;
let signedUrl: string | undefined;
for (let poll = 0; poll < MAX_POLLS; poll++) {
  const run = spawnSync(
    "cf",
    [
      "d1",
      "export",
      db.id,
      "--output-format",
      "polling",
      ...(bookmark === undefined ? [] : ["--current-bookmark", bookmark]),
    ],
    { cwd: new URL("..", import.meta.url).pathname, encoding: "utf8" },
  );
  if (run.error !== undefined) throw run.error;
  const response = parseExport(run.stdout ?? "", run.stderr ?? "");
  const status = response.status ?? response.result?.status;
  const url = response.result?.signed_url;
  const nextBookmark = response.at_bookmark ?? response.result?.at_bookmark;
  if (url !== undefined || status === "complete") {
    if (url === undefined) {
      throw new Error(`cf d1 export completed without a signed_url: ${run.stdout}`);
    }
    signedUrl = url;
    break;
  }
  if (status === "error" || response.success === false) {
    const detail =
      response.error ??
      response.errors?.map((e) => (typeof e === "string" ? e : e.message)).join("; ") ??
      run.stdout;
    throw new Error(`cf d1 export failed: ${String(detail)}`);
  }
  if (nextBookmark === undefined) {
    throw new Error(`cf d1 export returned neither a bookmark nor a result: ${run.stdout}`);
  }
  bookmark = nextBookmark;
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
if (signedUrl === undefined) {
  throw new Error(`cf d1 export did not complete within ${MAX_POLLS} polls`);
}

const download = await fetch(signedUrl);
if (!download.ok) {
  throw new Error(
    `signed_url download failed with HTTP ${download.status} (the URL is valid for one hour)`,
  );
}
await Bun.write(output, await download.text());
console.log(`d1-export: wrote ${output}`);
