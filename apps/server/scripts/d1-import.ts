// Imports a local SQL file into a remote D1 database via `cf` — the file path
// of the retired `wrangler d1 execute <db> --remote --file <path>` (the dump
// import step of "Restoring a D1 export" in docs/SELF_HOSTING.md).
//
// `cf d1 import` exposes the import API as raw actions (init / ingest / poll).
// This script owns the orchestration wrangler hid: md5-etag the file, `init`
// for a signed upload URL, PUT the bytes, `ingest`, then `poll` the bookmark
// to completion.
//
// Usage (from apps/server):
//   bun scripts/d1-import.ts <database-id> --file <path.sql>
// Requires CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID (or a `cf auth`
// profile). Remote-only — nothing is written to local state. Note: if the
// import fails partway, D1 rolls back to the pre-import bookmark, so a retry
// is safe (same guarantee wrangler's file import made).

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const databaseId = args[0];
let file: string | undefined;
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--file") file = args[++i];
}
if (databaseId === undefined || file === undefined) {
  console.error("usage: bun scripts/d1-import.ts <database-id> --file <path.sql>");
  process.exit(2);
}

// cf prints API responses as JSON (its default output format). The import
// actions share the export poll envelope: success/status/at_bookmark with
// result holding the upload instructions or final stats.
interface ImportResponse {
  success?: boolean;
  status?: string;
  error?: string;
  errors?: ReadonlyArray<{ message?: string } | string>;
  messages?: readonly string[];
  at_bookmark?: string;
  upload_url?: string;
  filename?: string;
  result?: { signed_url?: string; at_bookmark?: string };
}

function cfImport(extra: string[]): ImportResponse {
  const run = spawnSync("cf", ["d1", "import", databaseId, ...extra], {
    cwd: new URL("..", import.meta.url).pathname,
    encoding: "utf8",
  });
  if (run.error !== undefined) throw run.error;
  try {
    return JSON.parse(run.stdout ?? "") as ImportResponse;
  } catch {
    throw new Error(
      `cf d1 import did not return JSON\n--- stdout ---\n${run.stdout}\n--- stderr ---\n${run.stderr}`,
    );
  }
}

function fail(response: ImportResponse, raw: string): never {
  const detail =
    response.error ??
    response.errors?.map((e) => (typeof e === "string" ? e : e.message)).join("; ") ??
    raw;
  throw new Error(`cf d1 import failed: ${String(detail)}`);
}

const etag = new Bun.CryptoHasher("md5").update(await Bun.file(file).arrayBuffer()).digest("hex");

const init = cfImport(["--action", "init", "--etag", etag]);
const uploadRequired = init.upload_url !== undefined;

let response = init;
if (uploadRequired) {
  const put = await fetch(init.upload_url as string, {
    method: "PUT",
    headers: { "Content-length": String(Bun.file(file).size) },
    body: readFileSync(file),
  });
  if (put.status !== 200) {
    throw new Error(`SQL file upload failed with HTTP ${put.status}: ${await put.text()}`);
  }
  const echoedEtag = put.headers.get("etag")?.replace(/^"|"$/g, "");
  if (echoedEtag !== etag) {
    throw new Error("SQL file upload etag mismatch — retry");
  }
  response = cfImport([
    "--action",
    "ingest",
    "--filename",
    init.filename as string,
    "--etag",
    etag,
  ]);
}

const MAX_POLLS = 600;
let polls = 0;
while (response.status !== "complete") {
  if (polls++ >= MAX_POLLS) {
    throw new Error(`cf d1 import did not complete within ${MAX_POLLS} polls`);
  }
  if (response.success === false || response.status === "error") {
    fail(response, "");
  }
  const bookmark = response.at_bookmark ?? response.result?.at_bookmark;
  if (bookmark === undefined) {
    throw new Error("cf d1 import returned neither a bookmark nor a completed status");
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
  response = cfImport(["--action", "poll", "--current-bookmark", bookmark]);
}

for (const line of response.messages ?? []) {
  console.log(line);
}
console.log(`d1-import: ${file} imported into ${databaseId}`);
