// Imports a local SQL file into a remote D1 database — the file path of the
// retired `wrangler d1 execute <db> --remote --file <path>` (the dump import
// step of "Restoring a D1 export" in docs/SELF_HOSTING.md).
//
// The import endpoint takes raw actions (init / ingest / poll). This script
// owns the orchestration wrangler hid: md5-etag the file, `init` for a signed
// upload URL, PUT the bytes, `ingest`, then `poll` the bookmark to
// completion. The requests go through d1-api.ts (cf no longer ships a
// `d1 import` command).
//
// Usage (from apps/server):
//   bun scripts/d1-import.ts <database-id> --file <path.sql>
// Requires CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID. Remote-only — nothing
// is written to local state. Note: if the import fails partway, D1 rolls back
// to the pre-import bookmark, so a retry is safe (same guarantee wrangler's
// file import made).

import { readFileSync } from "node:fs";

import { redactUrls } from "./cf-config.ts";
import { d1ApiPost, pollErrorDetail, type D1PollResponse } from "./d1-api.ts";

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

function d1Import(body: Readonly<Record<string, unknown>>): Promise<D1PollResponse> {
  return d1ApiPost("d1-import", databaseId as string, "import", body);
}

const etag = new Bun.CryptoHasher("md5").update(await Bun.file(file).arrayBuffer()).digest("hex");

const init = await d1Import({ action: "init", etag });
const uploadRequired = init.upload_url !== undefined;

let response = init;
if (uploadRequired) {
  const put = await fetch(init.upload_url as string, {
    method: "PUT",
    headers: { "Content-length": String(Bun.file(file).size) },
    body: readFileSync(file),
  });
  if (put.status !== 200) {
    throw new Error(
      `SQL file upload failed with HTTP ${put.status}: ${redactUrls(await put.text())}`,
    );
  }
  const echoedEtag = put.headers.get("etag")?.replace(/^"|"$/g, "");
  if (echoedEtag !== etag) {
    throw new Error("SQL file upload etag mismatch — retry");
  }
  response = await d1Import({ action: "ingest", filename: init.filename, etag });
}

const MAX_POLLS = 600;
let polls = 0;
while (response.status !== "complete") {
  if (polls++ >= MAX_POLLS) {
    throw new Error(`D1 import did not complete within ${MAX_POLLS} polls`);
  }
  if (response.success === false || response.status === "error") {
    throw new Error(`D1 import failed: ${pollErrorDetail(response, JSON.stringify(response))}`);
  }
  const bookmark = response.at_bookmark ?? response.result?.at_bookmark;
  if (bookmark === undefined) {
    throw new Error("D1 import returned neither a bookmark nor a completed status");
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
  response = await d1Import({ action: "poll", current_bookmark: bookmark });
}

for (const line of response.messages ?? []) {
  console.log(line);
}
console.log(`d1-import: ${file} imported into ${databaseId}`);
