// `bun run preview`: serve the built site (dist/) locally under the
// production serving semantics (see scripts/wrangler-config.ts for why
// this is wrangler dev with a generated config, not `cf dev`).
import { spawn } from "node:child_process";
import { join } from "node:path";

import { writeWranglerConfig } from "./wrangler-config.ts";

const child = spawn(
  "bunx",
  ["wrangler", "dev", "--config", writeWranglerConfig(), "--port", "8789"],
  { cwd: join(import.meta.dirname, ".."), stdio: "inherit" },
);
child.on("exit", (code) => process.exit(code ?? 1));
