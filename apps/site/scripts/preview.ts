import { spawn } from "node:child_process";
import { join } from "node:path";

import { writeWranglerConfig } from "./wrangler-config.ts";

const child = spawn(
  "bunx",
  ["wrangler", "dev", "--config", writeWranglerConfig(), "--port", "8789"],
  { cwd: join(import.meta.dirname, ".."), stdio: "inherit" },
);
child.on("exit", (code) => process.exit(code ?? 1));
