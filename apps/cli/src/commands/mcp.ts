// `maruhi mcp` (discipline: see commands/index.ts).

import { Command } from "effect/cli";

import { mcpServeOp } from "../mcp.ts";
import { commonFlags } from "./flags.ts";

/**
 * `maruhi mcp` (PF5 — the MCP server over stdio). The same flags as
 * `maruhi schema`: the host config pins the project (and the default
 * environment) the way a human would on the command line (pf5-design.md
 * ruling M4).
 */
export const mcpConfig = { ...commonFlags() };

export function makeMcpCommand() {
  // `maruhi mcp` — the value-free schema over MCP (PF5). Keyless like
  // `maruhi schema`, and the agent-gate does not apply: it is the
  // agent-facing surface by construction and serves no values
  // (pf5-design.md rulings M3 / M7)
  const mcp = Command.make("mcp", mcpConfig, mcpServeOp).pipe(
    Command.withDescription(
      "Serve the value-free schema to AI agents over the Model Context Protocol (stdio). Never serves values",
    ),
  );

  return mcp;
}
