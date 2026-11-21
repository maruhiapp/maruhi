import { Effect } from "effect";
import { Command } from "effect/cli";

import { commonFlags } from "./flags.ts";

export const mcpConfig = { ...commonFlags() };

export function makeMcpCommand() {
  const mcp = Command.make("mcp", mcpConfig, (flags) =>
    Effect.flatMap(
      Effect.promise(() => import("../mcp.ts").then((m) => ({ mcpServeOp: m.mcpServeOp }))),
      ({ mcpServeOp }) => mcpServeOp(flags),
    ),
  ).pipe(
    Command.withDescription(
      "Serve the value-free schema to AI agents over the Model Context Protocol (stdio). Never serves values",
    ),
  );

  return mcp;
}
