// Deciding whether values may be displayed (ADR-0016 decision 7 — a
// fail-closed two-layer design with the primary boundary on the TTY).
//
// **Why a deny-list alone is not enough**: an approach that refuses when the
// environment matches a "list of known agent variables" makes the boundary's
// definition depend on an upstream list, and new agents not on the list,
// custom harnesses, CI, and log-collection paths **pass straight through**
// (fail-open). Environment-variable standardization is undecided (`AGENT` and
// `AI_AGENT` coexist, and each vendor's own variables proliferate), so the
// premise "the list is always correct" cannot even be held.
//
// So the requirement itself becomes the check: values may be seen **only when
// a human runs the command at an interactive terminal** (allow-list =
// fail-closed):
//
//   1. Primary boundary: are both stdin and stdout TTYs (`Stdio` service).
//      Agents, CI, pipes, and redirects are all refused by default.
//      Unknown agents are refused for the same reason (stopped even when
//      unrecognized)
//   2. Secondary layer: environment variables of known agents (naming them
//      makes diagnostics friendlier, and it also catches agents that allocate
//      a PTY to run)
//
// Both kinds of evidence are substitutable via Effect services (never reading
// `process.stdout` directly). Real detection is done by live.ts with std-env;
// tests fake both by substituting `Stdio.layerTest` and
// {@link AgentProfileRef}.
//
// The refusal message does not recommend `maruhi run -- <cmd>`: run is an
// injection path for *using* values, not a path for *seeing* them, and a use
// like `run -- printenv` ends up streaming plaintext into the agent's stdout
// (transcript) = bypassing the refused boundary. Do not hand agents a bypass
// recipe.
//
// Failures are represented by the shared maruhi {@link CliError} (execution
// failure = exit 1). The error type carries the exit code via
// `Runtime.errorExitCode` (errors.ts), so the runner needs no mapping table
// (ADR-0016 decision 4).

import { Context, Effect, Stdio } from "effect";

import { cliError, type CliError } from "./errors.ts";

/** Detection result for an AI coding agent (the detection itself is injected). */
export interface AgentProfile {
  readonly isAgent: boolean;
  readonly name?: string | undefined;
}

/**
 * Service holding the detection result. It only receives the value here so
 * the implementation (std-env / a custom table) can be swapped — a secondary
 * layer, not the boundary.
 */
export class AgentProfileRef extends Context.Reference<AgentProfile>("cli/AgentProfile", {
  defaultValue: (): AgentProfile => ({ isAgent: false }),
}) {}

/**
 * 3-channel TTY gate used for displaying / entering key material and
 * capabilities. One channel stricter than the stdin+stdout boundary for value
 * display, because there is also a path that writes to stderr.
 */
export function ensureSensitiveTerminalAllowed(input: {
  readonly agent: AgentProfile;
  readonly stderrIsTerminal: boolean;
  readonly agentError: string;
  readonly terminalError: string;
}): Effect.Effect<void, CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    if (input.agent.isAgent) {
      return yield* Effect.fail(cliError(input.agentError));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal || !input.stderrIsTerminal) {
      return yield* Effect.fail(cliError(input.terminalError));
    }
  });
}

/**
 * Names which side failed the primary boundary (whether stdin and stdout are
 * terminals) (DP5 supplement G). Saying only "both are not terminals" leaves
 * it unclear whether to drop `| less` or to stop using a heredoc. The check's
 * semantics are unchanged; the check result is used verbatim as message
 * material (no new check is added).
 */
export function describeNonTerminal(input: {
  readonly stdinIsTerminal: boolean;
  readonly stdoutIsTerminal: boolean;
}): string {
  if (!input.stdinIsTerminal && !input.stdoutIsTerminal) {
    return "neither stdin nor stdout is an interactive terminal";
  }
  return input.stdinIsTerminal
    ? "stdout is not an interactive terminal"
    : "stdin is not an interactive terminal";
}

/**
 * Refusal text when a known agent is detected (the name is shown only for
 * diagnosis). Message order is "what was refused → why → what to do"
 * (DP5 ruling G — the check's semantics are unchanged).
 */
function agentRejection(name: string | undefined): CliError {
  const detected = name === undefined ? "" : ` (${name})`;
  return cliError(
    `Refused to display values: an AI agent environment was detected${detected}. Values are shown only to a person at an interactive terminal, so they never land in an agent's transcript. Run this command yourself in a terminal`,
  );
}

/**
 * Fails unless value display is allowed: a human at an interactive terminal,
 * not an AI coding agent.
 *
 * There are two call sites (defense in depth): the pull entry point (before
 * decryption — the main line) and `showValues` (the post-decryption line of
 * defense — display.ts).
 */
export const ensureValueDisplayAllowed: Effect.Effect<void, CliError, Stdio.Stdio> = Effect.gen(
  function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      return yield* Effect.fail(agentRejection(agent.name));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      // Pipes, redirects, CI, and unknown agents stop here.
      // Not "stop what we know" but "let only a human terminal through"
      return yield* Effect.fail(
        cliError(
          `Refused to display values: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })}. Values are shown only to a person at a terminal (pipes, redirects, CI, and AI agents are refused), so they never land in a file or a log. Run this command yourself in a terminal, without redirecting its input or output`,
        ),
      );
    }
  },
);

/**
 * Shared shape of the ceremony two-layer gate (the same evidence as ADR-0016
 * decision 7: known-agent detection → whether stdin / stdout are terminals).
 * The refusal text is given per ceremony (what was refused → why → what to
 * do). `agentRefusal` receives the parenthesized detected name (an empty
 * string is possible).
 */
export function ensureHumanCeremonyAllowed(input: {
  readonly agentRefusal: (detected: string) => string;
  readonly terminalRefusal: (reason: string) => string;
}): Effect.Effect<void, CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      const detected = agent.name === undefined ? "" : ` (${agent.name})`;
      return yield* Effect.fail(cliError(input.agentRefusal(detected)));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      return yield* Effect.fail(
        cliError(input.terminalRefusal(describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal }))),
      );
    }
  });
}

/**
 * Ceremony gate for `maruhi device approve` (design record dk-design.md §9
 * K4-6 — the same evidence as the ADR-0016 decision 7 two layers): approval
 * is the act of a person comparing an FP carried over from another device,
 * and cannot hold in an agent environment or non-interactively (pipes, CI).
 * A fingerprint-registry match does not substitute for a person's yes either
 * (K4-3).
 */
export const ensureDeviceApproveAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to approve a device: an AI agent environment was detected${detected}. Approving a device key adds a signer to every project you are a member of, so it is done only by a person at an interactive terminal who compared the fingerprint with the new device. Run \`maruhi device approve\` yourself in a terminal`,
    terminalRefusal: (reason) =>
      `Refused to approve a device: ${reason}. Approving a device key is done only by a person at a terminal (pipes, redirects, CI, and AI agents are refused). Run \`maruhi device approve\` yourself in a terminal, without redirecting its input or output`,
  });
