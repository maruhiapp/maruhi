#!/usr/bin/env bun
// Entry point of the `maruhi` / `mh` binaries (Bun runtime).

// The runtime check must take effect before import hoisting, so it runs as
// the leading side-effect import (runtime-guard.ts)
import "./runtime-guard.ts";
import { runCli } from "./cli.ts";
import { liveLayer } from "./live.ts";

const exitCode = await runCli(process.argv.slice(2), liveLayer());
// Explicit exit rather than exitCode assignment: a pending Bun.secrets native
// call interrupted by the keychain-operation timeout (live.ts) was observed to
// keep the event loop alive and prevent the process from exiting
process.exit(exitCode);
