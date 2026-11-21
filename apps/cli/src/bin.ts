#!/usr/bin/env bun

import "./runtime-guard.ts";
import { runCli } from "./cli.ts";
import { liveLayer } from "./live.ts";

const exitCode = await runCli(process.argv.slice(2), liveLayer());
process.exit(exitCode);
