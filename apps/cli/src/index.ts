// @maruhi/cli — the `maruhi` / `mh` CLI on effect/unstable/cli + Effect.
// Diskless invariant: never write plaintext secrets to disk. Do not build
// features that generate .env-style files. Only the maruhi token, the master
// secret key (OS keychain), and non-secret settings may be persisted.

export { type CliServices, runCli } from "./cli.ts";
export { liveLayer } from "./live.ts";
