// The hand-written binding types (Env in src/do/chain-do.ts, RestoreEnv in
// src/restore-worker.ts) against the bindings cloudflare.config.ts declares.
// `cf build` writes .cloudflare/types/index.d.ts, whose Cloudflare.Env is
// `InferEnv<…>` over this same config; calling InferEnv on each mode's
// worker here checks the same thing with no generation step. The assertions
// are type-level: `bun run typecheck` (tsc) fails on a mismatch, and the
// test body only runs them.
// Workers Secrets are not in the config, so they stay hand-written only.
import type { InferEnv } from "cf/config";
import { describe, expectTypeOf, it } from "vitest";

import type { HOSTED_WORKER, RESTORE_WORKER, SELF_HOST_WORKER } from "../cloudflare.config.ts";
import type { Env } from "../src/do/chain-do.ts";
import type { RestoreEnv } from "../src/restore-worker.ts";

type SelfHostEnv = InferEnv<typeof SELF_HOST_WORKER>;
type HostedEnv = InferEnv<typeof HOSTED_WORKER>;
type RestoreModeEnv = InferEnv<typeof RESTORE_WORKER>;

type Secrets =
  | "GITHUB_CLIENT_ID"
  | "GITHUB_CLIENT_SECRET"
  | "SERVER_ENC_KEY_IKM"
  | "OPS_ALERT_WEBHOOK_URL";

// Without the generated GlobalProps, InferEnv types a Durable Object
// binding as DurableObjectNamespace<undefined>; the hand-written types
// carry the class. Compare the binding kind, and compare optionality
// separately (RequiredKeys).
type Kind<T> = T extends DurableObjectNamespace<infer _> ? DurableObjectNamespace : T;
type Bindings<E> = { readonly [K in keyof E]-?: Kind<Exclude<E[K], undefined>> };
type RequiredKeys<E> = { [K in keyof E]-?: undefined extends E[K] ? never : K }[keyof E];

type WorkerBindings = Omit<Env, Secrets>;

describe("hand-written Env types match cloudflare.config.ts bindings", () => {
  it("Env covers the self-host and hosted modes", () => {
    // Every binding either mode declares, with its type
    expectTypeOf<Bindings<WorkerBindings>>().toEqualTypeOf<Bindings<SelfHostEnv & HostedEnv>>();
    // Required in Env exactly when both modes declare it (the hosted-only
    // OPS_BACKUP_BUCKET stays optional)
    expectTypeOf<RequiredKeys<WorkerBindings>>().toEqualTypeOf<
      keyof SelfHostEnv & keyof HostedEnv
    >();
  });

  it("RestoreEnv matches the restore mode", () => {
    expectTypeOf<Bindings<RestoreEnv>>().toEqualTypeOf<Bindings<RestoreModeEnv>>();
  });
});
