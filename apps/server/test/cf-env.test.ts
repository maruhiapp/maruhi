// The hand-written binding types (Env in src/do/chain-do.ts, RestoreEnv in
// src/restore-worker.ts) against the bindings cloudflare.config.ts declares.
// `cf build` writes .cloudflare/types/index.d.ts, whose Cloudflare.Env is
// `InferEnv<…>` over this same config; calling InferEnv on each mode's
// worker here checks the same thing with no generation step. The assertions
// are type-level: `bun run typecheck` (tsc) fails on a mismatch, and the
// test body only runs them.
// The four secret fields are the exception to the plain parity below:
// the self-host config does not declare them at all (they are registered
// as Workers Secrets — AUTH_SPEC §3-2), while the hosted config binds
// them from the Secrets Store (ADR-0012 revision 3). Env therefore
// carries the union of both shapes (`string | SecretsStoreSecret`), and
// the second test pins each side of that split.
import type { InferEnv } from "cf/config";
import { describe, expectTypeOf, it } from "vite-plus/test";

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
    // Every binding either mode declares, with its type (the secret
    // fields are excluded here and pinned separately below)
    expectTypeOf<Bindings<WorkerBindings>>().toEqualTypeOf<
      Bindings<Omit<SelfHostEnv & HostedEnv, Secrets>>
    >();
    // Required in Env exactly when both modes declare it (the hosted-only
    // OPS_BACKUP_BUCKET stays optional)
    expectTypeOf<RequiredKeys<WorkerBindings>>().toEqualTypeOf<
      keyof SelfHostEnv & keyof HostedEnv
    >();
  });

  it("the secret fields are store bindings on hosted only, union-typed in Env", () => {
    // The hosted config binds each of the four from the Secrets Store
    expectTypeOf<HostedEnv["GITHUB_CLIENT_ID"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["GITHUB_CLIENT_SECRET"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["SERVER_ENC_KEY_IKM"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["OPS_ALERT_WEBHOOK_URL"]>().toEqualTypeOf<SecretsStoreSecret>();
    // Neither the self-host nor the restore config declares them (on
    // self-host they are Workers Secrets, outside the config entirely)
    expectTypeOf<Extract<keyof SelfHostEnv, Secrets>>().toEqualTypeOf<never>();
    expectTypeOf<Extract<keyof RestoreModeEnv, Secrets>>().toEqualTypeOf<never>();
    // Env carries both shapes: a plain string (self-host / .dev.vars /
    // tests) or the store binding object (hosted)
    expectTypeOf<Env["GITHUB_CLIENT_ID"]>().toEqualTypeOf<string | SecretsStoreSecret>();
    expectTypeOf<Env["GITHUB_CLIENT_SECRET"]>().toEqualTypeOf<string | SecretsStoreSecret>();
    expectTypeOf<Env["SERVER_ENC_KEY_IKM"]>().toEqualTypeOf<
      string | SecretsStoreSecret | undefined
    >();
    expectTypeOf<Env["OPS_ALERT_WEBHOOK_URL"]>().toEqualTypeOf<
      string | SecretsStoreSecret | undefined
    >();
    // Required in Env exactly for the OAuth pair (the IKM and the
    // webhook URL are optional features)
    expectTypeOf<RequiredKeys<Pick<Env, Secrets>>>().toEqualTypeOf<
      "GITHUB_CLIENT_ID" | "GITHUB_CLIENT_SECRET"
    >();
  });

  it("RestoreEnv matches the restore mode", () => {
    expectTypeOf<Bindings<RestoreEnv>>().toEqualTypeOf<Bindings<RestoreModeEnv>>();
  });
});
