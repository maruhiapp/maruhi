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

type Kind<T> = T extends DurableObjectNamespace<infer _> ? DurableObjectNamespace : T;
type Bindings<E> = { readonly [K in keyof E]-?: Kind<Exclude<E[K], undefined>> };
type RequiredKeys<E> = { [K in keyof E]-?: undefined extends E[K] ? never : K }[keyof E];

type WorkerBindings = Omit<Env, Secrets>;

describe("hand-written Env types match cloudflare.config.ts bindings", () => {
  it("Env covers the self-host and hosted modes", () => {
    expectTypeOf<Bindings<WorkerBindings>>().toEqualTypeOf<
      Bindings<Omit<SelfHostEnv & HostedEnv, Secrets>>
    >();
    expectTypeOf<RequiredKeys<WorkerBindings>>().toEqualTypeOf<
      keyof SelfHostEnv & keyof HostedEnv
    >();
  });

  it("the secret fields are store bindings on hosted only, union-typed in Env", () => {
    expectTypeOf<HostedEnv["GITHUB_CLIENT_ID"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["GITHUB_CLIENT_SECRET"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["SERVER_ENC_KEY_IKM"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<HostedEnv["OPS_ALERT_WEBHOOK_URL"]>().toEqualTypeOf<SecretsStoreSecret>();
    expectTypeOf<Extract<keyof SelfHostEnv, Secrets>>().toEqualTypeOf<never>();
    expectTypeOf<Extract<keyof RestoreModeEnv, Secrets>>().toEqualTypeOf<never>();
    expectTypeOf<Env["GITHUB_CLIENT_ID"]>().toEqualTypeOf<string | SecretsStoreSecret>();
    expectTypeOf<Env["GITHUB_CLIENT_SECRET"]>().toEqualTypeOf<string | SecretsStoreSecret>();
    expectTypeOf<Env["SERVER_ENC_KEY_IKM"]>().toEqualTypeOf<
      string | SecretsStoreSecret | undefined
    >();
    expectTypeOf<Env["OPS_ALERT_WEBHOOK_URL"]>().toEqualTypeOf<
      string | SecretsStoreSecret | undefined
    >();
    expectTypeOf<RequiredKeys<Pick<Env, Secrets>>>().toEqualTypeOf<
      "GITHUB_CLIENT_ID" | "GITHUB_CLIENT_SECRET"
    >();
  });

  it("RestoreEnv matches the restore mode", () => {
    expectTypeOf<Bindings<RestoreEnv>>().toEqualTypeOf<Bindings<RestoreModeEnv>>();
  });
});
