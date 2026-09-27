# Spike B results: wiring the server stack (Effect v4 HttpApi + DO + vitest-pool-workers + Alchemy v2)

Date: 2026-08-01. A ROADMAP Phase 0 verification spike.
**The throwaway code lives in `spikes/spike-b/` and is not product code.** `apps/server` was not modified.

## What was verified, and the setup

| Component | Version (exact pin) | Notes |
|---|---|---|
| effect | 4.0.0-beta.102 | **v4 has no stable release** (latest is 3.22.1). Per CLAUDE.md's "Effect v4 line" the beta was adopted, run under ADR-0011's exact pinning |
| @cloudflare/vitest-pool-workers | 0.20.1 | Same as session 01. The `cloudflareTest()` plugin form |
| alchemy | 2.0.0-beta.67 | v2 is the npm dist-tag `next`. Also without a stable release |
| wrangler | (transitive dependency of pool-workers) | Used for dry-run verification |

What was built: a dummy setup with a single counter.

- `src/api.ts` — the HttpApi definition (GET `/counter/:name`, POST `/counter/:name/increment`). In v4, @effect/platform is merged into the effect package and HttpApi lives at `effect/unstable/httpapi`
- `src/worker.ts` — keeps the plain Workers API (`export default { fetch }` + a `DurableObject` subclass), implemented internally in Effect:
  - **DO (the ManagedRuntime pattern)**: `CounterDO`'s constructor runs `ManagedRuntime.make` from a Layer exactly once, and the RPC methods (`getValue` / `increment`) run Effects via `runtime.runPromise`. Storage access is isolated behind an Effect service `CounterStore` (a miniature of ADR-0006). DO SQLite is used via `ctx.storage.sql` (UPSERT + RETURNING)
  - **Worker**: the handler is implemented with `HttpApiBuilder.group` → `HttpRouter.toWebHandler` built once per isolate. `env` (the DO binding) is injected per request via `handler(request, Context.make(WorkerEnv, env))` (the Layer is not rebuilt / disposed per request)
- `test/counter.test.ts` — vitest-pool-workers (the real workerd environment). An HttpApi integration via SELF + direct verification of real DO SQLite data via `runInDurableObject`
- `wrangler.jsonc` + `alchemy.run.ts` — the 2 paths supporting both ADR-0012 modes (below)

## Result: everything works

- **5/5 tests pass** (the real workerd environment; `navigator.userAgent === "Cloudflare-Workers"` confirmed)
  - The HttpApi routing → DO RPC → DO SQLite read/write round trip
  - The error response on a Schema validation failure
  - Direct assertion of SQLite rows inside the DO via `runInDurableObject`
- Effect v4 (beta.102) **runs as-is on workerd with no `nodejs_compat`**
- `tsc --noEmit` passes, the root quality gate's 7 steps pass
- The wrangler path: `wrangler deploy --dry-run` bundles successfully (**Total Upload 1259 KiB / gzip 261 KiB** — a sense of the size with the Effect runtime included; within Workers' script limits of 3 MiB (free) / 10 MiB (paid) gzip)
- The Alchemy path: `alchemy.run.ts` passes the type check, the CLI (`alchemy plan` etc.) launches

## Verifying ADR-0012 (supporting both Alchemy v2 and plain wrangler)

**It works.** The key is Alchemy v2's "**Async Worker**" form:

- The Worker implementation (`src/worker.ts`) stays on the plain Workers API. It contains no Alchemy-specific imports at all
- `alchemy.run.ts` is `Cloudflare.Worker("SpikeB", { main: "./src/worker.ts", env: { COUNTER: Cloudflare.DurableObject<CounterDO>("COUNTER", { className: "CounterDO" }) } })` — "pass no implementation Effect, just point at main". In this case Alchemy bundles the file as-is and does not pull the Effect runtime in from the deployment-definition side
- The same source can also be deployed via `wrangler.jsonc` (a durable_objects binding + a `new_sqlite_classes` migration). The double-management shrinks to just "declaring the binding in 2 places"
- Note: Alchemy also offers Effect-native Worker/DO descriptions (the two-phase Effect pattern, a schema-less RPC bridge), but **using those makes the source Alchemy-dependent and breaks the wrangler path**. For maruhi, fix on the Async Worker form

Real deploys (`alchemy deploy` / `wrangler deploy`) are **not done — no Cloudflare credentials**. `alchemy plan` could not run either because it requires credentials to fetch state (`AuthError: No credentials configured for 'Cloudflare'`). Stopped at the dry-run bundle and type check.

## Things that tripped us up (traps you may hit again in implementation)

1. **Passing a plain field list to HttpApiEndpoint's payload makes it form-urlencoded**: `payload: { by: Schema.Number }` is treated with the `application/x-www-form-urlencoded` codec, and a JSON body becomes a **415 Unsupported content-type**. To get JSON, write `payload: Schema.Struct({ by: Schema.Number })` with Schema explicit (the `HttpApiEndpoint.js` implementation where `getPayload` attaches `asFormUrlEncoded()` to a fields shorthand)
2. **`HttpApiBuilder.layer` type-requires `HttpPlatform` / `FileSystem` / `Etag.Generator` / `Path`** (for file responses — never called at runtime for a JSON-only API). workerd has no FS, so only the type requirements were satisfied via `FileSystem.layerNoop({})` + `HttpPlatform.layer` + `Etag.layer` + `Path.layer`
3. **The alchemy CLI demands optional peerDependencies at runtime**: under bun the CLI does not start until `@effect/platform-node` and `@effect/platform-bun` (4.0.0-beta.102) are added
4. **The Alchemy v2 docs' Async Worker + DO example uses a `bindings:` property, but the actual `WorkerProps` type is `env:`** (`bindings?` is a different thing on the WorkerVersion side). Doc drift because it is a beta
5. Typing `cloudflare:test`'s `env` is done via global augmentation of `Cloudflare.Env` (the `ProvidedEnv` extension still works but is deprecated. Importing `env` itself from `cloudflare:workers` is the new recommendation)
6. Telemetry: alchemy sends CLI telemetry (disable via `DO_NOT_TRACK=1` or `ALCHEMY_TELEMETRY_DISABLED=1`; a persistent opt-out at `~/.alchemy/telemetry-disabled`). Same for wrangler (`WRANGLER_SEND_METRICS=false`). **Since the "say nothing" principle should apply to the maintainers' CI too, Phase 1 should put the disables into CI environment variables**

## Implications for the adoption decision

- ADR-0005 (HttpApi, no Hono) and ADR-0012 (supporting both) **hold without problems** at this dummy scale. The experience of deriving typed handlers, validation, and error responses consistently from the schema is good
- Be aware that HttpApi lives under the `unstable/` namespace: it is explicitly marked that the API may move when v4 stabilizes. Assumed absorbed by exact pinning + independent-PR updates (ADR-0011)
- The ManagedRuntime pattern meshes cleanly with DOs. Since a DO has no explicit teardown hook, `runtime.dispose()` is not called (no problem — this Layer holds no resources). **Cleanup when a DO carries a resource-holding Layer (connections, timers) is a design task for implementation**
- The gzip 261 KiB with the Effect runtime included is within Workers limits, but the cold-start impact is unmeasured. Measure in Phase 1

## Remaining questions (to resolve in Phase 1)

1. **A real deploy is unverified**: both Alchemy v2 and wrangler need Cloudflare credentials. At Phase 1 kickoff, run `alchemy deploy` and `wrangler deploy` (or a Deploy to Cloudflare button) on a verification account. If doing it in a cloud dev environment, a CF token must be registered under Cloud Agents > Secrets
2. Drizzle (`drizzle-orm/durable-sqlite`, ADR-0006) is outside this spike's scope. Verifying in-DO self-migration + the Effect service boundary is separately needed (alchemy also has drizzle-orm 1.0.0-rc.4 as an optional peer, so check version alignment too)
3. Wiring to D1 (cross-project metadata) is unverified (only DO SQLite was verified)
4. The timing of Effect v4 stabilization (still a ROADMAP watch item)
5. The pace of alchemy 2.0.0-beta's breaking changes (the bridge behavior was still moving in beta.47's changelog). ADR-0011's exact-pin operation is mandatory

## Root changes to integrate when adopting for real

- Add `spikes/**` to `.fallowrc.json`'s `ignorePatterns` (the same single line as the spike-c branch — identical content, so no conflict whichever merges first)
- Root `package.json` / `vitest.config.ts` / `ci.yml` are unchanged
- When integrating into apps/server in Phase 1: add effect (v4 beta, exact-pinned) to apps/server's dependencies and replace the placeholder worker with the HttpApi setup. Add the telemetry disables (`DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false`) to CI environment variables
