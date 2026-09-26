# ADR-0004: Separation of runtime and execution environment

**Decision**: Development toolchain and CLI = Bun 1.4.x. Server execution = workerd (Workers). Server code uses Web standards + Workers APIs only; Bun APIs are banned. Tests are unified on Vitest (server / DO on @cloudflare/vitest-pool-workers, everything else on the normal environment). `bun:test` is not used.
**Rationale**: Bun does not run on the server (nor does it need to). The crypto core is constrained to WebCrypto so it runs in all three environments (browser / Bun / workerd); portability is guaranteed by CI.
