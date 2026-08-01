// cloudflare:test の env(Cloudflare.Env)に wrangler.jsonc のバインディング型を与える
declare namespace Cloudflare {
  interface Env {
    COUNTER: DurableObjectNamespace<import("../src/worker.ts").CounterDO>;
  }
}
