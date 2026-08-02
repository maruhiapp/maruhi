// cloudflare:test の env(Cloudflare.Env)に wrangler.jsonc のバインディング型を与える
declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/chain-do.ts").ProjectChainDO>;
  }
}
