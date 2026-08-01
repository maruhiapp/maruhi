# spike-b(使い捨て検証コード)

ROADMAP Phase 0 スパイク B: Effect v4 HttpApi + Durable Objects(ManagedRuntime パターン)+
vitest-pool-workers + Alchemy v2 / wrangler 両対応(ADR-0012)の結線検証。

**これは製品コードではない。** 検証結果は `docs/notes/spike-b.md` を参照。

実行方法:

```sh
cd spikes/spike-b
bun install
bunx vitest run                      # workerd 実環境で HttpApi → DO → DO SQLite を検証
bunx tsc --noEmit                    # alchemy.run.ts / worker の型チェック
bunx wrangler deploy --dry-run --outdir /tmp/spike-b-dist   # セルフホスト経路のバンドル検証
bunx alchemy plan                    # 運用経路(Cloudflare 資格情報が必要)
```
