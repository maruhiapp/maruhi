# Agent setup for `maruhi`

`data/maruhi/INFO.md` is filled. Do not regenerate it from placeholders.

Repo-specific policy (Japanese): `../docs/DEEPSEC.md`.

## Remaining work (human, credentials required)

`scan` is free. `process` / `setup` / `revalidate` send source to a
model and cost money — not part of `bun run check` or default CI.

```bash
pnpm install
pnpm deepsec scan --project-id maruhi
# then, with a logged-in claude/codex CLI or an API key:
#   pnpm deepsec setup --model-auth local
#   # or: pnpm deepsec setup --model-auth direct --ai-provider anthropic --ai-api-key-env ANTHROPIC_API_KEY
pnpm deepsec process --project-id maruhi
```

## Custom matchers

Do not add matchers speculatively. After a revalidated true positive,
read `node_modules/deepsec/dist/docs/writing-matchers.md` and grow a
matcher from that finding.
