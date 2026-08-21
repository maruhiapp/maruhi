# deepsec 導入

[Vercel Labs の deepsec](https://github.com/vercel-labs/deepsec) を、メンテナ向けの任意セキュリティレビューとして入れる。品質ゲート(`bun run check` / CI の 7 ステップ)には載せない(ADR-0010 を変えない)。

公式の導入は `npx deepsec init` がスキャフォールドから AI レビューまで一気に進める。こちらは `--scaffold-only` でワークスペースだけをコミットした。理由:

- `process` / `setup` はソースをモデルへ送り、ファイルあたり有料になる
- モデル資格情報をリポジトリに置かない
- deepsec 自身を「フルシェル付きコーディングエージェント」として扱う(公式の信頼モデル)

## 置き場所

隔離ワークスペースは `.deepsec/`(親 bun ワークスペースの外。`pnpm-workspace.yaml` の空 `packages` で祖先モノレポから切る)。製品依存にはしない。

| コミットする | コミットしない |
|---|---|
| `deepsec.config.ts` / `generated-matchers.ts` / `package.json` / lockfile | `node_modules/` |
| `data/maruhi/INFO.md`(プロンプト文脈) | `data/*/files/` `runs/` `reports/` `setup/` `project.json` |
| `data/maruhi/SETUP.md` | `.env.local`(資格情報) |

バージョンは `.deepsec/package.json` で厳密ピン。更新は独立 PR。

## スキルとして呼ぶ

公式手順どおり `npx skills add vercel-labs/deepsec` で入れた。正は `.agents/skills/deepsec/SKILL.md`、`.claude/skills/deepsec` は symlink。`skills-lock.json` がソースとハッシュを固定する。更新は `npx skills update deepsec`。

エージェントは `/deepsec` か「deepsec でスキャンして」で公式 runbook を読む。最初に範囲(未コミット / `origin/main` との差 / リポジトリ全体)を聞き、そのあと `process` する。`process` は有料なので、支出上限を先に決めてから呼ぶ。

バージョン一致のドキュメントは `.deepsec/node_modules/deepsec/SKILL.md` と `dist/docs/`(パッケージ同梱。名前は `deepsec-docs`)。

## 日常操作

```sh
cd .deepsec
pnpm install
pnpm deepsec scan --project-id maruhi          # 正規表現のみ。無料
# 資格情報を用意してから:
pnpm deepsec process --project-id maruhi       # AI 調査。有料
pnpm deepsec revalidate --project-id maruhi    # 偽陽性の削減
pnpm deepsec export --format md-dir --out ./findings
```

資格情報は次のどれか(値は環境か `.deepsec/.env.local`。名前だけを設定に残す):

- その機械の `claude` / `codex` ログイン — `pnpm deepsec setup --model-auth local`
- 手元の API キー — `--model-auth direct --ai-provider anthropic|openai --ai-api-key-env <ENV>`
- Vercel AI Gateway — 公式どおり。Sandbox 並列実行だけは Gateway 側のトークンが要る

`scan` までなら資格情報は不要。最初の AI レビューは人間が上限(`--max-cost-usd` / `--max-duration`)を決めてから行う。

## カスタム matcher

公式どおり、確認済みの真陽性から足す。推測で matcher を増やさない。手順は `.deepsec/node_modules/deepsec/dist/docs/writing-matchers.md`。

## CI

既定の PR CI には載せない。載せるなら公式の PR モード(`process --diff`)と二分割ジョブ(解析ジョブに write 権限を持たせない)を使い、支出とシークレットを人間が承認してからにする。fork PR にはシークレットを渡さない。

## 製品の「言わざる」との関係

これはメンテナが明示実行するレビューツールであり、製品へのテレメトリ追加ではない。`process` はソースを選んだモデルへ送る。その了承がない限り走らせない。
