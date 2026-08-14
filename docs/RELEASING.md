# リリース手順(CLI)

配布形態の決定は [ADR-0015](./adr/0015-cli-distribution.md)、実装は
[`.github/workflows/release.yml`](../.github/workflows/release.yml)。ここには**運用手順だけ**を書く。

## 初回のみ(所有者の人間タスク)

1. **npm org の publish 権限確認** — unscoped `maruhi` に対して publish できるアカウント
   /org であること(session-22 §4 の未完了項目)
2. **trusted publisher の設定**(npmjs.com → package `maruhi` → Settings → Trusted Publisher):
   - Provider: GitHub Actions
   - Organization/User: `maruhiapp` / Repository: `maruhi`
   - Workflow filename: `release.yml`(Environment は空欄)
   - 2026-05-20 以降の新規設定は allowed action の明示が必要 — 「publish」を選ぶ
3. GitHub Secrets への npm トークン登録は**不要**(OIDC のみ。長命トークンは置かない)
4. (推奨)GitHub の tag ruleset で `v*` タグの作成を管理者に制限する
   (workflow 側でも「タグ = main 系譜上のコミット」を検査するが、多層防御)

## 通常のリリース

1. **版を上げる PR**: `apps/cli/package.json` の `version` を上げる(それだけで
   `--version`・バイナリ・npm すべてに伝播する。単一の出所)。マージする
2. **main にタグを打つ**(タグ = `v` + package.json の version。一致しないと workflow が止まる):

   ```sh
   git switch main && git pull
   git tag v0.1.0-rc.1
   git push origin v0.1.0-rc.1
   ```

3. release workflow が自動で: 品質ゲート(ci.yml 全ステップ)→ 版一致検査 →
   バイナリ 5 対象 + checksums.txt → 5 実 OS runner でスモーク → GitHub Release 作成
   (ノート自動生成。`-rc.N` は prerelease マーク)→ npm publish(provenance 付き。
   `-rc.N` は dist-tag `next`、安定版は `latest`)
4. **確認**: Release に tar.gz × 5 + checksums.txt が付いていること、
   `npm view maruhi dist-tags` が期待どおりであること、npm ページに provenance
   バッジが出ていること

## ドライラン(タグを打つ前の配管検証)

release workflow は `workflow_dispatch` で publish 以外(ビルド + 5 OS スモーク +
チェックサム + npm ステージング)を全部通せる。workflow を触った PR では、
マージ前にブランチ指定で一度回すこと。

例外(bootstrap): `workflow_dispatch` は workflow が **default branch に存在して
初めて**使えるため、release.yml を新設・改名する PR 自体ではマージ前に回せない。
その場合はマージ直後・タグを打つ**前**に main でドライランを一度回す。

## やり直し

**タグの打ち直しはしない**(既存タグへの再 push は Release 作成が失敗して止まる。
これは仕様)。失敗したリリースは原因を直して **rc 番号を進めて**やり直す
(`v0.1.0-rc.1` → `v0.1.0-rc.2`)。npm に publish 済みの版は取り消さない
(unpublish はしない。上書き publish は npm 側が拒否する)。

## 注意

- **windows-x64 は experimental**(Credential Manager 経路が未検証。fail-closed
  設計のため危険側には壊れない — ADR-0015)
- **macOS は未公証**。ブラウザでダウンロードすると Gatekeeper に隔離される
  (curl 取得なら付かない)。公証は公開準備の段階で対応(ROADMAP)
- リリース成果物はソース由来のみ(バイナリ・バンドル JS・チェックサム)。
  `.dev.vars` 等の秘密がワークフローに入る経路はない
