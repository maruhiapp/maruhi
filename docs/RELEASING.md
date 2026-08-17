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

## Homebrew tap の更新(安定版のみ。リリース完了後)

tap は別リポジトリ `maruhiapp/homebrew-maruhi`。formula は**生成物**で、
[`apps/cli/scripts/generate-formula.ts`](../apps/cli/scripts/generate-formula.ts) が
Release の `checksums.txt` から作る(手で sha256 を書き写さない)。

**プレリリース(`-rc.N`)は tap に載せない** — 生成器も既定で拒否する
(`--allow-prerelease` で上書きできるが、通常は使わない)。

### 初回のみ(所有者の人間タスク)

1. GitHub で **`maruhiapp/homebrew-maruhi`** を作る(public。名前は `homebrew-` 接頭辞が必須 —
   これで `brew install maruhiapp/maruhi/maruhi` が解決する)
2. リポジトリ直下に `Formula/` ディレクトリを作る(README があると親切)
3. 初回の formula を置いたら、**tap を取り込んで信頼を与えてから** audit を通す。
   `brew audit` は formula の Ruby を読み込んで評価するので、未信頼 tap のままでは
   formula を読めずに落ちる(Homebrew 6.0.0 の tap trust。信頼はマシンごとに 1 回):

   ```sh
   brew tap maruhiapp/maruhi
   brew trust --tap maruhiapp/maruhi
   brew audit --new maruhiapp/maruhi/maruhi   # --new は --strict と --online を含意する
   ```

   **リポジトリ側の CI が見ているのは `ruby -c`(構文)と golden 一致までで、Homebrew の
   DSL 意味論(`on_macos` > `on_arm` のネスト、`bin.install_symlink`、`test do`)は tap が
   できるまで実行されない**。指摘が出たら手で formula を直さず
   `apps/cli/scripts/formula.ts` を直す(formula は生成物。手編集は次のリリースで消える)

### 毎リリース

```sh
# 1. Release の checksums.txt から formula を生成(既定の出力は packaging/homebrew/maruhi.rb)
bun apps/cli/scripts/generate-formula.ts --version v0.1.0

# 2. tap リポジトリへコピーして push(内容の差分は version / url / sha256 の 4 対象ぶんだけ)
cp packaging/homebrew/maruhi.rb ../homebrew-maruhi/Formula/maruhi.rb
cd ../homebrew-maruhi && git add Formula/maruhi.rb && git commit -m "maruhi 0.1.0" && git push

# 3. 実機で確認(既に tap 済みなら `brew update && brew upgrade maruhi`)。
#    Homebrew 6.0.0 以降、サードパーティ tap は評価前に明示的な信頼が要る(マシンごとに 1 回)
brew trust --tap maruhiapp/maruhi
brew install maruhiapp/maruhi/maruhi
maruhi --version && mh --version
brew test maruhi
```

`--checksums <path>`(ローカルの `apps/cli/dist/checksums.txt` を使う)、`--out <path>`
(tap のパスへ直接書く)も指定できる。`--version` を省略すると `apps/cli/package.json` の版を使う。

自動 PR(release workflow から tap へ push)にしていないのは、cross-repo の書き込み資格情報を
`contents: write` + `id-token: write` を持つリリース経路へ足すことになるため(ADR-0015 の
権限最小化と釣り合わない)。リリース頻度が上がったら再検討する。

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

**例外 — publish-npm だけが失敗した場合**(Release は作成済みで npm が出ていない):
rc を進める必要はない。npm 側はその版を未消費なので、原因(初回なら大抵
trusted publisher の設定 — workflow 名・org・allowed action)を直して、同じ run の
**失敗した job を re-run** すれば同一版で復旧できる(re-run はアーティファクトの
保持期間 = **30 日以内**。過ぎたら rc を進めるしかない)。
ただし **re-run で直るのは設定・環境起因のみ**。コード修正が要る失敗は re-run では
直らない(run はタグ時点の workflow と成果物で走る)ので、直して rc を進める
(v0.1.0-rc.1 の bin 正規化バグが実例)。Release 先行 → npm 後行の
順序はこの復旧を可能にするためのもの(逆だと publish 済み npm 版は再試行できない)。
なお **OIDC(trusted publishing)経路はドライランでは検証できない**(publish を
実行して初めて認証が走る)。最初のタグの前に、初回設定(上記 1〜3)を再確認すること。

## 注意

- **GitHub Release のリリースノートは英語で書く**(ADR-0017 決定 1)
- **windows-x64 は experimental**(Credential Manager 経路が未検証。fail-closed
  設計のため危険側には壊れない — ADR-0015)
- **macOS は未公証**。ブラウザでダウンロードすると Gatekeeper に隔離される
  (curl 取得なら付かない)。公証は公開準備の段階で対応(ROADMAP)
- リリース成果物はソース由来のみ(バイナリ・バンドル JS・チェックサム)。
  `.dev.vars` 等の秘密がワークフローに入る経路はない
- **install script はタグ固定の raw URL で配る**
  (`raw.githubusercontent.com/maruhiapp/maruhi/<tag>/packaging/install.sh`)。
  タグを打った時点でその版の script が公開されるので、リリース手順としての追加作業はない。
  script 自体の検証は PR ごとに [`installer.yml`](../.github/workflows/installer.yml) が
  実 OS 4 種で回している(実リリースには依存しない)
- ただし **`--version` 省略時の「最新の安定版を解決する」分岐だけは CI で踏めない**
  (プレリリース期間中は `releases/latest` が存在せず、ハーネスは `MARUHI_BASE_URL` 指定 =
  解決を飛ばす経路で回るため)。**最初の安定版 `v0.1.0` を出した直後に、`--version` を付けずに
  一度実行して確認すること**。壊れていても「タグを指定してください」の明示エラーに倒れる設計
  だが、無言で古い版が入るような壊れ方はしない
