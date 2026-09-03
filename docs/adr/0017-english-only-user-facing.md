# ADR-0017: ユーザーに見える文言は英語のみ(i18n 機構は持たない)

Status: 2026-08-16 所有者裁定。この ADR を追加する PR のマージをもって Accepted。

**Context**: 現状の CLI の文言は**日本語で書かれている**が、実際の出力は日本語と英語が混ざっている。パーサの既定ヘルプ描画だけが英語のまま残るためで、移行中の今は 2 つの様式が並んでいる:

```
$ maruhi pull --help          $ maruhi push --help
DESCRIPTION                   stdin から読んだ値を暗号化して push する…
  同期検査(§6.3)+ …          USAGE:
USAGE                           maruhi push <OPTIONS> <name>
  maruhi pull [flags]         ARGUMENTS:
FLAGS                           name  変数名(表示名。環境変数名になる)
  --server string  サーバー…   OPTIONS:
GLOBAL FLAGS                    -h, --help  Display this help message
  --help, -h  Show help …
```

英語が残るのは (a) 見出し(`DESCRIPTION` / `USAGE` / `FLAGS` — effect/unstable/cli、`USAGE:` / `ARGUMENTS:` / `OPTIONS:` — gunshi)、(b) 組み込みフラグの説明(`Show help information` / `Display this help message`)、(c) `args.ts` の写像に無いコード(customParse・conflict)で gunshi の英文をそのまま出す fallback、の 3 か所。

i18n の機構はどこにも入っていない。gunshi は `@gunshi/plugin-i18n` を持つが依存にも import にもなく、`effect/unstable/cli` にはロケール機構自体が存在しない(差し替え点は `CliOutput.Formatter` のみ — ADR-0016 決定 3)。

**Decision**:

1. **ユーザーに見える文言はすべて英語**にする。対象は CLI の出力(診断・ヘルプ・警告・確認プロンプト)、サーバー API のエラー文言のうちクライアントが表示するもの、web ダッシュボードの UI 文言、docs サイト、README・リリースノート
2. **i18n の機構は持たない**。言語は 1 つで、メッセージ表・ロケール検出・翻訳ファイルのいずれも作らない。`CliOutput.Formatter` は「maruhi の語彙で英語の文面を組む」ためだけに使う
3. **内部の文書は日本語のままでよい**。コード内コメント、ADR、`docs/notes/`、`CRYPTO_SPEC` / `AUTH_SPEC` / `AUDIT_SPEC`、コミットメッセージ、PR の説明は対象外(CLAUDE.md のコーディング規約「コード内コメント・内部ドキュメントは日本語可、公開 API の JSDoc は英語」を維持する)。**境界は「配布物からユーザーが読むか」**であって「ソースに書いてあるか」ではない
4. **移行は一括では行わない**。文言の書き換えは**コマンド単位**で、ADR-0016 の引数層移行と**同じ PR の中**で行う(そのコマンドのテストがどのみち書き換わるため)。gunshi 側に残るコマンドの文言は移行のタイミングまで日本語のままでよい — 混在期間は許容する。

   **例外: 引数層を先に移した 3 コマンド**(`pull` / `run` / `env create`)。この ADR より前に移行済みなので「引数層移行 PR」というトリガーが二度と来ない。決定 4 の紐付けをそのまま読むと**この 3 つだけが静かに漏れる**ため、ROADMAP Phase 2 に**独立項目**として起こす(この ADR と同じ PR で起票済み)
5. **ヘルプの見出しも英語で統一する**。ADR-0016 決定 3 の `formatHelpDoc` は既定フォーマッタへ委譲しているが、これは英語のままでよい(独自の見出しを作らない = 上流の様式に乗る)

**Rationale**: (1) maruhi は開発者向けの CLI で、配布は GitHub Releases / npm / brew、ROADMAP Phase 2 で OSS として公開する。**エラーメッセージは issue に貼られ、検索され、CI ログに残る**。その語彙が日本語だと、公開後に届く報告と回答の言語が分かれる。(2) 現状は「日本語 + 英語の足場」という**どちらの利点も得ていない状態**で、1 言語に倒せば足場との不整合そのものが消える。(3) i18n 機構を持たないことは maruhi の規律(独自機構を発明しない・依存を増やさない)と整合する。(4) 単一言語であれば、後から多言語化が必要になっても差し替え点は `CliOutput.Formatter` の 1 か所に閉じている。

**Consequences**: 書き換えの量は小さくない — `apps/cli/src` だけで日本語を含むファイルが 53、日本語を含む文字列リテラルが約 434(2026-08-16 時点の概算)。加えて**テストが日本語の部分文字列で挙動を固定している**ため、機械置換では危険側に壊れる(文面の一致で分岐している箇所がある — 例: `cli-formatter.ts` の `SAFE_EXPECTATIONS`、`args.ts` の写像)。決定 4 のコマンド単位の移行はこの理由による。

gunshi を廃止すると(ADR-0016 決定 1)、i18n 能力を持つ唯一の依存が無くなる。決定 2 のとおりそれは意図した結果であり、将来必要になった場合は Formatter の裏に自前のメッセージ表を置く(依存は増やさない)。

web(`apps/web/src/Root.tsx` の `<html lang="ja">`)と docs サイトは CLI と別作業になる。ROADMAP Phase 2 に項目として起こす。

---

**追記(2026-08-17 — 配布物ドキュメントとインストーラの英語化)**: 決定 1 の残り(CLI 以外)を実施した。境界は決定 3「配布物からユーザーが読むか」で切った。

**ユーザーが読む側(今回英語化)**:

- `README.md` / `CONTRIBUTING.md` — リポジトリの表紙と DCO 文書。コントリビュータは配布物から読む
- `docs/SELF_HOSTING.md` — セルフホスト利用者向けの検証済み runbook(ADR-0014 の上級者経路。セッション 19 で実デプロイ検証済み)
- `packaging/install.sh` のユーザー可視メッセージ(`warn` / `die` / `printf` / `--help`)。スクリプト内コメントは内部なので日本語のまま
- `apps/web/src/Root.tsx` の `lang="en"`(web の可視文字列に日本語は無く、日本語はコメントのみ = 決定 3 で維持)
- GitHub Release の公開本文は英語(決定 1)。手段は下の裁定 3

**内部(日本語のまま)**:

- `docs/CRYPTO_SPEC.md` / `AUTH_SPEC.md` / `AUDIT_SPEC.md`
- `docs/RELEASING.md` 本体(所有者向けの運用手順)
- `docs/notes/` / `docs/adr/`(本追記を除く)
- `CLAUDE.md` / `AGENTS.md`
- コード内コメント全般。**`packaging/install.sh` のヘッダコメントも含む**(裁定 2)
- `packaging/homebrew/maruhi.example.rb` のコメント(`desc` は既に英語)
- `packaging/install-test.sh` のラベル文字列(CI 内部。install.sh の文言を grep で固定している箇所だけ道連れに更新)
- ワークスペースの `apps/cli/package.json` に `description` フィールドは無い(追加しない)。npm へ出すマニフェストは `apps/cli/scripts/build-npm.ts` が組み立て、`description` と同梱 `README.md` は**既に英語**(今回の対象外。英語のまま維持する)

docs サイト(Blume)は当時未着工(`apps/docs` はプレースホルダのみ)で、サイト構築時に英語で書く旨を ROADMAP に残した。**2026-09-03 DP2 で `apps/site`(LP + docs)として構築し、LP / docs の全文言を英語で書いた**(ADR-0008 改訂 1)。

**裁定**:

1. `SELF_HOSTING.md` / `CONTRIBUTING.md` / `install.sh` のユーザー可視メッセージは、決定 3 の境界「配布物からユーザーが読む」側。`CRYPTO_SPEC` / `AUTH_SPEC` / `AUDIT_SPEC` / `RELEASING.md` 本体 / `docs/notes` / ADR 本体 / `CLAUDE.md` は内部
2. **`install.sh` のコメントは日本語のまま**。README は `less` してから実行する形を先に案内するが、利用者が読む信頼モデルの正は README の英語の trust-model 節である。スクリプトを開いたときに走る処理の説明(コメント)はメンテナ向けであり、実行時に出る文言(`usage` / `die` / `warn`)だけがユーザー可視。ヘッダ 5〜16 行をコメントだからといって英語化しない(決定 3 の「ソースに書いてあるか」ではなく「配布物からユーザーが読むか」)
3. **GitHub Release の公開本文は英語**(決定 1)。現行の `release.yml` は `gh release create --generate-notes` で、本文はマージ済み PR タイトルから組まれる(`--draft` なし = タグ push 時点で公開済み)。決定 3 はコミットメッセージと PR 説明を日本語のままとしており、PR タイトル英語化も `--notes-file` 化も `--draft` 化もこの追記では採らない。所有者は公開直後に Release 本文を英語へ直す(RELEASING.md に固定)。仕組み側の変更は別判断
4. `SELF_HOSTING.md` の見出し英訳に伴い、生きている内部文書(`AUTH_SPEC` / `SECURITY_REVIEW_2026-08-14.md`)の見出し参照だけ英語見出し名へ追随する。セッションノート(`docs/notes/`)は日付付きログなので触らない
