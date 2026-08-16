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
