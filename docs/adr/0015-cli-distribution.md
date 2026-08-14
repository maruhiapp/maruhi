# ADR-0015: CLI 配布 = コンパイル済みバイナリ一次 + npm は Bun 前提のバンドル JS

Status: 2026-08-14 提案。リリース基盤 PR(Phase 2 Wave 1 / PR-3)のマージをもって所有者承認(Accepted)とする。

**Context**: `maruhi` CLI は OS キーチェーン境界を `Bun.secrets` で、子プロセス注入を `Bun.spawn` で実装しており(いずれも `apps/cli/src/live.ts` のみ)、**Node.js では動かない**。キーチェーン不在環境では平文ファイルへフォールバックせず型付きエラーで止める設計(ディスクレス不変条件)のため、配布形態はこのランタイム制約を背負う。`bun build --compile` のクロスコンパイルは 5 対象(linux-x64/arm64、darwin-x64/arm64、windows-x64)すべて成功済みで、バイナリは素で 62〜96MB(gzip 後 23〜37MB)。npm には unscoped `maruhi` のプレースホルダが publish 済み。`bun publish` は provenance 未対応(oven-sh/bun#15601)。後続の PR-4(install script + brew tap)はこの決定の上に立つ。

**Decision**:

1. **一次配布は GitHub Releases のコンパイル済み単体バイナリ**(5 対象、`maruhi-<target>.tar.gz` + `checksums.txt`)。利用者に Bun を要求しない。生成は `apps/cli/scripts/build-binaries.ts` に一元化し、タグ駆動の release workflow(`.github/workflows/release.yml`)が品質ゲート(ci.yml の `workflow_call` 再利用)→ 5 実 OS runner でのスモーク(起動 + `--version` 照合)→ publish の順で回す
2. **npm(unscoped `maruhi`)は Bun 前提の単一バンドル JS** を配る。workspace 依存(`@maruhi/core` 等)と beta の `effect` はバンドルへ畳み、**利用者の依存グラフへ伝播させない**(ADR-0011 の系: 未安定依存はピン留めした一体の成果物としてのみ外へ出す)。`@maruhi/{core,crypto,api-schema}` の個別 publish は API が安定するまで行わない(行うときは別 ADR)。Node.js で起動された場合は入口ガードが案内を出して exit 1(深部の `ReferenceError` にしない)
3. **不採用**: (a) platform 別 optionalDependencies にバイナリを載せる esbuild 方式 — 毎リリース 380MB 超を npm レジストリへ複製することになり、`npm i -g maruhi` の失敗モード(Bun なし)を解消する対価として過大。(b) postinstall で GitHub Releases から取得する薄いインストーラ — postinstall スクリプト無効環境(bun 既定・多くの企業 CI)で壊れ、install 時の外部取得は供給網の面でも筋が悪い
4. **バージョンの単一の出所は `apps/cli/package.json`**(`cli.ts` が import し、テストが `--version` 出力との一致を固定)。リリースはリポジトリ単位の `v<version>` タグ(パッケージ別タグにしない)で、workflow がタグと package.json の一致を検査してから成果物を作る。プレリリースは `-rc.N` を用い、GitHub Release は prerelease マーク、npm は dist-tag `next` に置く。最初のリリースは `v0.1.0-rc.1` でパイプライン自体を検証してから `v0.1.0` を出す
5. **npm publish は npm CLI + trusted publishing(OIDC)+ `--provenance`**。長命トークンを GitHub Secrets に置かない。`v*` タグの push だけが publish 経路
6. **`mh` エイリアス**: npm は `bin` 2 本で自動提供。バイナリ配布はアーカイブに `maruhi` 1 本のみを入れ、リンクはインストーラ側(PR-4 の install script / brew tap)の責務とする(全対象を 2 本ずつ配ると転送量が倍になるだけで得るものがない)
7. **windows-x64 は experimental として出す**。Credential Manager 経路は未検証だが、キーチェーン不在・不調時は fail-closed(平文フォールバックなし・型付きエラー)であり、危険側に壊れない。実 runner での起動スモークは release workflow が毎回行う
8. **リリースノートは GitHub の自動生成**。CHANGELOG ファイルは 1.0 まで新設しない(いま作っても書き手と読者が不在のまま形骸化する。1.0 で再判断)

**Rationale**: 配布の主役はゼロ依存の単体バイナリ(secrets 管理ツールは導入先の環境を選べない)。npm 経路は「Bun ユーザーの `bun install -g maruhi`」と将来の `bunx` 実行が主用途であり、そこでは 1.2MB のバンドル JS が最適で、バイナリ 380MB/リリースを npm に持ち込む理由がない。provenance は npm CLI でしか付けられない実態(bun 未対応)に従い、認証は OIDC で秘密レス化する。beta 依存(effect)の伝播回避はバンドル/コンパイルの副産物として仕様化しておく。

**Consequences**: 運用手順は `docs/RELEASING.md`(所有者の人間タスク: npm org の publish 権限確認と trusted publisher 設定)。PR-4 は GitHub Releases の `maruhi-<target>.tar.gz` + `checksums.txt` を前提に書く。macOS 公証は公開 2〜3 週前に別途(ROADMAP。それまで README でブラウザダウンロード時の Gatekeeper 隔離を案内)。将来の検討残: linux musl / x64-baseline 対象の追加、バイナリへの GitHub artifact attestation、`macos-15-intel` runner の retire(2027-08)時の darwin-x64 スモーク代替。
