# スパイク A 検証結果: フロント基盤(funstack-static + funstack-router + Astryx)

日付: 2026-08-01。ROADMAP Phase 0 の検証スパイク(ADR-0007 / ADR-0013)。
作業場所は `apps/web`(このスパイクは使い捨てコードではなく、Phase 1 の下敷きになりうる骨格として apps/web に残した。捨てる判断も可)。e2e 検証は `apps/web/test/e2e.test.ts`(wrangler dev = Workers Static Assets 実配信 + Playwright/Chromium)で自動化し、**4/4 通過**。

## 使用バージョン(すべて厳密ピン)

react 19.2.8 / react-dom 19.2.8 / @funstack/static 1.2.0 / @funstack/router 1.2.0 / @astryxdesign/{core,cli,build,theme-neutral} 0.2.0 / @stylexjs/stylex 0.19.0 / vite 8.2.0 / @vitejs/plugin-react 6.0.5 / wrangler 4.118.0 / playwright 1.62.1

## 検証項目と結果

### 1. ビルド時 RSC と "use client" 境界 — ✅ 成立

- `vite build` が静的シェル `index.html` + RSC ペイロード(`funstack__/fun__rsc-payload/<hash>.txt`)+ アセットを `dist/public` に出力。サーバーコンポーネント(HomePage / AboutPage)の内容は**ビルド時に RSC ペイロードへ直列化**される(ビルド時刻の埋め込みで確認)
- `"use client"` 境界はペイロード内でモジュール参照(`I["...","CounterCard",...]`)として現れ、クライアント島(カウンタ)はブラウザで hydrate されて動作する
- Astryx の dist は各コンポーネントに `'use client'` ディレクティブを持っており、サーバーモジュール(App.tsx)から直接 import しても正しくクライアント境界になる
- 既定(ssr: false)ではシェルにアプリ本文の HTML は含まれない(マウントポイントのみ)。SEO が要るランディングは `ssr: true` の検討余地(未検証)

### 2. Navigation API 非対応ブラウザの劣化挙動 — ✅ 仕様通り劣化

- funstack-router に `<Link>` は存在せず、**素の `<a>` を Navigation API がインターセプト**する設計。Chromium では SPA 遷移(ページ破棄なし)を e2e で確認
- `<Router fallback="static">` を指定すると、Navigation API 非対応環境では StaticAdapter に切り替わり**全リンクがフルページロード(MPA)**になる。`navigate()` 呼び出しは console.warn。fallback 未指定なら NullAdapter(遷移不能)なので **`fallback="static"` は必須**と考えるべき
- 非対応環境の再現は `delete window.navigation`(Playwright addInitScript)で実施。MPA 劣化後もページ表示は成立(Workers Static Assets の `not_found_handling: "single-page-application"` により `/about` 直リクエストでも index.html が返る)
- 2026 年時点の Navigation API 対応: Chromium 系 + Firefox は対応済み、**Safari が未対応(TP のみ)**のため、Safari ユーザーは当面 MPA 劣化で使うことになる。ダッシュボードとして許容するかは人間の判断(E2EE 復号自体は劣化モードでも動く)

### 3. Astryx プリビルド CSS + テーマの Workers Static Assets 配信 — ✅ 成立

- `@astryxdesign/core/reset.css` + `astryx.css`(プリビルド、cascade layers 付き)を global.css で `@import` → Vite が 1 CSS アセットに束ね、静的配信できる
- ブランドテーマは `apps/web/theme/maruhi.ts`(defineTheme、neutralTheme を extends)を **`astryx theme build` で静的 CSS + JS にプリビルド**し、CSS は import、JS(`__built: true` のテーマオブジェクト)を `<Theme theme={...}>` に渡す。これで**ランタイム CSS 注入なし** = 厳格 CSP と両立
- 検証知見: `defineTheme` の `color.accent`(#C73E3A)は HCT でパレット導出されるため、最終 `--color-accent` は指定 hex そのものではなく導出値(#B22A2B)になる。ブランド色を厳密に一致させたい場合は `tokens: { '--color-accent': [...] }` の明示上書きを使う
- 生成物(maruhi.css / maruhi.js / *.d.ts)はコミットし、`theme:build` スクリプトで再生成。生成 d.ts が oxlint に引っかかるため `apps/web/.oxlintrc.json` の ignorePatterns で除外した

### 4. 厳格 CSP(script-src 'self')— ⚠ 成立(ただし 1 つ回避策が必要)

- **funstack-static 1.2.0 はブートストラップとしてインライン `<script id="_R_">` を index.html に埋め込む**(RSC ペイロードのマニフェスト設定 + エントリの動的 import)。素の `script-src 'self'` ではこれがブロックされ、**アプリが一切起動しない**
- 回避策: ビルド後にそのスクリプトの SHA-256 を計算し、`script-src 'self' 'sha256-...'` を `_headers` に書き出す(`apps/web/scripts/write-headers.ts`、`bun run build` に組み込み済み)。スクリプト内容はペイロードのコンテンツハッシュを含みビルドごとに変わるため、ハッシュ生成は必ずビルドパイプラインに入れる
- この状態で e2e 全機能(hydrate、カウンタ操作、SPA 遷移、テーマ、xstyle)が CSP 違反ゼロで動作
- **人間の判断が必要**: CLAUDE.md は「inline script・eval 禁止」。ハッシュ許可されたインラインスクリプトは実質的に自己配信スクリプトと等価の安全性(改竄されれば実行されない)だが、字義的には inline script。(a) ハッシュ方式を明文化して許容する、(b) upstream(funstack-static)に「ブートストラップの外部ファイル化オプション」を issue / PR する、の二択。b が筋が良い
- 小さな上流バグ: シェルの `<link rel="preload" as="stylesheet">` は無効な `as` 値(正しくは `style`)で、ブラウザが警告を出す(実害は preload が効かないだけ)。upstream 報告候補
- `default-src 'none'` 基調で必要なのは: script-src 'self' + ハッシュ / style-src 'self' / connect-src 'self'(RSC ペイロードの fetch)/ img-src 'self' data: / font-src 'self'

### 5. StyleX コンパイラ(xstyle 用)× Vite — ✅ 成立(重要な訂正あり)

- `@astryxdesign/build/vite` の `astryxStylex` を Vite プラグインに追加し、`stylex.create` + typed tokens(`spacingVars['--spacing-5']`)の xstyle が**静的 CSS(`.xqifx2i { margin-top: var(--spacing-5) }`)にコンパイルされて CSS アセットに追記**されることを確認。computed style で 20px 適用を e2e 検証
- **セッション 01 メモの訂正**: 「コンパイラ未設定だと無警告で無スタイル描画」は @stylexjs/stylex 0.19.0 では不正確。実際は**ビルドは無警告で成功**し、ブラウザで `stylex.create` が **`Unexpected 'stylex.create' call at runtime` を throw してクライアント島ごと描画されない**(コンソールにのみエラー)。つまり「静かな見た目崩れ」ではなく「ビルドは通るがランタイムで全損」。`SPIKE_NO_STYLEX=1 bun run build` で再現可能。CI でビルドが通ってもデプロイが壊れる点は同じなので、**e2e(今回の 4 テスト)を品質ゲートに含めることが実効的な防御**になる
- `astryxStylex` の API は 2 形態あり要注意: `stylexOptions` キーを渡すと **legacy モード**(今回使用。プリビルド CSS 消費 + アプリコードのみコンパイル。出力レイヤは `priority1`)。新形式(オプション直渡し)は `@astryxdesign/core` を **src へ alias するライブラリソースビルド**に切り替え、さらに `transformIndexHtml` でレイヤ順のインライン `<style>` を注入する(funstack-static の HTML 生成には適用されず、かつ CSP と衝突しうる)。**maruhi は legacy モード(プリビルド消費)が正解**。README は新形式を説明していないため、更新時に挙動が変わらないか注意
- dev サーバー(`vite dev`)での StyleX HMR は未検証(ビルド + 配信の検証を優先した)

### 6. エージェント統合・品質ゲート統合 — ✅ 実施(root 統合はメモのみ)

- `astryx init --features agents --agent all` → `apps/web/AGENTS.md` と `apps/web/.claude/CLAUDE.md` を生成(コミット済み)。内容は Astryx の運用規律(div 禁止・トークン強制・discover ワークフロー)で、本リポジトリの CLAUDE.md styling 規律と整合
- `astryx doctor` は全チェック通過(6 passed)。テーマ配線の warning は package.json の `astryx.theme` フィールドで解消。`doctor:astryx` スクリプトとして apps/web に追加済み
- `@stylexjs/eslint-plugin`(0.19.0)は **oxlint の jsPlugins で動く**ことを実証(`stylex/valid-styles` が不正プロパティ・不正値を検出)。ルート `.oxlintrc.json` を変えずに **`apps/web/.oxlintrc.json`(nested config、extends でルートを継承)**で有効化した
- web の vitest プロジェクト(`apps/web/vitest.config.ts`、e2e 4 テスト)を追加。**ルート `vitest.config.ts` にはあえて登録していない**(要ビルド + ブラウザ依存のため、ユニットテストと同じレーンに入れない方がよい)

## 本採用時に統合すべきルート変更

1. `.fallowrc.json`(このブランチで実施済み): `entry` に apps/web のエントリ(funstackStatic の root/app は vite.config の文字列参照で自動検出不能)+ `ignoreDependencies` に @stylexjs/unplugin・@stylexjs/eslint-plugin。**スパイク B / C のブランチも同ファイルの ignorePatterns 行を同一内容で変更しているため、マージ順によっては手動解決が要る**
2. ルート `vitest.config.ts` / `ci.yml`(未実施。提案): web の e2e はビルド成果物前提なので、`bun run --filter @maruhi/web build && bunx vitest run --config apps/web/vitest.config.ts` を CI の独立ステップ(テスト第 7 ステップの後)に足すのが良い。`doctor:astryx` も品質ゲートへ(`bun run doctor` の隣)
3. `bun.lock`: apps/web はワークスペースのためルートロックファイルが更新される(スパイク B / C は standalone install なので競合しない)

## 残った疑問(Phase 1 で解消すべきもの)

1. **CSP とインラインブートストラップの扱い**(上記 4。人間の判断待ち + upstream issue 候補)
2. Safari(Navigation API 未対応)の扱い: MPA 劣化を正式サポートと言うか。劣化モードでの UX(ローダー、フォーム)確認は未実施
3. `ssr: true`(ビルド時フル HTML)モードは未検証。ランディングページで欲しくなる可能性が高い
4. `vite dev` での開発体験(StyleX HMR、Astryx ソースマップ)は未検証
5. Astryx 0.2.0 は 0.x semver。`astryx upgrade` コードモッドの実運用も未検証(更新 PR が最初の機会)
6. react-doctor が apps/web を実検査するようになった(rules gated on)。現状は全通過
7. 実デプロイ(`wrangler deploy` での Static Assets + _headers 反映)は Cloudflare 資格情報がないため未実施。`wrangler dev` でのヘッダ付与までは確認済み
