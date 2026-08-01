# spike-c(使い捨て検証コード)

ROADMAP Phase 0 スパイク C: E2EE ラウンドトリップ + HPKE ライブラリ選定(CRYPTO_SPEC 未決事項 #1)。

**これは製品コードではない。** 検証結果は `docs/notes/spike-c.md` を参照。
`packages/crypto` には仕様承認・人間レビューを経るまで一切コードを置かない。

実行方法:

```sh
cd spikes/spike-c
bun install
bunx playwright install chromium   # browser プロジェクト用(初回のみ)
bun run test                       # node / workerd / browser の 3 プロジェクト
bun run test:bun-runtime           # Bun ランタイム実環境での検証
```
