# K0 スパイク: IV2 の裏付け元(GitHub 署名鍵 API / `gh ssh-key add`)— 所有者の手元で実施する項目

Status: 2026-09-13 — IV(補足 21)の K0。**本環境(Claude Code のリモート実行環境)からは `api.github.com` のユーザー系パスがプロキシで遮断され、実測できなかった**(403 "sessions are bound to their configured repositories")。K5 は GitHub の公開文書に基づいて実装し、テストは偽サーバー(`test/support/invite.ts` の `githubSigningKeysHandler`)で固定した。本ノートは「何を前提に実装したか」と「所有者が手元で確かめる項目」の一覧で、結果で文面を補正する(補足 21-5 の残)。

## 0. 実装が前提にしたこと(未検証 — 文書知識)

| 項目 | 実装の前提 | 出典 | 検証の種別 |
|---|---|---|---|
| エンドポイント | `GET https://api.github.com/users/{login}/ssh_signing_keys`(無認証・公開情報) | GitHub REST API docs「List SSH signing keys for a user」 | **未検証** |
| 応答の形 | JSON 配列。各要素は `{ id, key, title, created_at }` で、`key` は `ssh-ed25519 AAAA…` の OpenSSH 公開鍵行(コメント欄の有無は問わない) | 同上 | **未検証**(実装は `key` 以外の欄を読まない。`ssh-ed25519` 以外の種別は読み飛ばす) |
| 存在しない login | 404 | 同上 | **未検証** |
| 無認証の上限 | 60 回 / 時 / IP(超過は 403 または 429) | GitHub docs「Rate limits for the REST API」 | **未検証**(実装は 403 / 429 を「取得不能(rate limited)」として儀式へ戻す) |
| `HTTPS_PROXY` 下の Bun fetch | Effect の `FetchHttpClient` = Bun の fetch。Bun はプロキシ環境変数を読む(起動時の警告 "Proxy environment variables detected" で確認) | Bun docs | **未検証**(本環境ではプロキシが**遮断**した = 遮断時の挙動〔transport error → 儀式へ〕は実測済み) |
| `gh ssh-key add` | `gh ssh-key add - --type signing --title "maruhi <fp>"` で stdin から鍵を読む。必要スコープは `admin:ssh_signing_key`(`gh auth refresh -s admin:ssh_signing_key`) | gh manual | **未検証**(gh は本環境に無い。テストは ProcessRunner の偽装) |
| 遮断・オフライン時 | 10 秒のタイムアウト → 「取得不能」→ 儀式へ(note) | — | **検証済み**(ユニットテスト: transport 失敗・500・形違い) |

## 1. 所有者が手元で確かめる項目(チェックリスト)

1. **応答の形**: `curl -s https://api.github.com/users/<自分の login>/ssh_signing_keys` — 配列であること、`key` が `ssh-ed25519 …` 行であること、コメント欄(`title` とは別)が付くかどうか。→ 付くなら `parseOpenSshEd25519PublicKey` は 3 つ目以降のフィールドを無視するので問題ない(ベクター `invite-link.json` の `openssh.parse` に comment 付きの正例あり)
2. **404**: 存在しない login で 404 が返ること(実装は `no-user`)
3. **上限**: 連続 61 回目の応答(403 / 429)と `retry-after` / `x-ratelimit-reset` ヘッダ。→ 実装は待たずに儀式へ戻る。`member add` は稀なので上限に当たらない想定だが、CI 等の共有 IP では当たりうる — その場合の文言「github.com answered 403 (rate limited)」が実態に合うか
4. **プロキシ**: `HTTPS_PROXY` を設定した端末で `maruhi member add --github <login>` が GitHub に到達するか(Bun の fetch がプロキシを使うか)。到達しない場合は「could not reach github.com (…)」の note で儀式へ戻ることを確認
5. **`maruhi key publish --gh`**: `gh auth login` 済みの端末で実行 → GitHub の Settings → SSH and GPG keys に **Signing keys** として `maruhi <fp>` が並ぶこと。スコープ不足の失敗文言(実装は `gh auth refresh -s admin:ssh_signing_key` を案内)が gh の実際のエラーと噛み合うか
6. **往復**: 2 アカウントで `invite create --github` → `invite accept --from` → `member add` が **プロンプトなし**で通ること(充足形 4)。片方が未登録のときの二択(`member add`)と、受諾側のフォールバック(12 語)も一度ずつ
7. **鍵の再生成**: `key generate` をやり直したアカウントで古い登録が残っていると照合が外れて儀式へ落ちる — 案内文(「If an older key of yours from maruhi is registered there, remove it」)で足りるか

## 2. 結果で補正する箇所

- `apps/cli/src/github-signing-keys.ts` の `describeBackingFallback` / `fetchSigningKeys` の文言(上限・形違い)
- `apps/cli/src/key-publish.ts` の gh 失敗時の案内
- `apps/site/docs/invite-a-teammate.mdx`(「Before you start」の手順、`--gh` の前提)
- 補足 21-5(実装録)の「未検証」を「検証済み」へ
