# GLOSSARY.md — fixed English renderings of maruhi domain terms (ADR-0019)

Authoritative vocabulary for translating Japanese comments/docs and for writing
new text. When an established English identifier already exists in code
(`ensureDeviceStanding`, `appendEntry`, `chainHead`), the comment's translation
uses that identifier's wording rather than this table.

## Domain terms

| 日本語 | English | notes |
|---|---|---|
| 裁定 | ruling | 決定・裁定コードは `ruling X` / `decision X` |
| 所有者 | owner | 「所有者裁定」= "owner ruling" |
| 観測 | observation | 「観測の記録」= "observed record" |
| 追記 | append | 「追記形」= "append-only" |
| 台帳 | ledger | |
| 証跡 | evidence | |
| 鍵 | key | 端末鍵 = device key、予備鍵 = reserve key (DK K7-5)。`master key` は永続化された名前にのみ残す(oxlint 規則と同じ語彙) |
| 端末 | device | |
| 検査 | check | 被覆検査 = coverage check |
| 被覆 | coverage | |
| 経路 | path | 外部通信経路 = outbound path。URL の経路は route |
| 失効 | revocation | 失効する = revoke |
| 境界 | boundary | |
| 儀式 | ceremony | 対話的儀式 = interactive ceremony |
| 識別子 | identifier | |
| 写像 | mapping | |
| 語彙 | vocabulary | |
| 様式 | format | 表記様式 = notation |
| 回復 | recovery | |
| 埋め込み | embedding / embedded | |
| 引き継ぎ | handoff | |
| 委譲 | delegation | |
| 起票 / 起こす | file / record | 「ROADMAP に起こす」= "filed on the ROADMAP" |
| 紐付け | binding / association | |
| 足場 | scaffolding | |
| 上流 | upstream | |
| 既定 | default | |
| 正 / 唯一の正 | source of truth | 「唯一の正」= "the single source of truth" |
| 硬 / 柔 | strict / lenient | presence 硬 = presence-strict |
| 正例 / 負例 | positive case / negative case | |
| 在籍区間 | membership interval | |
| 宣言ヘッド | declared head | |
| 見出し | heading | |
| 規定文言 | prescribed wording | |
| 分片 | segment | 論理分片 = logical segment |
| 畳む | fold | |
| 名指し | naming specifically | |
| 道連れ | updated collaterally | 「道連れに更新」= "updated collaterally" |
| 握り潰す | swallow | エラーを握り潰す = swallow an error |
| 差し替え点 | substitution point | |
| 運用 | operation / operations | |
| 観点 | consideration | |
| 残存 / 残り | remaining | |
| 据え置き | kept as-is | |
| 再裁定 | re-ruling | |

## Do-not-translate tokens (kept verbatim)

Cross-reference codes and identifiers stay exactly as written — code and tests
cite them:

- Ruling / era codes: `DK`, `ES`, `KL3`, `IV`, `K15` (and other `K\d` codes),
  `DP1`–`DP5`, `BU`, `B-b`, `BM`, `PF1`, `W2`, `H0`, `H3`, `E` (追補 E →
  "supplement E")
- `§` section references (e.g. `§6.3`, `§4-4`, `§1-2`) — keep the `§` notation
  and numbering verbatim even when the referenced document is translated; the
  section numbering does not change
- `session-NN` references into `docs/notes/`
- `ADR-NNNN` identifiers, file paths, command names (`maruhi pull`), type and
  identifier names
- The brand glyph ㊙ (U+3299) where it names the maruhi mark

## Style rules for translated comments

- Keep the comment in the same position and roughly the same line grouping as
  the original; do not reflow surrounding code
- Translate `describe` / `it` / assertion-failure messages in tests like any
  other text
- A string that is **data** (fixtures exercising non-ASCII handling, recorded
  payloads) is not translated — mark the line `english-exempt: <reason>`
- Sentences keep their parenthesized side-notes as parentheses
- Existing English fragments inside Japanese comments stay as they are
