# ADR-0003: ライセンスは FSL-1.1-MIT(サーバー)+ MIT(CLI/SDK/crypto)【仮決定・公開前に最終確認】

**Status**: Accepted(仮決定・公開前に最終確認)
**Context**: 第三者による競合クラウドサービス化を禁じたい。AGPL では提供自体は禁止できない。
**Decision**: サーバー = FSL-1.1-MIT(競合利用のみ禁止、2 年後に MIT へ自動変換)。CLI / SDK / crypto = MIT。
**Rationale**: セルフホスト・自己利用は許可しつつ競合 SaaS を禁止できる唯一の要件適合。2 年後 MIT 変換は「作者が消えても資産は残る」という信頼の物語になる。
**Consequences**: OSI の「オープンソース」を名乗らない(source-available / Fair Source と表現)。公開時に DCO + CONTRIBUTING.md のライセンス条項が必須。公開まではクローズド開発。
