# ADR-0009: 認証は GitHub OAuth 直接実装、WorkOS は不採用(再判断ポイント付き)

**Context**: 将来のエンタープライズと無料ユーザー増を見据え WorkOS 採用を検討した。
**Decision**: コア認証は GitHub OAuth(web + device flow)の直接実装。Better Auth 等のフレームワークも不使用。ただし AUTH_SPEC の 6 項目(内部 user_id 主キー、メール検証 + 自動リンク禁止、org のファーストクラス化、DB バックセッション、maruhi 発行トークン、冪等 get-or-create)により将来の IdP 追加を無停止で可能に保つ。
**Rationale**: セルフホスト版は外部依存なしが製品価値でありGitHub 直実装が必須。同一コードベース戦略のため WorkOS は削減ではなく純増になる。自前実装の範囲は OAuth クライアント + セッション + トークンの数百行で、危険物(パスワード等)を含まない。Better Auth はスキーマ所有がE2EE 主導のユーザーモデル設計と衝突。
**Consequences**: 再判断ポイント: ホステッド版の着工日。メンバーシップチェーンにプロバイダ情報を書かないことが最重要の不可逆制約(CRYPTO_SPEC §6.1)。
