-- W3a(AUTH_SPEC §6 既定 TTL — SECURITY_REVIEW 2026-08-14 L-2 の解消)の移行:
-- 既存の無期限トークン(expires_at IS NULL)へ「適用時点 + 既定 TTL(90 日)」を
-- 再アンカーする(裁定 CE — docs/notes/session-44.md)。
--
-- - 発行時起点(created_at + 90 日)ではなく適用時点起点にするのは、90 日より
--   古い既存トークンを適用と同時に即死させない(静かな一斉停止を作らない)ため。
--   利用者には 90 日の再ログイン猶予が残り、期限は一覧 API / CLI で可視になる
-- - 本移行の後、expires_at が NULL の行は書き込み経路から二度と生まれない
--   (発行は常に expires_at を固定する)。移行を適用せず新コードだけを
--   デプロイした場合も、検証側が NULL を期限切れとして扱う(fail-closed —
--   apps/server/src/auth.package/token.ts の toPrincipal)ため無期限には戻らない
-- - 90 日 = 7776000000 ms。セルフホストで既定 TTL を調整する場合も、本移行は
--   過去の無期限行の有界化という一回性の処理であり合意規則ではない(§6)
UPDATE api_tokens
SET expires_at = (unixepoch('now') * 1000) + 7776000000
WHERE expires_at IS NULL;
