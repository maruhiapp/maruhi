// 固定長 hex 小文字文字列の Schema ヘルパ(チェーン・データプレーン共用)。

import { Schema } from "effect";

/** Schema for an exact-length lowercase-hex string (`bytes` decoded bytes). */
export function hexString(bytes: number): Schema.String {
  return Schema.String.check(
    Schema.isPattern(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), {
      description: `lowercase hex (${bytes} bytes)`,
    }),
  );
}
