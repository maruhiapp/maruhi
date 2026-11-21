import { Schema } from "effect";

import { recordKeysMatch } from "./json-record.ts";

export const BOOK_KEY = /^[A-Za-z0-9]\S{0,1023}$/;

export function originBookSchema<V extends number, Users extends Schema.Top>(
  version: V,
  users: Users,
) {
  return Schema.Struct({
    v: Schema.Literal(version),
    known: Schema.Record(
      Schema.String,
      Schema.Record(Schema.String, users).check(recordKeysMatch(BOOK_KEY)),
    ).check(recordKeysMatch(BOOK_KEY)),
  });
}
