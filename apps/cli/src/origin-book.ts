// The shared outer frame of the local book files keyed origin → user_id
// (known-fingerprints.json, own-devices.json): `{ v: version, known:
// { origin: { userId: users } } }` as one Schema. A single invalid record
// makes the whole file count as corrupt (no partial reads — same as pins).

import { Schema } from "effect";

import { recordKeysMatch } from "./json-record.ts";

// Record-key (origin / user_id) discipline: starts with an alphanumeric (like the
// invite id in pins.ts, this structurally excludes `__proto__`) and contains no
// whitespace. origin is a normalized URL (http(s)://…) and user_id is server-assigned
// — the rule depends on neither format
export const BOOK_KEY = /^[A-Za-z0-9]\S{0,1023}$/;

/**
 * The schema of `{ v: version, known: { origin: { user_id: users } } }`.
 * `users` describes one origin's entry (user_id → contents); origin and
 * user_id keys are checked at each level (a bad key rejects the whole file).
 */
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
