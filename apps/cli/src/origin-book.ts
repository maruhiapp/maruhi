// Decoding of the shared outer frame of the local book files keyed origin → user_id
// (known-fingerprints.json, own-devices.json). A single invalid record makes the whole
// file count as corrupt (no partial reads — same as pins).

// Record-key (origin / user_id) discipline: starts with an alphanumeric (like the
// invite id in pins.ts, this structurally excludes `__proto__`) and contains no
// whitespace. origin is a normalized URL (http(s)://…) and user_id is server-assigned
// — the rule depends on neither format
export const BOOK_KEY = /^[A-Za-z0-9]\S{0,1023}$/;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decodes `{ v: version, known: { origin: users } }`. `decodeUsers` reads one origin's
 * entry (user_id → contents) and returns null when it is invalid.
 */
export function decodeOriginBook<Users>(
  json: string,
  version: number,
  decodeUsers: (value: unknown) => Users | null,
): Record<string, Users> | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== version || !isRecord(value["known"])) {
    return null;
  }
  const known: Record<string, Users> = {};
  for (const [origin, rawUsers] of Object.entries(value["known"])) {
    const users = BOOK_KEY.test(origin) ? decodeUsers(rawUsers) : null;
    if (users === null) {
      return null;
    }
    known[origin] = users;
  }
  return known;
}
