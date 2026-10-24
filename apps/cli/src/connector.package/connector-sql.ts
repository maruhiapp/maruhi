// The `postgres` and `mysql` connectors (the connector overview lives in
// connector.ts): a new password, set with ALTER ROLE / ALTER USER over the
// admin connection (the SqlRunner service) on the alternated role not in
// use, or on the URL's own role in place, then a connection test of the
// new URL. Finalize gives the previous role a random password nobody holds
// or discards MySQL's secondary password; a Postgres role changed in place
// leaves nothing to finalize.
//
// The SqlRunner service and the password generation, with the byte source
// it draws from (ConnectorCrypto), live here: no other connector uses them.

import { Context, Effect } from "effect";

import {
  ConnectorError,
  type ConnectorOutcome,
  type CredentialValues,
  type FinalizeOutcome,
  reasonOf,
  type RotateInputs,
  type RotationPlan,
} from "./connector-shared.ts";
import type { RotateRule } from "./rotate-config.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/** Runs statements on a database (production: Bun's SQL client — live.ts; tests: a recorder). */
export interface SqlRunnerShape {
  /** Connects with `url`, runs the statements in order on one connection, disconnects. */
  readonly execute: (url: string, statements: readonly string[]) => Promise<void>;
  /** Connects with `url` and runs a trivial query (the connection test of a new credential). */
  readonly probe: (url: string) => Promise<void>;
}

export class SqlRunner extends Context.Service<SqlRunner, SqlRunnerShape>()("cli/SqlRunner") {}

/**
 * The byte source the connectors' password generation draws from
 * (production: WebCrypto's CSPRNG; tests: a deterministic filler). Effect's
 * own `Random` is deliberately not the answer — it is not cryptographically
 * secure, and the generated strings are credentials.
 */
interface ConnectorCryptoShape {
  readonly nextBytes: (length: number) => Uint8Array;
}

export class ConnectorCrypto extends Context.Reference<ConnectorCryptoShape>(
  "cli/ConnectorCrypto",
  {
    defaultValue: (): ConnectorCryptoShape => ({
      nextBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
    }),
  },
) {}

const PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LENGTH = 32;

/** 32 alphanumerics drawn without modulo bias (rejection sampling over 62 symbols). */
export function generatePassword(randomBytes: (length: number) => Uint8Array): string {
  const limit = 256 - (256 % PASSWORD_ALPHABET.length);
  let out = "";
  while (out.length < PASSWORD_LENGTH) {
    const bytes = randomBytes(PASSWORD_LENGTH);
    for (const byte of bytes) {
      if (byte < limit && out.length < PASSWORD_LENGTH) {
        out += PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length];
      }
    }
  }
  return out;
}

interface DbUrl {
  readonly url: URL;
  readonly user: string;
}

const DB_NAME = /^[A-Za-z0-9_.@-]{1,128}$/;

/** Parses a database URL and takes its (decoded) user; refuses one without credentials. */
function parseDbUrl(
  bytes: Uint8Array,
  scheme: "postgres" | "mysql",
): Effect.Effect<DbUrl, ConnectorError> {
  let url: URL;
  try {
    url = new URL(decoder.decode(bytes));
  } catch {
    return new ConnectorError({
      message: `the ${scheme} connector expects the variable to hold a connection URL`,
    });
  }
  const protocol = url.protocol.replace(/:$/, "");
  const accepted =
    scheme === "postgres" ? ["postgres", "postgresql"] : ["mysql", "mysql2", "mariadb"];
  if (!accepted.includes(protocol)) {
    return new ConnectorError({
      message: `the ${scheme} connector expects a ${accepted.join(" / ")} URL (the variable's URL has another scheme)`,
    });
  }
  const user = decodeURIComponent(url.username);
  if (user.length === 0) {
    return new ConnectorError({
      message: `the ${scheme} connector needs a user in the connection URL`,
    });
  }
  if (!DB_NAME.test(user)) {
    return new ConnectorError({
      message: `the ${scheme} connector supports role names of letters, digits, _ . @ - only (the URL's user is outside that set)`,
    });
  }
  return Effect.succeed({ url, user });
}

function withCredentials(base: URL, user: string, password: string): string {
  const url = new URL(base.toString());
  url.username = user;
  url.password = password;
  return url.toString();
}

/** The role the rotation sets a password on: the other one of an alternated pair, or the URL's own. */
function nextRole(
  rule: Extract<RotateRule, { connector: "postgres" | "mysql" }>,
  current: string,
): Effect.Effect<string, ConnectorError> {
  if (rule.roles === null) {
    return Effect.succeed(current);
  }
  const [first, second] = rule.roles;
  if (current === first) {
    return Effect.succeed(second);
  }
  if (current === second) {
    return Effect.succeed(first);
  }
  return new ConnectorError({
    message: `the connection URL's user is neither of the alternated roles in the rotation config (${first}, ${second})`,
  });
}

function pgIdentifier(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

function pgLiteral(text: string): string {
  return `'${text.replaceAll("'", "''")}'`;
}

function mysqlAccount(user: string, host: string): string {
  return `${mysqlLiteral(user)}@${mysqlLiteral(host)}`;
}

function mysqlLiteral(text: string): string {
  return `'${text.replaceAll("\\", "\\\\").replaceAll("'", "''")}'`;
}

function adminUrlOf(inputs: RotateInputs, current: DbUrl): string {
  const admin = inputs["adminUrl"];
  return admin === undefined ? current.url.toString() : decoder.decode(admin);
}

function describeSqlFailure(stage: string, error: unknown): ConnectorError {
  const reason = reasonOf(error, "unknown failure");
  // A driver message can echo the connection URL; keep only the first line
  // and strip anything that looks like a URL with credentials
  const line =
    reason.split("\n")[0]?.replace(/[a-z0-9+.-]+:\/\/[^\s]+/gi, "<url>") ?? "unknown failure";
  return new ConnectorError({ message: `${stage}: ${line}` });
}

export const dbPlan = Effect.fn("connector-sql.dbPlan")(function* (
  rule: Extract<RotateRule, { connector: "postgres" | "mysql" }>,
  current: CredentialValues,
): Effect.fn.Return<RotationPlan, ConnectorError> {
  const parsed = yield* parseDbUrl(current.primary, rule.connector);
  const role = yield* nextRole(rule, parsed.user);
  if (rule.roles !== null) {
    return {
      description: `set a new password on role ${role} (role ${parsed.user} keeps its password until you finalize)`,
      immediate: false,
    };
  }
  return rule.connector === "mysql"
    ? {
        description: `set a new password on account ${parsed.user}@${rule.host}, keeping the current one as a secondary password until you finalize`,
        immediate: false,
      }
    : {
        description: `change the password of role ${role} in place — the current password stops working at once (no grace period; alternate two roles to get one)`,
        immediate: true,
      };
});

/** Runs the statements against the admin connection (the SqlRunner service — Bun's SQL client or a test recorder). */
const sqlExecute = Effect.fn("connector-sql.sqlExecute")(function* (
  url: string,
  statements: readonly string[],
  stage: string,
): Effect.fn.Return<void, ConnectorError, SqlRunner> {
  const sql = yield* SqlRunner;
  yield* Effect.tryPromise({
    try: () => sql.execute(url, statements),
    catch: (error) => describeSqlFailure(stage, error),
  });
});

export const rotatePostgres = Effect.fn("connector-sql.rotatePostgres")(function* (
  rule: Extract<RotateRule, { connector: "postgres" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<ConnectorOutcome, ConnectorError, SqlRunner> {
  const parsed = yield* parseDbUrl(current.primary, "postgres");
  const role = yield* nextRole(rule, parsed.user);
  const password = generatePassword((yield* ConnectorCrypto).nextBytes);
  const statement = `ALTER ROLE ${pgIdentifier(role)} WITH PASSWORD ${pgLiteral(password)}`;
  yield* sqlExecute(
    adminUrlOf(inputs, parsed),
    [statement],
    `postgres: setting the password of role ${role} failed`,
  );
  const value = withCredentials(parsed.url, role, password);
  const warnings = yield* probe(value, `postgres: the new credential of role ${role}`);
  return {
    values: { primary: encoder.encode(value), companions: {} },
    facts: [
      rule.roles === null ? `role ${role}: password changed in place` : `role ${role} now in use`,
    ],
    previous:
      rule.roles === null
        ? "the previous password stopped working when the change was applied (nothing to finalize)"
        : `role ${parsed.user} keeps its previous password until you finalize`,
    recovery:
      rule.roles === null
        ? `role ${role}'s password is now one nobody holds — an admin sets a new one (ALTER ROLE ${pgIdentifier(role)} WITH PASSWORD …) and pushes the URL with it`
        : `re-running the rotation sets another password on role ${role} (role ${parsed.user} is untouched)`,
    warnings,
  };
});

export const rotateMysql = Effect.fn("connector-sql.rotateMysql")(function* (
  rule: Extract<RotateRule, { connector: "mysql" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<ConnectorOutcome, ConnectorError, SqlRunner> {
  const parsed = yield* parseDbUrl(current.primary, "mysql");
  const role = yield* nextRole(rule, parsed.user);
  const password = generatePassword((yield* ConnectorCrypto).nextBytes);
  const retain = rule.roles === null ? " RETAIN CURRENT PASSWORD" : "";
  const statement = `ALTER USER ${mysqlAccount(role, rule.host)} IDENTIFIED BY ${mysqlLiteral(password)}${retain}`;
  yield* sqlExecute(
    adminUrlOf(inputs, parsed),
    [statement],
    `mysql: setting the password of ${role}@${rule.host} failed`,
  );
  const value = withCredentials(parsed.url, role, password);
  const warnings = yield* probe(value, `mysql: the new credential of ${role}@${rule.host}`);
  return {
    values: { primary: encoder.encode(value), companions: {} },
    facts: [
      rule.roles === null
        ? `account ${role}@${rule.host}: new primary password set, previous kept as secondary`
        : `account ${role}@${rule.host} now in use`,
    ],
    previous:
      rule.roles === null
        ? "the previous password keeps working as the account's secondary password until you finalize"
        : `account ${parsed.user}@${rule.host} keeps its previous password until you finalize`,
    recovery:
      rule.roles === null
        ? `the primary password of ${role}@${rule.host} is now one nobody holds while the previous one still works as the secondary — an admin sets a new primary without RETAIN CURRENT PASSWORD (ALTER USER ${mysqlAccount(role, rule.host)} IDENTIFIED BY …; the secondary stays) and pushes the URL with it. Do not re-run the rotation first: RETAIN would keep the lost password and drop the working one`
        : `re-running the rotation sets another password on ${role}@${rule.host} (${parsed.user}@${rule.host} is untouched)`,
    warnings,
  };
});

/** The connection test of a new credential: a failure is a warning, never a refusal (the issuer accepted the change). */
const probe = Effect.fn("connector-sql.probe")(function* (
  url: string,
  what: string,
): Effect.fn.Return<readonly string[], never, SqlRunner> {
  const sql = yield* SqlRunner;
  return yield* Effect.tryPromise({
    try: () => sql.probe(url),
    catch: (error) =>
      describeSqlFailure(
        `${what} was set at the server but a connection test with it failed`,
        error,
      ),
  }).pipe(
    Effect.map(() => [] as readonly string[]),
    Effect.catchTag("ConnectorError", (error) =>
      Effect.succeed([`${error.message} — check the new value before finalizing`]),
    ),
  );
});

export const finalizePostgres = Effect.fn("connector-sql.finalizePostgres")(function* (
  rule: Extract<RotateRule, { connector: "postgres" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<FinalizeOutcome, ConnectorError, SqlRunner> {
  if (rule.roles === null) {
    return {
      kind: "nothing" as const,
      facts: ["an in-place password change left nothing to finalize"],
    };
  }
  const before = yield* parseDbUrl(previous.primary, "postgres");
  const now = yield* parseDbUrl(current.primary, "postgres");
  if (before.user === now.user) {
    return {
      kind: "nothing" as const,
      facts: [`role ${now.user} is in use by both versions (nothing to invalidate)`],
    };
  }
  const scrambled = generatePassword((yield* ConnectorCrypto).nextBytes);
  const statement = `ALTER ROLE ${pgIdentifier(before.user)} WITH PASSWORD ${pgLiteral(scrambled)}`;
  yield* sqlExecute(
    adminUrlOf(inputs, now),
    [statement],
    `postgres: invalidating the password of role ${before.user} failed`,
  );
  return {
    kind: "finalized" as const,
    facts: [`role ${before.user}: password replaced by a random one nobody holds`],
  };
});

export const finalizeMysql = Effect.fn("connector-sql.finalizeMysql")(function* (
  rule: Extract<RotateRule, { connector: "mysql" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<FinalizeOutcome, ConnectorError, SqlRunner> {
  const now = yield* parseDbUrl(current.primary, "mysql");
  if (rule.roles === null) {
    const statement = `ALTER USER ${mysqlAccount(now.user, rule.host)} DISCARD OLD PASSWORD`;
    yield* sqlExecute(
      adminUrlOf(inputs, now),
      [statement],
      `mysql: discarding the secondary password of ${now.user}@${rule.host} failed`,
    );
    return {
      kind: "finalized" as const,
      facts: [`account ${now.user}@${rule.host}: secondary password discarded`],
    };
  }
  const before = yield* parseDbUrl(previous.primary, "mysql");
  if (before.user === now.user) {
    return {
      kind: "nothing" as const,
      facts: [`account ${now.user} is in use by both versions (nothing to invalidate)`],
    };
  }
  const scrambled = generatePassword((yield* ConnectorCrypto).nextBytes);
  const statement = `ALTER USER ${mysqlAccount(before.user, rule.host)} IDENTIFIED BY ${mysqlLiteral(scrambled)}`;
  yield* sqlExecute(
    adminUrlOf(inputs, now),
    [statement],
    `mysql: invalidating the password of ${before.user}@${rule.host} failed`,
  );
  return {
    kind: "finalized" as const,
    facts: [`account ${before.user}@${rule.host}: password replaced by a random one nobody holds`],
  };
});
