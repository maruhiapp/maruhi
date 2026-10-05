// The connector frame of `maruhi var rotate` (PF6 — integration-options.md
// §4 option R2, §7 part ② "the connector frame is a client implementation";
// docs/notes/pf6-design.md rulings R2 / R3 / R4): the member's CLI creates a
// new credential at the issuer, the caller pushes it signed as the writer,
// and the old credential stays valid until `--finalize` invalidates it (the
// dual-credential grace period every competitor converged on — Infisical's
// active / inactive slots, Pulumi ESC's current / previous, AWS Secrets
// Manager's AWSCURRENT / AWSPREVIOUS).
//
// Four connectors:
//   - `aws-iam-access-key`: CreateAccessKey (reclaiming an inactive second
//     key first — IAM allows two); finalize = UpdateAccessKey Inactive on the
//     previous key (reversible; the next rotation deletes an inactive key)
//   - `cloudflare-api-token`: a second token with the same policies
//     (create-new-then-delete-old — a roll would invalidate the old value at
//     once); finalize = DELETE the previous token
//   - `postgres`: two roles alternated (ALTER ROLE … PASSWORD on the one not
//     in use; finalize scrambles the previous role's password), or one role
//     in place (no grace — the password changes at once, and the caller asks
//     for confirmation)
//   - `mysql`: the same two shapes, plus MySQL 8's dual password for the
//     in-place one (RETAIN CURRENT PASSWORD; finalize = DISCARD OLD PASSWORD)
//
// The issuer's admin credential is a maruhi variable decrypted into memory
// by the caller (never on the server, never on disk); with no admin input
// the credential rotates itself. New passwords are generated here from
// `crypto.getRandomValues` (32 alphanumerics — URL-safe and quote-safe).
//
// Why this is not a CRYPTO_SPEC operation: every call here is a client of a
// third party's own protocol on the member's behalf (CRYPTO_SPEC §12's scope
// note, class (b)); maruhi's data is touched only by the caller's ordinary
// signed push.
//
// Error wording carries the connector, the issuer's status code and
// message — never a credential, a password, or a URL with a password in it.

import { Clock, Context, Data, Effect, type Layer, Redacted, Schema } from "effect";
import {
  HttpBody,
  HttpClient,
  HttpClientError,
  HttpClientRequest,
  HttpClientResponse,
} from "effect/http";

import { countNoun, decodeValueText, displayText } from "./display.ts";
import { companionVariablesOf, EXEC_CONTROL_PREFIX, type RotateRule } from "./rotate-config.ts";
import {
  type CaptureOutcome,
  ProcessRunner,
  ScriptLeftoverError,
  ScriptStoppedError,
} from "./run.ts";
import { type AwsCredentials, signV4 } from "./sigv4.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync.package/index.ts";
import { CLI_VERSION } from "./version.ts";

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
 * The issuer API origins a run targets (production: the fixed hosts; the
 * rotate seams — `rotateDeps` in var-rotate.ts — redirect them in tests).
 */
interface IssuerEndpointsShape {
  readonly awsIamBase?: string | undefined;
  readonly awsStsBase?: string | undefined;
  readonly cloudflareBase?: string | undefined;
}

export class IssuerEndpoints extends Context.Reference<IssuerEndpointsShape>(
  "cli/IssuerEndpoints",
  {
    defaultValue: (): IssuerEndpointsShape => ({}),
  },
) {}

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

/**
 * What the caller provides around the connector call: the test seams
 * expressed as service overrides (`rotateDeps` in var-rotate.ts builds it;
 * production passes `Layer.empty` — the ambient `HttpClient`, `SqlRunner`,
 * `ProcessRunner` and the references' defaults answer).
 */
export type RotateDeps = Layer.Layer<never>;

/** The services a connector run requires. */
export type ConnectorServices = HttpClient.HttpClient | SqlRunner | ProcessRunner;

/**
 * The values every earlier version of a companion variable held (newest
 * first), each lineage-verified against the verified latest. A finalize
 * invalidates a credential the issuer lists only when one of these held
 * its id — the server's history metadata never picks the target.
 */
export type CompanionAncestors = Readonly<Record<string, readonly Uint8Array[]>>;

/** The decrypted inputs a connector consumes (input name → bytes). Empty = self-rotation. */
export type RotateInputs = Readonly<Record<string, Uint8Array>>;

/**
 * Where the rotation happens — the rule's variable and the environment
 * (the `exec` connector hands both to its scripts; the other connectors
 * do not need them).
 */
export interface RotationSite {
  readonly variable: string;
  readonly environmentId: string;
}

/** One credential as stored: the rule's variable and its companions (the AWS access key id). */
export interface CredentialValues {
  readonly primary: Uint8Array;
  readonly companions: Readonly<Record<string, Uint8Array>>;
}

/** What a rotation will do, decided before anything is sent (the caller confirms an immediate invalidation). */
export interface RotationPlan {
  /** What changes at the issuer, in one line (no credential). */
  readonly description: string;
  /** true = the old credential stops working as part of the rotation itself (no grace period). */
  readonly immediate: boolean;
}

export interface RotationOutcome {
  /** The new values to push (the primary and every companion the rule names). */
  readonly values: CredentialValues;
  /** The primary's shape ({@link shapeOf}) — for the local report; never a proposal fact. */
  readonly shape: ValueShape;
  /** Each companion's shape by name, for the same report. */
  readonly companionShapes: Readonly<Record<string, ValueShape>>;
  /** The current primary's shape, for the same report: a new value of another line count is worth a look before it is pushed (D-16 — a leftover's line is the common form). */
  readonly currentShape: ValueShape;
  /** Non-secret facts for the report (the new key id, the role now in use, the token id). */
  readonly facts: readonly string[];
  /** What the previous credential's state is now, in one line. */
  readonly previous: string;
  /**
   * How to recover when the issuer accepted the change but storing the new
   * value failed (the new credential is then held only by the process that
   * is about to exit): the issuer-specific step, in one line.
   */
  readonly recovery: string;
  /** Warnings (a connection test that failed after the issuer accepted the change). */
  readonly warnings: readonly string[];
}

export interface FinalizeOutcome {
  readonly kind: "finalized" | "already" | "nothing";
  readonly facts: readonly string[];
}

/** A connector failure the caller reports as-is (the message never carries a credential). */
export class ConnectorError extends Data.TaggedError("ConnectorError")<{
  readonly message: string;
}> {}

const USER_AGENT = `maruhi-cli/${CLI_VERSION}`;

/** An unknown thrown value's message (a fetch rejection, a driver error — the reason, never a credential). */
function reasonOf(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

/**
 * The message an `HttpClientError` carries: the transport's own cause (the
 * fetch rejection — a refused connection, a DNS failure) when it has one,
 * the client's wording ("Transport error", "Decode error"…) otherwise.
 */
function transportReason(error: HttpClientError.HttpClientError): string {
  return reasonOf(error.reason.cause, reasonOf(error, "request failed"));
}

/* -------------------------------------------------------------------------- */
/* Passwords                                                                    */
/* -------------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------- */
/* Databases (postgres / mysql)                                                  */
/* -------------------------------------------------------------------------- */

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

function dbPlan(
  rule: Extract<RotateRule, { connector: "postgres" | "mysql" }>,
  current: CredentialValues,
): Effect.Effect<RotationPlan, ConnectorError> {
  return Effect.gen(function* () {
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
}

/** Runs the statements against the admin connection (the SqlRunner service — Bun's SQL client or a test recorder). */
function sqlExecute(
  url: string,
  statements: readonly string[],
  stage: string,
): Effect.Effect<void, ConnectorError, SqlRunner> {
  return Effect.gen(function* () {
    const sql = yield* SqlRunner;
    yield* Effect.tryPromise({
      try: () => sql.execute(url, statements),
      catch: (error) => describeSqlFailure(stage, error),
    });
  });
}

function rotatePostgres(
  rule: Extract<RotateRule, { connector: "postgres" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<ConnectorOutcome, ConnectorError, SqlRunner> {
  return Effect.gen(function* () {
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
}

function rotateMysql(
  rule: Extract<RotateRule, { connector: "mysql" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<ConnectorOutcome, ConnectorError, SqlRunner> {
  return Effect.gen(function* () {
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
}

/** The connection test of a new credential: a failure is a warning, never a refusal (the issuer accepted the change). */
function probe(url: string, what: string): Effect.Effect<readonly string[], never, SqlRunner> {
  return Effect.gen(function* () {
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
}

function finalizePostgres(
  rule: Extract<RotateRule, { connector: "postgres" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<FinalizeOutcome, ConnectorError, SqlRunner> {
  return Effect.gen(function* () {
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
}

function finalizeMysql(
  rule: Extract<RotateRule, { connector: "mysql" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<FinalizeOutcome, ConnectorError, SqlRunner> {
  return Effect.gen(function* () {
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
      facts: [
        `account ${before.user}@${rule.host}: password replaced by a random one nobody holds`,
      ],
    };
  });
}

/* -------------------------------------------------------------------------- */
/* AWS IAM access keys                                                           */
/* -------------------------------------------------------------------------- */

const AWS_IAM_BASE = "https://iam.amazonaws.com";
const AWS_IAM_VERSION = "2010-05-08";
/** IAM's Query API lives in us-east-1 whatever the caller's region. */
const AWS_IAM_REGION = "us-east-1";
/** The global STS endpoint (`GetCallerIdentity` needs no permission: it only proves the credential pair authenticates). */
const AWS_STS_BASE = "https://sts.amazonaws.com";
const AWS_STS_VERSION = "2011-06-15";
/** STS answers one of these when the key id and the secret are not a pair (or the key is gone / inactive). */
const AWS_AUTH_FAILURE_CODES = new Set([
  "InvalidClientTokenId",
  "SignatureDoesNotMatch",
  "IncompleteSignature",
  "AuthFailure",
  "UnrecognizedClientException",
]);

const ACCESS_KEY_ID = /^[A-Z0-9]{16,128}$/;

/** The companion name every AWS rule carries (the rule's `accessKeyIdVariable` supplies it). */
const AWS_ACCESS_KEY_ID_COMPANION = "accessKeyId";

interface IamKey {
  readonly id: string;
  readonly status: "Active" | "Inactive";
  readonly createDate: string;
}

/** The credentials the IAM calls are signed with: the admin pair when named, else the key itself. */
function awsCallerOf(
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<AwsCredentials, ConnectorError> {
  return Effect.gen(function* () {
    const adminId = inputs["accessKeyId"];
    const adminSecret = inputs["secretAccessKey"];
    if (adminId !== undefined && adminSecret !== undefined) {
      const token = inputs["sessionToken"];
      return {
        accessKeyId: decoder.decode(adminId).trim(),
        secretAccessKey: decoder.decode(adminSecret).trim(),
        ...(token === undefined ? {} : { sessionToken: decoder.decode(token).trim() }),
      };
    }
    return {
      accessKeyId: yield* currentKeyId(current),
      secretAccessKey: decoder.decode(current.primary).trim(),
    };
  });
}

function currentKeyId(current: CredentialValues): Effect.Effect<string, ConnectorError> {
  const companion = current.companions[AWS_ACCESS_KEY_ID_COMPANION];
  if (companion === undefined) {
    return new ConnectorError({
      message: "aws-iam-access-key: the access key id companion is missing",
    });
  }
  const id = decoder.decode(companion).trim();
  if (!ACCESS_KEY_ID.test(id)) {
    return new ConnectorError({
      message:
        "aws-iam-access-key: the access key id variable does not hold an access key id (uppercase letters and digits)",
    });
  }
  return Effect.succeed(id);
}

/** One XML element's text (IAM responses are flat enough for this; values are never interpolated back). */
function xmlText(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
  return match === null ? null : (match[1] ?? "");
}

function xmlMembers(xml: string): string[] {
  return [...xml.matchAll(/<member>([\s\S]*?)<\/member>/g)].map((match) => match[1] ?? "");
}

interface AwsQueryService {
  readonly name: "iam" | "sts";
  readonly base: string;
  readonly version: string;
}

/** One SigV4-signed Query API call; the raw response (an error answer is returned, not thrown — the caller classifies it). */
function awsQueryCall(
  caller: AwsCredentials,
  service: AwsQueryService,
  action: string,
  params: Readonly<Record<string, string>>,
): Effect.Effect<
  { readonly ok: boolean; readonly status: number; readonly text: string },
  ConnectorError,
  HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const clock = yield* Clock.Clock;
    const body = new URLSearchParams({
      Action: action,
      Version: service.version,
      ...params,
    }).toString();
    const signed = yield* Effect.tryPromise({
      try: () =>
        signV4({
          method: "POST",
          url: `${service.base}/`,
          region: AWS_IAM_REGION,
          service: service.name,
          headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
          body,
          credentials: caller,
          nowMs: clock.currentTimeMillisUnsafe(),
        }),
      catch: (error) => new ConnectorError({ message: reasonOf(error, "the connector failed") }),
    });
    const response = yield* client
      .execute(
        HttpClientRequest.post(`${service.base}/`).pipe(
          HttpClientRequest.setHeaders({ ...signed.headers, "user-agent": USER_AGENT }),
          HttpClientRequest.setBody(HttpBody.raw(body)),
        ),
      )
      .pipe(
        Effect.mapError(
          (error) =>
            new ConnectorError({
              message: `aws-iam-access-key: ${action} could not reach ${service.name.toUpperCase()} (${transportReason(error)})`,
            }),
        ),
      );
    const text = yield* response.text.pipe(
      Effect.mapError((error) => new ConnectorError({ message: transportReason(error) })),
    );
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      text,
    };
  });
}

function awsErrorText(text: string): string {
  const code = xmlText(text, "Code") ?? "unknown";
  const message = xmlText(text, "Message") ?? "";
  return `${code}${message === "" ? "" : `: ${message}`}`;
}

function iamCall(
  caller: AwsCredentials,
  action: string,
  params: Readonly<Record<string, string>>,
): Effect.Effect<string, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const endpoints = yield* IssuerEndpoints;
    const response = yield* awsQueryCall(
      caller,
      { name: "iam", base: endpoints.awsIamBase ?? AWS_IAM_BASE, version: AWS_IAM_VERSION },
      action,
      params,
    );
    if (!response.ok) {
      return yield* new ConnectorError({
        message: `aws-iam-access-key: IAM answered ${response.status} to ${action} (${awsErrorText(response.text)})`,
      });
    }
    return response.text;
  });
}

/**
 * Whether a key id and a secret are a pair: `sts:GetCallerIdentity` needs
 * no permission, so a success proves the pair and an authentication error
 * refutes it. Any other answer (a network failure, a throttle) is surfaced,
 * never read as "not the pair".
 */
function awsPairAuthenticates(
  candidate: AwsCredentials,
): Effect.Effect<boolean, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const endpoints = yield* IssuerEndpoints;
    const response = yield* awsQueryCall(
      candidate,
      { name: "sts", base: endpoints.awsStsBase ?? AWS_STS_BASE, version: AWS_STS_VERSION },
      "GetCallerIdentity",
      {},
    );
    if (response.ok) {
      return true;
    }
    if (AWS_AUTH_FAILURE_CODES.has(xmlText(response.text, "Code") ?? "")) {
      return false;
    }
    return yield* new ConnectorError({
      message: `aws-iam-access-key: STS answered ${response.status} to GetCallerIdentity (${awsErrorText(response.text)})`,
    });
  });
}

function iamUserOf(
  caller: AwsCredentials,
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  keyId: string,
): Effect.Effect<string, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (rule.user !== null) {
      return rule.user;
    }
    const xml = yield* iamCall(caller, "GetAccessKeyLastUsed", { AccessKeyId: keyId });
    const user = xmlText(xml, "UserName");
    if (user === null || user.length === 0) {
      return yield* new ConnectorError({
        message:
          "aws-iam-access-key: IAM did not name the user of the current access key (set `user` in the rotation config)",
      });
    }
    return user;
  });
}

function iamListKeys(
  caller: AwsCredentials,
  user: string,
): Effect.Effect<IamKey[], ConnectorError, HttpClient.HttpClient> {
  return Effect.map(iamCall(caller, "ListAccessKeys", { UserName: user }), (xml) =>
    xmlMembers(xml).flatMap((member) => {
      const id = xmlText(member, "AccessKeyId");
      const status = xmlText(member, "Status");
      const createDate = xmlText(member, "CreateDate") ?? "";
      return id === null || (status !== "Active" && status !== "Inactive")
        ? []
        : [{ id, status, createDate }];
    }),
  );
}

/** The IAM user the current key belongs to and its keys (the opening read of a rotation and of a finalize). */
function iamKeysOf(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<
  {
    readonly caller: AwsCredentials;
    readonly currentId: string;
    readonly user: string;
    readonly keys: IamKey[];
  },
  ConnectorError,
  HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const caller = yield* awsCallerOf(current, inputs);
    const currentId = yield* currentKeyId(current);
    const user = yield* iamUserOf(caller, rule, currentId);
    const keys = yield* iamListKeys(caller, user);
    return { caller, currentId, user, keys };
  });
}

function rotateAwsIam(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<ConnectorOutcome, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const { caller, currentId, user, keys } = yield* iamKeysOf(rule, current, inputs);
    const facts: string[] = [];
    if (keys.length >= 2) {
      // IAM allows two keys per user. An inactive one that is not the key in
      // use is a finalized previous rotation — reclaim it (Vault / Infisical
      // reclaim the oldest; we never delete an active key)
      const reclaimable = keys.find((key) => key.id !== currentId && key.status === "Inactive");
      if (reclaimable === undefined) {
        return yield* new ConnectorError({
          message: `aws-iam-access-key: user ${user} already has two active access keys, so IAM cannot create a third. Finalize the previous rotation (\`--finalize\` deactivates the key the previous version held) or deactivate one at the issuer, then retry`,
        });
      }
      yield* iamCall(caller, "DeleteAccessKey", { UserName: user, AccessKeyId: reclaimable.id });
      facts.push(
        `deleted the inactive access key ${reclaimable.id} (the slot a previous rotation left)`,
      );
    }
    const xml = yield* iamCall(caller, "CreateAccessKey", { UserName: user });
    const newId = xmlText(xml, "AccessKeyId");
    const newSecret = xmlText(xml, "SecretAccessKey");
    if (newId === null || newSecret === null || newId.length === 0 || newSecret.length === 0) {
      return yield* new ConnectorError({
        message: "aws-iam-access-key: IAM did not return the new access key",
      });
    }
    facts.push(
      `user ${user}: new access key ${newId} created (the previous key ${currentId} stays active)`,
    );
    return {
      values: {
        primary: encoder.encode(newSecret),
        companions: { [AWS_ACCESS_KEY_ID_COMPANION]: encoder.encode(newId) },
      },
      facts,
      previous: `access key ${currentId} stays active until you finalize (IAM keys take a few seconds to become usable)`,
      recovery: `access key ${newId} exists at the issuer and its secret is held only by this process (it is not shown) — delete ${newId} for user ${user} at the issuer, then re-run the rotation (a re-run refuses while two active keys exist; only an inactive key is reclaimed)`,
      warnings: [],
    };
  });
}

/** The key ids earlier versions of the key id variable held (ill-formed values are ignored, never matched). */
function storedKeyIds(ancestors: CompanionAncestors): ReadonlySet<string> {
  const ids = new Set<string>();
  for (const value of ancestors[AWS_ACCESS_KEY_ID_COMPANION] ?? []) {
    const id = decoder.decode(value).trim();
    if (ACCESS_KEY_ID.test(id)) {
      ids.add(id);
    }
  }
  return ids;
}

/**
 * Finalize: the key to deactivate is decided against the issuer, not
 * against the server's history metadata. IAM lists the user's keys (at
 * most two); a key other than the current one is deactivated only when (1)
 * an earlier version of the key id variable held its id — lineage-verified,
 * so a key a human created by hand is never touched — and (2) it
 * authenticates with the previous version's secret at STS, which proves it
 * is exactly the credential that version held. Either check failing
 * leaves the key as it is and says so.
 */
function finalizeAwsIam(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  ancestors: CompanionAncestors,
): Effect.Effect<FinalizeOutcome, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const { caller, currentId, user, keys } = yield* iamKeysOf(rule, current, inputs);
    const others = keys.filter((key) => key.id !== currentId);
    if (others.length === 0) {
      return {
        kind: "nothing" as const,
        facts: [`access key ${currentId} is the only key of user ${user} (nothing to deactivate)`],
      };
    }
    const stored = storedKeyIds(ancestors);
    const previousSecret = decoder.decode(previous.primary).trim();
    const facts: string[] = [];
    for (const key of others) {
      if (!stored.has(key.id)) {
        facts.push(
          `access key ${key.id} of user ${user} was never a version of ${rule.accessKeyIdVariable} (not created through maruhi) — left untouched`,
        );
        continue;
      }
      if (key.status === "Inactive") {
        return {
          kind: "already" as const,
          facts: [
            ...facts,
            `access key ${key.id} is already inactive (the next rotation deletes it)`,
          ],
        };
      }
      const pairs = yield* awsPairAuthenticates({
        accessKeyId: key.id,
        secretAccessKey: previousSecret,
      });
      if (!pairs) {
        facts.push(
          `access key ${key.id} is active but does not authenticate with the previous version's secret (not that version's key) — left untouched`,
        );
        continue;
      }
      yield* iamCall(caller, "UpdateAccessKey", {
        UserName: user,
        AccessKeyId: key.id,
        Status: "Inactive",
      });
      return {
        kind: "finalized" as const,
        facts: [
          ...facts,
          `access key ${key.id} deactivated (reversible at the issuer; the next rotation deletes it)`,
        ],
      };
    }
    return { kind: "nothing" as const, facts };
  });
}

/* -------------------------------------------------------------------------- */
/* Cloudflare API tokens                                                         */
/* -------------------------------------------------------------------------- */

const CLOUDFLARE_BASE = "https://api.cloudflare.com";

/** Cloudflare's JSON envelope (`{success, errors, result}`; other keys are not read). */
const CloudflareEnvelope = Schema.Struct({
  success: Schema.optionalKey(Schema.Boolean),
  errors: Schema.optionalKey(
    Schema.Array(
      Schema.Struct({
        code: Schema.optionalKey(Schema.Number),
        message: Schema.optionalKey(Schema.String),
      }),
    ),
  ),
  result: Schema.optionalKey(Schema.Unknown),
});
type CloudflareEnvelope = typeof CloudflareEnvelope.Type;

function tokensPath(rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>): string {
  return rule.accountId === null
    ? "/client/v4/user/tokens"
    : `/client/v4/accounts/${rule.accountId}/tokens`;
}

function cloudflareCall(
  bearer: string,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown,
): Effect.Effect<
  { readonly status: number; readonly envelope: CloudflareEnvelope },
  ConnectorError,
  HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const endpoints = yield* IssuerEndpoints;
    const base = endpoints.cloudflareBase ?? CLOUDFLARE_BASE;
    let request = HttpClientRequest.make(method)(`${base}${path}`).pipe(
      HttpClientRequest.bearerToken(bearer),
      HttpClientRequest.setHeaders({ "user-agent": USER_AGENT }),
    );
    if (body !== undefined) {
      request = request.pipe(
        HttpClientRequest.setBody(
          HttpBody.raw(JSON.stringify(body), { contentType: "application/json" }),
        ),
      );
    }
    const response = yield* client.execute(request).pipe(
      Effect.mapError(
        (error) =>
          new ConnectorError({
            message: `cloudflare-api-token: ${method} ${path} could not reach Cloudflare (${transportReason(error)})`,
          }),
      ),
    );
    // A successful answer that is not the JSON envelope is a connector
    // error now (it was read as an empty envelope before — silently). An
    // error status may not carry the envelope either, and there the status
    // classification below still owns the message — an edge answer of HTML
    // still reads "Cloudflare answered 502 to …", a 404 still "already".
    const envelope = yield* response.pipe(
      HttpClientResponse.schemaBodyJson(CloudflareEnvelope),
      Effect.catch(() =>
        response.status >= 200 && response.status < 300
          ? Effect.fail(
              new ConnectorError({
                message: `cloudflare-api-token: ${method} ${path} — Cloudflare's answer was not the JSON envelope it returns`,
              }),
            )
          : Effect.succeed<CloudflareEnvelope>({}),
      ),
    );
    return { status: response.status, envelope };
  });
}

function cloudflareFailure(
  what: string,
  status: number,
  envelope: CloudflareEnvelope,
): ConnectorError {
  const first = envelope.errors?.[0];
  const detail =
    first === undefined
      ? ""
      : ` (${first.code ?? "?"}${first.message === undefined ? "" : `: ${first.message}`})`;
  return new ConnectorError({
    message: `cloudflare-api-token: Cloudflare answered ${status} to ${what}${detail}`,
  });
}

/** The id of the token whose value this is (`/verify` with the token itself), or null when it is not valid. */
function cloudflareTokenId(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  token: string,
): Effect.Effect<string | null, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const { status, envelope } = yield* cloudflareCall(token, "GET", `${tokensPath(rule)}/verify`);
    if (status === 401 || status === 403 || envelope.success === false) {
      return null;
    }
    if (status !== 200) {
      return yield* cloudflareFailure("the token verification", status, envelope);
    }
    const result = envelope.result as { readonly id?: unknown } | undefined;
    return typeof result?.id === "string" && result.id.length > 0 ? result.id : null;
  });
}

function adminTokenOf(current: CredentialValues, inputs: RotateInputs): string {
  const admin = inputs["token"];
  return decoder.decode(admin ?? current.primary).trim();
}

/** The definition of a token (name, policies, condition, validity window) as the replacement's request body. */
function cloudflareDefinition(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  admin: string,
  id: string,
): Effect.Effect<Record<string, unknown>, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const detail = yield* cloudflareCall(admin, "GET", `${tokensPath(rule)}/${id}`);
    if (detail.status !== 200 || detail.envelope.success === false) {
      return yield* cloudflareFailure(`reading token ${id}`, detail.status, detail.envelope);
    }
    const definition = detail.envelope.result as
      | {
          readonly name?: unknown;
          readonly policies?: unknown;
          readonly condition?: unknown;
          readonly expires_on?: unknown;
          readonly not_before?: unknown;
        }
      | undefined;
    if (
      definition === undefined ||
      typeof definition.name !== "string" ||
      !Array.isArray(definition.policies)
    ) {
      return yield* new ConnectorError({
        message: `cloudflare-api-token: token ${id} came back without a name and policies`,
      });
    }
    const request: Record<string, unknown> = {
      name: definition.name,
      policies: definition.policies,
    };
    if (definition.condition !== undefined) {
      request["condition"] = definition.condition;
    }
    if (typeof definition.expires_on === "string") {
      request["expires_on"] = definition.expires_on;
    }
    if (typeof definition.not_before === "string") {
      request["not_before"] = definition.not_before;
    }
    return request;
  });
}

function rotateCloudflare(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<ConnectorOutcome, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const token = decoder.decode(current.primary).trim();
    const admin = adminTokenOf(current, inputs);
    const id = yield* cloudflareTokenId(rule, token);
    if (id === null) {
      return yield* new ConnectorError({
        message:
          "cloudflare-api-token: the current value is not a valid token (Cloudflare refused to verify it), so its policies cannot be copied. Create the replacement at the issuer and push it",
      });
    }
    const request = yield* cloudflareDefinition(rule, admin, id);
    const created = yield* cloudflareCall(admin, "POST", tokensPath(rule), request);
    if (created.status !== 200 || created.envelope.success === false) {
      return yield* cloudflareFailure(
        "creating the replacement token",
        created.status,
        created.envelope,
      );
    }
    const result = created.envelope.result as
      | { readonly id?: unknown; readonly value?: unknown }
      | undefined;
    if (
      result === undefined ||
      typeof result.id !== "string" ||
      typeof result.value !== "string" ||
      result.value.length === 0
    ) {
      return yield* new ConnectorError({
        message: "cloudflare-api-token: Cloudflare did not return the new token's value",
      });
    }
    return {
      values: { primary: encoder.encode(result.value), companions: {} },
      facts: [
        `token ${String(request["name"])}: replacement ${result.id} created with the same policies`,
      ],
      previous: `token ${id} stays valid until you finalize`,
      recovery: `token ${result.id} exists at the issuer and its value is held only by this process (it is not shown) — delete it at the issuer, then re-run the rotation (a re-run creates another token)`,
      warnings: [],
    };
  });
}

function finalizeCloudflare(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<FinalizeOutcome, ConnectorError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const admin = adminTokenOf(current, inputs);
    const previousToken = decoder.decode(previous.primary).trim();
    const currentToken = decoder.decode(current.primary).trim();
    if (previousToken === currentToken) {
      return {
        kind: "nothing" as const,
        facts: ["both versions hold the same token (nothing to delete)"],
      };
    }
    const previousId = yield* cloudflareTokenId(rule, previousToken);
    if (previousId === null) {
      return { kind: "already" as const, facts: ["the previous token is no longer valid"] };
    }
    const currentId = yield* cloudflareTokenId(rule, currentToken);
    if (currentId === previousId) {
      return {
        kind: "nothing" as const,
        facts: [`token ${previousId} is the one in use (nothing to delete)`],
      };
    }
    const deleted = yield* cloudflareCall(admin, "DELETE", `${tokensPath(rule)}/${previousId}`);
    if (deleted.status === 404) {
      return { kind: "already" as const, facts: [`token ${previousId} no longer exists`] };
    }
    if (deleted.status !== 200 || deleted.envelope.success === false) {
      return yield* cloudflareFailure(
        `deleting token ${previousId}`,
        deleted.status,
        deleted.envelope,
      );
    }
    return { kind: "finalized" as const, facts: [`token ${previousId} deleted`] };
  });
}

/* -------------------------------------------------------------------------- */
/* The exec connector (a script of the repository — PF8)                        */
/* -------------------------------------------------------------------------- */

type ExecRule = Extract<RotateRule, { connector: "exec" }>;

/** The lines of a script's stderr shown on failure (the tail, scrubbed). */
const EXEC_SHOWN_LINES = 20;
/** The lines of a finalize script's stdout kept as facts. */
const EXEC_FACT_LINES = 10;

/** A secret the script could echo, in the shape the scrubber takes. */
function secretOf(name: string, bytes: Uint8Array): SyncWrite {
  return { name, value: Redacted.make(bytes, { label: "exec-secret" }) };
}

/** Scrubs script output of every secret it could carry and keeps the tail (the sync driver's discipline). */
function scrubbedLines(output: string, secrets: readonly SyncWrite[], lines: number): string[] {
  return scrubVendorOutput(output, secrets).slice(-lines);
}

/**
 * The environment of a script: the credential under the rule's variable
 * name and `MH_ROTATE_CURRENT`, its companions and the admin inputs under
 * their names (the `maruhi run` shape — every value is a UTF-8 text
 * without NUL, as an environment variable must be), and the control
 * variables. The previous credential (finalize) rides as
 * `MH_ROTATE_PREVIOUS`. Names were validated at config time; here only
 * the values can refuse, each naming the variable and never the value.
 */
function scriptEnvironment(input: {
  readonly rule: ExecRule;
  readonly site: RotationSite;
  readonly phase: "rotate" | "finalize";
  readonly current: CredentialValues;
  readonly previous: CredentialValues | null;
  readonly inputs: RotateInputs;
}): Effect.Effect<Readonly<Record<string, string>>, ConnectorError> {
  return Effect.gen(function* () {
    const env: Record<string, string> = {
      [`${EXEC_CONTROL_PREFIX}VARIABLE`]: input.site.variable,
      [`${EXEC_CONTROL_PREFIX}ENVIRONMENT`]: input.site.environmentId,
      [`${EXEC_CONTROL_PREFIX}PHASE`]: input.phase,
    };
    const set = (
      name: string,
      bytes: Uint8Array,
      what: string,
    ): Effect.Effect<void, ConnectorError> => {
      const text = decodeValueText(bytes);
      if (text === null || text.includes("\0")) {
        return new ConnectorError({
          message: `exec: ${what} is not a UTF-8 text without NUL, so it cannot be set in the script's environment`,
        });
      }
      return Effect.sync(() => {
        env[name] = text;
      });
    };
    yield* set(
      input.site.variable,
      input.current.primary,
      `the value of ${displayText(input.site.variable)}`,
    );
    yield* set(
      `${EXEC_CONTROL_PREFIX}CURRENT`,
      input.current.primary,
      `the value of ${displayText(input.site.variable)}`,
    );
    if (input.previous !== null) {
      yield* set(
        `${EXEC_CONTROL_PREFIX}PREVIOUS`,
        input.previous.primary,
        "the previous credential",
      );
    }
    for (const [envName, variable] of Object.entries(input.rule.companions)) {
      const bytes = input.current.companions[envName];
      if (bytes !== undefined) {
        yield* set(envName, bytes, `the value of ${displayText(variable)}`);
      }
      // The companion the previous credential carried (the key id to
      // retire), when the finalize knows it (C-7)
      const previousBytes = input.previous?.companions[envName];
      if (previousBytes !== undefined) {
        yield* set(
          `${EXEC_CONTROL_PREFIX}PREVIOUS_${envName}`,
          previousBytes,
          `the previous value of ${displayText(variable)}`,
        );
      }
    }
    for (const [envName, bytes] of Object.entries(input.inputs)) {
      yield* set(envName, bytes, `the input ${displayText(envName)}`);
    }
    return env;
  });
}

/** The secrets a script of this rotation could echo (scrubbed out of anything shown). */
function scriptSecrets(input: {
  readonly current: CredentialValues;
  readonly previous: CredentialValues | null;
  readonly inputs: RotateInputs;
  readonly produced?: CredentialValues | undefined;
}): SyncWrite[] {
  const secrets = [secretOf("current", input.current.primary)];
  for (const [name, bytes] of Object.entries(input.current.companions)) {
    secrets.push(secretOf(`current:${name}`, bytes));
  }
  if (input.previous !== null) {
    secrets.push(secretOf("previous", input.previous.primary));
    for (const [name, bytes] of Object.entries(input.previous.companions)) {
      secrets.push(secretOf(`previous:${name}`, bytes));
    }
  }
  for (const [name, bytes] of Object.entries(input.inputs)) {
    secrets.push(secretOf(`input:${name}`, bytes));
  }
  if (input.produced !== undefined) {
    secrets.push(secretOf("new", input.produced.primary));
    for (const [name, bytes] of Object.entries(input.produced.companions)) {
      secrets.push(secretOf(`new:${name}`, bytes));
    }
  }
  return secrets;
}

/** A capture that rejected, as the connector's error: stopped by maruhi (D-6), a leftover's output (D-14), or a launch failure. */
function captureFailure(
  error: unknown,
  phase: "rotate" | "finalize",
  script: string,
): ConnectorError {
  if (error instanceof ScriptStoppedError) {
    // Stopped by maruhi after it started (a flooded stdout) — not a
    // launch failure (ruling D revision, round 4); a rotate script had
    // started printing, so the credential may exist at the issuer (D-17)
    const created =
      phase === "rotate"
        ? ". The new credential may exist at the issuer: re-run the rotation once the script prints only the value (make it idempotent, or retire the unused credential at the issuer by hand)"
        : "";
    return new ConnectorError({
      message: `exec: the ${phase} script ${script} was stopped: ${error.message}${created}`,
    });
  }
  if (error instanceof ScriptLeftoverError) {
    // The script's own answer cannot be told from a leftover process's
    // output (D-14); a script that exited 0 may have created the
    // credential, so the recovery is named
    const created =
      error.exitCode === 0 && phase === "rotate"
        ? ". The script exited 0, so the new credential may exist at the issuer: re-run the rotation once the script redirects that output (make it idempotent, or retire the unused credential at the issuer by hand)"
        : "";
    return new ConnectorError({ message: `exec: ${error.message}${created}` });
  }
  const reason = reasonOf(error, "it could not be started");
  return new ConnectorError({
    message: `exec: the ${phase} script ${script} did not start: ${reason}`,
  });
}

/** Runs one script; a launch failure or a non-zero exit is a connector error naming the script and the scrubbed stderr tail. */
function runScript(
  rule: ExecRule,
  argv: readonly string[],
  env: Readonly<Record<string, string>>,
  secrets: readonly SyncWrite[],
  phase: "rotate" | "finalize",
): Effect.Effect<CaptureOutcome, ConnectorError, ProcessRunner> {
  return Effect.gen(function* () {
    const runner = yield* ProcessRunner;
    const outcome = yield* Effect.tryPromise({
      try: () => runner.captureScript({ command: argv, cwd: rule.cwd, extraEnv: env }),
      catch: (error) => captureFailure(error, phase, argv[0] ?? ""),
    });
    if (outcome.exitCode !== 0) {
      const tail = scrubbedLines(outcome.stderr, secrets, EXEC_SHOWN_LINES);
      return yield* new ConnectorError({
        message: `exec: the ${phase} script ${argv[0] ?? ""} exited with code ${outcome.exitCode}${tail.length === 0 ? "" : ` (its stderr, filtered: ${tail.join(" | ")})`}`,
      });
    }
    return outcome;
  });
}

/**
 * The shape of a value (D-7 / D-8): "N bytes, M lines", shown in the local
 * rotation report and, at an acceptance, computed from the opened value on
 * the member's device — never sent to the server (a line count is
 * plaintext-derived information the ciphertext does not give away). A
 * script that printed its own chatter on stdout shows here before the
 * value is pushed.
 */
export function shapeOf(value: Uint8Array): ValueShape {
  let lines = 1;
  for (const byte of value) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  return { bytes: value.length, lines };
}

/** The numbers a value's shape is made of; the text is formatted at display time ({@link describeShape}) and never parsed back (D-19). */
export interface ValueShape {
  readonly bytes: number;
  readonly lines: number;
}

/** "N bytes, M lines". */
export function describeShape(shape: ValueShape): string {
  return `${countNoun(shape.bytes, "byte")}, ${countNoun(shape.lines, "line")}`;
}

/** The primary's shape, then each companion's by name (the same parity as the acceptance's per-value shapes). */
export function describeValueShapes(
  outcome: Pick<RotationOutcome, "shape" | "companionShapes">,
): string {
  return [
    describeShape(outcome.shape),
    ...Object.entries(outcome.companionShapes)
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(([name, shape]) => `${name} ${describeShape(shape)}`),
  ].join("; ");
}

/**
 * The warning a changed line count earns before the push (D-16 at `var
 * rotate`, D-18 at the acceptance): the one form of a leftover's output no
 * timing can tell apart. A warning, never a refusal (a token becoming a
 * PEM is legitimate). null = the line count is unchanged.
 */
export function lineCountWarning(
  name: string,
  next: ValueShape,
  current: ValueShape,
  connector: string,
): string | null {
  if (next.lines === current.lines) {
    return null;
  }
  // Only a script can have printed more than the credential; an API
  // connector's value is the issuer's answer, so the difference is the
  // current value's layout (round 9)
  const cause =
    connector === "exec"
      ? "check that the rotate script printed only the credential (a process it started may have written to its stdout)"
      : `the ${connector} connector produced it as the issuer answered, so the current value had another layout (pushed by hand?) — nothing to fix unless the issuer's answer changed shape`;
  return `the new value of ${name} has ${countNoun(next.lines, "line")} where the current value has ${countNoun(current.lines, "line")}: ${cause}`;
}

/** The new value as the rotate script printed it: one trailing newline (LF or CRLF) is dropped, nothing else is touched. */
function valueFromStdout(stdout: Uint8Array): Effect.Effect<Uint8Array, ConnectorError> {
  let end = stdout.length;
  if (end > 0 && stdout[end - 1] === 0x0a) {
    end -= 1;
    if (end > 0 && stdout[end - 1] === 0x0d) {
      end -= 1;
    }
  }
  const value = stdout.subarray(0, end);
  if (value.length === 0) {
    return new ConnectorError({
      message:
        "exec: the rotate script printed no value on stdout (its stdout is the new credential; commentary belongs on stderr)",
    });
  }
  return producedText(value, "the value the rotate script printed on stdout");
}

interface ScriptAnswer {
  readonly values: CredentialValues;
  readonly facts: readonly string[];
}

/** The rotate script's stdout as a JSON object (anything else is refused with the contract spelled out). */
function jsonObjectFromStdout(
  stdout: Uint8Array,
): Effect.Effect<Record<string, unknown>, ConnectorError> {
  const text = decodeValueText(stdout);
  let parsed: unknown;
  try {
    parsed = text === null ? undefined : JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return new ConnectorError({
      message:
        'exec: the rotate script did not print a JSON object on stdout (the rule declares "output": "json": print {"value": "<new credential>", "companions": {…}, "facts": […]})',
    });
  }
  const record = parsed as Record<string, unknown>;
  const unknown = Object.keys(record).filter(
    (key) => !["value", "companions", "facts"].includes(key),
  );
  // The keys are the script's words: counted, never echoed
  if (unknown.length > 0) {
    return new ConnectorError({
      message: `exec: the rotate script's JSON answer has ${countNoun(unknown.length, "unknown key")}; it takes value, companions, facts`,
    });
  }
  return Effect.succeed(record);
}

/** One answered companion: declared by the rule and a non-empty string. */
function companionBytes(
  rule: ExecRule,
  name: string,
  value: unknown,
): Effect.Effect<Uint8Array, ConnectorError> {
  // The script's own words never reach an error message (a mistyped key
  // could be a credential): the message names what the rule declares
  if (!(name in rule.companions)) {
    return new ConnectorError({
      message: `exec: the rotate script answered a companion the rule does not declare (the rule declares ${declaredCompanions(rule)}); declare it under companions in the rotation config`,
    });
  }
  return producedBytes(value, `the companion ${displayText(name)} in the rotate script's answer`);
}

/** The declared companion names for a message ("STRIPE_KEY_ID", "none"). */
function declaredCompanions(rule: ExecRule): string {
  const names = Object.keys(rule.companions);
  return names.length === 0 ? "none" : names.map(displayText).join(", ");
}

/**
 * A produced value (the primary or a companion) as bytes: a non-empty
 * string of UTF-8 text without NUL — what a value must be to be injected
 * by `maruhi run` later. `what` names the value, never carries it.
 */
function producedBytes(value: unknown, what: string): Effect.Effect<Uint8Array, ConnectorError> {
  if (typeof value !== "string" || value.length === 0) {
    return new ConnectorError({ message: `exec: ${what} is not a non-empty string` });
  }
  return producedText(encoder.encode(value), what);
}

/** The produced bytes checked as UTF-8 text without NUL (a value that could not be injected is refused before it is stored). */
function producedText(bytes: Uint8Array, what: string): Effect.Effect<Uint8Array, ConnectorError> {
  const text = decodeValueText(bytes);
  if (text === null || text.includes("\0")) {
    return new ConnectorError({
      message: `exec: ${what} is not UTF-8 text without NUL, so it could never be injected into a process environment; it is refused before anything is stored`,
    });
  }
  return Effect.succeed(bytes);
}

/** The answer's companions: every one the rule declares, nothing it does not, each a non-empty string. */
function companionsFromAnswer(
  rule: ExecRule,
  raw: unknown,
): Effect.Effect<Record<string, Uint8Array>, ConnectorError> {
  return Effect.gen(function* () {
    const companionsRaw = raw ?? {};
    if (
      typeof companionsRaw !== "object" ||
      companionsRaw === null ||
      Array.isArray(companionsRaw)
    ) {
      return yield* new ConnectorError({
        message:
          "exec: the rotate script's JSON answer has a companions field that is not an object",
      });
    }
    const companions: Record<string, Uint8Array> = {};
    for (const [name, value] of Object.entries(companionsRaw as Record<string, unknown>)) {
      companions[name] = yield* companionBytes(rule, name, value);
    }
    const missing = Object.keys(rule.companions).find((name) => !(name in companions));
    if (missing !== undefined) {
      return yield* new ConnectorError({
        message: `exec: the rotate script's answer lacks the companion ${displayText(missing)} the rule declares (every declared companion is pushed with the new value, so all of them must be answered)`,
      });
    }
    return companions;
  });
}

/** The rotate script's JSON answer: `{ value, companions?, facts? }`. */
function answerFromJson(
  rule: ExecRule,
  stdout: Uint8Array,
): Effect.Effect<ScriptAnswer, ConnectorError> {
  return Effect.gen(function* () {
    const record = yield* jsonObjectFromStdout(stdout);
    const primary = yield* producedBytes(
      record["value"],
      "the value in the rotate script's JSON answer",
    );
    const companions = yield* companionsFromAnswer(rule, record["companions"]);
    const factsRaw = record["facts"] ?? [];
    if (!Array.isArray(factsRaw) || !factsRaw.every((fact) => typeof fact === "string")) {
      return yield* new ConnectorError({
        message:
          "exec: the rotate script's JSON answer has a facts field that is not a list of strings",
      });
    }
    return { values: { primary, companions }, facts: factsRaw as string[] };
  });
}

function rotateExec(
  rule: ExecRule,
  site: RotationSite,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<ConnectorOutcome, ConnectorError, ProcessRunner> {
  return Effect.gen(function* () {
    const env = yield* scriptEnvironment({
      rule,
      site,
      phase: "rotate",
      current,
      previous: null,
      inputs,
    });
    const secrets = scriptSecrets({ current, previous: null, inputs });
    const outcome = yield* runScript(rule, rule.rotate, env, secrets, "rotate");
    const answer: ScriptAnswer =
      rule.output === "json"
        ? yield* answerFromJson(rule, outcome.stdout)
        : {
            values: { primary: yield* valueFromStdout(outcome.stdout), companions: {} },
            facts: [],
          };
    // The script's own words may carry a credential by mistake: scrub them
    // of everything this run knows before they reach the report
    const all = scriptSecrets({ current, previous: null, inputs, produced: answer.values });
    const facts = answer.facts.flatMap((fact) => scrubbedLines(fact, all, 1));
    const script = rule.rotate[0] ?? "";
    return {
      values: answer.values,
      facts: [
        `${script}: new credential produced${facts.length === 0 ? "" : ` (${facts.join("; ")})`}`,
      ],
      previous:
        rule.finalize === null
          ? "the rotate script was expected to retire the previous credential itself (nothing to finalize)"
          : `the previous credential stays valid until you finalize (${rule.finalize[0] ?? ""} runs with it)`,
      recovery: `the new credential is held only by this process (it is not shown) — re-run the rotation (${script} runs again; make it idempotent, or retire the unused credential at the issuer by hand)`,
      warnings: [],
    };
  });
}

function finalizeExec(
  rule: ExecRule,
  site: RotationSite,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.Effect<FinalizeOutcome, ConnectorError, ProcessRunner> {
  return Effect.gen(function* () {
    if (rule.finalize === null) {
      return {
        kind: "nothing" as const,
        facts: [
          "the rule has no finalize script (its rotate script retires the previous credential itself)",
        ],
      };
    }
    const env = yield* scriptEnvironment({
      rule,
      site,
      phase: "finalize",
      current,
      previous,
      inputs,
    });
    const secrets = scriptSecrets({ current, previous, inputs });
    const outcome = yield* runScript(rule, rule.finalize, env, secrets, "finalize");
    const said = scrubbedLines(decoder.decode(outcome.stdout), secrets, EXEC_FACT_LINES);
    return {
      kind: "finalized" as const,
      facts: [
        `${rule.finalize[0] ?? ""}: previous credential retired${said.length === 0 ? "" : ` (${said.join("; ")})`}`,
      ],
    };
  });
}

/* -------------------------------------------------------------------------- */
/* The frame                                                                     */
/* -------------------------------------------------------------------------- */

/** The companions a rule's credential carries (companion name → the variable that holds it). */
export function companionsOf(rule: RotateRule): Readonly<Record<string, string>> {
  return companionVariablesOf(rule);
}

/** What the rotation will do at the issuer (decided from the current value alone — nothing is sent). */
export function planRotation(
  rule: RotateRule,
  current: CredentialValues,
): Effect.Effect<RotationPlan, ConnectorError> {
  switch (rule.connector) {
    case "postgres":
    case "mysql":
      return dbPlan(rule, current);
    case "aws-iam-access-key":
      return Effect.map(currentKeyId(current), (keyId) => ({
        description: `create a second access key for the IAM user (the current key ${keyId} stays active until you finalize)`,
        immediate: false,
      }));
    case "cloudflare-api-token":
      return Effect.succeed({
        description:
          "create a second token with the current token's policies (the current token stays valid until you finalize)",
        immediate: false,
      });
    case "exec":
      return Effect.succeed(
        rule.finalize === null
          ? {
              description: `run ${rule.rotate[0] ?? ""} — the rule has no finalize script, so that script is expected to retire the current credential itself (no grace period)`,
              immediate: true,
            }
          : {
              description: `run ${rule.rotate[0] ?? ""} to create the new credential (the current one stays valid until you finalize with ${rule.finalize[0] ?? ""})`,
              immediate: false,
            },
      );
  }
}

/** Creates the new credential at the issuer. Fails with {@link ConnectorError}. */
export function rotateCredential(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
  /** Where the rotation happens (the `exec` connector's scripts receive it; required for that connector). */
  site?: RotationSite,
): Effect.Effect<RotationOutcome, ConnectorError, ConnectorServices> {
  return Effect.map(rotateWith(rule, current, inputs, site), (outcome) => ({
    ...outcome,
    shape: shapeOf(outcome.values.primary),
    companionShapes: Object.fromEntries(
      Object.entries(outcome.values.companions).map(([name, bytes]) => [name, shapeOf(bytes)]),
    ),
    currentShape: shapeOf(current.primary),
  }));
}

/** A connector's own outcome (the frame adds the values' shapes). */
type ConnectorOutcome = Omit<RotationOutcome, "shape" | "companionShapes" | "currentShape">;

function rotateWith(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
  site?: RotationSite,
): Effect.Effect<ConnectorOutcome, ConnectorError, ConnectorServices> {
  switch (rule.connector) {
    case "postgres":
      return rotatePostgres(rule, current, inputs);
    case "mysql":
      return rotateMysql(rule, current, inputs);
    case "aws-iam-access-key":
      return rotateAwsIam(rule, current, inputs);
    case "cloudflare-api-token":
      return rotateCloudflare(rule, current, inputs);
    case "exec":
      return requireSite(site).pipe(
        Effect.flatMap((resolved) => rotateExec(rule, resolved, current, inputs)),
      );
  }
}

/** What finalizing will do, in one line (for the confirmation). */
export function describeFinalize(rule: RotateRule): string {
  switch (rule.connector) {
    case "postgres":
      return rule.roles === null
        ? "nothing to invalidate (an in-place password change has no previous credential)"
        : "replace the previous role's password with a random one nobody holds";
    case "mysql":
      return rule.roles === null
        ? "discard the account's secondary (previous) password"
        : "replace the previous account's password with a random one nobody holds";
    case "aws-iam-access-key":
      return "deactivate the access key that authenticates with the previous version's secret at the issuer (only a key id an earlier version of the key id variable held; reversible at the issuer; deleted by the next rotation)";
    case "cloudflare-api-token":
      return "delete the previous token";
    case "exec":
      return rule.finalize === null
        ? "nothing to invalidate (the rule has no finalize script — its rotate script retires the previous credential itself)"
        : `run ${rule.finalize[0] ?? ""} with the previous credential in its environment (MH_ROTATE_PREVIOUS)`;
  }
}

/** Invalidates the previous credential at the issuer. Fails with {@link ConnectorError}. */
export function finalizeCredential(
  rule: RotateRule,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  ancestors: CompanionAncestors = {},
  /** Where the rotation happens (required for the `exec` connector). */
  site?: RotationSite,
): Effect.Effect<FinalizeOutcome, ConnectorError, ConnectorServices> {
  switch (rule.connector) {
    case "postgres":
      return finalizePostgres(rule, previous, current, inputs);
    case "mysql":
      return finalizeMysql(rule, previous, current, inputs);
    case "aws-iam-access-key":
      return finalizeAwsIam(rule, previous, current, inputs, ancestors);
    case "cloudflare-api-token":
      return finalizeCloudflare(rule, previous, current, inputs);
    case "exec":
      return requireSite(site).pipe(
        Effect.flatMap((resolved) => finalizeExec(rule, resolved, previous, current, inputs)),
      );
  }
}

/** The exec connector cannot run without knowing the variable and environment (an internal inconsistency, never a user error). */
function requireSite(site: RotationSite | undefined): Effect.Effect<RotationSite, ConnectorError> {
  return site === undefined
    ? new ConnectorError({
        message: "exec: the rotation site (variable and environment) was not supplied",
      })
    : Effect.succeed(site);
}
