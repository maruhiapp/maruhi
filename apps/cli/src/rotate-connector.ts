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

import { Context, Redacted } from "effect";

import { countNoun, decodeValueText, displayText } from "./display.ts";
import { companionVariablesOf, EXEC_CONTROL_PREFIX, type RotateRule } from "./rotate-config.ts";
import type { CaptureInput, CaptureOutcome } from "./run.ts";
import { type AwsCredentials, signV4 } from "./sigv4.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
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

/** The seams a connector uses (tests redirect the issuer APIs and the clock). */
export interface RotateDeps {
  readonly fetch: typeof fetch;
  readonly now: () => number;
  readonly randomBytes: (length: number) => Uint8Array;
  readonly sql: SqlRunnerShape;
  /** Runs a script of the `exec` connector (production: Bun.spawn — live.ts; tests: a fake). */
  readonly exec: (input: CaptureInput) => Promise<CaptureOutcome>;
  /** The issuer API origins (production: the fixed hosts). */
  readonly awsIamBase?: string | undefined;
  readonly awsStsBase?: string | undefined;
  readonly cloudflareBase?: string | undefined;
}

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
export class ConnectorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConnectorError";
  }
}

const USER_AGENT = `maruhi-cli/${CLI_VERSION}`;

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
function parseDbUrl(bytes: Uint8Array, scheme: "postgres" | "mysql"): DbUrl {
  let url: URL;
  try {
    url = new URL(decoder.decode(bytes));
  } catch {
    throw new ConnectorError(
      `the ${scheme} connector expects the variable to hold a connection URL`,
    );
  }
  const protocol = url.protocol.replace(/:$/, "");
  const accepted =
    scheme === "postgres" ? ["postgres", "postgresql"] : ["mysql", "mysql2", "mariadb"];
  if (!accepted.includes(protocol)) {
    throw new ConnectorError(
      `the ${scheme} connector expects a ${accepted.join(" / ")} URL (the variable's URL has another scheme)`,
    );
  }
  const user = decodeURIComponent(url.username);
  if (user.length === 0) {
    throw new ConnectorError(`the ${scheme} connector needs a user in the connection URL`);
  }
  if (!DB_NAME.test(user)) {
    throw new ConnectorError(
      `the ${scheme} connector supports role names of letters, digits, _ . @ - only (the URL's user is outside that set)`,
    );
  }
  return { url, user };
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
): string {
  if (rule.roles === null) {
    return current;
  }
  const [first, second] = rule.roles;
  if (current === first) {
    return second;
  }
  if (current === second) {
    return first;
  }
  throw new ConnectorError(
    `the connection URL's user is neither of the alternated roles in the rotation config (${first}, ${second})`,
  );
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
  const reason = error instanceof Error ? error.message : "unknown failure";
  // A driver message can echo the connection URL; keep only the first line
  // and strip anything that looks like a URL with credentials
  const line =
    reason.split("\n")[0]?.replace(/[a-z0-9+.-]+:\/\/[^\s]+/gi, "<url>") ?? "unknown failure";
  return new ConnectorError(`${stage}: ${line}`);
}

function dbPlan(
  rule: Extract<RotateRule, { connector: "postgres" | "mysql" }>,
  current: CredentialValues,
): RotationPlan {
  const parsed = parseDbUrl(current.primary, rule.connector);
  const role = nextRole(rule, parsed.user);
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
}

async function rotatePostgres(
  rule: Extract<RotateRule, { connector: "postgres" }>,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<RotationOutcome> {
  const parsed = parseDbUrl(current.primary, "postgres");
  const role = nextRole(rule, parsed.user);
  const password = generatePassword(deps.randomBytes);
  const statement = `ALTER ROLE ${pgIdentifier(role)} WITH PASSWORD ${pgLiteral(password)}`;
  try {
    await deps.sql.execute(adminUrlOf(inputs, parsed), [statement]);
  } catch (error) {
    throw describeSqlFailure(`postgres: setting the password of role ${role} failed`, error);
  }
  const value = withCredentials(parsed.url, role, password);
  const warnings = await probe(deps, value, `postgres: the new credential of role ${role}`);
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
}

async function rotateMysql(
  rule: Extract<RotateRule, { connector: "mysql" }>,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<RotationOutcome> {
  const parsed = parseDbUrl(current.primary, "mysql");
  const role = nextRole(rule, parsed.user);
  const password = generatePassword(deps.randomBytes);
  const retain = rule.roles === null ? " RETAIN CURRENT PASSWORD" : "";
  const statement = `ALTER USER ${mysqlAccount(role, rule.host)} IDENTIFIED BY ${mysqlLiteral(password)}${retain}`;
  try {
    await deps.sql.execute(adminUrlOf(inputs, parsed), [statement]);
  } catch (error) {
    throw describeSqlFailure(`mysql: setting the password of ${role}@${rule.host} failed`, error);
  }
  const value = withCredentials(parsed.url, role, password);
  const warnings = await probe(deps, value, `mysql: the new credential of ${role}@${rule.host}`);
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
}

async function probe(deps: RotateDeps, url: string, what: string): Promise<readonly string[]> {
  try {
    await deps.sql.probe(url);
    return [];
  } catch (error) {
    const reason = describeSqlFailure(
      `${what} was set at the server but a connection test with it failed`,
      error,
    );
    return [`${reason.message} — check the new value before finalizing`];
  }
}

async function finalizePostgres(
  rule: Extract<RotateRule, { connector: "postgres" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<FinalizeOutcome> {
  if (rule.roles === null) {
    return { kind: "nothing", facts: ["an in-place password change left nothing to finalize"] };
  }
  const before = parseDbUrl(previous.primary, "postgres");
  const now = parseDbUrl(current.primary, "postgres");
  if (before.user === now.user) {
    return {
      kind: "nothing",
      facts: [`role ${now.user} is in use by both versions (nothing to invalidate)`],
    };
  }
  const scrambled = generatePassword(deps.randomBytes);
  const statement = `ALTER ROLE ${pgIdentifier(before.user)} WITH PASSWORD ${pgLiteral(scrambled)}`;
  try {
    await deps.sql.execute(adminUrlOf(inputs, now), [statement]);
  } catch (error) {
    throw describeSqlFailure(
      `postgres: invalidating the password of role ${before.user} failed`,
      error,
    );
  }
  return {
    kind: "finalized",
    facts: [`role ${before.user}: password replaced by a random one nobody holds`],
  };
}

async function finalizeMysql(
  rule: Extract<RotateRule, { connector: "mysql" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<FinalizeOutcome> {
  const now = parseDbUrl(current.primary, "mysql");
  if (rule.roles === null) {
    const statement = `ALTER USER ${mysqlAccount(now.user, rule.host)} DISCARD OLD PASSWORD`;
    try {
      await deps.sql.execute(adminUrlOf(inputs, now), [statement]);
    } catch (error) {
      throw describeSqlFailure(
        `mysql: discarding the secondary password of ${now.user}@${rule.host} failed`,
        error,
      );
    }
    return {
      kind: "finalized",
      facts: [`account ${now.user}@${rule.host}: secondary password discarded`],
    };
  }
  const before = parseDbUrl(previous.primary, "mysql");
  if (before.user === now.user) {
    return {
      kind: "nothing",
      facts: [`account ${now.user} is in use by both versions (nothing to invalidate)`],
    };
  }
  const scrambled = generatePassword(deps.randomBytes);
  const statement = `ALTER USER ${mysqlAccount(before.user, rule.host)} IDENTIFIED BY ${mysqlLiteral(scrambled)}`;
  try {
    await deps.sql.execute(adminUrlOf(inputs, now), [statement]);
  } catch (error) {
    throw describeSqlFailure(
      `mysql: invalidating the password of ${before.user}@${rule.host} failed`,
      error,
    );
  }
  return {
    kind: "finalized",
    facts: [`account ${before.user}@${rule.host}: password replaced by a random one nobody holds`],
  };
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
function awsCallerOf(current: CredentialValues, inputs: RotateInputs): AwsCredentials {
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
    accessKeyId: currentKeyId(current),
    secretAccessKey: decoder.decode(current.primary).trim(),
  };
}

function currentKeyId(current: CredentialValues): string {
  const companion = current.companions[AWS_ACCESS_KEY_ID_COMPANION];
  if (companion === undefined) {
    throw new ConnectorError("aws-iam-access-key: the access key id companion is missing");
  }
  const id = decoder.decode(companion).trim();
  if (!ACCESS_KEY_ID.test(id)) {
    throw new ConnectorError(
      "aws-iam-access-key: the access key id variable does not hold an access key id (uppercase letters and digits)",
    );
  }
  return id;
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
async function awsQueryCall(
  deps: RotateDeps,
  caller: AwsCredentials,
  service: AwsQueryService,
  action: string,
  params: Readonly<Record<string, string>>,
): Promise<{ readonly ok: boolean; readonly status: number; readonly text: string }> {
  const body = new URLSearchParams({
    Action: action,
    Version: service.version,
    ...params,
  }).toString();
  const signed = await signV4({
    method: "POST",
    url: `${service.base}/`,
    region: AWS_IAM_REGION,
    service: service.name,
    headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
    body,
    credentials: caller,
    nowMs: deps.now(),
  });
  let response: Response;
  try {
    response = await deps.fetch(`${service.base}/`, {
      method: "POST",
      headers: { ...signed.headers, "user-agent": USER_AGENT },
      body,
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    throw new ConnectorError(
      `aws-iam-access-key: ${action} could not reach ${service.name.toUpperCase()} (${reason})`,
    );
  }
  return { ok: response.ok, status: response.status, text: await response.text() };
}

function awsErrorText(text: string): string {
  const code = xmlText(text, "Code") ?? "unknown";
  const message = xmlText(text, "Message") ?? "";
  return `${code}${message === "" ? "" : `: ${message}`}`;
}

async function iamCall(
  deps: RotateDeps,
  caller: AwsCredentials,
  action: string,
  params: Readonly<Record<string, string>>,
): Promise<string> {
  const response = await awsQueryCall(
    deps,
    caller,
    { name: "iam", base: deps.awsIamBase ?? AWS_IAM_BASE, version: AWS_IAM_VERSION },
    action,
    params,
  );
  if (!response.ok) {
    throw new ConnectorError(
      `aws-iam-access-key: IAM answered ${response.status} to ${action} (${awsErrorText(response.text)})`,
    );
  }
  return response.text;
}

/**
 * Whether a key id and a secret are a pair: `sts:GetCallerIdentity` needs
 * no permission, so a success proves the pair and an authentication error
 * refutes it. Any other answer (a network failure, a throttle) is surfaced,
 * never read as "not the pair".
 */
async function awsPairAuthenticates(deps: RotateDeps, candidate: AwsCredentials): Promise<boolean> {
  const response = await awsQueryCall(
    deps,
    candidate,
    { name: "sts", base: deps.awsStsBase ?? AWS_STS_BASE, version: AWS_STS_VERSION },
    "GetCallerIdentity",
    {},
  );
  if (response.ok) {
    return true;
  }
  if (AWS_AUTH_FAILURE_CODES.has(xmlText(response.text, "Code") ?? "")) {
    return false;
  }
  throw new ConnectorError(
    `aws-iam-access-key: STS answered ${response.status} to GetCallerIdentity (${awsErrorText(response.text)})`,
  );
}

async function iamUserOf(
  deps: RotateDeps,
  caller: AwsCredentials,
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  keyId: string,
): Promise<string> {
  if (rule.user !== null) {
    return rule.user;
  }
  const xml = await iamCall(deps, caller, "GetAccessKeyLastUsed", { AccessKeyId: keyId });
  const user = xmlText(xml, "UserName");
  if (user === null || user.length === 0) {
    throw new ConnectorError(
      "aws-iam-access-key: IAM did not name the user of the current access key (set `user` in the rotation config)",
    );
  }
  return user;
}

async function iamListKeys(
  deps: RotateDeps,
  caller: AwsCredentials,
  user: string,
): Promise<IamKey[]> {
  const xml = await iamCall(deps, caller, "ListAccessKeys", { UserName: user });
  return xmlMembers(xml).flatMap((member) => {
    const id = xmlText(member, "AccessKeyId");
    const status = xmlText(member, "Status");
    const createDate = xmlText(member, "CreateDate") ?? "";
    return id === null || (status !== "Active" && status !== "Inactive")
      ? []
      : [{ id, status, createDate }];
  });
}

/** The IAM user the current key belongs to and its keys (the opening read of a rotation and of a finalize). */
async function iamKeysOf(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
) {
  const caller = awsCallerOf(current, inputs);
  const currentId = currentKeyId(current);
  const user = await iamUserOf(deps, caller, rule, currentId);
  const keys = await iamListKeys(deps, caller, user);
  return { caller, currentId, user, keys };
}

async function rotateAwsIam(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<RotationOutcome> {
  const { caller, currentId, user, keys } = await iamKeysOf(rule, current, inputs, deps);
  const facts: string[] = [];
  if (keys.length >= 2) {
    // IAM allows two keys per user. An inactive one that is not the key in
    // use is a finalized previous rotation — reclaim it (Vault / Infisical
    // reclaim the oldest; we never delete an active key)
    const reclaimable = keys.find((key) => key.id !== currentId && key.status === "Inactive");
    if (reclaimable === undefined) {
      throw new ConnectorError(
        `aws-iam-access-key: user ${user} already has two active access keys, so IAM cannot create a third. Finalize the previous rotation (\`--finalize\` deactivates the key the previous version held) or deactivate one at the issuer, then retry`,
      );
    }
    await iamCall(deps, caller, "DeleteAccessKey", { UserName: user, AccessKeyId: reclaimable.id });
    facts.push(
      `deleted the inactive access key ${reclaimable.id} (the slot a previous rotation left)`,
    );
  }
  const xml = await iamCall(deps, caller, "CreateAccessKey", { UserName: user });
  const newId = xmlText(xml, "AccessKeyId");
  const newSecret = xmlText(xml, "SecretAccessKey");
  if (newId === null || newSecret === null || newId.length === 0 || newSecret.length === 0) {
    throw new ConnectorError("aws-iam-access-key: IAM did not return the new access key");
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
async function finalizeAwsIam(
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
  ancestors: CompanionAncestors,
): Promise<FinalizeOutcome> {
  const { caller, currentId, user, keys } = await iamKeysOf(rule, current, inputs, deps);
  const others = keys.filter((key) => key.id !== currentId);
  if (others.length === 0) {
    return {
      kind: "nothing",
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
        kind: "already",
        facts: [
          ...facts,
          `access key ${key.id} is already inactive (the next rotation deletes it)`,
        ],
      };
    }
    const pairs = await awsPairAuthenticates(deps, {
      accessKeyId: key.id,
      secretAccessKey: previousSecret,
    });
    if (!pairs) {
      facts.push(
        `access key ${key.id} is active but does not authenticate with the previous version's secret (not that version's key) — left untouched`,
      );
      continue;
    }
    await iamCall(deps, caller, "UpdateAccessKey", {
      UserName: user,
      AccessKeyId: key.id,
      Status: "Inactive",
    });
    return {
      kind: "finalized",
      facts: [
        ...facts,
        `access key ${key.id} deactivated (reversible at the issuer; the next rotation deletes it)`,
      ],
    };
  }
  return { kind: "nothing", facts };
}

/* -------------------------------------------------------------------------- */
/* Cloudflare API tokens                                                         */
/* -------------------------------------------------------------------------- */

const CLOUDFLARE_BASE = "https://api.cloudflare.com";

interface CloudflareEnvelope {
  readonly success?: boolean;
  readonly errors?: readonly { readonly code?: number; readonly message?: string }[];
  readonly result?: unknown;
}

function tokensPath(rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>): string {
  return rule.accountId === null
    ? "/client/v4/user/tokens"
    : `/client/v4/accounts/${rule.accountId}/tokens`;
}

async function cloudflareCall(
  deps: RotateDeps,
  bearer: string,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown,
): Promise<{ readonly status: number; readonly envelope: CloudflareEnvelope }> {
  const base = deps.cloudflareBase ?? CLOUDFLARE_BASE;
  let response: Response;
  try {
    response = await deps.fetch(`${base}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${bearer}`,
        "user-agent": USER_AGENT,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    throw new ConnectorError(
      `cloudflare-api-token: ${method} ${path} could not reach Cloudflare (${reason})`,
    );
  }
  let envelope: CloudflareEnvelope = {};
  try {
    envelope = (await response.json()) as CloudflareEnvelope;
  } catch {
    envelope = {};
  }
  return { status: response.status, envelope };
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
  return new ConnectorError(
    `cloudflare-api-token: Cloudflare answered ${status} to ${what}${detail}`,
  );
}

/** The id of the token whose value this is (`/verify` with the token itself), or null when it is not valid. */
async function cloudflareTokenId(
  deps: RotateDeps,
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  token: string,
): Promise<string | null> {
  const { status, envelope } = await cloudflareCall(
    deps,
    token,
    "GET",
    `${tokensPath(rule)}/verify`,
  );
  if (status === 401 || status === 403 || envelope.success === false) {
    return null;
  }
  if (status !== 200) {
    throw cloudflareFailure("the token verification", status, envelope);
  }
  const result = envelope.result as { readonly id?: unknown } | undefined;
  return typeof result?.id === "string" && result.id.length > 0 ? result.id : null;
}

function adminTokenOf(current: CredentialValues, inputs: RotateInputs): string {
  const admin = inputs["token"];
  return decoder.decode(admin ?? current.primary).trim();
}

/** The definition of a token (name, policies, condition, validity window) as the replacement's request body. */
async function cloudflareDefinition(
  deps: RotateDeps,
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  admin: string,
  id: string,
): Promise<Record<string, unknown>> {
  const detail = await cloudflareCall(deps, admin, "GET", `${tokensPath(rule)}/${id}`);
  if (detail.status !== 200 || detail.envelope.success === false) {
    throw cloudflareFailure(`reading token ${id}`, detail.status, detail.envelope);
  }
  const definition = detail.envelope.result as {
    readonly name?: unknown;
    readonly policies?: unknown;
    readonly condition?: unknown;
    readonly expires_on?: unknown;
    readonly not_before?: unknown;
  };
  if (typeof definition.name !== "string" || !Array.isArray(definition.policies)) {
    throw new ConnectorError(
      `cloudflare-api-token: token ${id} came back without a name and policies`,
    );
  }
  const request: Record<string, unknown> = { name: definition.name, policies: definition.policies };
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
}

async function rotateCloudflare(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<RotationOutcome> {
  const token = decoder.decode(current.primary).trim();
  const admin = adminTokenOf(current, inputs);
  const id = await cloudflareTokenId(deps, rule, token);
  if (id === null) {
    throw new ConnectorError(
      "cloudflare-api-token: the current value is not a valid token (Cloudflare refused to verify it), so its policies cannot be copied. Create the replacement at the issuer and push it",
    );
  }
  const request = await cloudflareDefinition(deps, rule, admin, id);
  const created = await cloudflareCall(deps, admin, "POST", tokensPath(rule), request);
  if (created.status !== 200 || created.envelope.success === false) {
    throw cloudflareFailure("creating the replacement token", created.status, created.envelope);
  }
  const result = created.envelope.result as { readonly id?: unknown; readonly value?: unknown };
  if (
    typeof result.id !== "string" ||
    typeof result.value !== "string" ||
    result.value.length === 0
  ) {
    throw new ConnectorError(
      "cloudflare-api-token: Cloudflare did not return the new token's value",
    );
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
}

async function finalizeCloudflare(
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<FinalizeOutcome> {
  const admin = adminTokenOf(current, inputs);
  const previousToken = decoder.decode(previous.primary).trim();
  const currentToken = decoder.decode(current.primary).trim();
  if (previousToken === currentToken) {
    return { kind: "nothing", facts: ["both versions hold the same token (nothing to delete)"] };
  }
  const previousId = await cloudflareTokenId(deps, rule, previousToken);
  if (previousId === null) {
    return { kind: "already", facts: ["the previous token is no longer valid"] };
  }
  const currentId = await cloudflareTokenId(deps, rule, currentToken);
  if (currentId === previousId) {
    return {
      kind: "nothing",
      facts: [`token ${previousId} is the one in use (nothing to delete)`],
    };
  }
  const deleted = await cloudflareCall(deps, admin, "DELETE", `${tokensPath(rule)}/${previousId}`);
  if (deleted.status === 404) {
    return { kind: "already", facts: [`token ${previousId} no longer exists`] };
  }
  if (deleted.status !== 200 || deleted.envelope.success === false) {
    throw cloudflareFailure(`deleting token ${previousId}`, deleted.status, deleted.envelope);
  }
  return { kind: "finalized", facts: [`token ${previousId} deleted`] };
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
}): Readonly<Record<string, string>> {
  const env: Record<string, string> = {
    [`${EXEC_CONTROL_PREFIX}VARIABLE`]: input.site.variable,
    [`${EXEC_CONTROL_PREFIX}ENVIRONMENT`]: input.site.environmentId,
    [`${EXEC_CONTROL_PREFIX}PHASE`]: input.phase,
  };
  const set = (name: string, bytes: Uint8Array, what: string): void => {
    const text = decodeValueText(bytes);
    if (text === null || text.includes("\0")) {
      throw new ConnectorError(
        `exec: ${what} is not a UTF-8 text without NUL, so it cannot be set in the script's environment`,
      );
    }
    env[name] = text;
  };
  set(
    input.site.variable,
    input.current.primary,
    `the value of ${displayText(input.site.variable)}`,
  );
  set(
    `${EXEC_CONTROL_PREFIX}CURRENT`,
    input.current.primary,
    `the value of ${displayText(input.site.variable)}`,
  );
  if (input.previous !== null) {
    set(`${EXEC_CONTROL_PREFIX}PREVIOUS`, input.previous.primary, "the previous credential");
  }
  for (const [envName, variable] of Object.entries(input.rule.companions)) {
    const bytes = input.current.companions[envName];
    if (bytes !== undefined) {
      set(envName, bytes, `the value of ${displayText(variable)}`);
    }
    // The companion the previous credential carried (the key id to
    // retire), when the finalize knows it (C-7)
    const previousBytes = input.previous?.companions[envName];
    if (previousBytes !== undefined) {
      set(
        `${EXEC_CONTROL_PREFIX}PREVIOUS_${envName}`,
        previousBytes,
        `the previous value of ${displayText(variable)}`,
      );
    }
  }
  for (const [envName, bytes] of Object.entries(input.inputs)) {
    set(envName, bytes, `the input ${displayText(envName)}`);
  }
  return env;
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

/** Runs one script; a launch failure or a non-zero exit is a connector error naming the script and the scrubbed stderr tail. */
async function runScript(
  deps: RotateDeps,
  rule: ExecRule,
  argv: readonly string[],
  env: Readonly<Record<string, string>>,
  secrets: readonly SyncWrite[],
  phase: "rotate" | "finalize",
): Promise<CaptureOutcome> {
  let outcome: CaptureOutcome;
  try {
    outcome = await deps.exec({ command: argv, cwd: rule.cwd, extraEnv: env });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "it could not be started";
    throw new ConnectorError(`exec: the ${phase} script ${argv[0] ?? ""} did not start: ${reason}`);
  }
  if (outcome.exitCode !== 0) {
    const tail = scrubbedLines(outcome.stderr, secrets, EXEC_SHOWN_LINES);
    throw new ConnectorError(
      `exec: the ${phase} script ${argv[0] ?? ""} exited with code ${outcome.exitCode}${tail.length === 0 ? "" : ` (its stderr, filtered: ${tail.join(" | ")})`}`,
    );
  }
  return outcome;
}

/**
 * The shape of a produced value, as a fact for the member who accepts it
 * (D-7): a script that printed its own chatter on stdout, or a one-byte
 * value, shows here before the value is pushed. Nothing of the value
 * itself (its ciphertext length tells the same).
 */
function valueShape(value: Uint8Array): string {
  let lines = 1;
  for (const byte of value) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  return `${countNoun(value.length, "byte")}, ${countNoun(lines, "line")}`;
}

/** The new value as the rotate script printed it: one trailing newline (LF or CRLF) is dropped, nothing else is touched. */
function valueFromStdout(stdout: Uint8Array): Uint8Array {
  let end = stdout.length;
  if (end > 0 && stdout[end - 1] === 0x0a) {
    end -= 1;
    if (end > 0 && stdout[end - 1] === 0x0d) {
      end -= 1;
    }
  }
  const value = stdout.subarray(0, end);
  if (value.length === 0) {
    throw new ConnectorError(
      "exec: the rotate script printed no value on stdout (its stdout is the new credential; commentary belongs on stderr)",
    );
  }
  return producedText(value, "the value the rotate script printed on stdout");
}

interface ScriptAnswer {
  readonly values: CredentialValues;
  readonly facts: readonly string[];
}

/** The rotate script's stdout as a JSON object (anything else is refused with the contract spelled out). */
function jsonObjectFromStdout(stdout: Uint8Array): Record<string, unknown> {
  const text = decodeValueText(stdout);
  let parsed: unknown;
  try {
    parsed = text === null ? undefined : JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ConnectorError(
      'exec: the rotate script did not print a JSON object on stdout (the rule declares "output": "json": print {"value": "<new credential>", "companions": {…}, "facts": […]})',
    );
  }
  const record = parsed as Record<string, unknown>;
  const unknown = Object.keys(record).filter(
    (key) => !["value", "companions", "facts"].includes(key),
  );
  // The keys are the script's words: counted, never echoed
  if (unknown.length > 0) {
    throw new ConnectorError(
      `exec: the rotate script's JSON answer has ${countNoun(unknown.length, "unknown key")}; it takes value, companions, facts`,
    );
  }
  return record;
}

/** One answered companion: declared by the rule and a non-empty string. */
function companionBytes(rule: ExecRule, name: string, value: unknown): Uint8Array {
  // The script's own words never reach an error message (a mistyped key
  // could be a credential): the message names what the rule declares
  if (!(name in rule.companions)) {
    throw new ConnectorError(
      `exec: the rotate script answered a companion the rule does not declare (the rule declares ${declaredCompanions(rule)}); declare it under companions in the rotation config`,
    );
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
function producedBytes(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new ConnectorError(`exec: ${what} is not a non-empty string`);
  }
  return producedText(encoder.encode(value), what);
}

/** The produced bytes checked as UTF-8 text without NUL (a value that could not be injected is refused before it is stored). */
function producedText(bytes: Uint8Array, what: string): Uint8Array {
  const text = decodeValueText(bytes);
  if (text === null || text.includes("\0")) {
    throw new ConnectorError(
      `exec: ${what} is not UTF-8 text without NUL, so it could never be injected into a process environment; it is refused before anything is stored`,
    );
  }
  return bytes;
}

/** The answer's companions: every one the rule declares, nothing it does not, each a non-empty string. */
function companionsFromAnswer(rule: ExecRule, raw: unknown): Record<string, Uint8Array> {
  const companionsRaw = raw ?? {};
  if (typeof companionsRaw !== "object" || companionsRaw === null || Array.isArray(companionsRaw)) {
    throw new ConnectorError(
      "exec: the rotate script's JSON answer has a companions field that is not an object",
    );
  }
  const companions: Record<string, Uint8Array> = {};
  for (const [name, value] of Object.entries(companionsRaw as Record<string, unknown>)) {
    companions[name] = companionBytes(rule, name, value);
  }
  const missing = Object.keys(rule.companions).find((name) => !(name in companions));
  if (missing !== undefined) {
    throw new ConnectorError(
      `exec: the rotate script's answer lacks the companion ${displayText(missing)} the rule declares (every declared companion is pushed with the new value, so all of them must be answered)`,
    );
  }
  return companions;
}

/** The rotate script's JSON answer: `{ value, companions?, facts? }`. */
function answerFromJson(rule: ExecRule, stdout: Uint8Array): ScriptAnswer {
  const record = jsonObjectFromStdout(stdout);
  const primary = producedBytes(record["value"], "the value in the rotate script's JSON answer");
  const companions = companionsFromAnswer(rule, record["companions"]);
  const factsRaw = record["facts"] ?? [];
  if (!Array.isArray(factsRaw) || !factsRaw.every((fact) => typeof fact === "string")) {
    throw new ConnectorError(
      "exec: the rotate script's JSON answer has a facts field that is not a list of strings",
    );
  }
  return { values: { primary, companions }, facts: factsRaw as string[] };
}

async function rotateExec(
  rule: ExecRule,
  site: RotationSite,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<RotationOutcome> {
  const env = scriptEnvironment({ rule, site, phase: "rotate", current, previous: null, inputs });
  const secrets = scriptSecrets({ current, previous: null, inputs });
  const outcome = await runScript(deps, rule, rule.rotate, env, secrets, "rotate");
  const answer: ScriptAnswer =
    rule.output === "json"
      ? answerFromJson(rule, outcome.stdout)
      : { values: { primary: valueFromStdout(outcome.stdout), companions: {} }, facts: [] };
  // The script's own words may carry a credential by mistake: scrub them
  // of everything this run knows before they reach the report
  const all = scriptSecrets({ current, previous: null, inputs, produced: answer.values });
  const facts = [
    valueShape(answer.values.primary),
    ...answer.facts.flatMap((fact) => scrubbedLines(fact, all, 1)),
  ];
  const script = rule.rotate[0] ?? "";
  return {
    values: answer.values,
    facts: [`${script}: new credential produced (${facts.join("; ")})`],
    previous:
      rule.finalize === null
        ? "the rotate script was expected to retire the previous credential itself (nothing to finalize)"
        : `the previous credential stays valid until you finalize (${rule.finalize[0] ?? ""} runs with it)`,
    recovery: `the new credential is held only by this process (it is not shown) — re-run the rotation (${script} runs again; make it idempotent, or retire the unused credential at the issuer by hand)`,
    warnings: [],
  };
}

async function finalizeExec(
  rule: ExecRule,
  site: RotationSite,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
): Promise<FinalizeOutcome> {
  if (rule.finalize === null) {
    return {
      kind: "nothing",
      facts: [
        "the rule has no finalize script (its rotate script retires the previous credential itself)",
      ],
    };
  }
  const env = scriptEnvironment({ rule, site, phase: "finalize", current, previous, inputs });
  const secrets = scriptSecrets({ current, previous, inputs });
  const outcome = await runScript(deps, rule, rule.finalize, env, secrets, "finalize");
  const said = scrubbedLines(decoder.decode(outcome.stdout), secrets, EXEC_FACT_LINES);
  return {
    kind: "finalized",
    facts: [
      `${rule.finalize[0] ?? ""}: previous credential retired${said.length === 0 ? "" : ` (${said.join("; ")})`}`,
    ],
  };
}

/* -------------------------------------------------------------------------- */
/* The frame                                                                     */
/* -------------------------------------------------------------------------- */

/** The companions a rule's credential carries (companion name → the variable that holds it). */
export function companionsOf(rule: RotateRule): Readonly<Record<string, string>> {
  return companionVariablesOf(rule);
}

/** What the rotation will do at the issuer (decided from the current value alone — nothing is sent). */
export function planRotation(rule: RotateRule, current: CredentialValues): RotationPlan {
  switch (rule.connector) {
    case "postgres":
    case "mysql":
      return dbPlan(rule, current);
    case "aws-iam-access-key":
      return {
        description: `create a second access key for the IAM user (the current key ${currentKeyId(current)} stays active until you finalize)`,
        immediate: false,
      };
    case "cloudflare-api-token":
      return {
        description:
          "create a second token with the current token's policies (the current token stays valid until you finalize)",
        immediate: false,
      };
    case "exec":
      return rule.finalize === null
        ? {
            description: `run ${rule.rotate[0] ?? ""} — the rule has no finalize script, so that script is expected to retire the current credential itself (no grace period)`,
            immediate: true,
          }
        : {
            description: `run ${rule.rotate[0] ?? ""} to create the new credential (the current one stays valid until you finalize with ${rule.finalize[0] ?? ""})`,
            immediate: false,
          };
  }
}

/** Creates the new credential at the issuer. Rejects with {@link ConnectorError}. */
export async function rotateCredential(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
  /** Where the rotation happens (the `exec` connector's scripts receive it; required for that connector). */
  site?: RotationSite,
): Promise<RotationOutcome> {
  switch (rule.connector) {
    case "postgres":
      return rotatePostgres(rule, current, inputs, deps);
    case "mysql":
      return rotateMysql(rule, current, inputs, deps);
    case "aws-iam-access-key":
      return rotateAwsIam(rule, current, inputs, deps);
    case "cloudflare-api-token":
      return rotateCloudflare(rule, current, inputs, deps);
    case "exec":
      return rotateExec(rule, requireSite(site), current, inputs, deps);
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

/** Invalidates the previous credential at the issuer. Rejects with {@link ConnectorError}. */
export async function finalizeCredential(
  rule: RotateRule,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  deps: RotateDeps,
  ancestors: CompanionAncestors = {},
  /** Where the rotation happens (required for the `exec` connector). */
  site?: RotationSite,
): Promise<FinalizeOutcome> {
  switch (rule.connector) {
    case "postgres":
      return finalizePostgres(rule, previous, current, inputs, deps);
    case "mysql":
      return finalizeMysql(rule, previous, current, inputs, deps);
    case "aws-iam-access-key":
      return finalizeAwsIam(rule, previous, current, inputs, deps, ancestors);
    case "cloudflare-api-token":
      return finalizeCloudflare(rule, previous, current, inputs, deps);
    case "exec":
      return finalizeExec(rule, requireSite(site), previous, current, inputs, deps);
  }
}

/** The exec connector cannot run without knowing the variable and environment (an internal inconsistency, never a user error). */
function requireSite(site: RotationSite | undefined): RotationSite {
  if (site === undefined) {
    throw new ConnectorError("exec: the rotation site (variable and environment) was not supplied");
  }
  return site;
}
