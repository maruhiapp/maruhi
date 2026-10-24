// The `aws-iam-access-key` connector (the connector overview lives in
// connector.ts): IAM's Query API, signed with SigV4 (sigv4.ts). A rotation
// creates a second access key for the key's IAM user, deleting an inactive
// one first. Finalize deactivates the previous key once an earlier version
// of the key id variable held its id and STS proves it authenticates with
// the previous version's secret.

import { Clock, Effect } from "effect";
import { HttpBody, HttpClient, HttpClientRequest } from "effect/http";

import { type AwsCredentials, signV4 } from "../sigv4.ts";
import {
  type CompanionAncestors,
  ConnectorError,
  type ConnectorOutcome,
  type CredentialValues,
  type FinalizeOutcome,
  IssuerEndpoints,
  reasonOf,
  type RotateInputs,
  transportReason,
  USER_AGENT,
} from "./connector-shared.ts";
import type { RotateRule } from "./rotate-config.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const AWS_IAM_BASE = "https://iam.amazonaws.com";
const AWS_IAM_VERSION = "2010-05-08";
/** IAM's Query API lives in us-east-1 whatever the caller's region. */
const AWS_IAM_REGION = "us-east-1";
/**
 * The Query API body's content type. SigV4 signs it (`SignedHeaders` names
 * content-type), so the request must carry exactly this value: the body
 * declares it, because setting a body rewrites the content-type header
 * from the body's own type.
 */
const AWS_QUERY_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8";
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
const awsCallerOf = Effect.fn("connector-aws-iam.awsCallerOf")(function* (
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<AwsCredentials, ConnectorError> {
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

export function currentKeyId(current: CredentialValues): Effect.Effect<string, ConnectorError> {
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
const awsQueryCall = Effect.fn("connector-aws-iam.awsQueryCall")(function* (
  caller: AwsCredentials,
  service: AwsQueryService,
  action: string,
  params: Readonly<Record<string, string>>,
): Effect.fn.Return<
  { readonly ok: boolean; readonly status: number; readonly text: string },
  ConnectorError,
  HttpClient.HttpClient
> {
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
        headers: { "content-type": AWS_QUERY_CONTENT_TYPE },
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
        HttpClientRequest.setBody(HttpBody.raw(body, { contentType: AWS_QUERY_CONTENT_TYPE })),
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

function awsErrorText(text: string): string {
  const code = xmlText(text, "Code") ?? "unknown";
  const message = xmlText(text, "Message") ?? "";
  return `${code}${message === "" ? "" : `: ${message}`}`;
}

const iamCall = Effect.fn("connector-aws-iam.iamCall")(function* (
  caller: AwsCredentials,
  action: string,
  params: Readonly<Record<string, string>>,
): Effect.fn.Return<string, ConnectorError, HttpClient.HttpClient> {
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

/**
 * Whether a key id and a secret are a pair: `sts:GetCallerIdentity` needs
 * no permission, so a success proves the pair and an authentication error
 * refutes it. Any other answer (a network failure, a throttle) is surfaced,
 * never read as "not the pair".
 */
const awsPairAuthenticates = Effect.fn("connector-aws-iam.awsPairAuthenticates")(function* (
  candidate: AwsCredentials,
): Effect.fn.Return<boolean, ConnectorError, HttpClient.HttpClient> {
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

const iamUserOf = Effect.fn("connector-aws-iam.iamUserOf")(function* (
  caller: AwsCredentials,
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  keyId: string,
): Effect.fn.Return<string, ConnectorError, HttpClient.HttpClient> {
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
const iamKeysOf = Effect.fn("connector-aws-iam.iamKeysOf")(function* (
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<
  {
    readonly caller: AwsCredentials;
    readonly currentId: string;
    readonly user: string;
    readonly keys: IamKey[];
  },
  ConnectorError,
  HttpClient.HttpClient
> {
  const caller = yield* awsCallerOf(current, inputs);
  const currentId = yield* currentKeyId(current);
  const user = yield* iamUserOf(caller, rule, currentId);
  const keys = yield* iamListKeys(caller, user);
  return { caller, currentId, user, keys };
});

export const rotateAwsIam = Effect.fn("connector-aws-iam.rotateAwsIam")(function* (
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<ConnectorOutcome, ConnectorError, HttpClient.HttpClient> {
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
export const finalizeAwsIam = Effect.fn("connector-aws-iam.finalizeAwsIam")(function* (
  rule: Extract<RotateRule, { connector: "aws-iam-access-key" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  ancestors: CompanionAncestors,
): Effect.fn.Return<FinalizeOutcome, ConnectorError, HttpClient.HttpClient> {
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
