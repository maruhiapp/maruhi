import type { MetaStatementTarget } from "@maruhi/crypto";
import {
  computeMetaSignedBytesHash,
  computeVariablesDigest,
  signMetaStatement as signMetaStatementBytes,
  SUITE_ID,
} from "@maruhi/crypto";
import {
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
  unwrapResult,
} from "@maruhi/crypto/test-support";

import type { ChainHead } from "./chain.ts";
import type { SigningIdentity, TestIdentity } from "./identity.ts";
import { signingKeyOf } from "./identity.ts";
import type {
  WireDistributedEnvironmentStatement,
  WireDistributedVariableStatement,
  WireStatementSchema,
  WireStatementStatus,
  WireVariableMetaStatement,
} from "./wire.ts";

export type UnsignedMetaStatement = Omit<
  WireVariableMetaStatement,
  "signatureHex" | "variableId" | "suite"
> & {
  readonly suite: string;
  readonly variableId?: string;
};

export interface WireDigestEntry {
  readonly variableId: string;
  readonly status: WireStatementStatus;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

function metaTargetOf(statement: { readonly variableId?: string }): MetaStatementTarget {
  return statement.variableId === undefined
    ? { kind: "environment" }
    : { kind: "variable", variableId: testVariableId(statement.variableId) };
}

function metaContextOf(projectId: string, statement: UnsignedMetaStatement, authorUserId: string) {
  return {
    suite: statement.suite,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(statement.environmentId),
    target: metaTargetOf(statement),
    name: statement.name,
    status: statement.status,
    layoutVersion: statement.layoutVersion,
    ...(statement.layoutVersion === undefined ||
    statement.varType === undefined ||
    statement.required === undefined ||
    statement.description === undefined
      ? {}
      : {
          schema: {
            varType: statement.varType,
            required: statement.required ? ("true" as const) : ("false" as const),
            description: statement.description,
            maxAgeDays:
              statement.maxAgeDays === undefined || statement.maxAgeDays === null
                ? ""
                : String(statement.maxAgeDays),
          },
        }),
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    authorUserId: testUserId(authorUserId),
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
  };
}

type StatementAuthor = SigningIdentity & Pick<TestIdentity, "userId">;

export async function signMetaStatement<const T extends UnsignedMetaStatement>(
  author: StatementAuthor,
  projectId: string,
  unsigned: T,
): Promise<T & { readonly signatureHex: string }> {
  const signatureHex = unwrapResult(
    await signMetaStatementBytes({
      context: metaContextOf(projectId, unsigned, author.userId),
      signingKey: await signingKeyOf(author),
    }),
    "signMetaStatement",
  );
  return { ...unsigned, signatureHex };
}

export async function metaSignedBytesHashOf(
  projectId: string,
  statement: UnsignedMetaStatement,
  authorUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeMetaSignedBytesHash(metaContextOf(projectId, statement, authorUserId)),
    "computeMetaSignedBytesHash",
  );
}

export async function variablesDigestOf(entries: readonly WireDigestEntry[]): Promise<string> {
  return unwrapResult(
    await computeVariablesDigest(
      SUITE_ID,
      entries.map((entry) => ({ ...entry, variableId: testVariableId(entry.variableId) })),
    ),
    "computeVariablesDigest",
  );
}

export async function createVariableStatement(input: {
  readonly author: StatementAuthor;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly head: ChainHead;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatement(input.author, input.projectId, {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

export interface DistributedStatementInput {
  readonly projectId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly author: TestIdentity;
  readonly head: ChainHead;
  readonly status?: WireStatementStatus;
  readonly metaVersion?: number;
  readonly prevMetaSigHashHex?: string;
  readonly schema?: WireStatementSchema;
}

type DistributedStatementLayout = Partial<WireStatementSchema> & {
  readonly layoutVersion?: number;
};

async function signDistributedStatement(
  input: Omit<DistributedStatementInput, "status" | "schema">,
  variable: {
    readonly variableId: string | undefined;
    readonly status: WireStatementStatus;
    readonly schema: WireStatementSchema | undefined;
  },
): Promise<Omit<WireDistributedVariableStatement, "variableId">> {
  const { variableId, status, schema } = variable;
  const metaVersion = input.metaVersion ?? 1;
  const prevMetaSigHashHex = input.prevMetaSigHashHex ?? (metaVersion === 1 ? "" : "cd".repeat(32));
  const layout: DistributedStatementLayout =
    schema === undefined
      ? {}
      : { layoutVersion: 3, ...schema, maxAgeDays: schema.maxAgeDays ?? null };
  const signed = await signMetaStatement(input.author, input.projectId, {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    ...(variableId === undefined ? {} : { variableId }),
    name: input.name,
    status,
    metaVersion,
    prevMetaSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    ...layout,
  });
  return {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    name: input.name,
    status,
    metaVersion,
    prevMetaSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    signatureHex: signed.signatureHex,
    authorUserId: input.author.userId,
    authorKeyFingerprintHex: input.author.fingerprintHex,
    ...layout,
  };
}

export async function distributedVariableStatement(
  input: DistributedStatementInput & { readonly variableId: string },
): Promise<WireDistributedVariableStatement> {
  const statement = await signDistributedStatement(input, {
    variableId: input.variableId,
    status: input.status ?? "active",
    schema: input.schema,
  });
  return { ...statement, variableId: input.variableId };
}

export async function distributedEnvironmentStatement(
  input: Omit<DistributedStatementInput, "status" | "schema">,
): Promise<WireDistributedEnvironmentStatement> {
  const statement = await signDistributedStatement(input, {
    variableId: undefined,
    status: "active",
    schema: undefined,
  });
  return { ...statement, status: "active" };
}

function withCompleteLayoutOnly(statement: UnsignedMetaStatement): UnsignedMetaStatement {
  const { layoutVersion, varType, required, description, maxAgeDays, ...base } = statement;
  return layoutVersion === undefined ||
    varType === undefined ||
    required === undefined ||
    description === undefined
    ? base
    : {
        ...base,
        layoutVersion,
        varType,
        required,
        description,
        ...(maxAgeDays === undefined ? {} : { maxAgeDays }),
      };
}

export async function distributedStatementHashOf(
  projectId: string,
  statement: WireDistributedVariableStatement | WireDistributedEnvironmentStatement,
): Promise<string> {
  return metaSignedBytesHashOf(
    projectId,
    withCompleteLayoutOnly(statement),
    statement.authorUserId,
  );
}

export async function distributedVariablesDigestOf(
  projectId: string,
  statements: readonly WireDistributedVariableStatement[],
): Promise<string> {
  return variablesDigestOf(
    await Promise.all(
      statements.map(async (statement) => ({
        variableId: statement.variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        metaSigHashHex: await distributedStatementHashOf(projectId, statement),
      })),
    ),
  );
}
