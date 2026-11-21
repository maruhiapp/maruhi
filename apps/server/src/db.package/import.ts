import type { OrgId, ProjectId, ProviderUserId, UserId } from "@maruhi/core";
import { cryptoServicesLayer } from "@maruhi/core";
import { and, eq, inArray } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import { drizzle } from "drizzle-orm/d1";
import { Effect } from "effect";

import { newOrgId } from "../ids.ts";
import { orgAuditInsert, userAuditInsert } from "./audit.ts";
import {
  linkedIdentities,
  memberships,
  organizations,
  projectMembers,
  projects,
  users,
} from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export interface ImportedIdentity {
  readonly userId: UserId;
  readonly provider: "github";
  readonly providerUserId: ProviderUserId;
  readonly providerLogin: string | null;
}

export interface ImportProjectInput {
  readonly projectId: ProjectId;
  readonly exportedBy: UserId;
  readonly identities: readonly ImportedIdentity[];
}

export type ImportRefusalCode =
  | "identities-empty"
  | "identities-malformed"
  | "exporter-missing"
  | "exporter-org-missing"
  | "identity-conflict"
  | "user-id-taken"
  | "project-exists";

export type ImportProvisionResult =
  | {
      readonly kind: "provisioned";
      readonly existing: number;
      readonly created: number;
      readonly members: number;
      readonly project: "created" | "kept";
    }
  | { readonly kind: "refused"; readonly code: ImportRefusalCode };

export type ImportClassification =
  | { readonly kind: "refused"; readonly code: ImportRefusalCode }
  | {
      readonly kind: "ok";
      readonly toCreate: readonly ImportedIdentity[];
      readonly existing: number;
      readonly project: "absent" | "exporter";
    };

function personalOrgSlug(userId: UserId): string {
  return `u-${userId.toLowerCase()}`;
}

const IN_CHUNK = 90;

function chunked<T extends string>(values: readonly T[]): readonly (readonly T[])[] {
  const chunks: (readonly T[])[] = [];
  for (let start = 0; start < values.length; start += IN_CHUNK) {
    chunks.push(values.slice(start, start + IN_CHUNK));
  }
  return chunks;
}

async function classify(
  db: Db,
  input: ImportProjectInput,
): Promise<
  | { readonly kind: "refused"; readonly code: ImportRefusalCode }
  | {
      readonly kind: "ok";
      readonly toCreate: readonly ImportedIdentity[];
      readonly existing: number;
    }
> {
  const ids = input.identities.map((identity) => identity.userId);
  const providerIds = input.identities.map((identity) => identity.providerUserId);
  const linkedByProvider = new Map<ProviderUserId, UserId>();
  for (const chunk of chunked(providerIds)) {
    const linked = await db
      .select({
        userId: linkedIdentities.userId,
        providerUserId: linkedIdentities.providerUserId,
      })
      .from(linkedIdentities)
      .where(
        and(
          eq(linkedIdentities.provider, "github"),
          inArray(linkedIdentities.providerUserId, chunk),
        ),
      );
    for (const row of linked) {
      linkedByProvider.set(row.providerUserId, row.userId);
    }
  }
  const existingUsers = new Set<UserId>();
  for (const chunk of chunked(ids)) {
    const found = await db.select({ id: users.id }).from(users).where(inArray(users.id, chunk));
    for (const row of found) {
      existingUsers.add(row.id);
    }
  }
  const toCreate: ImportedIdentity[] = [];
  let existing = 0;
  for (const identity of input.identities) {
    const boundTo = linkedByProvider.get(identity.providerUserId);
    if (boundTo !== undefined) {
      if (boundTo !== identity.userId) {
        return { kind: "refused", code: "identity-conflict" };
      }
      existing += 1;
      continue;
    }
    if (existingUsers.has(identity.userId)) {
      return { kind: "refused", code: "user-id-taken" };
    }
    toCreate.push(identity);
  }
  return { kind: "ok", toCreate, existing };
}

async function ownedByChainOwner(
  db: Db,
  orgId: OrgId,
  owners: readonly UserId[],
): Promise<boolean> {
  for (const owner of owners) {
    if ((await existingPersonalOrg(db, owner)) === orgId) {
      return true;
    }
  }
  return false;
}

async function existingPersonalOrg(db: Db, userId: UserId): Promise<OrgId | null> {
  const row = await db
    .select({ id: organizations.id })
    .from(organizations)
    .innerJoin(memberships, eq(memberships.orgId, organizations.id))
    .where(and(eq(memberships.userId, userId), eq(organizations.slug, personalOrgSlug(userId))))
    .get();
  return row?.id ?? null;
}

function validate(input: ImportProjectInput): ImportRefusalCode | null {
  if (input.identities.length === 0) {
    return "identities-empty";
  }
  const ids = new Set(input.identities.map((identity) => identity.userId));
  const providerIds = new Set(input.identities.map((identity) => identity.providerUserId));
  if (ids.size !== input.identities.length || providerIds.size !== input.identities.length) {
    return "identities-malformed";
  }
  return ids.has(input.exportedBy) ? null : "exporter-missing";
}

export async function classifyImportedProject(
  d1: D1Database,
  input: ImportProjectInput,
  owners: readonly UserId[],
): Promise<ImportClassification> {
  const invalid = validate(input);
  if (invalid !== null) {
    return { kind: "refused", code: invalid };
  }
  const db = drizzle(d1);
  const projectRow = await db
    .select({ orgId: projects.orgId })
    .from(projects)
    .where(eq(projects.id, input.projectId))
    .get();
  let project: "absent" | "exporter" = "absent";
  if (projectRow !== undefined) {
    if (!(await ownedByChainOwner(db, projectRow.orgId, owners))) {
      return { kind: "refused", code: "project-exists" };
    }
    project = "exporter";
  }
  const classified = await classify(db, input);
  return classified.kind === "refused" ? classified : { ...classified, project };
}

export async function provisionImportedProject(
  d1: D1Database,
  input: ImportProjectInput,
  nowMs: number,
  owners: readonly UserId[],
): Promise<ImportProvisionResult> {
  const classified = await classifyImportedProject(d1, input, owners);
  if (classified.kind === "refused") {
    return classified;
  }
  const db = drizzle(d1);
  const statements: BatchItem<"sqlite">[] = [];
  const orgOf = new Map<UserId, OrgId>();
  const creations = await Effect.runPromise(
    Effect.forEach(classified.toCreate, (identity) =>
      Effect.map(newOrgId(nowMs), (orgId) => ({ identity, orgId })),
    ).pipe(Effect.provide(cryptoServicesLayer)),
  );
  for (const { identity, orgId } of creations) {
    const { userId } = identity;
    orgOf.set(userId, orgId);
    const actor = { userId };
    statements.push(
      db.insert(users).values({
        id: userId,
        email: null,
        emailVerified: 0,
        createdAt: nowMs,
        updatedAt: nowMs,
      }),
      db.insert(linkedIdentities).values({
        userId,
        provider: identity.provider,
        providerUserId: identity.providerUserId,
        providerLogin: identity.providerLogin,
        linkedAt: nowMs,
      }),
      db.insert(organizations).values({
        id: orgId,
        slug: personalOrgSlug(userId),
        name: identity.providerLogin ?? "personal",
        createdAt: nowMs,
      }),
      db.insert(memberships).values({ orgId, userId, role: "owner" }),
      userAuditInsert(db, nowMs, {
        event: "auth.user_created",
        actor,
        payload: { imported: true },
      }),
      userAuditInsert(db, nowMs, {
        event: "auth.identity_linked",
        actor,
        payload: { provider: identity.provider },
      }),
      orgAuditInsert(db, nowMs, {
        event: "org.created",
        actor,
        orgId,
        payload: { personal: true, imported: true },
      }),
      orgAuditInsert(db, nowMs, {
        event: "org.member_added",
        actor,
        orgId,
        targetUserId: userId,
        payload: { role: "owner" },
      }),
    );
  }
  const exporterOrg =
    orgOf.get(input.exportedBy) ?? (await existingPersonalOrg(db, input.exportedBy));
  if (exporterOrg === null) {
    return { kind: "refused", code: "exporter-org-missing" };
  }
  if (classified.project === "absent") {
    statements.push(
      db.insert(projects).values({ id: input.projectId, orgId: exporterOrg, createdAt: nowMs }),
      orgAuditInsert(db, nowMs, {
        event: "org.project_created",
        actor: { userId: input.exportedBy },
        orgId: exporterOrg,
        projectId: input.projectId,
        payload: { imported: true },
      }),
    );
  }
  statements.push(
    ...input.identities.map((identity) =>
      db
        .insert(projectMembers)
        .values({ projectId: input.projectId, userId: identity.userId, createdAt: nowMs })
        .onConflictDoNothing(),
    ),
  );
  const [first, ...rest] = statements;
  if (first === undefined) {
    return { kind: "refused", code: "identities-empty" };
  }
  await db.batch([first, ...rest]);
  return {
    kind: "provisioned",
    existing: classified.existing,
    created: classified.toCreate.length,
    members: input.identities.length,
    project: classified.project === "absent" ? "created" : "kept",
  };
}
