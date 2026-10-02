// D1 provisioning of an imported project (PF3 — AUTH_SPEC §11-6,
// docs/notes/pf3-design.md ruling I).
//
// After the restore worker has written an exported project into an
// empty Durable Object, the deployment's D1 must look as if every
// member had logged in once and the owner had created the project
// here: a `users` row **with the chain's user id** and the matching
// `linked_identities` row (so the first login resolves to the id the
// chain names — ruling G), a personal org with its owner membership
// (what first login creates — AUTH_SPEC §9-1), the `projects` row under
// the exporter's personal org (§11-3), and the membership projection
// rows (§11-5). One atomic batch; every conflict refuses the whole
// import before anything is written.
//
// A plain async function: the restore worker has no Effect runtime.
// Drizzle stays inside this package (ADR-0006).

import { and, eq, inArray } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import { drizzle } from "drizzle-orm/d1";

import { ulid } from "../ids.ts";
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

/** One identity as the export's companion lists it (api-schema's ExportIdentitySchema). */
export interface ImportedIdentity {
  readonly userId: string;
  readonly provider: "github";
  readonly providerUserId: string;
  readonly providerLogin: string | null;
}

export interface ImportProjectInput {
  /** The genesis hash the DO was restored under. */
  readonly projectId: string;
  /** The exporting owner (the project is attached to their personal org). */
  readonly exportedBy: string;
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
      /** Members whose users row already existed with the same identity (nothing created for them). */
      readonly existing: number;
      /** Members created with their chain user id, identity, and personal org. */
      readonly created: number;
      /** Projection rows written (every listed member). */
      readonly members: number;
      /** `created` on the first import; `kept` when the exporter's project row was already here (a re-run provisions the missing members only). */
      readonly project: "created" | "kept";
    }
  | { readonly kind: "refused"; readonly code: ImportRefusalCode };

/** The read-only verdict of an import against this deployment (the pre-check of a job, and the first step of provisioning). */
export type ImportClassification =
  | { readonly kind: "refused"; readonly code: ImportRefusalCode }
  | {
      readonly kind: "ok";
      readonly toCreate: readonly ImportedIdentity[];
      readonly existing: number;
      /** `absent` = first import; `exporter` = the projects row is under the exporter's personal org (a re-run). */
      readonly project: "absent" | "exporter";
    };

/** The personal org's slug, as first login names it (repos.ts createUserBatch). */
function personalOrgSlug(userId: string): string {
  return `u-${userId.toLowerCase()}`;
}

/** The IN chunk (inside D1's bound-parameter cap with headroom — the same width as repos.ts identitiesOf). */
const IN_CHUNK = 90;

function chunked(values: readonly string[]): readonly (readonly string[])[] {
  const chunks: (readonly string[])[] = [];
  for (let start = 0; start < values.length; start += IN_CHUNK) {
    chunks.push(values.slice(start, start + IN_CHUNK));
  }
  return chunks;
}

/**
 * Classifies every identity against the deployment: existing (same id,
 * same provider identity), to create, or a conflict. Read-only.
 */
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
  const linkedByProvider = new Map<string, string>();
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
  const existingUsers = new Set<string>();
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
        // The person logged in here before the import and holds a
        // different id: the chain's id cannot be bound to them now
        return { kind: "refused", code: "identity-conflict" };
      }
      existing += 1;
      continue;
    }
    if (existingUsers.has(identity.userId)) {
      // The chain's id is held by someone else on this deployment
      return { kind: "refused", code: "user-id-taken" };
    }
    toCreate.push(identity);
  }
  return { kind: "ok", toCreate, existing };
}

/** The personal org id of an already-existing exporter (by the slug first login assigned). */
async function existingPersonalOrg(db: Db, userId: string): Promise<string | null> {
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
  // A repeated id inside the file is a malformed companion, not a
  // conflict with this deployment
  if (ids.size !== input.identities.length || providerIds.size !== input.identities.length) {
    return "identities-malformed";
  }
  return ids.has(input.exportedBy) ? null : "exporter-missing";
}

/**
 * Classifies an import without writing: the companion's shape, the
 * projects row (absent, the exporter's own — a re-run — or someone
 * else's: `project-exists`), and every identity against the deployment.
 * The restore worker asks this before the DO is touched (ruling H
 * revision) and reports it as the rehearsal of a drill.
 */
export async function classifyImportedProject(
  d1: D1Database,
  input: ImportProjectInput,
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
    // The exporter's own project row (an earlier import of the same
    // project here) is re-run: the members missing since are provisioned,
    // nothing else is touched. Anyone else's row refuses
    const exporterOrg = await existingPersonalOrg(db, input.exportedBy);
    if (exporterOrg === null || exporterOrg !== projectRow.orgId) {
      return { kind: "refused", code: "project-exists" };
    }
    project = "exporter";
  }
  const classified = await classify(db, input);
  return classified.kind === "refused" ? classified : { ...classified, project };
}

/**
 * Writes the D1 side of an imported project in one batch. A second run on
 * the exporter's own project provisions only what is missing (ruling I
 * revision); a row of anyone else's refuses (`project-exists`).
 */
export async function provisionImportedProject(
  d1: D1Database,
  input: ImportProjectInput,
  nowMs: number,
): Promise<ImportProvisionResult> {
  const classified = await classifyImportedProject(d1, input);
  if (classified.kind === "refused") {
    return classified;
  }
  const db = drizzle(d1);
  const statements: BatchItem<"sqlite">[] = [];
  const orgOf = new Map<string, string>();
  for (const identity of classified.toCreate) {
    const { userId } = identity;
    const orgId = ulid(nowMs);
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
      // The same rows first login writes (AUDIT_SPEC §3.1 / §3.2), marked
      // as an import; the provider id and login are never recorded
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
