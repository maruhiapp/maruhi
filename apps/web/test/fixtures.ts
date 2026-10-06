// The shared fixtures for the dashboard e2e and screenshots (DP3
// ruling F). W3b (S8 invite management, S9 token management) rulings
// CE / CO / CQ are also pinned by the fixtures here.
//
// Literals conforming to the api-schema-derived types
// (src/dashboard/types.ts); tsc detects any divergence. A decode
// check against the real Schemas lives in e2e.test.ts (ruling BV).
// This is a test-process-only module and never enters the shipped
// bundle (only screenshots.ts and e2e.test.ts import it).
import type {
  AuditEvent,
  ChainSnapshot,
  DeviceList,
  EnvironmentList,
  EnvironmentMetadataPull,
  InvitationList,
  Me,
  ProjectList,
  RotationFlagList,
  TokenList,
} from "../src/dashboard/types.ts";

export const PROJECT_1 = "ab".repeat(32);
export const PROJECT_2 = "cd".repeat(32);
const HEX64 = "12".repeat(32);
const SIG = "34".repeat(64);
const FP = "56".repeat(16);
const ROW_ID_1 = "78".repeat(16);
const ROW_ID_2 = "9a".repeat(16);
const ROW_ID_3 = "bc".repeat(16);
const ROW_ID_4 = "de".repeat(16);
// Device keys (DK K5): D2 = phone (cap member / production), R =
// reserve key (owner / all). The public keys are chosen not to collide
// with the first key (HEX64) (chain-view's duplicate-member-key fold)
export const FP_D2 = "d2".repeat(16);
const KEYS_D2 = { encPubHex: "a2".repeat(32), sigPubHex: "b2".repeat(32) };
const KEYS_R = { encPubHex: "ae".repeat(32), sigPubHex: "be".repeat(32) };

export const meFixture: Me = { userId: "user_e2e", orgs: [] };

export const PROJECT_GHOST_CURSOR = "ef".repeat(32);

export const projectsPage1: ProjectList = {
  projects: [{ projectId: PROJECT_1, role: "admin" }],
  nextAfter: PROJECT_1,
};
// An empty page + nextAfter (AUTH_SPEC §11-5 — the shape where
// excluding ghosts and skipping failed confirmations empties the
// candidate page). The UI must not misjudge this as the end and still
// advances the cursor
export const projectsPageEmpty: ProjectList = {
  projects: [],
  nextAfter: PROJECT_GHOST_CURSOR,
};
export const projectsPage2: ProjectList = {
  projects: [{ projectId: PROJECT_2, role: "reader" }],
};

// Contains the 2 device-key ops (DK K5): seq 3 = D1 adds D2,
// seq 4 = D2 signs and adds R (this is where D2's FP gets bound),
// seq 5 = D1 revokes D2. After the fold, user_e2e's devices =
// D1 (FP bound) + R (FP unbound, owner/all) = 2 devices
export const chainFixture: ChainSnapshot = {
  projectId: PROJECT_1,
  headSeq: 5,
  headHashHex: HEX64,
  entries: [
    {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "00".repeat(32),
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_000_000,
      signatureHex: SIG,
      op: "genesis",
      payload: { encPubHex: HEX64, sigPubHex: HEX64 },
    },
    {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_100_000,
      signatureHex: SIG,
      op: "add_member",
      payload: {
        targetUserId: "user_colleague",
        encPubHex: HEX64,
        sigPubHex: HEX64,
        role: "reader",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    },
    {
      suite: "maruhi/v1",
      seq: 3,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_200_000,
      signatureHex: SIG,
      op: "add_device",
      payload: {
        ...KEYS_D2,
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["production"],
      },
    },
    {
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP_D2 },
      timestampMs: 1_756_000_300_000,
      signatureHex: SIG,
      op: "add_device",
      payload: { ...KEYS_R, roleCap: "owner", scopeKind: "all", scopeEnvironmentIds: [] },
    },
    {
      suite: "maruhi/v1",
      seq: 5,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_400_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: "user_e2e", deviceFingerprintsHex: [FP_D2] },
    },
  ],
  attestations: [],
};

// A chain containing 1 unreadable device op (for rendering the K5-17
// note): the revocation targets a non-member
export const chainWithUnreadableEntry: ChainSnapshot = {
  ...chainFixture,
  headSeq: 6,
  entries: [
    ...chainFixture.entries,
    {
      suite: "maruhi/v1",
      seq: 6,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_500_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: "user_ghost", deviceFingerprintsHex: [FP_D2] },
    },
  ],
};

const environmentStatement = {
  suite: "maruhi/v1",
  environmentId: "production",
  name: "production",
  chainHeadHashHex: HEX64,
  chainHeadSeq: 1,
  signatureHex: SIG,
  status: "active",
  metaVersion: 1,
  prevMetaSigHashHex: "",
  authorUserId: "user_e2e",
  authorKeyFingerprintHex: FP,
} as const;

export const environmentsFixture: EnvironmentList = {
  environments: [{ environmentId: "production", currentEpoch: 1, statement: environmentStatement }],
  schemaPolicy: "enabled",
};

export const metadataPullFixture: EnvironmentMetadataPull = {
  environmentId: "production",
  currentEpoch: 1,
  statement: environmentStatement,
  variables: [
    {
      ...environmentStatement,
      variableId: "var-database-url",
      name: "DATABASE_URL",
    },
  ],
  deletedVariables: [],
  // The distributed environment manifest (required on the wire since
  // 0.28-draft — a schema-valid dummy; the dashboard never reads it)
  manifest: {
    suite: "maruhi/v1",
    environmentId: "production",
    epoch: 1,
    manifestVersion: 1,
    variablesDigestHex: HEX64,
    envMetaVersion: 1,
    envMetaSigHashHex: HEX64,
    prevManifestSigHashHex: "",
    chainHeadHashHex: HEX64,
    chainHeadSeq: 1,
    signatureHex: SIG,
    issuerUserId: "user_e2e",
    issuerKeyFingerprintHex: FP,
  },
  schemaPolicy: "enabled",
};

// The admin-visible project-DO response (with seq — AUDIT_SPEC §7).
// The two device events (AUDIT_SPEC §3.4 — DK) keep the generic
// rendering (K5-6): the payload comes out as the recorded JSON
export const projectAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_4,
      seq: 5,
      serverTs: 1_756_000_400_000,
      event: "chain.device_revoked",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 5,
      payload: { deviceKeyFingerprints: [FP_D2] },
    },
    {
      id: ROW_ID_3,
      seq: 3,
      serverTs: 1_756_000_200_000,
      event: "chain.device_added",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 3,
      payload: {
        deviceKeyFingerprint: FP_D2,
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["production"],
      },
    },
    {
      id: ROW_ID_1,
      seq: 2,
      serverTs: 1_756_000_100_000,
      event: "chain.member_added",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_colleague",
      chainSeq: 2,
    },
    {
      id: ROW_ID_2,
      seq: 1,
      serverTs: 1_756_000_000_000,
      event: "chain.genesis",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 1,
    },
  ],
};

// The self axis (the D1 path — seq is returned to nobody)
export const selfAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_1,
      serverTs: 1_756_000_200_000,
      event: "auth.login_succeeded",
      actor: { type: "user", userId: "user_e2e" },
    },
  ],
};

export const rotationFlagsFixture: RotationFlagList = {
  flags: [
    {
      environmentId: "production",
      variableId: "var-database-url",
      basis: "read",
      targetUserId: "user_colleague",
      recommendedAtMs: 1_756_000_300_000,
      triggerChainSeq: 3,
      trigger: "remove_member",
    },
    // The device-revocation variant (AUDIT_SPEC §4.1 — DK): trigger =
    // revoke_device; the target is a person (no FP is carried)
    {
      environmentId: "production",
      variableId: "var-api-key",
      basis: "readable",
      targetUserId: "user_e2e",
      recommendedAtMs: 1_756_000_400_000,
      triggerChainSeq: 5,
      trigger: "revoke_device",
    },
  ],
};

// ---------------------------------------------------------------------------
// Fixtures for S8 (invite management) and S9 (token management).
// Expiry values are fixed at "future = 2100 / past = 2023" (stable
// against the clock at run time — ruling CQ's Expired display
// compares against the client clock, so nothing near the boundary is
// used)
// ---------------------------------------------------------------------------

const FUTURE_MS = 4_102_444_800_000; // 2100-01-01
const PAST_MS = 1_700_000_000_000; // 2023-11-14

const acceptanceFixture = {
  inviteeUserId: "user_colleague",
  inviteeEncPubHex: HEX64,
  inviteeSigPubHex: HEX64,
  signatureHex: SIG,
  linkSignatureHex: SIG,
  acceptedAtMs: 1_756_000_100_000,
} as const;

// The issuance statement (AUTH_SPEC §15-1 — IV): the link public key,
// the head at issuance time, and the issuance signature (public
// values)
const issuanceFixture = {
  linkPubHex: HEX64,
  headHashHex: HEX64,
  headSeq: 3,
  issueSignatureHex: SIG,
} as const;

const pendingInvite = {
  id: "inv-pending",
  projectId: PROJECT_1,
  role: "member",
  scopeKind: "all",
  scopeEnvironmentIds: [],
  status: "pending",
  inviterUserId: "user_e2e",
  issuance: issuanceFixture,
  createdAtMs: 1_756_000_000_000,
  expiresAtMs: FUTURE_MS,
  acceptance: null,
} as const;

export const invitationsFixture: InvitationList = {
  invitations: [
    pendingInvite,
    {
      id: "inv-accepted",
      projectId: PROJECT_1,
      role: "reader",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      status: "accepted",
      inviterUserId: "user_e2e",
      issuance: issuanceFixture,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: FUTURE_MS,
      acceptance: acceptanceFixture,
    },
    {
      id: "inv-completed",
      projectId: PROJECT_1,
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      status: "completed",
      inviterUserId: "user_e2e",
      issuance: issuanceFixture,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: PAST_MS,
      acceptance: acceptanceFixture,
    },
  ],
};

// The server's report after revocation (the pending row moves to
// revoked) — the UI transcribes it on refetch (ruling CO)
export const invitationsAfterRevoke: InvitationList = {
  invitations: [
    { ...pendingInvite, status: "revoked" },
    ...invitationsFixture.invitations.slice(1),
  ],
};

export const tokensFixture: TokenList = {
  tokens: [
    {
      id: "tok-active",
      name: "ci",
      tokenPrefix: "maruhi_pat_abcdefgh",
      scopes: [{ project: "*", permission: "admin" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: 1_756_000_100_000,
      expiresAtMs: FUTURE_MS,
    },
    {
      id: "tok-expired",
      name: "old-laptop",
      tokenPrefix: "maruhi_pat_ijklmnop",
      scopes: [{ project: PROJECT_1, permission: "read" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: null,
      expiresAtMs: PAST_MS,
    },
  ],
};

// A targeted revocation deletes the row (the server implementation —
// it disappears from the list)
export const tokensAfterRevoke: TokenList = { tokens: tokensFixture.tokens.slice(1) };

// ---------------------------------------------------------------------------
// S11 (the device registry — AUTH_SPEC §13-11. advisory). The tokenId
// is collated by id against the tokens listing (K5-8): row 1 is tied
// to "ci" (tok-active), row 2 names a token absent from the listing,
// row 3 has no link
// ---------------------------------------------------------------------------

export const devicesFixture: DeviceList = {
  devices: [
    {
      keyFingerprintHex: FP,
      encPubHex: HEX64,
      sigPubHex: HEX64,
      label: "macbook",
      tokenId: "tok-active",
      createdAtMs: 1_756_000_000_000,
    },
    {
      keyFingerprintHex: FP_D2,
      ...KEYS_D2,
      label: "phone",
      tokenId: "tok-gone",
      createdAtMs: 1_756_000_200_000,
    },
    {
      keyFingerprintHex: "0e".repeat(16),
      ...KEYS_R,
      label: "codespace",
      createdAtMs: 1_756_000_300_000,
    },
  ],
};
