import {
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  testVariableId,
} from "@maruhi/crypto/test-support";

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

export const PROJECT_1 = testProjectId("ab".repeat(32));
export const PROJECT_2 = testProjectId("cd".repeat(32));
const HEX64 = "12".repeat(32);
const USER_E2E = testUserId("user_e2e");
const USER_COLLEAGUE = testUserId("user_colleague");
const USER_GHOST = testUserId("user_ghost");
const ENV_PRODUCTION = testEnvironmentId("production");
const VAR_DATABASE_URL = testVariableId("var-database-url");
const VAR_API_KEY = testVariableId("var-api-key");
const SIG = "34".repeat(64);
const FP = testKeyFingerprintHex("56".repeat(16));
const ROW_ID_1 = "78".repeat(16);
const ROW_ID_2 = "9a".repeat(16);
const ROW_ID_3 = "bc".repeat(16);
const ROW_ID_4 = "de".repeat(16);
export const FP_D2 = testKeyFingerprintHex("d2".repeat(16));
const KEYS_D2 = { encPubHex: "a2".repeat(32), sigPubHex: "b2".repeat(32) };
const KEYS_R = { encPubHex: "ae".repeat(32), sigPubHex: "be".repeat(32) };

export const meFixture: Me = { userId: USER_E2E, orgs: [] };

export const PROJECT_GHOST_CURSOR = testProjectId("ef".repeat(32));

export const projectsPage1: ProjectList = {
  projects: [{ projectId: PROJECT_1, role: "admin" }],
  nextAfter: PROJECT_1,
};
export const projectsPageEmpty: ProjectList = {
  projects: [],
  nextAfter: PROJECT_GHOST_CURSOR,
};
export const projectsPage2: ProjectList = {
  projects: [{ projectId: PROJECT_2, role: "reader" }],
};

export const chainFixture: ChainSnapshot = {
  projectId: PROJECT_1,
  headSeq: 5,
  headHashHex: HEX64,
  entries: [
    {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "00".repeat(32),
      actor: { userId: USER_E2E, keyFingerprintHex: FP },
      timestampMs: 1_756_000_000_000,
      signatureHex: SIG,
      op: "genesis",
      payload: { encPubHex: HEX64, sigPubHex: HEX64 },
    },
    {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: HEX64,
      actor: { userId: USER_E2E, keyFingerprintHex: FP },
      timestampMs: 1_756_000_100_000,
      signatureHex: SIG,
      op: "add_member",
      payload: {
        targetUserId: USER_COLLEAGUE,
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
      actor: { userId: USER_E2E, keyFingerprintHex: FP },
      timestampMs: 1_756_000_200_000,
      signatureHex: SIG,
      op: "add_device",
      payload: {
        ...KEYS_D2,
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: [ENV_PRODUCTION],
      },
    },
    {
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: HEX64,
      actor: { userId: USER_E2E, keyFingerprintHex: FP_D2 },
      timestampMs: 1_756_000_300_000,
      signatureHex: SIG,
      op: "add_device",
      payload: { ...KEYS_R, roleCap: "owner", scopeKind: "all", scopeEnvironmentIds: [] },
    },
    {
      suite: "maruhi/v1",
      seq: 5,
      prevHashHex: HEX64,
      actor: { userId: USER_E2E, keyFingerprintHex: FP },
      timestampMs: 1_756_000_400_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: USER_E2E, deviceFingerprintsHex: [FP_D2] },
    },
  ],
  attestations: [],
};

export const chainWithUnreadableEntry: ChainSnapshot = {
  ...chainFixture,
  headSeq: 6,
  entries: [
    ...chainFixture.entries,
    {
      suite: "maruhi/v1",
      seq: 6,
      prevHashHex: HEX64,
      actor: { userId: USER_E2E, keyFingerprintHex: FP },
      timestampMs: 1_756_000_500_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: USER_GHOST, deviceFingerprintsHex: [FP_D2] },
    },
  ],
};

const environmentStatement = {
  suite: "maruhi/v1",
  environmentId: ENV_PRODUCTION,
  name: "production",
  chainHeadHashHex: HEX64,
  chainHeadSeq: 1,
  signatureHex: SIG,
  status: "active",
  metaVersion: 1,
  prevMetaSigHashHex: "",
  authorUserId: USER_E2E,
  authorKeyFingerprintHex: FP,
} as const;

export const environmentsFixture: EnvironmentList = {
  environments: [
    { environmentId: ENV_PRODUCTION, currentEpoch: 1, statement: environmentStatement },
  ],
  schemaPolicy: "enabled",
};

export const metadataPullFixture: EnvironmentMetadataPull = {
  environmentId: ENV_PRODUCTION,
  currentEpoch: 1,
  statement: environmentStatement,
  variables: [
    {
      ...environmentStatement,
      variableId: VAR_DATABASE_URL,
      name: "DATABASE_URL",
    },
  ],
  deletedVariables: [],
  manifest: {
    suite: "maruhi/v1",
    environmentId: ENV_PRODUCTION,
    epoch: 1,
    manifestVersion: 1,
    variablesDigestHex: HEX64,
    envMetaVersion: 1,
    envMetaSigHashHex: HEX64,
    prevManifestSigHashHex: "",
    chainHeadHashHex: HEX64,
    chainHeadSeq: 1,
    signatureHex: SIG,
    issuerUserId: USER_E2E,
    issuerKeyFingerprintHex: FP,
  },
  schemaPolicy: "enabled",
};

export const projectAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_4,
      seq: 5,
      serverTs: 1_756_000_400_000,
      event: "chain.device_revoked",
      actor: { type: "user", userId: USER_E2E, keyFingerprintHex: FP },
      targetUserId: USER_E2E,
      chainSeq: 5,
      payload: { deviceKeyFingerprints: [FP_D2] },
    },
    {
      id: ROW_ID_3,
      seq: 3,
      serverTs: 1_756_000_200_000,
      event: "chain.device_added",
      actor: { type: "user", userId: USER_E2E, keyFingerprintHex: FP },
      targetUserId: USER_E2E,
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
      actor: { type: "user", userId: USER_E2E, keyFingerprintHex: FP },
      targetUserId: USER_COLLEAGUE,
      chainSeq: 2,
    },
    {
      id: ROW_ID_2,
      seq: 1,
      serverTs: 1_756_000_000_000,
      event: "chain.genesis",
      actor: { type: "user", userId: USER_E2E, keyFingerprintHex: FP },
      targetUserId: USER_E2E,
      chainSeq: 1,
    },
  ],
};

export const selfAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_1,
      serverTs: 1_756_000_200_000,
      event: "auth.login_succeeded",
      actor: { type: "user", userId: USER_E2E },
    },
  ],
};

export const rotationFlagsFixture: RotationFlagList = {
  flags: [
    {
      environmentId: ENV_PRODUCTION,
      variableId: VAR_DATABASE_URL,
      basis: "read",
      targetUserId: USER_COLLEAGUE,
      recommendedAtMs: 1_756_000_300_000,
      triggerChainSeq: 3,
      trigger: "remove_member",
    },
    {
      environmentId: ENV_PRODUCTION,
      variableId: VAR_API_KEY,
      basis: "readable",
      targetUserId: USER_E2E,
      recommendedAtMs: 1_756_000_400_000,
      triggerChainSeq: 5,
      trigger: "revoke_device",
    },
  ],
};

const FUTURE_MS = 4_102_444_800_000;
const PAST_MS = 1_700_000_000_000;

const acceptanceFixture = {
  inviteeUserId: USER_COLLEAGUE,
  inviteeEncPubHex: HEX64,
  inviteeSigPubHex: HEX64,
  signatureHex: SIG,
  linkSignatureHex: SIG,
  acceptedAtMs: 1_756_000_100_000,
} as const;

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
  inviterUserId: USER_E2E,
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
      inviterUserId: USER_E2E,
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
      inviterUserId: USER_E2E,
      issuance: issuanceFixture,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: PAST_MS,
      acceptance: acceptanceFixture,
    },
  ],
};

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

export const tokensAfterRevoke: TokenList = { tokens: tokensFixture.tokens.slice(1) };

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
      keyFingerprintHex: testKeyFingerprintHex("0e".repeat(16)),
      ...KEYS_R,
      label: "codespace",
      createdAtMs: 1_756_000_300_000,
    },
  ],
};
