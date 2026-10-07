// `maruhi project` and `project policy approvals / schema` (discipline: see commands/index.ts).

import { APPROVAL_TARGET_OPS, type ApprovalTargetOp, isApprovalTargetOp } from "@maruhi/crypto";
import { Effect } from "effect";
import { Command } from "effect/cli";

import { buildRepositoryAnchor, formatRepositoryAnchor } from "../anchor.ts";
import { DEFAULT_POLICY_OPS, describePolicy, proposalViews } from "../approval-rules.ts";
import { type PolicyRequest, setApprovalPolicyOp } from "../approval.ts";
import { syncProject } from "../chain-sync.ts";
import { issueCheckpoint } from "../checkpoint.ts";
import {
  type CliServices,
  type CommonFlags,
  checkInviteAnchor,
  floorHandleFor,
  loadCheckedFloor,
  openMetadataProject,
  openProject,
  openSession,
  reconcileGossip,
  resolveProjectId,
} from "../context.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import { CliError, cliError, usageError } from "../errors.ts";
import { type FloorHandle } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { formatMemberListRow, memberListRows } from "../member-list.ts";
import { logNote, logWarning } from "../notice.ts";
import { describeExport, projectExportOp } from "../project-export.ts";
import { projectInitOp } from "../project-init.ts";
import { projectListOp } from "../project-list.ts";
import {
  isSchemaPolicy,
  SCHEMA_POLICIES,
  setSchemaPolicyOp,
  showSchemaPolicyOp,
} from "../project-schema-policy.ts";
import { describeUnconvergedMandate, resolveUnconvergedMandates } from "../rotation-sweep.ts";
import { loadMasterKeys } from "../session.ts";
import { projectFlags, proposalFlags, serverOnlyFlags, singleFlag, singleValued } from "./flags.ts";
import { proposalInputOf, reportProposed } from "./shared.ts";

export const projectInitConfig = {
  ...serverOnlyFlags(),
  org: singleValued(
    "org",
    "Org to create the project in (needed only when you belong to multiple orgs)",
  ),
};

export const projectListConfig = { ...serverOnlyFlags() };

export const projectVerifyConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

export const projectAnchorConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

export const projectCheckpointConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

export const projectExportConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
  out: singleValued(
    "out",
    "Path of the snapshot file to write (refused if it exists); the identities companion is written as <out>.identities.json",
  ),
};

export const projectPolicyApprovalsConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  required: singleValued(
    "required",
    "Enable (or change) the four-eyes policy: number of distinct owner approvals an operation needs (at least 2; the project must have at least that many owners)",
  ),
  ops: singleValued(
    "ops",
    `Comma-separated operations that need approval (${APPROVAL_TARGET_OPS.join(" | ")}; default ${DEFAULT_POLICY_OPS.join(",")} — add_member is left out because adding an owner always needs approval, and other invites are already protected by the acceptance ceremony)`,
  ),
  off: singleFlag(
    "off",
    "Turn the policy off (while a policy is active, this itself needs the approvals)",
  ),
};

export const projectPolicySchemaConfig = {
  ...projectFlags(),
  set: singleValued(
    "set",
    `Set the schema policy (${SCHEMA_POLICIES.join(" | ")}; locked = creating a variable requires a declared type; needs the admin role)`,
  ),
};

/**
 * `maruhi project policy schema [--set <tier>]` (AUTH_SPEC §12-11): no
 * flag = show the policy; `--set` = set it (admin). Keyless and chain-free
 * — the policy is a server acceptance setting (project-schema-policy.ts).
 */
const projectPolicySchemaCommand = Effect.fn("commands-project.projectPolicySchemaCommand")(
  function* (flags: CommonFlags & { readonly set?: string | undefined }) {
    const tier = flags.set;
    if (tier !== undefined && !isSchemaPolicy(tier)) {
      return yield* Effect.fail(usageError(`--set must be one of ${SCHEMA_POLICIES.join(" | ")}`));
    }
    const context = yield* openSession(flags.server);
    const projectId = yield* resolveProjectId(flags.project, context.config);
    if (tier === undefined) {
      return yield* showSchemaPolicyOp({ client: context.client, projectId });
    }
    return yield* setSchemaPolicyOp({ client: context.client, projectId, policy: tier });
  },
);

/** `maruhi project verify`: chain verification + floor / anchor checks + state display. */
const projectVerify = Effect.fn("commands-project.projectVerify")(function* (
  serverFlag: string | undefined,
  projectFlag: string | undefined,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const context = yield* openSession(serverFlag);
  const projectId = yield* resolveProjectId(projectFlag, context.config);
  const synced = yield* syncProject(context.client, projectId);
  // The chain-floor check (§6.3 rule (a)) is also part of verify
  const checked = (yield* loadCheckedFloor(
    projectId,
    synced,
    syncProject(context.client, projectId),
  )).verified;
  // The mechanical matching of the invite-link anchor (§6.3 (a) / §6.5) is also part of verify
  yield* checkInviteAnchor(projectId, checked);
  // Matching against other members' head claims (§6.3 head gossip /
  // §6.6) is also part of verify (a contradictory claim = hard evidence
  // of a split view → abort and preserve the evidence). No submission
  // happens (verify is a read command that does not require the master
  // key). The floor head's advance happens inside reconcileGossip after
  // every check passes, same as attachProject
  const verified = yield* reconcileGossip(
    projectId,
    checked,
    syncProject(context.client, projectId),
  );
  yield* io.log(`Chain verification OK (head seq=${verified.state.headSeq})`);
  yield* io.log(`head: ${verified.state.headHashHex}`);
  // The scope column (2026-09-15 ES K4 — ruling M). The same row format as `maruhi member list`
  yield* io.log(`Members (${verified.state.members.size}):`);
  for (const row of memberListRows(verified)) {
    yield* io.log(`  ${formatMemberListRow(row)}`);
  }
  for (const [environmentId, environment] of verified.state.environments) {
    const deleted =
      environment.deletedAtSeq === null ? "" : `, deleted at seq=${environment.deletedAtSeq}`;
    yield* io.log(
      `Environment ${environmentId}: epoch=${environment.currentEpoch} (created at seq=${environment.createdAtSeq}${deleted})`,
    );
  }
  // The unconverged rotation duties (§7 — chain-derived, chain-deleted
  // environments excluded) are also part of verify (the always-on warning
  // — rotation-sweep.ts — detail display; no request)
  const pending = resolveUnconvergedMandates({ verified });
  if (pending.length === 0) {
    yield* io.log("Rotation mandates: none unconverged (CRYPTO_SPEC §7)");
    return;
  }
  for (const mandate of pending) {
    yield* io.logError(
      `Unconverged rotation mandate: ${describeUnconvergedMandate(verified, mandate)} (holders of the old DEK may still be able to read current values)`,
    );
  }
});

/** Parsing `--ops a,b` (a closed set — a typo is a usage error. Ascending, no duplicates). */
function parsePolicyOps(
  text: string | undefined,
): Effect.Effect<readonly ApprovalTargetOp[], CliError> {
  if (text === undefined) {
    return Effect.succeed(DEFAULT_POLICY_OPS);
  }
  const ops: ApprovalTargetOp[] = [];
  for (const raw of text.split(",")) {
    const op = raw.trim();
    if (!isApprovalTargetOp(op)) {
      return Effect.fail(
        usageError(
          `--ops must list operations from ${APPROVAL_TARGET_OPS.join(" | ")} (comma-separated)`,
        ),
      );
    }
    if (!ops.includes(op)) {
      ops.push(op);
    }
  }
  return Effect.succeed(ops.toSorted());
}

/** `--required N` / `--off` → the policy request (neither = null = display only). */
const parsePolicyRequest = Effect.fn("commands-project.parsePolicyRequest")(function* (flags: {
  readonly required?: string | undefined;
  readonly ops?: string | undefined;
  readonly off: boolean;
}): Effect.fn.Return<PolicyRequest | null, CliError> {
  if (flags.off) {
    if (flags.required !== undefined || flags.ops !== undefined) {
      return yield* Effect.fail(usageError("--off cannot be combined with --required / --ops"));
    }
    return { kind: "off" } as const;
  }
  if (flags.required === undefined) {
    if (flags.ops !== undefined) {
      return yield* Effect.fail(usageError("--ops requires --required <n>"));
    }
    return null;
  }
  const required = Number(flags.required);
  if (!Number.isInteger(required) || required < 2 || required > 64) {
    return yield* Effect.fail(
      usageError("--required must be an integer of at least 2 (CRYPTO_SPEC §6.2)"),
    );
  }
  const ops = yield* parsePolicyOps(flags.ops);
  return { kind: "on", requiredApprovals: required, ops } as const;
});

/**
 * `maruhi project policy approvals [--required N [--ops …]] [--off]`
 * (approval item 17 / K6-H): no flags = display the current policy
 * (keyless). Enable / change / off are an owner's signature. While the
 * policy is enabled, set_approval_policy itself is a four-eyes target, so
 * it becomes a proposal (CRYPTO_SPEC §6.2).
 */
const projectPolicyApprovalsCommand = Effect.fn("commands-project.projectPolicyApprovalsCommand")(
  function* (
    flags: CommonFlags & {
      readonly required?: string | undefined;
      readonly ops?: string | undefined;
      readonly off: boolean;
      readonly expires?: string | undefined;
    },
  ): Effect.fn.Return<number, CliError, CliServices> {
    const io = yield* CliIo;
    const request = yield* parsePolicyRequest(flags);
    const proposal = yield* proposalInputOf(flags.expires);
    if (request === null) {
      const context = yield* openMetadataProject(flags);
      yield* io.log(`Four-eyes policy: ${describePolicy(context.verified.state.approvalPolicy)}`);
      const owners = [...context.verified.state.members.values()].filter((m) => m.role === "owner");
      yield* io.log(
        `Owners (${owners.length}): ${owners.map((m) => displayText(m.userId)).join(", ")}`,
      );
      return 0;
    }
    const context = yield* openProject(flags);
    const outcome = yield* setApprovalPolicyOp({
      client: context.client,
      verified: context.verified,
      request,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      proposal,
    });
    if (outcome.kind === "unchanged") {
      yield* io.log(
        request.kind === "off"
          ? "The four-eyes policy is already off — nothing to do"
          : "The four-eyes policy already has these settings — nothing to do",
      );
      return 0;
    }
    if (outcome.kind === "proposed") {
      const code = yield* reportProposed(io, outcome.proposal);
      yield* warnPolicyAvailability(context.verified, request);
      return code;
    }
    yield* io.log(
      request.kind === "off"
        ? `Appended set_approval_policy to the chain (seq=${outcome.headSeq}): the four-eyes policy is now off`
        : `Appended set_approval_policy to the chain (seq=${outcome.headSeq}): ${describePolicy({ requiredApprovals: request.requiredApprovals, ops: request.ops })}`,
    );
    yield* warnPolicyAvailability(context.verified, request);
    return 0;
  },
);

/**
 * The guidance of the enablement's operational prerequisites (the owner
 * selection (i) of approval item 17 — kept as guidance, never a prompt):
 * owner ≥ required + 1, and every owner's recovery registration.
 */
const warnPolicyAvailability = Effect.fn("commands-project.warnPolicyAvailability")(function* (
  verified: Parameters<typeof proposalViews>[0],
  request: PolicyRequest,
): Effect.fn.Return<void, never, CliIo> {
  if (request.kind === "off") {
    return;
  }
  const owners = [...verified.state.members.values()].filter((m) => m.role === "owner").length;
  if (owners <= request.requiredApprovals) {
    yield* logWarning(
      `the project has ${countNoun(owners, "owner")} and the policy requires ${request.requiredApprovals} approvals: if one owner becomes unavailable (lost key, left the team), owner additions, removals and policy changes can no longer reach the quorum and the admin plane locks up (data access keeps working). Keep at least ${request.requiredApprovals + 1} owners`,
    );
  }
  yield* logNote(
    "make sure every owner has a recovery registered (`maruhi key recovery` or a guardian group) — under the four-eyes policy a lost owner key cannot be replaced without the quorum",
  );
});

export function makeProjectCommands(onExitCode: (code: number) => void) {
  const projectInit = Command.make(
    "init",
    projectInitConfig,
    Effect.fn("commands-project.projectInit")(function* (values) {
      const context = yield* openSession(values.server);
      const masterKeys = yield* loadMasterKeys(context.session);
      yield* projectInitOp({
        client: context.client,
        session: context.session,
        masterKeys,
        ...(values.org === undefined ? {} : { orgFlag: values.org }),
      });
    }),
  ).pipe(Command.withDescription("Create a project (signs and submits the genesis entry)"));

  const projectList = Command.make(
    "list",
    projectListConfig,
    Effect.fn("commands-project.projectList")(function* (values) {
      const context = yield* openSession(values.server);
      yield* projectListOp({ client: context.client });
    }),
  ).pipe(
    Command.withDescription("List the projects you are a member of (as reported by the server)"),
  );

  const projectExport = Command.make(
    "export",
    projectExportConfig,
    Effect.fn("commands-project.projectExport")(function* (values) {
      const io = yield* CliIo;
      if (values.out === undefined) {
        return yield* Effect.fail(
          usageError("project export requires --out <file> (the snapshot file to write)"),
        );
      }
      // The same keyless prologue as verify (chain sync + the floor
      // check): the export is cross-checked against this verified view
      const context = yield* openSession(values.server);
      const projectId = yield* resolveProjectId(values.project, context.config);
      const synced = yield* syncProject(context.client, projectId);
      const verified = (yield* loadCheckedFloor(
        projectId,
        synced,
        syncProject(context.client, projectId),
      )).verified;
      const result = yield* projectExportOp({
        client: context.client,
        projectId,
        verified,
        outPath: values.out,
      });
      for (const line of describeExport(result, verified)) {
        yield* io.log(line);
      }
    }),
  ).pipe(
    Command.withDescription(
      "Export the whole project (chain, ciphertexts, wraps, statements, audit log) as a snapshot file for import into another maruhi deployment (owner only)",
    ),
  );

  const projectVerifyCommand = Command.make("verify", projectVerifyConfig, (values) =>
    projectVerify(values.server, values.project),
  ).pipe(
    Command.withDescription(
      "Verify the chain, the local floor, and the invite anchor, then print the project state",
    ),
  );

  const projectAnchor = Command.make(
    "anchor",
    projectAnchorConfig,
    Effect.fn("commands-project.projectAnchor")(function* (values) {
      const io = yield* CliIo;
      // The prologue is the same keyless class as verify (chain sync +
      // §6.3 checks + floor + the invite anchor's mechanical matching) —
      // the anchor is built only from the verified view
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      // stdout is only the command's output (the anchor JSON) (decision
      // 9): a redirect can commit it into a repository as-is. The content
      // is non-secret (hashes, serials, epoch numbers only — anchor.ts)
      yield* io.log(formatRepositoryAnchor(buildRepositoryAnchor(context.verified)).trimEnd());
    }),
  ).pipe(
    Command.withDescription(
      "Print the repository anchor as JSON to stdout (commit it and pass it to `ci run --anchor`)",
    ),
  );

  const projectPolicyApprovals = Command.make(
    "approvals",
    projectPolicyApprovalsConfig,
    Effect.fn("commands-project.projectPolicyApprovals")(function* (values) {
      onExitCode(
        yield* projectPolicyApprovalsCommand({
          server: values.server,
          project: values.project,
          required: values.required,
          ops: values.ops,
          off: values.off,
          expires: values.expires,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Show or set the four-eyes approval policy (owner approvals required for sensitive operations); no flags = show",
    ),
  );

  const projectPolicySchema = Command.make(
    "schema",
    projectPolicySchemaConfig,
    Effect.fn("commands-project.projectPolicySchema")(function* (values) {
      yield* projectPolicySchemaCommand({
        server: values.server,
        project: values.project,
        set: values.set,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Show or set the schema policy (enabled = types optional, locked = creating a variable requires a declared type); no flags = show",
    ),
  );

  const projectPolicy = Command.make("policy").pipe(
    Command.withDescription("Project policies (approvals / schema)"),
    Command.withSubcommands([projectPolicyApprovals, projectPolicySchema]),
  );

  const projectCheckpoint = Command.make(
    "checkpoint",
    projectCheckpointConfig,
    Effect.fn("commands-project.projectCheckpoint")(function* (values) {
      const io = yield* CliIo;
      // Issuance accompanies a chain append (an Ed25519 signature), so it
      // requires the master key. Building the verified view (the verified
      // pull of every environment) is the checkpoint's material itself —
      // the value fetches are correctly recorded as var.read (an explicit
      // operation)
      const context = yield* openProject({ server: values.server, project: values.project });
      // The environment-floor handle is resolved ahead (keeps issueCheckpoint's R at CliIo)
      const floors = new Map<string, FloorHandle>();
      for (const environmentId of context.verified.state.environments.keys()) {
        floors.set(environmentId, yield* floorHandleFor(context, environmentId));
      }
      const summary = yield* issueCheckpoint({
        client: context.client,
        verified: context.verified,
        resync: context.resync,
        environmentIds: "all",
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        floorFor: (environmentId) => {
          const handle = floors.get(environmentId);
          return handle === undefined
            ? Effect.fail(
                cliError(`No floor handle for environment ${displayText(environmentId)} — re-run`),
              )
            : Effect.succeed(handle);
        },
      });
      yield* logWarnings(summary.warnings);
      yield* io.log(
        `Checkpoint accepted at chain seq ${summary.headSeq}, covering ${countNoun(summary.environmentIds.length, "environment")}${summary.attestedAuditHead ? " (audit head attested)" : ""}`,
      );
      if (summary.skippedEnvironmentIds.length > 0) {
        yield* logWarning(
          `${countNoun(summary.skippedEnvironmentIds.length, "environment")} could not be covered (${summary.skippedEnvironmentIds.map(displayText).join(", ")}). Re-run \`maruhi project checkpoint\` later to cover them`,
        );
      }
    }),
  ).pipe(
    Command.withDescription(
      "Notarize the verified data state (and, with effective admin permission, the audit head) onto the chain",
    ),
  );

  const project = Command.make("project").pipe(
    Command.withDescription(
      "Manage projects (init / list / verify / anchor / checkpoint / policy)",
    ),
    Command.withSubcommands([
      projectInit,
      projectList,
      projectVerifyCommand,
      projectAnchor,
      projectCheckpoint,
      projectExport,
      projectPolicy,
    ]),
  );

  return project;
}
