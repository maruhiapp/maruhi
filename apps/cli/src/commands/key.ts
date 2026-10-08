// `maruhi key` (discipline: see commands/index.ts).

import { PASSKEY_LABEL_PATTERN } from "@maruhi/api-schema";
import { Effect, Schema } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import { PASSKEY_LABEL_MESSAGE } from "../cli-formatter.ts";
import { identityBackingOf } from "../config.ts";
import { usageError } from "../errors.ts";
import { listPasskeysOp, removePasskeyOp, sealPasskeyOp } from "../passkey.package/index.ts";
import { NonBlank, serverOnlyFlags, singleFlag } from "./flags.ts";

export const keyGenerateConfig = {
  ...serverOnlyFlags(),
  "new-identity": singleFlag(
    "new-identity",
    "Create a new identity even though your account already has a reserve key in the recovery ledger (only when every device and every recovery path is lost)",
  ),
};
export const keyShowConfig = serverOnlyFlags();
export const keyPublishConfig = {
  ...serverOnlyFlags(),
  gh: singleFlag(
    "gh",
    "Add the key to your GitHub account through the gh CLI (`gh ssh-key add --type signing`) instead of printing it",
  ),
};
export const keyRecoverConfig = {
  ...serverOnlyFlags(),
  handoff: singleFlag(
    "handoff",
    "Open the reserve key by approval from your guardians instead of a recovery code",
  ),
  passkey: singleFlag(
    "passkey",
    "Open the reserve key with a passkey registered by `maruhi key seal passkey` instead of a recovery code",
  ),
  resume: singleFlag(
    "resume",
    "Keep the device key already on this machine and only register it on the projects where it is still missing (re-run after an interrupted recovery)",
  ),
};
/** The passkey's label (the ledger's display name — the api-schema acceptance shape is checked early on the declaration side). */
const PasskeyLabel = Schema.String.check(
  Schema.isPattern(PASSKEY_LABEL_PATTERN, { message: PASSKEY_LABEL_MESSAGE }),
);
export const keySealPasskeyConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the ledger with an already registered passkey instead of the recovery code",
  ),
  label: Flag.String("label").pipe(
    Flag.withDescription(
      "Display name for this passkey in `maruhi key seal list` (1 to 64 characters)",
    ),
    Flag.withSchema(PasskeyLabel),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
};
export const keySealListConfig = serverOnlyFlags();
export const keySealRemoveConfig = {
  ...serverOnlyFlags(),
  "wrap-id": Argument.String("wrap-id").pipe(
    Argument.withDescription("Passkey wrap ID (see `maruhi key seal list`)"),
    Argument.withSchema(NonBlank),
  ),
};
export const keyRecoveryConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the existing ledger with a passkey instead of the current recovery code",
  ),
  replace: singleFlag(
    "replace",
    "Replace the reserve key with a new one without opening the ledger (when the recovery code is lost or may be compromised); the reserve keys recorded on this machine are revoked on every project the server lists for you once those chains confirm each is not a device key",
  ),
};
export const keyReserveRotateConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the current ledger with a passkey instead of the recovery code",
  ),
};

export function makeKeyCommands(onExitCode: (code: number) => void) {
  const keyGenerate = Command.make(
    "generate",
    keyGenerateConfig,
    Effect.fn("commands-key.keyGenerate")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyGenerateOp } = yield* Effect.promise(() => import("../keygen.ts"));

      const context = yield* openSession(values.server);
      yield* keyGenerateOp({
        session: context.session,
        client: context.client,
        identityBacking: identityBackingOf(context.config),
        newIdentity: values["new-identity"],
      });
    }),
  ).pipe(
    Command.withDescription(
      "Generate this device's key and store it in the OS keychain (or in the current `maruhi agent` session); the first time, also create the reserve key and seal it with a recovery code",
    ),
  );

  const keyShow = Command.make(
    "show",
    keyShowConfig,
    Effect.fn("commands-key.keyShow")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyShowOp } = yield* Effect.promise(() => import("../keygen.ts"));

      const context = yield* openSession(values.server);
      yield* keyShowOp({ session: context.session, client: context.client });
    }),
  ).pipe(
    Command.withDescription(
      "Print this device's public keys and fingerprint, and the reserve key fingerprint (never the private keys)",
    ),
  );

  const keyPublish = Command.make(
    "publish",
    keyPublishConfig,
    Effect.fn("commands-key.keyPublish")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyPublishOp } = yield* Effect.promise(() => import("../key-publish.ts"));

      const context = yield* openSession(values.server);
      yield* keyPublishOp({ session: context.session, viaGh: values.gh });
    }),
  ).pipe(
    Command.withDescription(
      "Print your signing public key as an OpenSSH line to register on GitHub as a signing key (--gh adds it through the gh CLI)",
    ),
  );

  const keyRecover = Command.make(
    "recover",
    keyRecoverConfig,
    Effect.fn("commands-key.keyRecover")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyRecoverOp } = yield* Effect.promise(() => import("../key-recover.ts"));

      // A misspelling drops before the session resolution (network)
      if (values.handoff && values.passkey) {
        return yield* Effect.fail(usageError("Choose one of --handoff and --passkey"));
      }
      const context = yield* openSession(values.server);
      yield* keyRecoverOp({
        session: context.session,
        client: context.client,
        via: values.handoff ? "handoff" : values.passkey ? "passkey" : "code",
        resume: values.resume,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Recover on a new machine: open the reserve key (recovery code, --passkey, or --handoff via your guardians), then register a new device key for this machine with it",
    ),
  );

  const keySealPasskey = Command.make(
    "passkey",
    keySealPasskeyConfig,
    Effect.fn("commands-key.keySealPasskey")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { openLedgerReserveForChange } = yield* Effect.promise(
        () => import("../ledger-open.ts"),
      );

      const context = yield* openSession(values.server);
      const reserve = yield* openLedgerReserveForChange({
        session: context.session,
        client: context.client,
        via: values.passkey ? "passkey" : "code",
        command: "maruhi key seal passkey",
      });
      yield* sealPasskeyOp({
        session: context.session,
        client: context.client,
        reserve,
        ...(values.label === undefined ? {} : { label: values.label }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Seal the reserve key to a new passkey via a page served on localhost (opens the ledger first with the recovery code or --passkey)",
    ),
  );

  const keySealList = Command.make(
    "list",
    keySealListConfig,
    Effect.fn("commands-key.keySealList")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));

      const context = yield* openSession(values.server);
      yield* listPasskeysOp({ client: context.client });
    }),
  ).pipe(Command.withDescription("List the passkeys your reserve key is sealed to"));

  const keySealRemove = Command.make(
    "remove",
    keySealRemoveConfig,
    Effect.fn("commands-key.keySealRemove")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));

      const context = yield* openSession(values.server);
      yield* removePasskeyOp({ client: context.client, wrapId: values["wrap-id"] });
    }),
  ).pipe(Command.withDescription("Remove a passkey wrap from the recovery ledger"));

  const keySeal = Command.make("seal").pipe(
    Command.withDescription("Seal the reserve key to a passkey (passkey / list / remove)"),
    Command.withSubcommands([keySealPasskey, keySealList, keySealRemove]),
  );

  const keyReserveRotate = Command.make(
    "rotate",
    keyReserveRotateConfig,
    Effect.fn("commands-key.keyReserveRotate")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyReserveRotateOp } = yield* Effect.promise(() => import("../key-recover.ts"));

      const context = yield* openSession(values.server);
      onExitCode(
        yield* keyReserveRotateOp({
          session: context.session,
          client: context.client,
          via: values.passkey ? "passkey" : "code",
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Replace the reserve key: create a new one, seal it with a new recovery code, register it on every project and revoke the old one",
    ),
  );

  const keyReserve = Command.make("reserve").pipe(
    Command.withDescription("Manage the reserve key (rotate)"),
    Command.withSubcommands([keyReserveRotate]),
  );

  const keyRecovery = Command.make(
    "recovery",
    keyRecoveryConfig,
    Effect.fn("commands-key.keyRecovery")(function* (values) {
      const { openSession } = yield* Effect.promise(() => import("../context.ts"));
      const { keyRecoveryOp } = yield* Effect.promise(() => import("../key-recover.ts"));

      const context = yield* openSession(values.server);
      onExitCode(
        yield* keyRecoveryOp({
          session: context.session,
          client: context.client,
          via: values.passkey ? "passkey" : "code",
          replace: values.replace,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Create the reserve key and its recovery code (first time), replace a ledger key that cannot serve as your reserve key, or reissue the recovery code",
    ),
  );

  const key = Command.make("key").pipe(
    Command.withDescription(
      "Manage this device's key and your reserve key (generate / show / publish / recover / recovery / seal / reserve)",
    ),
    Command.withSubcommands([
      keyGenerate,
      keyShow,
      keyPublish,
      keyRecover,
      keyRecovery,
      keySeal,
      keyReserve,
    ]),
  );

  return key;
}
