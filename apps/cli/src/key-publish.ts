// `maruhi key publish [--gh]` and the key-registration route
// (CRYPTO_SPEC §6.5 backing source — IV2, supplement 21 rulings G ④ /
// G ⑥).
//
// Display and assistance for registering my maruhi sig public key
// (Ed25519) as a GitHub **SSH signing key**. The only key material is
// the public key, so this is not a ceremony and needs no display
// gate.
//
// - Default: emits one OpenSSH public-key line (`ssh-ed25519 …`) to
//   stdout and the registration procedure
//   (https://github.com/settings/ssh/new — Key type = Signing Key) to
//   stderr
// - `--gh`: calls an installed gh CLI (`gh ssh-key add - --type
//   signing`) via ProcessRunner (never fetches it — same as
//   supplement 16). Direct API is not allowed (maruhi holds no GitHub
//   token — AUTH_SPEC §4). The key line goes via stdin
// - The registration route (G ⑥): right after key generation (`key
//   generate` / the generation inside `invite accept`), when on an
//   interactive terminal and not an agent, ask "register now?" and
//   call gh only on yes (never register silently — do not change the
//   user's GitHub account without consent). Non-interactive / EOF is
//   treated as "do not register" and only the guidance is shown (the
//   key generation itself is already complete)

import { fromCryptoResult } from "@maruhi/core";
import { decodeHex, encodeOpenSshEd25519PublicKey } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import { logNote } from "./notice.ts";
import { ProcessRunner } from "./run.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import { GH_ENV } from "./sync.package/index.ts";

/** The manual registration destination (GitHub's settings page). */
const GITHUB_SSH_SETTINGS_URL = "https://github.com/settings/ssh/new";

/** My sig public key's OpenSSH line (no comment — an interop encoding, not a new primitive). */
function openSshSigningKeyLine(keys: MasterKeys): Effect.Effect<string, CliError> {
  const raw = decodeHex(keys.record.sigPubHex);
  if (raw === null) {
    return Effect.fail(cliError("The stored signing public key is malformed"));
  }
  return fromCryptoResult(encodeOpenSshEd25519PublicKey(raw)).pipe(
    Effect.mapError(() =>
      cliError("The stored signing public key cannot be encoded as an OpenSSH key"),
    ),
  );
}

/** The title on the gh side (carries the FP so the key is recognizable as maruhi's in the list). */
function keyTitleOf(keys: MasterKeys): string {
  return `maruhi ${keys.fingerprintHex}`;
}

/**
 * Calls `gh ssh-key add - --type signing` (stdin = the key line).
 * gh not installed / not logged in / refused is a CliError (the
 * output contains only the public key, so it is formatted and
 * attached).
 */
const registerViaGh = Effect.fn("key-publish.registerViaGh")(function* (input: {
  readonly line: string;
  readonly keys: MasterKeys;
}): Effect.fn.Return<void, CliError, ProcessRunner> {
  const runner = yield* ProcessRunner;
  const outcome = yield* runner.exec({
    command: ["gh", "ssh-key", "add", "-", "--type", "signing", "--title", keyTitleOf(input.keys)],
    cwd: ".",
    extraEnv: GH_ENV,
    // A public key is not secret, but exec's stdin contract takes Redacted (run.ts)
    stdin: Redacted.make(new TextEncoder().encode(`${input.line}\n`), {
      label: "openssh-public-key",
    }),
  });
  if (outcome.exitCode !== 0) {
    const detail = outcome.output.trim().split("\n").slice(-3).join(" ").trim();
    return yield* Effect.fail(
      cliError(
        `gh could not add the signing key (exit ${outcome.exitCode}${detail.length > 0 ? `: ${detail}` : ""}). Sign in with \`gh auth login\` (the token needs the admin:ssh_signing_key scope — run \`gh auth refresh -s admin:ssh_signing_key\`), or add the key by hand at ${GITHUB_SSH_SETTINGS_URL}`,
      ),
    );
  }
});

/** The manual registration procedure (stderr). */
const manualInstructions = Effect.fn("key-publish.manualInstructions")(function* (
  keys: MasterKeys,
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  yield* io.logError(
    `Add the line above at ${GITHUB_SSH_SETTINGS_URL} with Key type = Signing Key (title e.g. "${keyTitleOf(keys)}"), or run \`maruhi key publish --gh\` to add it through the gh CLI`,
  );
  yield* io.logError(
    "Once registered, inviters who named your GitHub login can add you without the 12-word call (CRYPTO_SPEC §6.5). If an older key of yours from maruhi is registered there, remove it",
  );
});

/** `maruhi key publish [--gh]`. */
export const keyPublishOp = Effect.fn("key-publish.keyPublishOp")(function* (input: {
  readonly session: CliSession;
  readonly viaGh: boolean;
}): Effect.fn.Return<void, CliError, Keychain | CliIo | ProcessRunner | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const keys = yield* loadMasterKeys(input.session);
  const line = yield* openSshSigningKeyLine(keys);
  if (!input.viaGh) {
    // stdout carries only the key line (usable via `maruhi key publish > key.pub` / `| pbcopy`)
    yield* io.log(line);
    yield* manualInstructions(keys);
    return;
  }
  yield* registerViaGh({ line, keys });
  yield* io.log(
    `Registered your signing key on GitHub as "${keyTitleOf(keys)}" (fingerprint ${keys.fingerprintHex})`,
  );
  yield* io.log(
    "Inviters who name your GitHub login can now add you without the 12-word call (CRYPTO_SPEC §6.5)",
  );
});

/**
 * The registration route right after key generation (ruling G ⑥
 * (b)): on an interactive terminal + non-agent, a yes completes
 * registration via `gh`. Everything else (non-interactive, agent,
 * EOF, no) only shows guidance. A failure here must not affect the
 * key generation's success (registration can be done later).
 */
export const offerGithubRegistration = Effect.fn("key-publish.offerGithubRegistration")(
  function* (input: {
    readonly session: CliSession;
  }): Effect.fn.Return<
    void,
    never,
    Keychain | CliIo | ProcessRunner | Stdio.Stdio | HttpClient.HttpClient
  > {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const interactive =
      !io.agentProfile().isAgent &&
      (yield* stdio.stdinIsTerminal) &&
      (yield* stdio.stdoutIsTerminal);
    const keys = yield* loadMasterKeys(input.session).pipe(Effect.orElseSucceed(() => null));
    if (keys === null) {
      return;
    }
    const line = yield* openSshSigningKeyLine(keys).pipe(Effect.orElseSucceed(() => null));
    if (line === null) {
      return;
    }
    if (!interactive) {
      yield* logNote(
        "register this key on GitHub as a signing key with `maruhi key publish` so inviters can add you without the 12-word call",
      );
      return;
    }
    yield* io.log(
      "Registering this key on GitHub as a signing key lets inviters who name your GitHub login add you without the 12-word call (CRYPTO_SPEC §6.5)",
    );
    const answer = yield* io
      .promptLine({
        prompt:
          "Type yes to register it now through the gh CLI (requires `gh auth login`); anything else to skip: ",
      })
      .pipe(Effect.orElseSucceed(() => ""));
    if (answer.trim().toLowerCase() !== "yes") {
      yield* logNote("skipped. You can register it later with `maruhi key publish`");
      return;
    }
    yield* registerViaGh({ line, keys }).pipe(
      Effect.flatMap(() =>
        io.log(`Registered your signing key on GitHub as "${keyTitleOf(keys)}"`),
      ),
      Effect.catch((error) =>
        logNote(`${error.message} (you can register it later with \`maruhi key publish\`)`),
      ),
    );
  },
);
