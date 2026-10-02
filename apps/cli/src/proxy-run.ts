// `maruhi proxy run -- <command>` (PF4 — credential brokering and
// short-lived connectors. Design record: docs/notes/pf4-design.md).
//
// The command of `maruhi run`, with one difference in what the child
// receives: for a variable with a `broker` or `connector` rule the child
// gets a **placeholder**, and the real value is written into requests
// only at the proxy, only toward the hosts the rule names. The agent (or
// any program) running under it cannot print, log, or exfiltrate a value
// it never had. Values a proxy cannot substitute (a database URL, a key
// used locally) are passed through only when a rule says so; everything
// else is withheld (fail closed — ruling P5).
//
// Flow:
//   1. classify the decrypted variables by the config's rules
//      (broker / connector / passthrough / withhold / unlisted);
//   2. create the run's CA (proxy-cert.ts) and start the proxy
//      (proxy-server.ts) on a loopback port;
//   3. write the CA certificate (public) and a bundle (system roots +
//      CA) into a private temp directory — the only files this command
//      creates, and never a secret;
//   4. build the child's environment: placeholders, pass-through values
//      (through `buildInjectionEnv`'s name and value checks), and the
//      control variables every TLS client reads — HTTP(S)_PROXY, the
//      CA-file variables, NODE_USE_ENV_PROXY — written **after** the
//      variables so a variable of the same name cannot redirect the
//      child's traffic;
//   5. run the child with signals held (the proxy must outlive it), then
//      close the proxy, remove the directory, and print how many requests
//      were brokered, tunnelled, blocked, or failed.
//
// Pass-through values are also handed to the run-output redaction
// (ROADMAP Phase 3 ⑤ — run.ts) under the same trigger as `maruhi run`.
// The server is not involved: no endpoint, no acceptance rule, no audit
// row beyond the pull's own `var.read`. No spec text changes.

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import tls from "node:tls";

import { Context, Effect, Redacted, type Stdio } from "effect";

import { privateRuntimeDir } from "./agent.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { makeEphemeralCa } from "./proxy-cert.ts";
import type { HostPattern, ProxyConfig, VariableRule } from "./proxy-config.ts";
import { type ConnectorDeps, makeConnectorCredential } from "./proxy-connector.ts";
import { isLoopbackBind } from "./proxy-guard.ts";
import { type BrokeredCredential, makePlaceholder, randomAlphanumeric } from "./proxy-rules.ts";
import {
  type ProxyDecision,
  type ProxyHandle,
  type ProxyOptions,
  startProxy,
} from "./proxy-server.ts";
import type { DecryptedVariable } from "./pull.ts";
import { buildInjectionEnv, ProcessRunner, redactionFragments } from "./run.ts";

/**
 * Test seams (absent in production): where the proxy's upstream
 * connections go and how a connector reaches its API. Provided by the
 * test layer through {@link ProxySeams}.
 */
export interface ProxySeamsShape {
  readonly upstream?: ProxyOptions["upstream"];
  readonly connector?: Partial<ConnectorDeps>;
}

export class ProxySeams extends Context.Reference<ProxySeamsShape | null>("cli/ProxySeams", {
  defaultValue: (): ProxySeamsShape | null => null,
}) {}

export interface ProxyRunInput {
  readonly command: readonly string[];
  readonly config: ProxyConfig;
  readonly configPath: string;
  readonly environmentId: string;
  readonly variables: readonly DecryptedVariable[];
  /** One stderr line per request the proxy handled. */
  readonly verbose: boolean;
  /**
   * Sandbox mode (pf4-design.md §20 — the structural answer to ruling M):
   * `listen` = `host[:port]` to bind beyond the loopback so a container or
   * another network namespace can reach the proxy; `advertise` = the
   * `host[:port]` the child is told (what the sandbox sees the host as).
   */
  readonly listen?: string | undefined;
  readonly advertise?: string | undefined;
}

/** `[host]` or `[host]:port` → the two parts; null when the brackets are malformed. */
function splitBracketed(text: string): { readonly host: string; readonly portText: string } | null {
  const close = text.indexOf("]");
  if (close < 0) {
    return null;
  }
  const after = text.slice(close + 1);
  if (after.length === 0) {
    return { host: text.slice(1, close), portText: "0" };
  }
  return after.startsWith(":") ? { host: text.slice(1, close), portText: after.slice(1) } : null;
}

/** `host` or `host:port` → the two parts (more than one colon and no bracket = a bare IPv6 address). */
function splitPlain(text: string): { readonly host: string; readonly portText: string } {
  const colon = text.lastIndexOf(":");
  if (colon < 0 || text.indexOf(":") !== colon) {
    return { host: text, portText: "0" };
  }
  return { host: text.slice(0, colon), portText: text.slice(colon + 1) };
}

/**
 * `host[:port]` of a bind address: an IPv4 literal, a host name, or an IPv6
 * literal (`[::1]:8080`, `[::1]`, or a bare `::1`); port 0 = ephemeral.
 * Exported for tests.
 */
export function parseListenAddress(
  text: string,
): { readonly host: string; readonly port: number } | null {
  const trimmed = text.trim();
  const parts = trimmed.startsWith("[") ? splitBracketed(trimmed) : splitPlain(trimmed);
  if (parts === null) {
    return null;
  }
  const { host, portText } = parts;
  if (host.length === 0 || host.includes("/") || !/^\d{1,5}$/.test(portText)) {
    return null;
  }
  const port = Number(portText);
  return port <= 65535 ? { host, port } : null;
}

/* -------------------------------------------------------------------------- */
/* Classification                                                               */
/* -------------------------------------------------------------------------- */

interface Plan {
  readonly credentials: readonly BrokeredCredential[];
  /** Env-var name → placeholder, in rule order. */
  readonly placeholders: ReadonlyMap<string, string>;
  /** Variables injected with their real value. */
  readonly passthrough: readonly DecryptedVariable[];
  readonly withheld: readonly string[];
  /** Variables consumed by connectors (never injected). */
  readonly consumed: readonly string[];
  /** Rules naming a variable the environment does not hold. */
  readonly absent: readonly string[];
}

const encoder = new TextEncoder();

function describeHosts(hosts: readonly HostPattern[]): string {
  return hosts
    .map((pattern) => {
      const scheme = pattern.scheme === "http" ? "http://" : "";
      const host = pattern.wildcard ? `*.${pattern.host}` : pattern.host;
      const defaultPort = pattern.scheme === "https" ? 443 : 80;
      return `${scheme}${host}${pattern.port === defaultPort ? "" : `:${pattern.port}`}`;
    })
    .join(", ");
}

const placeholderFor = (name: string, rule: { readonly placeholder: string | undefined }) =>
  rule.placeholder ?? makePlaceholder(name);

/** A `broker` rule's credential: the variable's own bytes, resolved per request. */
function brokerCredential(
  name: string,
  rule: Extract<VariableRule, { mode: "broker" }>,
  variable: DecryptedVariable,
): BrokeredCredential {
  return {
    name,
    placeholder: placeholderFor(name, rule),
    hosts: rule.hosts,
    surfaces: rule.surfaces,
    // Reason for unwrapping: the proxy writes the value into a request
    // toward a host the rule names (the sanctioned consumption path of
    // this command). Resolved per request, never stored anywhere else
    resolve: () => Promise.resolve(Redacted.value(variable.value)),
    known: () => [Redacted.value(variable.value)],
  };
}

/** A `connector` rule's credential, or the fail-fast error (before the child starts). */
function connectorCredential(input: {
  readonly name: string;
  readonly rule: Extract<VariableRule, { mode: "connector" }>;
  readonly byName: ReadonlyMap<string, DecryptedVariable>;
  readonly deps: ConnectorDeps;
}): Effect.Effect<
  { readonly credential: BrokeredCredential; readonly consumed: readonly string[] },
  CliError
> {
  const { name, rule, byName } = input;
  const inputs: Record<string, Uint8Array> = {};
  const consumed: string[] = [];
  for (const [inputName, variableName] of Object.entries(rule.inputs)) {
    const variable = byName.get(variableName);
    if (variable === undefined) {
      // Fail fast, before the child starts: a connector that cannot mint has nothing to broker
      return Effect.fail(
        cliError(
          `The connector rule for ${displayText(name)} names variable ${displayText(variableName)} as its ${inputName}, but the environment has no value for it. Set it with \`maruhi push ${displayText(variableName)}\`, or fix the rule. The command was not started`,
        ),
      );
    }
    // Reason for unwrapping: the connector consumes the input in memory to
    // mint a short-lived credential (integration-options.md §6 D3). The
    // input never reaches the child
    inputs[inputName] = Redacted.value(variable.value);
    consumed.push(variableName);
  }
  if (byName.has(name)) {
    return Effect.fail(
      cliError(
        `The connector rule for ${displayText(name)} would inject a minted credential under a name the environment already holds a value for. Rename the rule (the child sees it as that environment variable). The command was not started`,
      ),
    );
  }
  return Effect.succeed({
    consumed,
    credential: makeConnectorCredential({
      name,
      kind: rule.connector,
      inputs,
      placeholder: placeholderFor(name, rule),
      hosts: rule.hosts,
      surfaces: rule.surfaces,
      deps: input.deps,
    }),
  });
}

/** Files a non-connector rule into the plan's buckets (by what it does with the variable it names, or does not find). */
function placeRule(input: {
  readonly name: string;
  readonly rule: Exclude<VariableRule, { mode: "connector" }>;
  readonly variable: DecryptedVariable | undefined;
  readonly credentials: BrokeredCredential[];
  readonly passthrough: DecryptedVariable[];
  readonly withheld: string[];
  readonly absent: string[];
}): void {
  const { name, rule, variable } = input;
  if (variable === undefined) {
    if (rule.mode !== "withhold") {
      input.absent.push(name);
    }
    return;
  }
  switch (rule.mode) {
    case "broker":
      input.credentials.push(brokerCredential(name, rule, variable));
      return;
    case "passthrough":
      input.passthrough.push(variable);
      return;
    case "withhold":
      input.withheld.push(name);
  }
}

function planFor(input: {
  readonly config: ProxyConfig;
  readonly variables: readonly DecryptedVariable[];
  readonly connectorDeps: ConnectorDeps;
}): Effect.Effect<Plan, CliError> {
  return Effect.gen(function* () {
    const byName = new Map(input.variables.map((variable) => [variable.name, variable]));
    const credentials: BrokeredCredential[] = [];
    const passthrough: DecryptedVariable[] = [];
    const withheld: string[] = [];
    const consumed = new Set<string>();
    const absent: string[] = [];

    for (const [name, rule] of input.config.variables) {
      if (rule.mode === "connector") {
        const made = yield* connectorCredential({ name, rule, byName, deps: input.connectorDeps });
        credentials.push(made.credential);
        for (const consumedName of made.consumed) {
          consumed.add(consumedName);
        }
        continue;
      }
      placeRule({
        name,
        rule,
        variable: byName.get(name),
        credentials,
        passthrough,
        withheld,
        absent,
      });
    }

    // Variables no rule names follow `unlisted`; a connector's inputs never reach the child, whatever it says
    const unlisted = input.variables.filter(
      (variable) => !input.config.variables.has(variable.name) && !consumed.has(variable.name),
    );
    if (input.config.unlisted === "passthrough") {
      passthrough.push(...unlisted);
    } else {
      withheld.push(...unlisted.map((variable) => variable.name));
    }
    return {
      credentials,
      placeholders: new Map(
        credentials.map((credential) => [credential.name, credential.placeholder]),
      ),
      passthrough,
      withheld: withheld.toSorted(),
      consumed: [...consumed].toSorted(),
      absent,
    };
  });
}

/** How one rule is summarized on stderr before the child starts (names and hosts only). */
function describeRule(name: string, rule: VariableRule): string {
  switch (rule.mode) {
    case "broker":
      return `${displayText(name)} → ${describeHosts(rule.hosts)} (${rule.surfaces.join(", ")})`;
    case "connector":
      return `${displayText(name)} (connector ${rule.connector}) → ${describeHosts(rule.hosts)} (${rule.surfaces.join(", ")})`;
    case "passthrough":
    case "withhold":
      return displayText(name);
  }
}

/**
 * One line summarizing a config's rules, for `maruhi proxy accept` (what a
 * person is accepting: brokered variables and their hosts, pass-through
 * and withheld names, the two defaults). Names only, never a value.
 */
export function describeProxyConfig(config: ProxyConfig): string {
  const rules = [...config.variables];
  const brokered = rules.filter(([, rule]) => rule.mode === "broker" || rule.mode === "connector");
  const names = (mode: VariableRule["mode"]) =>
    rules
      .filter(([, rule]) => rule.mode === mode)
      .map(([name]) => displayText(name))
      .toSorted();
  const parts = [
    brokered.length === 0
      ? "brokers nothing"
      : `brokers ${brokered.map(([name, rule]) => describeRule(name, rule)).join("; ")}`,
  ];
  const passthrough = names("passthrough");
  if (passthrough.length > 0) {
    parts.push(`passes through ${passthrough.join(", ")}`);
  }
  const withheld = names("withhold");
  if (withheld.length > 0) {
    parts.push(`withholds ${withheld.join(", ")}`);
  }
  parts.push(
    `unlisted variables are ${config.unlisted === "passthrough" ? "passed through with their real value" : "withheld"}`,
    `hosts no rule names are ${config.unmatched === "block" ? "blocked" : "tunnelled untouched"}`,
  );
  return parts.join("; ");
}

/* -------------------------------------------------------------------------- */
/* The child's control environment                                             */
/* -------------------------------------------------------------------------- */

/**
 * The variables that point a child's HTTP clients at the proxy and make
 * them trust the run's CA. `bundle` = system roots + the CA (OpenSSL-style
 * clients replace their store with this file, so the roots must ride
 * along for the hosts the proxy only tunnels); `caOnly` = the CA alone
 * (additive variables). Exported for tests.
 */
export function proxyControlEnv(input: {
  readonly proxyUrl: string;
  readonly bundlePath: string;
  readonly caPath: string;
}): Readonly<Record<string, string>> {
  return {
    HTTP_PROXY: input.proxyUrl,
    HTTPS_PROXY: input.proxyUrl,
    http_proxy: input.proxyUrl,
    https_proxy: input.proxyUrl,
    // An inherited NO_PROXY could route a brokered host around the proxy
    NO_PROXY: "",
    no_proxy: "",
    // Node 24+ fetch (undici) honours the proxy variables only when asked
    NODE_USE_ENV_PROXY: "1",
    // OpenSSL-based clients (curl, Python, Ruby, Go, git): the whole store
    SSL_CERT_FILE: input.bundlePath,
    REQUESTS_CA_BUNDLE: input.bundlePath,
    CURL_CA_BUNDLE: input.bundlePath,
    GIT_SSL_CAINFO: input.bundlePath,
    AWS_CA_BUNDLE: input.bundlePath,
    PIP_CERT: input.bundlePath,
    CARGO_HTTP_CAINFO: input.bundlePath,
    NIX_SSL_CERT_FILE: input.bundlePath,
    GRPC_DEFAULT_SSL_ROOTS_FILE_PATH: input.bundlePath,
    // Additive stores
    NODE_EXTRA_CA_CERTS: input.caPath,
    DENO_CERT: input.caPath,
  };
}

/**
 * PEM text of the roots the child should keep trusting for the hosts the
 * proxy only tunnels: the runtime's bundled Mozilla roots plus, where the
 * runtime exposes it, the operating system's store (a corporate root
 * behind a TLS-inspecting network proxy — review finding §19 D-13a).
 */
function rootCertificatesPem(): string {
  const system = typeof tls.getCACertificates === "function" ? tls.getCACertificates("system") : [];
  const unique = new Set<string>([...tls.rootCertificates, ...system]);
  return [...unique].map((cert) => (cert.endsWith("\n") ? cert : `${cert}\n`)).join("");
}

/* -------------------------------------------------------------------------- */
/* The command                                                                  */
/* -------------------------------------------------------------------------- */

interface Tally {
  brokered: number;
  relayed: number;
  tunnelled: number;
  blocked: number;
  errors: number;
}

function describeDecision(decision: ProxyDecision): string {
  const where = `${decision.target.host}:${decision.target.port}`;
  switch (decision.kind) {
    case "brokered":
      return `proxy: brokered ${decision.method} ${where}${displayText(decision.path)} [${decision.substituted.join(", ") || "no substitution"}] → ${decision.status}`;
    case "relayed":
      return `proxy: relayed ${decision.method} ${where}${displayText(decision.path)} (plain HTTP, no rule names it) → ${decision.status}`;
    case "tunnelled":
      return `proxy: tunnelled ${where} (no rule names it; not inspected)`;
    case "blocked":
      return `proxy: blocked ${decision.method} ${where}${displayText(decision.path)} — ${displayText(decision.reason)}`;
    case "error":
      return `proxy: error ${decision.method} ${where}${displayText(decision.path)} — ${displayText(decision.reason)}`;
  }
}

/** Says on stderr what the child will get, before anything starts (ruling P5: the config decides where values go). */
function announcePlan(plan: Plan, input: ProxyRunInput): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const brokeredRules = [...input.config.variables].filter(
      ([name, rule]) =>
        (rule.mode === "broker" || rule.mode === "connector") && plan.placeholders.has(name),
    );
    if (brokeredRules.length > 0) {
      yield* logNote(
        `proxy run: brokering ${brokeredRules.map(([name, rule]) => describeRule(name, rule)).join("; ")}`,
      );
    } else {
      yield* logWarning(
        `proxy run: no variable is brokered (${input.configPath} has no broker or connector rule that names a variable of environment ${displayText(input.environmentId)})`,
      );
    }
    if (plan.passthrough.length > 0) {
      yield* logNote(
        `proxy run: passing through with the real value: ${plan.passthrough
          .map((variable) => displayText(variable.name))
          .toSorted()
          .join(", ")}`,
      );
    }
    if (plan.withheld.length > 0) {
      yield* logNote(
        `proxy run: withheld (not injected): ${plan.withheld.map(displayText).join(", ")} — add a rule in ${input.configPath} to broker or pass a variable through`,
      );
    }
    if (plan.absent.length > 0) {
      yield* logWarning(
        `proxy run: ${plan.absent.map(displayText).join(", ")} ${plan.absent.length === 1 ? "has a rule but no value" : "have rules but no values"} in environment ${displayText(input.environmentId)}; nothing is injected for ${plan.absent.length === 1 ? "it" : "them"}`,
      );
    }
    yield* logNote(
      input.config.unmatched === "block"
        ? "proxy run: hosts no rule names are blocked"
        : "proxy run: hosts no rule names are tunnelled untouched (not inspected)",
    );
  });
}

/** The child's variables: placeholders ride the same checks as values (name shape, execution-control names, case collisions). */
function injectionEnvFor(plan: Plan): Effect.Effect<Readonly<Record<string, string>>, CliError> {
  const placeholderVariables: DecryptedVariable[] = [...plan.placeholders].map(
    ([name, placeholder]) => ({
      variableId: `placeholder:${name}`,
      name,
      version: 0,
      epoch: 0,
      varType: "",
      required: false,
      value: Redacted.make(encoder.encode(placeholder), { label: "placeholder" }),
    }),
  );
  return buildInjectionEnv([...plan.passthrough, ...placeholderVariables]);
}

/** `--listen` / `--advertise` checked (usage errors) and the non-loopback warning. */
interface Addresses {
  readonly listen: { readonly host: string; readonly port: number } | undefined;
  readonly advertise: { readonly host: string; readonly port: number } | undefined;
}

function resolveListen(input: ProxyRunInput): Effect.Effect<Addresses, CliError, CliIo> {
  return Effect.gen(function* () {
    const listen = input.listen === undefined ? undefined : parseListenAddress(input.listen);
    if (listen === null) {
      return yield* Effect.fail(
        usageError(
          "--listen must be host[:port] (an address of this machine; port 0 or omitted = any free port)",
        ),
      );
    }
    const advertise =
      input.advertise === undefined ? undefined : parseListenAddress(input.advertise);
    if (advertise === null) {
      return yield* Effect.fail(usageError("--advertise must be host[:port]"));
    }
    if (listen !== undefined && !isLoopbackBind(listen.host)) {
      yield* logWarning(
        `proxy run: the proxy listens on ${listen.host} and is reachable from that network; every request needs this run's proxy credential, which only the command's environment carries. Destinations on this machine (loopback, link-local) are refused unless a rule names them`,
      );
    }
    return { listen, advertise };
  });
}

/** Teardown: revoke the credentials connectors minted (best effort, a Note on failure), then close the proxy. */
function releaseAndClose(
  credentials: readonly BrokeredCredential[],
  proxy: ProxyHandle,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    for (const credential of credentials) {
      if (credential.release !== undefined) {
        yield* Effect.tryPromise({
          try: credential.release,
          catch: (error) => (error instanceof Error ? error.message : "revocation failed"),
        }).pipe(
          Effect.catch((reason) =>
            logNote(
              `proxy run: could not revoke the credential minted for ${displayText(credential.name)} (${reason}); it expires on its own`,
            ),
          ),
        );
      }
    }
    yield* Effect.promise(() => proxy.close());
  });
}

/** `maruhi proxy run`: broker the environment's values to one command. Returns the child's exit code. */
export function proxyRunOp(
  input: ProxyRunInput,
): Effect.Effect<number, CliError, CliIo | ProcessRunner | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const runner = yield* ProcessRunner;
    const seams = yield* ProxySeams;
    const connectorDeps: ConnectorDeps = {
      fetch: globalThis.fetch,
      now: Date.now,
      ...seams?.connector,
    };
    const plan = yield* planFor({
      config: input.config,
      variables: input.variables,
      connectorDeps,
    });
    yield* announcePlan(plan, input);
    const injected = yield* injectionEnvFor(plan);
    const ca = yield* Effect.tryPromise({
      try: () => makeEphemeralCa(),
      catch: () =>
        cliError("Cannot create the run's certificate authority (WebCrypto unavailable)"),
    });
    const tally: Tally = { brokered: 0, relayed: 0, tunnelled: 0, blocked: 0, errors: 0 };
    const onDecision = (decision: ProxyDecision): void => {
      tally[decision.kind === "error" ? "errors" : decision.kind] += 1;
      if (input.verbose) {
        // Written synchronously as it happens (stderr; names, hosts, paths without
        // their query — never a value). runSync: the live CliIo writes with writeSync
        Effect.runSync(io.logError(`Note: ${describeDecision(decision)}`));
      }
    };
    // The private directory first: a failure here leaves nothing to tear down
    const { dir, removeDir } = yield* privateRuntimeDir({
      envVar: io.envVar,
      prefix: "maruhi-proxy-",
      purpose: "the proxy's CA certificate",
      removeFailure: (path) =>
        `proxy run: could not remove the proxy CA directory (${path}) — remove it by hand`,
    });
    const { listen, advertise } = yield* resolveListen(input);
    // The run's proxy credential (userinfo of the proxy URL — §19 D-14b).
    // Whoever holds it can use the proxy, so the redaction covers it too:
    // a `printenv` under an agent must not leave it in a transcript (§21 R-10)
    const proxyPassword = randomAlphanumeric(22);
    const exitCode = yield* Effect.gen(function* () {
      const proxy = yield* Effect.tryPromise({
        try: () =>
          startProxy({
            credentials: plan.credentials,
            unmatched: input.config.unmatched,
            ca,
            hopDir: dir,
            // Every client must present this run's proxy credential (userinfo in
            // the proxy URL — honoured by curl, git, Python, Go, Node, Bun; §19 D-14b)
            credential: { user: "maruhi", password: proxyPassword },
            ...(listen === undefined ? {} : { listen }),
            ...(advertise === undefined ? {} : { advertise }),
            ...(seams?.upstream === undefined ? {} : { upstream: seams.upstream }),
            onDecision,
          }),
        catch: () =>
          cliError(
            `Cannot start the local proxy (${input.listen === undefined ? "its loopback port or its private sockets could not be opened" : `cannot listen on ${input.listen}, or its private sockets could not be opened`})`,
          ),
      });
      return yield* Effect.gen(function* () {
        // The CA certificate is public; the bundle is the roots plus the CA.
        // Neither is a secret — the CA key stays in memory
        const caPath = join(dir, "ca.pem");
        const bundlePath = join(dir, "ca-bundle.pem");
        yield* Effect.tryPromise({
          try: async () => {
            await writeFile(caPath, ca.certPem, { mode: 0o600 });
            await writeFile(bundlePath, `${rootCertificatesPem()}${ca.certPem}`, { mode: 0o600 });
          },
          catch: () => cliError(`Cannot write the proxy's CA certificate under ${dir}`),
        });
        const control = proxyControlEnv({ proxyUrl: proxy.url, bundlePath, caPath });
        // Control variables are written last: a variable named HTTPS_PROXY
        // (a co-member can choose names) must not redirect the child's traffic
        const extraEnv = { ...injected, ...control };
        yield* logNote(
          proxy.advertised === proxy.address
            ? `proxy run: proxy listening on ${proxy.address}; starting the command`
            : `proxy run: proxy listening on ${proxy.address}, told to the command as ${proxy.advertised}; starting the command`,
        );
        // The redaction covers pass-through values and the brokered values
        // known at start (defence in depth: the child should never print a
        // brokered value, so there is no false positive to fear)
        const brokeredAtStart = plan.credentials.flatMap((credential) => credential.known());
        return yield* runner.run({
          command: input.command,
          extraEnv,
          holdSignals: true,
          redact: yield* redactionFragments(plan.passthrough, [
            ...brokeredAtStart,
            new TextEncoder().encode(proxyPassword),
          ]),
        });
      }).pipe(Effect.ensuring(releaseAndClose(plan.credentials, proxy)));
    }).pipe(Effect.ensuring(removeDir));
    yield* logNote(
      `proxy run: ${tally.brokered} requests brokered, ${tally.relayed} plain requests relayed, ${tally.tunnelled} connections tunnelled, ${tally.blocked} blocked, ${tally.errors} failed`,
    );
    return exitCode;
  });
}
