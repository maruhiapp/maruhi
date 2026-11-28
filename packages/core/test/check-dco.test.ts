import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

const repoRoot = join(import.meta.dirname, "..", "..", "..");
const SCRIPT = join(repoRoot, "scripts", "check-dco.mjs");

const ANN = { name: "Ann Example", email: "ann@example.invalid" };
const BOB = { name: "Bob Example", email: "bob@example.invalid" };

const GIT_ENV = {
  PATH: process.env["PATH"] ?? "",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
};

let workDir: string;

function git(...args: readonly string[]): string {
  const result = spawnSync("git", args, { cwd: workDir, env: GIT_ENV, encoding: "utf8" });
  expect(result.status, `git ${args.join(" ")}\n${result.stderr}`).toBe(0);
  return result.stdout.trim();
}

function commit(author: typeof ANN, message: string, committer: typeof ANN = author): void {
  git(
    "-c",
    `user.name=${committer.name}`,
    "-c",
    `user.email=${committer.email}`,
    "commit",
    "--quiet",
    "--allow-empty",
    `--author=${author.name} <${author.email}>`,
    "--message",
    message,
  );
}

function signedOffBy(...signers: ReadonlyArray<typeof ANN>): string {
  return signers.map((signer) => `Signed-off-by: ${signer.name} <${signer.email}>`).join("\n");
}

function branchWith(name: string, build: () => void): string {
  git("checkout", "--quiet", "-b", name, "main");
  build();
  return name;
}

interface Outcome {
  readonly code: number | null;
  readonly out: string;
  readonly err: string;
}

function checkDco(env: Readonly<Record<string, string>>): Outcome {
  const result = spawnSync(process.execPath, [SCRIPT], {
    cwd: workDir,
    env: { ...GIT_ENV, ...env },
    encoding: "utf8",
  });
  return { code: result.status, out: result.stdout, err: result.stderr };
}

const checkBranch = (head: string) => checkDco({ DCO_BASE: "main", DCO_HEAD: head });

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "maruhi-check-dco-"));
  git("init", "--quiet", "--initial-branch", "main");
  commit(BOB, "base, never signed off");
});

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe("check-dco: every commit of the range is signed off by its author", () => {
  it("passes when each commit carries its author's sign-off", () => {
    const head = branchWith("signed", () => {
      commit(ANN, `first\n\n${signedOffBy(ANN)}`);
      commit(BOB, `second\n\nBody text.\n\n${signedOffBy(BOB)}`);
    });
    const outcome = checkBranch(head);
    expect(outcome.err).toBe("");
    expect(outcome.out).toContain("check-dco: clean (2 commit(s) signed off by their authors)");
    expect(outcome.code).toBe(0);
  });

  it("fails on a commit without a sign-off and names it", () => {
    const head = branchWith("unsigned", () => {
      commit(ANN, `signed\n\n${signedOffBy(ANN)}`);
      commit(ANN, "forgot the sign-off");
    });
    const outcome = checkBranch(head);
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain("check-dco: 1 of 2 commit(s) lack a Signed-off-by trailer");
    expect(outcome.err).toMatch(
      /^ {2}[0-9a-f]{7,} "forgot the sign-off" \(author ann@example\.invalid\)$/m,
    );
    expect(outcome.err).not.toContain('"signed"');
  });

  it("fails when the only sign-off is another person's", () => {
    const head = branchWith("signed-by-another", () => {
      commit(ANN, `relayed\n\n${signedOffBy(BOB)}`);
    });
    const outcome = checkBranch(head);
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain('"relayed" (author ann@example.invalid)');
  });

  it("fails when the committer signed off and the author did not", () => {
    const head = branchWith("signed-by-committer", () => {
      commit(ANN, `applied for the author\n\n${signedOffBy(BOB)}`, BOB);
    });
    const outcome = checkBranch(head);
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain('"applied for the author" (author ann@example.invalid)');
  });

  it("fails on a sign-off whose value holds a second address", () => {
    const head = branchWith("two-addresses", () => {
      commit(ANN, `forged\n\nSigned-off-by: ${BOB.name} <${BOB.email}> <${ANN.email}>`);
    });
    expect(checkBranch(head).code).toBe(1);
  });

  it("reads a subject that holds separator bytes as a subject", () => {
    const head = branchWith("separators-in-subject", () => {
      commit(ANN, `unsigned\x1fx <${ANN.email}>`);
      commit(ANN, `sig\x1ened\n\n${signedOffBy(ANN)}`);
    });
    const outcome = checkBranch(head);
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain("check-dco: 1 of 2 commit(s) lack a Signed-off-by trailer");
    expect(outcome.err).toContain('"unsigned\\u001fx <ann@example.invalid>"');
  });

  it("accepts the author's sign-off among several, whatever the letter case of the address", () => {
    const head = branchWith("several-signers", () => {
      commit(ANN, `relayed\n\n${signedOffBy(BOB, { ...ANN, email: "Ann@Example.INVALID" })}`);
      commit({ ...ANN, email: "ANN@example.invalid" }, `shouted\n\n${signedOffBy(ANN)}`);
    });
    const outcome = checkBranch(head);
    expect(outcome.out).toContain("check-dco: clean (2 commit(s) signed off by their authors)");
    expect(outcome.code).toBe(0);
  });

  it("does not count a sign-off line outside the trailer block", () => {
    const head = branchWith("sign-off-in-body", () => {
      commit(ANN, `quoted\n\n${signedOffBy(ANN)}\n\nA later paragraph ends the message.`);
    });
    expect(checkBranch(head).code).toBe(1);
  });

  it("skips merge commits and the commits the base already has", () => {
    const head = branchWith("merged-base", () => {
      commit(ANN, `work\n\n${signedOffBy(ANN)}`);
    });
    git("checkout", "--quiet", "main");
    commit(BOB, "base moves on, never signed off");
    git("checkout", "--quiet", head);
    git(
      "-c",
      `user.name=${ANN.name}`,
      "-c",
      `user.email=${ANN.email}`,
      "merge",
      "--quiet",
      "--no-ff",
      "--message",
      "merge the base",
      "main",
    );
    const outcome = checkBranch(head);
    expect(outcome.out).toContain("check-dco: clean (1 commit(s) signed off by their authors)");
    expect(outcome.code).toBe(0);
  });

  it("fails on a range that holds no commit to check", () => {
    const outcome = checkBranch("main");
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain("holds no commit to check");
  });

  it("fails without a commit range", () => {
    const outcome = checkDco({});
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain("set DCO_BASE and DCO_HEAD");
  });

  it("fails when the range cannot be read", () => {
    expect(checkDco({ DCO_BASE: "main", DCO_HEAD: "no-such-branch" }).code).not.toBe(0);
  });
});

describe("dco.yml: the check runs on pull requests from forks only", () => {
  const lines = readFileSync(join(repoRoot, ".github", "workflows", "dco.yml"), "utf8").split("\n");

  it("skips a pull request whose branch is in this repository", () => {
    expect(lines).toContain(
      "    if: github.event.pull_request.head.repo.full_name != github.repository",
    );
  });

  it("measures the range from the base branch as fetched, not from the event's base sha", () => {
    expect(lines).toContain("          fetch-depth: 0");
    expect(lines).toContain("          DCO_BASE: origin/${{ github.event.pull_request.base.ref }}");
    expect(lines).toContain("          DCO_HEAD: ${{ github.event.pull_request.head.sha }}");
  });

  it("runs again when the base branch of the pull request changes", () => {
    expect(lines).toContain("    types: [opened, edited, synchronize, reopened]");
  });
});
