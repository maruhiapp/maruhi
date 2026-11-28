import { execFileSync } from "node:child_process";

const FIELDS_PER_COMMIT = 4;
const FORMAT = `%h%x00%ae%x00%s%x00%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x1f)%x00`;

function emailOf(signOff) {
  return /^[^<>]*<([^<>]+)>$/.exec(signOff.trim())?.[1]?.toLowerCase();
}

function commitsOf(base, head) {
  const log = execFileSync(
    "git",
    ["log", "--no-merges", `--format=${FORMAT}`, `${base}..${head}`],
    {
      encoding: "utf8",
      maxBuffer: 1 << 26,
    },
  );
  const fields = log.split("\0");
  const commits = [];
  for (let at = 0; at + FIELDS_PER_COMMIT <= fields.length; at += FIELDS_PER_COMMIT) {
    const [sha, authorEmail, subject, signOffs] = fields.slice(at, at + FIELDS_PER_COMMIT);
    commits.push({
      sha: sha.trim(),
      authorEmail,
      subject,
      signOffs: signOffs.split("\x1f"),
    });
  }
  return commits;
}

function isSignedOff({ authorEmail, signOffs }) {
  return signOffs.some((signOff) => emailOf(signOff) === authorEmail.toLowerCase());
}

const { DCO_BASE: base, DCO_HEAD: head } = process.env;
if (!base || !head) {
  console.error("check-dco: set DCO_BASE and DCO_HEAD to the two ends of the commit range.");
  process.exit(1);
}

const commits = commitsOf(base, head);
if (commits.length === 0) {
  console.error(`check-dco: ${base}..${head} holds no commit to check, merge commits aside.`);
  process.exit(1);
}

const unsigned = commits.filter((commit) => !isSignedOff(commit));
if (unsigned.length > 0) {
  console.error(
    `check-dco: ${unsigned.length} of ${commits.length} commit(s) lack a Signed-off-by trailer with the commit author's email address.`,
  );
  for (const { sha, authorEmail, subject } of unsigned) {
    console.error(`  ${sha} ${JSON.stringify(subject)} (author ${authorEmail})`);
  }
  console.error(
    'A sign-off counts when its address is the one the commit is authored with. How to add one: CONTRIBUTING.md, "DCO".',
  );
  process.exit(1);
}
console.log(`check-dco: clean (${commits.length} commit(s) signed off by their authors)`);
