// Unit tests for the vector-delta review aid (vector-delta.mjs). Picked up
// by the packages/crypto node vitest project (root `bun run test`); the
// workerd / browser configs only include test/**.
//
// The snapshots are synthetic: one src file and one vector file shaped like
// the real ones. A real-history run (e.g. the #329 range) is the CLI's job.

import { describe, expect, it } from "vitest";

import { analyze, canonicalSource, lpShape, sourceFacts } from "./vector-delta.mjs";

/** §2.1 length-prefixed encoding of UTF-8 fields, as lowercase hex. */
function lp(fields) {
  return fields
    .map((f) => {
      const body = Buffer.from(f, "utf8");
      const length = Buffer.alloc(4);
      length.writeUInt32BE(body.length);
      return Buffer.concat([length, body]).toString("hex");
    })
    .join("");
}

const SIG = "ab".repeat(64);
const OLD_SIG = "cd".repeat(64);

const BASE_SRC = `// Signs a thing (CRYPTO_SPEC §0)
import * as HPKE from "hpke";
import { encodeLengthPrefixed } from "./encoding.ts";

/** Supported layouts. */
export const SUPPORTED_THING_LAYOUTS: readonly number[] = [1, 2];

export function thingBytes(suite: string, layout: number, a: string): Uint8Array {
  const kem = HPKE.KEM_DHKEM_X25519_HKDF_SHA256;
  void kem;
  return encodeLengthPrefixed([\`\${suite}/thing-sig-v\${layout}\`, a, "b"]);
}
`;

function baseVectors() {
  return {
    description: "thing vectors",
    thing_signed_fields_order: ["domain", "a", "b"],
    vectors: [
      { name: "basic", signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "a", "b"]), note: "v1" },
      {
        name: "legacy",
        signed_bytes_hex: lp(["maruhi/v1/thing-sig-v2", "old", "b"]),
        signature_hex: OLD_SIG,
      },
    ],
    negative: [
      {
        name: "tampered",
        base: "basic",
        verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "x", "b"]),
        signature_hex: SIG,
        must_fail: true,
        note: "one field swapped",
      },
      {
        name: "legacy-transplant",
        base: "legacy",
        verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "old", "b"]),
        signature_hex: OLD_SIG,
        must_fail: true,
        kind: "signature",
      },
    ],
  };
}

function snapshot(src, vectors, extra = {}) {
  return new Map([
    ["src/thing.ts", src],
    ["test-vectors/thing.json", `${JSON.stringify(vectors, null, 2)}\n`],
    ["package.json", JSON.stringify({ dependencies: { hpke: "1.1.7" } })],
    ...Object.entries(extra),
  ]);
}

/** An encoding.json-style file with one case (extra snapshot entry). */
function encoding(hex) {
  return {
    "test-vectors/encoding.json": JSON.stringify({
      cases: [{ name: "ab-c", fields: ["ab", "c"], expected_hex: hex }],
    }),
  };
}

// Stands in for Bun.Transpiler: comments and formatting do not reach the
// runtime form, anything else does
const runtimeForm = (_path, text) => canonicalSource(text);

const run = (src, vectors, extra) =>
  analyze(snapshot(BASE_SRC, baseVectors()), snapshot(src, vectors, extra), runtimeForm);

describe("canonicalSource", () => {
  it("drops comments and formatting but keeps strings, templates and regexes", () => {
    const a =
      'const u = "http://x"; // trailing\nconst r = /a\\/\\/b/g; /* block */ f(`${a}//`, x);';
    const b = 'const u="http://x";\nconst r=/a\\/\\/b/g;\nf( `${a}//` ,x);';
    expect(canonicalSource(a)).toBe(canonicalSource(b));
    expect(canonicalSource(a)).toContain('"http://x"');
    // A regex holding a quote: read as a division, the quote would open a
    // string and swallow the comment
    expect(canonicalSource('return /"/.test(y); // "')).toBe('return/"/.test(y);');
    expect(canonicalSource("a = b / c; // d")).toBe("a=b/c;");
  });

  it("keeps identifier boundaries and sees a changed string", () => {
    expect(canonicalSource("return x")).not.toBe(canonicalSource("returnx"));
    expect(canonicalSource('a("v1")')).not.toBe(canonicalSource('a("v2")'));
  });
});

describe("sourceFacts", () => {
  it("extracts domain patterns, SUPPORTED_* sets and hpke primitives", () => {
    const facts = sourceFacts(BASE_SRC);
    expect([...facts.domains]).toEqual(["<suite>/thing-sig-v*"]);
    expect(facts.supported.get("SUPPORTED_THING_LAYOUTS")).toEqual({
      parsed: true,
      values: ["1", "2"],
    });
    expect(facts.primitives).toContain("hpke:KEM_DHKEM_X25519_HKDF_SHA256");
    expect(facts.primitives).toContain("module hpke");
  });

  it("ignores domains that only appear in comments", () => {
    expect([...sourceFacts('// LP("maruhi/v1/ghost", x)\nconst a = 1;').domains]).toEqual([]);
  });
});

describe("lpShape", () => {
  it("reads the domain and field count of a length-prefixed value", () => {
    expect(lpShape(lp(["maruhi/v1/thing-sig-v1", "a", "b"]))).toEqual({
      domain: "maruhi/v1/thing-sig-v1",
      fields: 3,
    });
  });

  it("rejects values that are not a domain-led encoding", () => {
    expect(lpShape(SIG)).toBeNull();
    expect(lpShape(lp(["not a domain", "a"]))).toBeNull();
  });
});

describe("analyze", () => {
  it("R0: comment and prose edits only", () => {
    const vectors = baseVectors();
    vectors.vectors[0].note = "the first layout";
    vectors.description = "thing vectors, reworded";
    const result = run(BASE_SRC.replace("Signs a thing", "Builds the signed bytes"), vectors);
    expect(result.risk).toBe("R0");
    expect(result.files.cosmetic).toEqual(["src/thing.ts"]);
    expect(result.vectors.changed.map((c) => [...c.kinds])).toEqual([["prose"], ["prose"]]);
  });

  it("R0 needs the runtime form too: without it a code edit is logic", () => {
    const head = snapshot(BASE_SRC.replace("Signs a thing", "Signs"), baseVectors());
    const result = analyze(snapshot(BASE_SRC, baseVectors()), head);
    expect(result.files.code).toEqual(["src/thing.ts"]);
    expect(result.risk).toBe("R2");
  });

  it("R1: a layout removed, its vector deleted and a dependent negative rebased", () => {
    const vectors = baseVectors();
    vectors.vectors.splice(1, 1);
    vectors.negative[1] = {
      name: "legacy-transplant",
      base: "basic",
      verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "a", "z"]),
      signature_hex: SIG,
      must_fail: true,
      kind: "signature",
    };
    const src = BASE_SRC.replace("[1, 2]", "[1]");
    const result = run(src, vectors);
    expect(result.risk).toBe("R1");
    expect(result.vectors.removed).toEqual(["thing.json › vectors › legacy"]);
    expect(result.vectors.rebased.map((c) => c.id)).toEqual([
      "thing.json › negative › legacy-transplant",
    ]);
    expect(result.vectors.rebased[0].rebasedOff).toEqual(expect.arrayContaining(["legacy"]));
    expect(result.supported).toEqual([
      {
        name: "SUPPORTED_THING_LAYOUTS",
        before: "[1, 2]",
        after: "[1]",
        shrinks: true,
      },
    ]);
    expect(result.shapes.removed).toEqual(["<suite>/thing-sig-v2 ×3"]);
    expect(result.domains.new).toEqual([]);
  });

  it("R2: a surviving vector's expected outcome changed", () => {
    const vectors = baseVectors();
    vectors.negative[0].must_fail = false;
    const result = run(BASE_SRC, vectors);
    expect(result.risk).toBe("R2");
    expect(result.vectors.outcomeChanged.map((c) => c.id)).toEqual([
      "thing.json › negative › tampered",
    ]);
  });

  it("treats `kind` as an outcome in a negative and as data in a positive", () => {
    const negative = baseVectors();
    negative.negative[1].kind = "invalid-input";
    expect(run(BASE_SRC, negative).vectors.outcomeChanged).toHaveLength(1);
    const positive = baseVectors();
    positive.vectors[0].kind = "guardian";
    const result = run(BASE_SRC, positive);
    expect(result.vectors.outcomeChanged).toHaveLength(0);
    expect([...result.vectors.changed[0].kinds]).toEqual(["data"]);
  });

  it("R2: a supported set grows and logic changes without any narrowing", () => {
    const result = run(BASE_SRC.replace("[1, 2]", "[1, 2, 3]"), baseVectors());
    expect(result.risk).toBe("R2");
    expect(result.reasons.R2).toContain(
      "SUPPORTED_THING_LAYOUTS changed without only shrinking: [1, 2] → [1, 2, 3]",
    );
  });

  it("R3: a new domain string in src", () => {
    const src = BASE_SRC.replace(
      "return encodeLengthPrefixed",
      "void `${suite}/other`;\n  return encodeLengthPrefixed",
    );
    const result = run(src, baseVectors());
    expect(result.risk).toBe("R3");
    expect(result.domains.new).toEqual(["<suite>/other"]);
  });

  it("does not call a domain new when a base pattern covers it", () => {
    const src = BASE_SRC.replace("thing-sig-v${layout}", "thing-sig-v1");
    expect(run(src, baseVectors()).domains.new).toEqual([]);
  });

  it("R3: an expected_hex change is data, not an outcome (Cursor Bugbot)", () => {
    const result = analyze(
      snapshot(BASE_SRC, baseVectors(), encoding("0000000261620000000163")),
      snapshot(BASE_SRC, baseVectors(), encoding("0000000261620000000164")),
      runtimeForm,
    );
    expect(result.vectors.outcomeChanged).toEqual([]);
    expect(result.vectors.unexplained.map((c) => c.id)).toEqual(["encoding.json › cases › ab-c"]);
    expect(result.risk).toBe("R3");
  });

  it("counts an unknown expected_* key as data, not an outcome", () => {
    const base = baseVectors();
    base.vectors[0].expected_widget = "round";
    const head = baseVectors();
    head.vectors[0].expected_widget = "square";
    const result = analyze(snapshot(BASE_SRC, base), snapshot(BASE_SRC, head), runtimeForm);
    expect(result.vectors.outcomeChanged).toEqual([]);
    expect([...result.vectors.changed[0].kinds]).toEqual(["data"]);
    expect(result.risk).toBe("R3");
  });

  it("lets a `*` pattern cover a layout number only", () => {
    for (const suffix of ["vault", "v2-hybrid"]) {
      const src = BASE_SRC.replace("thing-sig-v${layout}", `thing-sig-${suffix}`);
      const result = run(src, baseVectors());
      expect(result.domains.new).toEqual([`<suite>/thing-sig-${suffix}`]);
      expect(result.risk).toBe("R3");
    }
  });

  it("R2: a negative removed with the check behind it while its surface remains (pullfrog)", () => {
    // base: a positive plus a too-long rejection, and src that throws on
    // length; head: the rejection and the throw both gone. The v1 shape
    // the negative exercised is still accepted, so acceptance may widen
    const guarded = BASE_SRC.replace(
      "const kem",
      'if (a.length > 64) throw new Error("too long");\n  const kem',
    );
    const base = baseVectors();
    base.negative.push({
      name: "too-long",
      base: "basic",
      verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "a".repeat(65), "b"]),
      signature_hex: SIG,
      must_fail: true,
    });
    const result = analyze(snapshot(guarded, base), snapshot(BASE_SRC, baseVectors()), runtimeForm);
    expect(result.risk).toBe("R2");
    expect(result.reasons.R1).toEqual([]);
    expect(result.reasons.R2).toContain(
      "1 rejection vector(s) removed while their surface remains: thing.json › negative › too-long",
    );
  });

  it("R2: a removed SUPPORTED member never vouches for a negative (Cursor Bugbot)", () => {
    // A lone `version` leaf equal to the dropped layout used to count as
    // naming it; the v1 surface the negative exercised is still accepted
    const base = baseVectors();
    base.negative.push({
      name: "stale-version",
      base: "basic",
      version: 2,
      verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "a", "stale"]),
      signature_hex: SIG,
      must_fail: true,
    });
    const result = analyze(
      snapshot(BASE_SRC, base),
      snapshot(BASE_SRC.replace("[1, 2]", "[1]"), baseVectors()),
      runtimeForm,
    );
    expect(result.vectors.removedNegatives[0].retiredBy).toEqual([]);
    expect(result.reasons.R2).toContain(
      "1 rejection vector(s) removed while their surface remains: thing.json › negative › stale-version",
    );
    expect(result.risk).toBe("R2");
  });

  it("R2: a suite only a negative used is not retired when that negative goes (Cursor Bugbot)", () => {
    const base = baseVectors();
    base.negative.push({
      name: "unknown-suite",
      base: "basic",
      verify_signed_bytes_hex: lp(["maruhi/v9/thing-sig-v1", "a", "b"]),
      signature_hex: SIG,
      must_fail: true,
    });
    const result = analyze(
      snapshot(BASE_SRC, base),
      snapshot(BASE_SRC, baseVectors()),
      runtimeForm,
    );
    expect(result.vectors.removedNegatives[0].retiredBy).toEqual([]);
    expect(result.reasons.R1).toEqual([]);
    expect(result.risk).toBe("R2");
  });

  it("R3: a domain only a base negative used is still new when src adopts it", () => {
    const base = baseVectors();
    base.negative[0].verify_signed_bytes_hex = lp(["maruhi/v1/other", "a", "b"]);
    const head = baseVectors();
    head.negative[0].verify_signed_bytes_hex = lp(["maruhi/v1/other", "a", "b"]);
    const src = BASE_SRC.replace(
      "return encodeLengthPrefixed",
      "void `${suite}/other`;\n  return encodeLengthPrefixed",
    );
    const result = analyze(snapshot(BASE_SRC, base), snapshot(src, head), runtimeForm);
    expect(result.domains.new).toEqual(["<suite>/other"]);
    expect(result.risk).toBe("R3");
  });

  it("R3: material shared only with a removed negative does not rebase a byte change", () => {
    const base = baseVectors();
    base.vectors[0].signature_hex = OLD_SIG; // shared with legacy-transplant only after legacy goes
    base.vectors.splice(1, 1);
    const head = structuredClone(base);
    head.negative.splice(1, 1);
    head.vectors[0].signature_hex = SIG;
    const result = analyze(snapshot(BASE_SRC, base), snapshot(BASE_SRC, head), runtimeForm);
    expect(result.vectors.unexplained.map((c) => c.id)).toEqual(["thing.json › vectors › basic"]);
    expect(result.risk).toBe("R3");
  });

  it("R1: negatives removed together with the layout they exercised", () => {
    // `legacy-v2-tampered` carries the retired v2 shape; `legacy-transplant`
    // has v1 bytes but replays the removed v2 positive's signature
    const base = baseVectors();
    base.negative.push({
      name: "legacy-v2-tampered",
      base: "legacy",
      verify_signed_bytes_hex: lp(["maruhi/v1/thing-sig-v2", "old", "x"]),
      signature_hex: OLD_SIG,
      must_fail: true,
    });
    const head = baseVectors();
    head.vectors.splice(1, 1);
    head.negative.splice(1, 1);
    const result = analyze(
      snapshot(BASE_SRC, base),
      snapshot(BASE_SRC.replace("[1, 2]", "[1]"), head),
      runtimeForm,
    );
    expect(result.risk).toBe("R1");
    expect(result.reasons.R1).toEqual([
      "narrowing: 3 vector entries removed, a supported set shrank",
    ]);
    const retired = Object.fromEntries(
      result.vectors.removedNegatives.map((n) => [n.id, n.retiredBy]),
    );
    expect(retired["thing.json › negative › legacy-v2-tampered"]).toEqual(
      expect.arrayContaining(["<suite>/thing-sig-v2 ×3", "<suite>/thing-sig-v2"]),
    );
    expect(retired["thing.json › negative › legacy-transplant"]).toEqual(["derived from legacy"]);
  });

  it("R3: a surviving vector's bytes changed with nothing removed to explain it", () => {
    const vectors = baseVectors();
    vectors.vectors[0].signed_bytes_hex = lp(["maruhi/v1/thing-sig-v1", "a", "c"]);
    const result = run(BASE_SRC, vectors);
    expect(result.risk).toBe("R3");
    expect(result.vectors.unexplained.map((c) => c.id)).toEqual(["thing.json › vectors › basic"]);
  });

  it("R3: a new signed-bytes shape and field order; negatives do not add shapes", () => {
    const vectors = baseVectors();
    vectors.vectors.push({
      name: "wide",
      signed_bytes_hex: lp(["maruhi/v1/thing-sig-v1", "a", "b", "c"]),
    });
    vectors.thing_signed_fields_order = ["domain", "a", "b", "c"];
    const result = run(BASE_SRC, vectors);
    expect(result.shapes.added).toEqual(["<suite>/thing-sig-v1 ×4"]);
    expect(result.fieldOrders.added).toHaveLength(1);
    expect(result.risk).toBe("R3");

    const malformed = baseVectors();
    malformed.negative[0].verify_signed_bytes_hex = lp(["maruhi/v1/thing-sig-v1", "a"]);
    expect(run(BASE_SRC, malformed).shapes.added).toEqual([]);
  });

  it("R3: a new primitive or a runtime dependency change", () => {
    const src = BASE_SRC.replace(
      "HPKE.KEM_DHKEM_X25519_HKDF_SHA256",
      "HPKE.KEM_DHKEM_P256_HKDF_SHA256",
    );
    expect(run(src, baseVectors()).primitives.added).toEqual(["hpke:KEM_DHKEM_P256_HKDF_SHA256"]);
    const deps = run(BASE_SRC, baseVectors(), {
      "package.json": JSON.stringify({ dependencies: { hpke: "1.2.0" } }),
    });
    expect(deps.runtimeDependencyChange).toBe(true);
    expect(deps.risk).toBe("R3");
  });
});
