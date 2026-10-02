// Tests for the SigV4 signer (sigv4.ts — PF6): pinned to the worked example
// of AWS's "Create a signed AWS API request" (IAM ListUsers, the example
// credentials AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
// 2015-08-30T12:36:00Z): the canonical request hash, the derived signing
// key, and the signature are the documented values.

import { describe, expect, it } from "vitest";

import { amzDate, signingKey, signV4 } from "../src/sigv4.ts";

const SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const NOW = Date.parse("2015-08-30T12:36:00Z");

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("SigV4", () => {
  it("formats the x-amz-date pair", () => {
    expect(amzDate(NOW)).toEqual({ dateTime: "20150830T123600Z", date: "20150830" });
  });

  it("derives the documented signing key", async () => {
    const key = await signingKey(SECRET, "20150830", "us-east-1", "iam");
    expect(hex(key)).toBe("c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
  });

  it("signs the documented IAM ListUsers request", async () => {
    const out = await signV4({
      method: "GET",
      url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
      region: "us-east-1",
      service: "iam",
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: "",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: SECRET },
      nowMs: NOW,
    });
    expect(out.canonicalRequest).toBe(
      [
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        "content-type:application/x-www-form-urlencoded; charset=utf-8",
        "host:iam.amazonaws.com",
        "x-amz-date:20150830T123600Z",
        "",
        "content-type;host;x-amz-date",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ].join("\n"),
    );
    expect(out.stringToSign).toBe(
      [
        "AWS4-HMAC-SHA256",
        "20150830T123600Z",
        "20150830/us-east-1/iam/aws4_request",
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
      ].join("\n"),
    );
    expect(out.signature).toBe("5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    expect(out.headers["authorization"]).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
  });

  it("signs the session token as a header and the body's hash for a POST", async () => {
    const out = await signV4({
      method: "POST",
      url: "https://iam.amazonaws.com/",
      region: "us-east-1",
      service: "iam",
      headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: "Action=CreateAccessKey&UserName=app&Version=2010-05-08",
      credentials: { accessKeyId: "ASIAEXAMPLE", secretAccessKey: SECRET, sessionToken: "tok" },
      nowMs: NOW,
    });
    expect(out.headers["x-amz-security-token"]).toBe("tok");
    expect(out.canonicalRequest).toContain("content-type;host;x-amz-date;x-amz-security-token");
    expect(out.canonicalRequest.split("\n")[2]).toBe("");
    expect(out.canonicalRequest).not.toContain(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
