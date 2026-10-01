// Tests for the ephemeral CA (proxy-cert.ts — PF4 ruling P3): the
// hand-encoded X.509 structures are accepted by an independent parser
// (node:crypto's X509Certificate), the chain verifies, the leaf matches
// its host, and a real TLS handshake (node:tls server + client trusting
// only the CA) succeeds.

import { X509Certificate } from "node:crypto";
import type { AddressInfo } from "node:net";
import tls from "node:tls";

import { describe, expect, it } from "vitest";

import { makeEphemeralCa } from "../src/proxy-cert.ts";

describe("makeEphemeralCa", () => {
  it("produces a self-signed CA and host leaves an independent parser accepts and verifies", async () => {
    const ca = await makeEphemeralCa();
    const caCert = new X509Certificate(ca.certPem);
    expect(caCert.ca).toBe(true);
    expect(caCert.subject).toContain("CN=maruhi ephemeral CA");
    expect(caCert.verify(caCert.publicKey)).toBe(true);

    const leaf = await ca.issue("api.github.com");
    const leafCert = new X509Certificate(leaf.certPem);
    expect(leafCert.ca).toBe(false);
    expect(leafCert.checkIssued(caCert)).toBe(true);
    expect(leafCert.verify(caCert.publicKey)).toBe(true);
    expect(leafCert.checkHost("api.github.com")).toBe("api.github.com");
    expect(leafCert.checkHost("github.com")).toBeUndefined();
    expect(leafCert.subjectAltName).toBe("DNS:api.github.com");
    expect(leafCert.keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    // Validity brackets now
    expect(new Date(leafCert.validFrom).getTime()).toBeLessThan(Date.now());
    expect(new Date(leafCert.validTo).getTime()).toBeGreaterThan(Date.now());

    // The leaf key is a usable PKCS#8 EC key
    expect(leaf.keyPem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
    // Issuance is cached per host
    expect(await ca.issue("api.github.com")).toBe(leaf);
    expect((await ca.issue("other.example")).certPem).not.toBe(leaf.certPem);
  });

  it("encodes an IPv4 literal as an iPAddress name", async () => {
    const ca = await makeEphemeralCa();
    const leaf = new X509Certificate((await ca.issue("127.0.0.1")).certPem);
    expect(leaf.subjectAltName).toBe("IP Address:127.0.0.1");
    expect(leaf.checkIP("127.0.0.1")).toBe("127.0.0.1");
  });

  it("completes a real TLS handshake with a client that trusts only the CA", async () => {
    const ca = await makeEphemeralCa();
    const leaf = await ca.issue("api.example.test");
    const server = tls.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (socket) => {
      socket.end("hello");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as AddressInfo).port;
    try {
      const received = await new Promise<string>((resolve, reject) => {
        const client = tls.connect(
          { host: "127.0.0.1", port, servername: "api.example.test", ca: [ca.certPem] },
          () => {
            expect(client.authorized).toBe(true);
          },
        );
        let data = "";
        client.on("data", (chunk: Buffer) => {
          data += chunk.toString();
        });
        client.on("end", () => resolve(data));
        client.on("error", reject);
      });
      expect(received).toBe("hello");
      // A client trusting only the CA refuses a different CA's leaf
      const other = await makeEphemeralCa();
      await expect(
        new Promise<void>((resolve, reject) => {
          const client = tls.connect(
            { host: "127.0.0.1", port, servername: "api.example.test", ca: [other.certPem] },
            () => resolve(),
          );
          client.on("error", reject);
        }),
      ).rejects.toThrow(/self[- ]signed|unable to verify|certificate/i);
    } finally {
      server.close();
    }
  });
});
