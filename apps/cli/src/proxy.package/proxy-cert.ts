// The ephemeral certificate authority of `maruhi proxy run` (PF4 —
// pf4-design.md ruling P3).
//
// The proxy terminates TLS for the hosts it brokers (a CONNECT to such a
// host is answered with a certificate for that host), so the child
// process must trust a CA. That CA is created **per run, in memory**: a
// fresh ECDSA P-256 key pair, a self-signed root, and one leaf per
// brokered host, signed on demand. The CA's **private key never touches
// disk** and dies with the process; only the CA **certificate** (public)
// is written to a private temp file so the child's TLS libraries can read
// it (`SSL_CERT_FILE` and friends — proxy-run.ts). Nothing here is a
// maruhi protocol object: the certificates protect the loopback hop
// between the child and the proxy, not stored data (CRYPTO_SPEC is
// untouched — the ruling is recorded in pf4-design.md).
//
// Primitives are WebCrypto only (ECDSA P-256 / SHA-256 — CLAUDE.md). What
// this module adds is **encoding**: a minimal DER writer for the X.509 v3
// structures a TLS client needs (RFC 5280 — version, serial, issuer /
// subject CN, validity, SPKI, basicConstraints, keyUsage, extKeyUsage,
// subjectAltName, subject / authority key identifiers) and the IEEE
// P1363 → DER conversion of the ECDSA signature. No parsing, no other
// algorithm, no certificate ever read back by maruhi.
//
// Runs under Node (vitest) and Bun alike. The DER primitives are der.ts.

import {
  bitString,
  boolTrue,
  explicit,
  octetString,
  oid,
  pem,
  seq,
  set,
  smallInteger,
  tlv,
  unsignedInteger,
  utf8String,
} from "../der.ts";

const encoder = new TextEncoder();

const OID = {
  commonName: "2.5.4.3",
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectAltName: "2.5.29.17",
  subjectKeyIdentifier: "2.5.29.14",
  authorityKeyIdentifier: "2.5.29.35",
  serverAuth: "1.3.6.1.5.5.7.3.1",
} as const;

/** `YYMMDDHHMMSSZ` (UTCTime — years 1950..2049; the certificates live days). */
const two = (n: number) => String(n).padStart(2, "0");

function utcTime(date: Date): Uint8Array {
  const text =
    two(date.getUTCFullYear() % 100) +
    two(date.getUTCMonth() + 1) +
    two(date.getUTCDate()) +
    two(date.getUTCHours()) +
    two(date.getUTCMinutes()) +
    two(date.getUTCSeconds()) +
    "Z";
  return tlv(0x17, encoder.encode(text));
}

/** `CN=<name>`. */
function nameOf(commonName: string): Uint8Array {
  return seq(set(seq(oid(OID.commonName), utf8String(commonName))));
}

/** One extension (critical when asked). */
function extension(id: string, critical: boolean, value: Uint8Array): Uint8Array {
  return critical ? seq(oid(id), boolTrue(), octetString(value)) : seq(oid(id), octetString(value));
}

/** KeyUsage BIT STRING with the given bit positions set (RFC 5280 §4.2.1.3 numbering). */
function keyUsage(bits: readonly number[]): Uint8Array {
  let byte = 0;
  for (const bit of bits) {
    byte |= 0x80 >>> bit;
  }
  const highest = Math.max(...bits);
  const unused = 7 - highest;
  return tlv(0x03, new Uint8Array([unused, byte]));
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** A SubjectAltName GeneralName: an IPv4 literal is an iPAddress, anything else a dNSName. */
function generalName(host: string): Uint8Array {
  const v4 = IPV4.exec(host);
  if (v4 !== null) {
    const bytes = v4.slice(1, 5).map(Number);
    if (bytes.every((b) => b <= 255)) {
      return tlv(0x87, new Uint8Array(bytes));
    }
  }
  if (host === "::1") {
    return tlv(0x87, new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
  }
  // [2] dNSName (IA5String content — ASCII only; a non-ASCII host is
  // refused upstream by the rule parser). The context tag carries its own
  // length (review finding §19 C-10: slicing a 2-byte IA5String length
  // broke hosts of 128+ characters)
  return tlv(0x82, encoder.encode(host));
}

/* -------------------------------------------------------------------------- */
/* Keys and signatures                                                          */
/* -------------------------------------------------------------------------- */

const ECDSA_P256: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_PARAMS: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

/** WebCrypto's raw `r || s` (64 bytes) → the DER `SEQUENCE { INTEGER r, INTEGER s }` TLS expects. */
function ecdsaSignatureToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  return seq(unsignedInteger(raw.subarray(0, half)), unsignedInteger(raw.subarray(half)));
}

/** A positive random serial (RFC 5280: ≤ 20 octets, non-negative). */
function randomSerial(): Uint8Array {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0] = ((bytes[0] ?? 0) & 0x7f) | 0x01;
  return bytes;
}

/** A key identifier derived from the SPKI (any unique octet string is allowed; SHA-256 truncated to 20 bytes). */
async function keyIdentifier(spki: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  return digest.subarray(0, 20);
}

interface Signer {
  readonly privateKey: CryptoKey;
  readonly spki: Uint8Array<ArrayBuffer>;
  readonly keyId: Uint8Array;
  readonly subject: string;
}

/** `extractable` only for a leaf, whose key must be exported (PKCS#8) for node:tls; the CA key never leaves WebCrypto. */
async function generateSigner(subject: string, extractable: boolean): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(ECDSA_P256, extractable, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { privateKey: pair.privateKey, spki, keyId: await keyIdentifier(spki), subject };
}

/** Signs a TBSCertificate with the issuer's key and assembles the Certificate. */
async function assembleCertificate(
  tbs: Uint8Array<ArrayBuffer>,
  issuer: Signer,
): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, issuer.privateKey, tbs));
  return seq(tbs, seq(oid(OID.ecdsaWithSha256)), bitString(ecdsaSignatureToDer(raw)));
}

/** How long a run's certificates stay valid (a session rarely lasts this long; the key dies with the process anyway). */
const VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;
/** Back-dated notBefore (clock skew between the proxy and a container's clock). */
const BACKDATE_MS = 5 * 60 * 1000;

function validity(now: number): Uint8Array {
  return seq(utcTime(new Date(now - BACKDATE_MS)), utcTime(new Date(now + VALIDITY_MS)));
}

function tbsCertificate(input: {
  readonly subject: Signer;
  readonly issuer: Signer;
  readonly now: number;
  readonly extensions: readonly Uint8Array[];
}): Uint8Array<ArrayBuffer> {
  return seq(
    explicit(0, smallInteger(2)),
    unsignedInteger(randomSerial()),
    seq(oid(OID.ecdsaWithSha256)),
    nameOf(input.issuer.subject),
    validity(input.now),
    nameOf(input.subject.subject),
    input.subject.spki,
    explicit(3, seq(...input.extensions)),
  );
}

/* -------------------------------------------------------------------------- */
/* The CA                                                                       */
/* -------------------------------------------------------------------------- */

/** A leaf certificate for one host, with its private key (PEM — in memory only). */
export interface LeafCertificate {
  readonly keyPem: string;
  readonly certPem: string;
}

/** The run's certificate authority. */
export interface EphemeralCa {
  /** The CA certificate (public — the one thing the child must trust). */
  readonly certPem: string;
  /** A certificate for `host` signed by this CA (cached per host). */
  readonly issue: (host: string) => Promise<LeafCertificate>;
}

/** The subject the child sees when it inspects the certificate chain. */
const CA_SUBJECT = "maruhi ephemeral CA (one proxy run only)";

/**
 * Creates the run's CA: a fresh P-256 key pair and a self-signed root
 * (basicConstraints CA, keyUsage keyCertSign + cRLSign). Leaves are issued
 * on demand (`issue`) with serverAuth, digitalSignature, and a
 * subjectAltName for the host. The CA private key lives only in this
 * closure.
 */
export async function makeEphemeralCa(now: number = Date.now()): Promise<EphemeralCa> {
  const ca = await generateSigner(CA_SUBJECT, false);
  const caTbs = tbsCertificate({
    subject: ca,
    issuer: ca,
    now,
    extensions: [
      extension(OID.basicConstraints, true, seq(boolTrue())),
      // keyCertSign (5), cRLSign (6)
      extension(OID.keyUsage, true, keyUsage([5, 6])),
      extension(OID.subjectKeyIdentifier, false, octetString(ca.keyId)),
    ],
  });
  const caDer = await assembleCertificate(caTbs, ca);
  const certPem = pem("CERTIFICATE", caDer);
  const leaves = new Map<string, Promise<LeafCertificate>>();

  const issueLeaf = async (host: string): Promise<LeafCertificate> => {
    const leaf = await generateSigner(host, true);
    const tbs = tbsCertificate({
      subject: leaf,
      issuer: ca,
      now: Date.now(),
      extensions: [
        extension(OID.basicConstraints, true, seq()),
        // digitalSignature (0)
        extension(OID.keyUsage, true, keyUsage([0])),
        extension(OID.extKeyUsage, false, seq(oid(OID.serverAuth))),
        extension(OID.subjectAltName, false, seq(generalName(host))),
        extension(OID.subjectKeyIdentifier, false, octetString(leaf.keyId)),
        // AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier }
        extension(OID.authorityKeyIdentifier, false, seq(tlv(0x80, ca.keyId))),
      ],
    });
    const der = await assembleCertificate(tbs, ca);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", leaf.privateKey));
    return { keyPem: pem("PRIVATE KEY", pkcs8), certPem: pem("CERTIFICATE", der) };
  };

  return {
    certPem,
    issue: (host) => {
      let pending = leaves.get(host);
      if (pending === undefined) {
        pending = issueLeaf(host);
        leaves.set(host, pending);
        // A failed issuance is not remembered: the next CONNECT to the host
        // tries again (a rejected promise in the cache would keep the host
        // unreachable for the rest of the run — review finding §21 R-5)
        pending.catch(() => leaves.delete(host));
      }
      return pending;
    },
  };
}
