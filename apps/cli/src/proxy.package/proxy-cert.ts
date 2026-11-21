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

function nameOf(commonName: string): Uint8Array {
  return seq(set(seq(oid(OID.commonName), utf8String(commonName))));
}

function extension(id: string, critical: boolean, value: Uint8Array): Uint8Array {
  return critical ? seq(oid(id), boolTrue(), octetString(value)) : seq(oid(id), octetString(value));
}

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
  return tlv(0x82, encoder.encode(host));
}

const ECDSA_P256: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_PARAMS: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

function ecdsaSignatureToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  return seq(unsignedInteger(raw.subarray(0, half)), unsignedInteger(raw.subarray(half)));
}

function randomSerial(): Uint8Array {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0] = ((bytes[0] ?? 0) & 0x7f) | 0x01;
  return bytes;
}

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

async function generateSigner(subject: string, extractable: boolean): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(ECDSA_P256, extractable, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { privateKey: pair.privateKey, spki, keyId: await keyIdentifier(spki), subject };
}

async function assembleCertificate(
  tbs: Uint8Array<ArrayBuffer>,
  issuer: Signer,
): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, issuer.privateKey, tbs));
  return seq(tbs, seq(oid(OID.ecdsaWithSha256)), bitString(ecdsaSignatureToDer(raw)));
}

const VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;
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

export interface LeafCertificate {
  readonly keyPem: string;
  readonly certPem: string;
}

export interface EphemeralCa {
  readonly certPem: string;
  readonly issue: (host: string) => Promise<LeafCertificate>;
}

const CA_SUBJECT = "maruhi ephemeral CA (one proxy run only)";

export async function makeEphemeralCa(now: () => number): Promise<EphemeralCa> {
  const ca = await generateSigner(CA_SUBJECT, false);
  const caTbs = tbsCertificate({
    subject: ca,
    issuer: ca,
    now: now(),
    extensions: [
      extension(OID.basicConstraints, true, seq(boolTrue())),
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
      now: now(),
      extensions: [
        extension(OID.basicConstraints, true, seq()),
        extension(OID.keyUsage, true, keyUsage([0])),
        extension(OID.extKeyUsage, false, seq(oid(OID.serverAuth))),
        extension(OID.subjectAltName, false, seq(generalName(host))),
        extension(OID.subjectKeyIdentifier, false, octetString(leaf.keyId)),
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
        pending.catch(() => leaves.delete(host));
      }
      return pending;
    },
  };
}
