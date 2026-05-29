import { describe, it, expect } from "vitest";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import {
  base58btcEncode,
  canonicalAttestationBytes,
  loadPrivateKeyFromSeed,
  signAttestation,
} from "../src/signing.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s: string): Uint8Array {
  let num = 0n;
  for (const ch of s) num = num * 58n + BigInt(B58.indexOf(ch));
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

const SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i)); // 0..31, matches Python test

describe("canonicalAttestationBytes", () => {
  it("is byte-exact and matches the Python/Worker contract", () => {
    const got = Buffer.from(
      canonicalAttestationBytes({
        attesterAirId: "AIR-ATT1-ATT1-ATT1",
        attestationType: "identity_verification",
        signedAt: "2026-05-29T00:00:00Z",
        subjectAirId: "AIR-SUB1-SUB1-SUB1",
        statement: "I verify this agent",
      }),
    ).toString("utf-8");
    expect(got).toBe(
      '{"attestation_type":"identity_verification",' +
        '"attester_air_id":"AIR-ATT1-ATT1-ATT1",' +
        '"signed_at":"2026-05-29T00:00:00Z",' +
        '"statement":"I verify this agent",' +
        '"subject_air_id":"AIR-SUB1-SUB1-SUB1"}',
    );
  });

  it("always includes statement, even when omitted", () => {
    const got = Buffer.from(
      canonicalAttestationBytes({
        attesterAirId: "AIR-A",
        attestationType: "dependency",
        signedAt: "2026-05-29T00:00:00Z",
        subjectAirId: "AIR-B",
      }),
    ).toString("utf-8");
    expect(got).toContain('"statement":""');
  });
});

describe("base58btcEncode", () => {
  it("maps leading zero bytes to leading 1s", () => {
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe("112");
    expect(base58btcEncode(new Uint8Array([]))).toBe("");
  });
});

describe("signAttestation", () => {
  it("round-trips through node:crypto Ed25519 verify", () => {
    const key = loadPrivateKeyFromSeed(SEED);
    const payload = {
      attesterAirId: "AIR-ATT1-ATT1-ATT1",
      attestationType: "operator_confirmation",
      signedAt: "2026-05-29T12:00:00Z",
      subjectAirId: "AIR-SUB1-SUB1-SUB1",
      statement: "ships in prod",
    };
    const sigMb = signAttestation(key, payload);
    expect(sigMb.startsWith("z")).toBe(true);

    const sig = b58decode(sigMb.slice(1));
    expect(sig.length).toBe(64);

    const pub = createPublicKey(key);
    expect(nodeVerify(null, canonicalAttestationBytes(payload), pub, sig)).toBe(true);
  });

  it("rejects an invalid attestation type", () => {
    const key = loadPrivateKeyFromSeed(SEED);
    expect(() =>
      signAttestation(key, {
        attesterAirId: "AIR-A",
        attestationType: "not_real",
        signedAt: "2026-05-29T00:00:00Z",
        subjectAirId: "AIR-B",
      }),
    ).toThrow(/invalid attestationType/);
  });
});

describe("loadPrivateKeyFromSeed", () => {
  it("accepts hex and raw bytes equivalently", () => {
    const seedHex = Buffer.from(SEED).toString("hex");
    const a = createPublicKey(loadPrivateKeyFromSeed(SEED)).export({ format: "der", type: "spki" });
    const b = createPublicKey(loadPrivateKeyFromSeed(seedHex)).export({ format: "der", type: "spki" });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("rejects a wrong-length seed", () => {
    expect(() => loadPrivateKeyFromSeed(new Uint8Array(8))).toThrow(/32 bytes/);
  });
});
