/**
 * Ed25519 attestation signing — the client side of AIR Verified (Phase 4).
 *
 * The attester signs a canonical payload; the registry Worker re-derives the
 * exact same bytes and verifies the signature (Lock 1). The canonical form must
 * byte-match the Worker's `jcsCanonicalize` in api/src/index.js — and since the
 * Worker is JS using `JSON.stringify`, this SDK using `JSON.stringify` over the
 * same sorted keys is byte-identical by construction.
 *
 * Contract:
 *   1. Object {attester_air_id, attestation_type, signed_at, statement,
 *      subject_air_id} — statement ALWAYS present ("" if absent).
 *   2. Sort keys, no whitespace, JSON-escape each string. No NFC normalization.
 *   3. Ed25519-sign the UTF-8 bytes → 64-byte signature (node:crypto, zero deps).
 *   4. multibase-encode: "z" + base58btc(signature).
 */

import { createPrivateKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";

/** Bitcoin/IPFS base58 alphabet — identical to BASE58_ALPHABET in the Worker. */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** PKCS#8 DER prefix for a raw 32-byte Ed25519 private seed. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** The four lockable attestation types (must match the Worker's set). */
export const VALID_ATTESTATION_TYPES = [
  "identity_verification",
  "operator_confirmation",
  "dependency",
  "safety_review",
] as const;

export type AttestationType = (typeof VALID_ATTESTATION_TYPES)[number];

export interface AttestationPayload {
  attesterAirId: string;
  attestationType: string;
  signedAt: string;
  subjectAirId: string;
  /** Optional free-form note; defaults to "" and is always part of the signed payload. */
  statement?: string;
}

/** Encode raw bytes as base58btc (no multibase prefix). Mirrors the Worker. */
export function base58btcEncode(data: Uint8Array): string {
  if (data.length === 0) return "";
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < data.length; i++) {
    let carry = data[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "1".repeat(zeros);
  for (let k = digits.length - 1; k >= 0; k--) out += BASE58_ALPHABET[digits[k] as number];
  return out;
}

/**
 * Produce the exact JCS-canonical bytes the attester must sign — byte-identical
 * to the Worker's jcsCanonicalize({...}): keys sorted, no whitespace, every
 * value JSON-escaped, `statement` always present.
 */
export function canonicalAttestationBytes(p: AttestationPayload): Uint8Array {
  const obj: Record<string, string> = {
    attester_air_id: p.attesterAirId,
    attestation_type: p.attestationType,
    signed_at: p.signedAt,
    statement: p.statement ?? "",
    subject_air_id: p.subjectAirId,
  };
  const json =
    "{" +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + JSON.stringify(obj[k]))
      .join(",") +
    "}";
  return new TextEncoder().encode(json);
}

/**
 * Sign an attestation payload and return the `signatureMultibase` string
 * ("z" + base58btc of the 64-byte Ed25519 signature) — the exact format the
 * Worker's verifyEd25519Signature() expects.
 */
export function signAttestation(privateKey: KeyObject, p: AttestationPayload): string {
  if (!(VALID_ATTESTATION_TYPES as readonly string[]).includes(p.attestationType)) {
    throw new Error(
      `invalid attestationType "${p.attestationType}"; must be one of: ${VALID_ATTESTATION_TYPES.join(", ")}`,
    );
  }
  // Ed25519 signs the message directly — the algorithm argument MUST be null.
  const signature = nodeSign(null, canonicalAttestationBytes(p), privateKey);
  return "z" + base58btcEncode(new Uint8Array(signature));
}

/**
 * Load an Ed25519 private key from a 32-byte seed (raw bytes or hex string).
 * Wraps the seed in the fixed PKCS#8 DER prefix so node:crypto accepts it.
 */
export function loadPrivateKeyFromSeed(seed: Uint8Array | string): KeyObject {
  const bytes = typeof seed === "string" ? Buffer.from(seed, "hex") : Buffer.from(seed);
  if (bytes.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${bytes.length}`);
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, bytes]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}
