import { describe, it, expect } from "vitest";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import {
  AIRClient,
  AgentNotFoundError,
  AuthenticationError,
  ValidationError,
  canonicalAttestationBytes,
  loadPrivateKeyFromSeed,
} from "../src/index.js";

type Handler = (url: string, init: RequestInit) => { status: number; body: unknown };

function stub(handler: Handler) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    const { status, body } = handler(url, init);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetchImpl, calls };
}

const reqBody = (init: RequestInit) => JSON.parse(init.body as string);
const reqHeaders = (init: RequestInit) => init.headers as Record<string, string>;
const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s: string): Uint8Array {
  let num = 0n;
  for (const ch of s) num = num * 58n + BigInt(b58.indexOf(ch));
  const out: number[] = [];
  while (num > 0n) {
    out.unshift(Number(num % 256n));
    num /= 256n;
  }
  return new Uint8Array(out);
}
const SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));

describe("AIRClient reads", () => {
  it("getHealth round-trips", async () => {
    const { fetchImpl } = stub(() => ({ status: 200, body: { status: "ok", version: "0.1.0", registry: "AIR" } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    expect((await air.getHealth()).status).toBe("ok");
  });

  it("listAgents sends limit/offset", async () => {
    const { fetchImpl, calls } = stub(() => ({ status: 200, body: { agents: [], total: 0, limit: 5, offset: 10 } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    await air.listAgents({ limit: 5, offset: 10 });
    expect(calls[0]!.url).toContain("limit=5");
    expect(calls[0]!.url).toContain("offset=10");
  });

  it("getAgent 404 throws AgentNotFoundError with airId", async () => {
    const { fetchImpl } = stub(() => ({ status: 404, body: { error: "Agent not found" } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    await expect(air.getAgent("AIR-NONE-NONE-NONE")).rejects.toMatchObject({
      airId: "AIR-NONE-NONE-NONE",
    });
    await expect(air.getAgent("AIR-NONE-NONE-NONE")).rejects.toBeInstanceOf(AgentNotFoundError);
  });

  it("parses verification_status on getAgent", async () => {
    const { fetchImpl } = stub(() => ({
      status: 200,
      body: {
        air_id: "AIR-X", name: "Bot", description: "", creator: {}, capabilities: [],
        security: { certifications: [] }, transparency: { open_source: false },
        verified: true, verification_level: "attested",
        verification_status: { verified: true, score: 420, score_required: 300, attestation_count: 3, distinct_whois_roots: 3, distinct_whois_roots_required: 3 },
        is_demo: false, status: "active", created: "2026-05-29T00:00:00Z", updated: "2026-05-29T00:00:00Z",
      },
    }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    const agent = await air.getAgent("AIR-X");
    expect(agent.verification_status?.score).toBe(420);
  });

  it("maps 429 to RateLimitedError with retryAfterSeconds", async () => {
    const { fetchImpl } = stub(() => ({ status: 429, body: { error: "Rate limit exceeded", retry_after_seconds: 3600 } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    await expect(air.registerAgent({ name: "X", publicKey: "A".repeat(43) })).rejects.toMatchObject({
      retryAfterSeconds: 3600,
    });
  });
});

describe("AIRClient writes", () => {
  it("registerAgent omits creator_did when not given", async () => {
    const { fetchImpl, calls } = stub(() => ({
      status: 201,
      body: { air_id: "AIR-1", name: "B", creator_did: "did:wba:x", status: "active", verification_level: "self", trust_score: 540, trust_grade: "BB", created: "2026-05-29T00:00:00Z", agent_secret: "x", agent_secret_note: "store", message: "ok" },
    }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    await air.registerAgent({ name: "B", publicKey: "A".repeat(43), capabilities: ["x"] });
    const body = reqBody(calls[0]!.init);
    expect(body.creator_did).toBeUndefined();
    expect(body.public_key).toBe("A".repeat(43));
  });

  it("updateAgent with no fields throws before any request", async () => {
    const { fetchImpl, calls } = stub(() => ({ status: 200, body: {} }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    expect(() => air.updateAgent("AIR-X", { agentSecret: "s" })).toThrow(ValidationError);
    expect(calls.length).toBe(0);
  });

  it("admin call without adminKey throws AuthenticationError", async () => {
    const { fetchImpl } = stub(() => ({ status: 200, body: {} }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    expect(() => air.getAdminStats()).toThrow(AuthenticationError);
  });
});

describe("AIRClient attestations", () => {
  const ok201 = { status: 201, body: { attestation_id: 1, subject_air_id: "AIR-SUBJ", attester_air_id: "AIR-ME", attestation_type: "dependency", statement: "", signed_at: "2026-05-29T00:00:00Z", attester_whois_root: "x.com", attester_trust_at_issue: 600, tenure_multiplier_at_issue: 1.0, weight: 600.0, verified_status: { verified: false, verification_score: 120, distinct_whois_roots: 1, attestation_count: 1 } } };

  it("createAttestation sends body + attester secret header", async () => {
    const { fetchImpl, calls } = stub(() => ok201);
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    const r = await air.createAttestation("AIR-SUBJ", {
      attesterAirId: "AIR-ME", attestationType: "identity_verification",
      signedAt: "2026-05-29T00:00:00Z", signatureMultibase: "zSIG", agentSecret: "sek", statement: "ok",
    });
    expect(reqHeaders(calls[0]!.init)["X-Agent-Secret"]).toBe("sek");
    expect(reqBody(calls[0]!.init).signature_multibase).toBe("zSIG");
    expect(r.attestation_id).toBe(1);
  });

  it("attest signs the canonical bytes it sends and defaults signedAt to ...Z", async () => {
    const { fetchImpl, calls } = stub(() => ok201);
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    const key = loadPrivateKeyFromSeed(SEED);
    await air.attest("AIR-SUBJ", {
      attesterAirId: "AIR-ME", attestationType: "dependency", privateKey: key, agentSecret: "s",
    });
    const body = reqBody(calls[0]!.init);
    expect(body.signed_at).toMatch(/Z$/);
    expect(body.signature_multibase.startsWith("z")).toBe(true);
    const sig = b58decode(body.signature_multibase.slice(1));
    const canonical = canonicalAttestationBytes({
      attesterAirId: "AIR-ME", attestationType: "dependency", signedAt: body.signed_at,
      subjectAirId: "AIR-SUBJ", statement: "",
    });
    expect(nodeVerify(null, canonical, createPublicKey(key), sig)).toBe(true);
  });

  it("revokeAttestation issues DELETE with the attester secret", async () => {
    const { fetchImpl, calls } = stub(() => ({ status: 200, body: { revoked: true, attestation_id: 7, subject_air_id: "AIR-SUBJ", revoked_at: "2026-05-29T01:00:00Z", verified_status: { verified: false, verification_score: 0, distinct_whois_roots: 0, attestation_count: 0 } } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    const r = await air.revokeAttestation("AIR-SUBJ", 7, { agentSecret: "sek" });
    expect(calls[0]!.init.method).toBe("DELETE");
    expect(calls[0]!.url).toContain("/agents/AIR-SUBJ/attestations/7");
    expect(reqHeaders(calls[0]!.init)["X-Agent-Secret"]).toBe("sek");
    expect(r.revoked).toBe(true);
  });

  it("recentAttestations sends limit", async () => {
    const { fetchImpl, calls } = stub(() => ({ status: 200, body: { attestations: [], total: 0, limit: 200 } }));
    const air = new AIRClient({ baseUrl: "https://test.invalid", fetch: fetchImpl });
    await air.recentAttestations({ limit: 200 });
    expect(calls[0]!.url).toContain("limit=200");
  });
});
