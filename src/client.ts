/**
 * AIRClient — TypeScript client for the Agent Identity Registry HTTP API.
 *
 * Zero runtime dependencies: uses global `fetch` and (for signing) node:crypto.
 * Mirrors the Python SDK's surface and behavior. Method arguments are camelCase
 * options objects; responses keep the API's snake_case wire shape (see models.ts).
 *
 *     const air = new AIRClient();
 *     const agent = await air.getAgent("AIR-XXXX-XXXX-XXXX");
 */

import type { KeyObject } from "node:crypto";
import {
  AuthenticationError,
  NetworkError,
  ValidationError,
  raiseForStatus,
  type ErrorEnvelope,
} from "./errors.js";
import { signAttestation } from "./signing.js";
import type {
  AdminRecent,
  AdminStats,
  Agent,
  AgentList,
  AttestationList,
  AttestationResult,
  DeleteResult,
  DidDocument,
  Health,
  NameCheck,
  RecentAttestations,
  RegistrationResult,
  RevokeResult,
  TrustScore,
  UpdateResult,
} from "./models.js";

const DEFAULT_BASE_URL = "https://agentidentityregistry.org";
const API_PREFIX = "/api/v1";

/** Minimal structural type for the fetch implementation (lets tests inject a stub). */
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface AIRClientOptions {
  baseUrl?: string;
  /** Required for deleteAgent / getAdminStats / getAdminRecent. */
  adminKey?: string;
  /** Per-request timeout in milliseconds (default 30000). */
  timeoutMs?: number;
  /** Inject a custom fetch (e.g. a stub in tests). Defaults to global fetch. */
  fetch?: FetchLike;
}

interface RequestOptions {
  params?: Record<string, string | number | undefined>;
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
  airId?: string;
}

export class AIRClient {
  private readonly baseUrl: string;
  private readonly adminKey: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;

  constructor(opts: AIRClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.adminKey = opts.adminKey;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) throw new Error("No fetch available — pass `fetch` in options (Node <18).");
    this.fetchImpl = f;
  }

  private async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    let url = this.baseUrl + API_PREFIX + path;
    if (opts.params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.params)) {
        if (v !== undefined) qs.set(k, String(v));
      }
      const s = qs.toString();
      if (s) url += `?${s}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: {
          accept: "application/json",
          ...(opts.body ? { "content-type": "application/json" } : {}),
          ...opts.headers,
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (e) {
      throw new NetworkError(`Request failed: ${(e as Error).message}`, { statusCode: null });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { error: `Non-JSON response: ${text.slice(0, 200)}` };
      }
    }

    if (response.status >= 400) {
      raiseForStatus(response.status, (parsed as ErrorEnvelope) ?? null, opts.airId ?? null);
    }
    return (parsed ?? {}) as T;
  }

  private adminHeader(): Record<string, string> {
    if (!this.adminKey) {
      throw new AuthenticationError("Admin endpoints require an adminKey. Pass it to new AIRClient({ adminKey }).");
    }
    return { "X-Admin-Key": this.adminKey };
  }

  // ---- Public reads -------------------------------------------------------

  getHealth(): Promise<Health> {
    return this.request<Health>("GET", "/health");
  }

  listAgents(opts: { limit?: number; offset?: number } = {}): Promise<AgentList> {
    return this.request<AgentList>("GET", "/agents", {
      params: { limit: opts.limit ?? 20, offset: opts.offset ?? 0 },
    });
  }

  getAgent(airId: string): Promise<Agent> {
    return this.request<Agent>("GET", `/agents/${airId}`, { airId });
  }

  getTrustScore(airId: string): Promise<TrustScore> {
    return this.request<TrustScore>("GET", `/agents/${airId}/trust-score`, { airId });
  }

  getDidDocument(airId: string): Promise<DidDocument> {
    return this.request<DidDocument>("GET", `/agents/${airId}/did-document`, { airId });
  }

  checkName(name: string): Promise<NameCheck> {
    return this.request<NameCheck>("GET", "/agents/check-name", { params: { name } });
  }

  // ---- Writes -------------------------------------------------------------

  registerAgent(opts: {
    name: string;
    description?: string;
    creatorDid?: string;
    publicKey?: string;
    creatorName?: string;
    creatorType?: string;
    capabilities?: string[];
    securityCertifications?: string[];
    openSource?: boolean;
    codeRepository?: string;
    documentationUrl?: string;
  }): Promise<RegistrationResult> {
    const body: Record<string, unknown> = {
      name: opts.name,
      description: opts.description ?? "",
      creator_name: opts.creatorName ?? "",
      creator_type: opts.creatorType ?? "individual",
      open_source: opts.openSource ?? false,
      code_repository: opts.codeRepository ?? "",
      documentation_url: opts.documentationUrl ?? "",
    };
    if (opts.creatorDid !== undefined) body.creator_did = opts.creatorDid;
    if (opts.publicKey !== undefined) body.public_key = opts.publicKey;
    if (opts.capabilities !== undefined) body.capabilities = opts.capabilities;
    if (opts.securityCertifications !== undefined) body.security_certifications = opts.securityCertifications;
    return this.request<RegistrationResult>("POST", "/agents/register", { body });
  }

  updateAgent(
    airId: string,
    opts: {
      agentSecret: string;
      description?: string;
      capabilities?: string[];
      securityCertifications?: string[];
      openSource?: boolean;
      codeRepository?: string;
      documentationUrl?: string;
    },
  ): Promise<UpdateResult> {
    const body: Record<string, unknown> = {};
    if (opts.description !== undefined) body.description = opts.description;
    if (opts.capabilities !== undefined) body.capabilities = opts.capabilities;
    if (opts.securityCertifications !== undefined) body.security_certifications = opts.securityCertifications;
    if (opts.openSource !== undefined) body.open_source = opts.openSource;
    if (opts.codeRepository !== undefined) body.code_repository = opts.codeRepository;
    if (opts.documentationUrl !== undefined) body.documentation_url = opts.documentationUrl;
    if (Object.keys(body).length === 0) {
      // Mirror the server's 400 client-side — no wasted round-trip.
      throw new ValidationError("updateAgent() requires at least one field to change.");
    }
    return this.request<UpdateResult>("PUT", `/agents/${airId}`, {
      body,
      headers: { "X-Agent-Secret": opts.agentSecret },
      airId,
    });
  }

  // ---- Attestations (AIR Verified) ---------------------------------------

  createAttestation(
    subjectAirId: string,
    opts: {
      attesterAirId: string;
      attestationType: string;
      signedAt: string;
      signatureMultibase: string;
      agentSecret: string;
      statement?: string;
    },
  ): Promise<AttestationResult> {
    return this.request<AttestationResult>("POST", `/agents/${subjectAirId}/attestations`, {
      body: {
        attester_air_id: opts.attesterAirId,
        attestation_type: opts.attestationType,
        signed_at: opts.signedAt,
        signature_multibase: opts.signatureMultibase,
        statement: opts.statement ?? "",
      },
      headers: { "X-Agent-Secret": opts.agentSecret },
      airId: subjectAirId,
    });
  }

  /** Sign and submit an attestation in one call. `signedAt` defaults to now (UTC, ...Z). */
  attest(
    subjectAirId: string,
    opts: {
      attesterAirId: string;
      attestationType: string;
      privateKey: KeyObject;
      agentSecret: string;
      statement?: string;
      signedAt?: string;
    },
  ): Promise<AttestationResult> {
    const signedAt = opts.signedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const statement = opts.statement ?? "";
    const signatureMultibase = signAttestation(opts.privateKey, {
      attesterAirId: opts.attesterAirId,
      attestationType: opts.attestationType,
      signedAt,
      subjectAirId,
      statement,
    });
    return this.createAttestation(subjectAirId, {
      attesterAirId: opts.attesterAirId,
      attestationType: opts.attestationType,
      signedAt,
      signatureMultibase,
      agentSecret: opts.agentSecret,
      statement,
    });
  }

  listAttestations(subjectAirId: string): Promise<AttestationList> {
    return this.request<AttestationList>("GET", `/agents/${subjectAirId}/attestations`, {
      airId: subjectAirId,
    });
  }

  recentAttestations(opts: { limit?: number } = {}): Promise<RecentAttestations> {
    return this.request<RecentAttestations>("GET", "/attestations/recent", {
      params: { limit: opts.limit ?? 50 },
    });
  }

  revokeAttestation(
    subjectAirId: string,
    attestationId: number,
    opts: { agentSecret: string },
  ): Promise<RevokeResult> {
    return this.request<RevokeResult>("DELETE", `/agents/${subjectAirId}/attestations/${attestationId}`, {
      headers: { "X-Agent-Secret": opts.agentSecret },
      airId: subjectAirId,
    });
  }

  // ---- Admin (require adminKey) ------------------------------------------

  deleteAgent(airId: string): Promise<DeleteResult> {
    return this.request<DeleteResult>("DELETE", `/agents/${airId}`, {
      headers: this.adminHeader(),
      airId,
    });
  }

  getAdminStats(): Promise<AdminStats> {
    return this.request<AdminStats>("GET", "/admin/stats", { headers: this.adminHeader() });
  }

  getAdminRecent(opts: { limit?: number } = {}): Promise<AdminRecent> {
    return this.request<AdminRecent>("GET", "/admin/recent", {
      params: { limit: opts.limit ?? 20 },
      headers: this.adminHeader(),
    });
  }
}
