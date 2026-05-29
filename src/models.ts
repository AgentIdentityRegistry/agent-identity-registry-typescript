/**
 * Response types — typed to the live API JSON (snake_case wire shape, like the
 * Python SDK and the OpenAPI spec). Method *arguments* use camelCase options
 * objects; *responses* keep the wire field names so what you read matches the
 * API docs exactly (the Stripe-node convention).
 *
 * These are compile-time types only — no runtime validation, zero dependencies.
 */

export interface Health {
  status: string;
  version: string;
  registry: string;
}

export interface TrustComponents {
  provenance: number;
  behavioral: number;
  transparency: number;
  security: number;
  peer_attestations: number;
}

export interface TrustScore {
  air_id: string;
  total_score: number;
  grade: string;
  components: TrustComponents;
  calculated_at: string;
}

export interface Creator {
  did: string | null;
  name: string | null;
  type: string | null;
  public_key: string | null;
}

/** AIR Verified breakdown on GET /agents/{id} (display shape with thresholds). */
export interface VerificationStatus {
  verified: boolean;
  score: number;
  score_required: number;
  attestation_count: number;
  distinct_whois_roots: number;
  distinct_whois_roots_required: number;
}

export interface Agent {
  air_id: string;
  name: string;
  description: string;
  creator: Creator;
  capabilities: string[];
  security: { certifications: string[] };
  transparency: { open_source: boolean; code_repository?: string | null; documentation_url?: string | null };
  verified: boolean;
  verification_level: string;
  /** Present since the Phase 4 attestation ship; absent on older API responses. */
  verification_status?: VerificationStatus;
  is_demo: boolean;
  status: string;
  created: string;
  updated: string;
  trust_score?: number | null;
  trust_grade?: string | null;
  components?: TrustComponents | null;
}

export interface AgentSummary {
  air_id: string;
  name: string;
  description: string;
  verified: boolean;
  verification_level: string;
  is_demo: boolean;
  trust_score?: number | null;
  trust_grade?: string | null;
  created: string;
}

export interface AgentList {
  agents: AgentSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface DidVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  alsoKnownAs?: string[];
  verificationMethod: DidVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service: { id: string; type: string; serviceEndpoint: string }[];
}

export interface NameCheck {
  name: string;
  exists: boolean;
  count: number;
  existing_agents: { air_id: string; name: string }[];
}

export interface RegistrationResult {
  air_id: string;
  name: string;
  creator_did: string;
  air_minted_did?: boolean | null;
  status: string;
  verification_level: string;
  trust_score: number;
  trust_grade: string;
  created: string;
  public_key?: string | null;
  did_wba_resolved?: boolean | null;
  agent_secret: string;
  agent_secret_note: string;
  warnings?: string[] | null;
  message: string;
}

export interface UpdateResult {
  air_id: string;
  updated_fields: number;
  trust_score: number;
  trust_grade: string;
  updated: string;
  message: string;
}

export interface DeleteResult {
  air_id: string;
  name: string;
  status: string;
  deleted_at: string;
  message: string;
}

export interface AdminStats {
  total_agents: number;
  real_agents: number;
  demo_agents: number;
  verified: number;
  unverified: number;
  registered_last_7_days: number;
  average_trust_score?: number | null;
  grade_distribution: Record<string, number>;
}

export interface AdminRecentItem {
  air_id: string;
  name: string;
  creator_did?: string | null;
  creator_name: string;
  creator_type?: string | null;
  verified: boolean;
  is_demo: boolean;
  verification_level: string;
  trust_score?: number | null;
  trust_grade?: string | null;
  registered: string;
}

export interface AdminRecent {
  recent_registrations: AdminRecentItem[];
  count: number;
}

// ---- Attestations (AIR Verified, Phase 4) --------------------------------

/** `verified_status` embedded in attestation write/list responses (raw computeVerifiedStatus). */
export interface VerifiedStatus {
  verified: boolean;
  verification_score: number;
  distinct_whois_roots: number;
  attestation_count: number;
}

export interface Attestation {
  id: number;
  attester_air_id: string;
  attester_whois_root: string | null;
  attestation_type: string;
  statement: string;
  signed_payload: string;
  signature_multibase: string;
  signed_at: string;
  attester_trust_at_issue: number;
  tenure_multiplier_at_issue: number;
  weight: number;
  revoked_at: string | null;
  is_active: boolean;
  created_at: string;
}

export interface AttestationResult {
  attestation_id: number;
  subject_air_id: string;
  attester_air_id: string;
  attestation_type: string;
  statement: string;
  signed_at: string;
  attester_whois_root: string | null;
  attester_trust_at_issue: number;
  tenure_multiplier_at_issue: number;
  weight: number;
  verified_status: VerifiedStatus;
}

export interface AttestationList {
  subject_air_id: string;
  attestations: Attestation[];
  total: number;
  active: number;
  verified_status: VerifiedStatus;
}

export interface RecentAttestation {
  id: number;
  subject_air_id: string;
  attester_air_id: string;
  attester_whois_root: string | null;
  attestation_type: string;
  statement: string;
  signed_at: string;
  weight: number;
  created_at: string;
}

export interface RecentAttestations {
  attestations: RecentAttestation[];
  total: number;
  limit: number;
}

export interface RevokeResult {
  revoked: boolean;
  attestation_id: number;
  subject_air_id: string;
  revoked_at: string;
  verified_status: VerifiedStatus;
}
