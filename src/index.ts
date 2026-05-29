/**
 * TypeScript SDK for the Agent Identity Registry (AIR).
 *
 *     import { AIRClient } from "agent-identity-registry";
 *     const air = new AIRClient();
 *     const agent = await air.getAgent("AIR-XXXX-XXXX-XXXX");
 */

export { AIRClient } from "./client.js";
export type { AIRClientOptions, FetchLike } from "./client.js";

export {
  AirError,
  ValidationError,
  AuthenticationError,
  AgentNotFoundError,
  ConflictError,
  RateLimitedError,
  ServerError,
  NetworkError,
} from "./errors.js";
export type { ErrorEnvelope } from "./errors.js";

export {
  signAttestation,
  canonicalAttestationBytes,
  base58btcEncode,
  loadPrivateKeyFromSeed,
  VALID_ATTESTATION_TYPES,
} from "./signing.js";
export type { AttestationType, AttestationPayload } from "./signing.js";

export type {
  Health,
  TrustComponents,
  TrustScore,
  Creator,
  VerificationStatus,
  Agent,
  AgentSummary,
  AgentList,
  DidVerificationMethod,
  DidDocument,
  NameCheck,
  RegistrationResult,
  UpdateResult,
  DeleteResult,
  AdminStats,
  AdminRecentItem,
  AdminRecent,
  VerifiedStatus,
  Attestation,
  AttestationResult,
  AttestationList,
  RecentAttestation,
  RecentAttestations,
  RevokeResult,
} from "./models.js";
