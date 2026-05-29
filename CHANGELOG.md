# Changelog

All notable changes to the TypeScript `agent-identity-registry` package are recorded here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-29

Initial release — a TypeScript port of the Python SDK, at parity with Python v0.5.0.

### Added
- **`AIRClient`** covering the full API surface: `getHealth`, `listAgents`, `getAgent`, `getTrustScore`, `getDidDocument`, `checkName`, `registerAgent`, `updateAgent`, the attestation suite (`createAttestation`, `attest`, `listAttestations`, `recentAttestations`, `revokeAttestation`), and admin (`deleteAgent`, `getAdminStats`, `getAdminRecent`).
- **AIR Verified signing** in `node:crypto` (zero deps): `signAttestation`, `canonicalAttestationBytes` (byte-identical to the Worker's `jcsCanonicalize` and the Python SDK), `base58btcEncode`, `loadPrivateKeyFromSeed`, `VALID_ATTESTATION_TYPES`.
- Typed error hierarchy mirroring the Python SDK (`AirError` + `ValidationError`, `AuthenticationError`, `AgentNotFoundError`, `ConflictError`, `RateLimitedError`, `ServerError`, `NetworkError`).
- Full response types (snake_case wire shape) including `Agent.verification_status`, `VerifiedStatus`, and the attestation models.
- Dual **ESM + CommonJS** build with `.d.ts` types (via `tsup`).
- 19 tests (vitest): byte-exact canonical vector cross-checked against the Python SDK, full sign→`node:crypto`-verify roundtrip, and injected-`fetch` coverage for every client method.

### Notes
- Zero runtime dependencies — platform `fetch` + `node:crypto`.
- Method arguments are `camelCase` options objects; responses keep the API's `snake_case` field names (Stripe-node convention), matching the OpenAPI spec.
