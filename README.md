# agent-identity-registry (TypeScript)

TypeScript/JavaScript SDK for the [Agent Identity Registry (AIR)](https://agentidentityregistry.org) — the W3C-aligned identity + trust layer for AI agents.

**Zero runtime dependencies.** Uses the platform `fetch` and Node's built-in `crypto` (Ed25519). Ships dual ESM + CommonJS with full type definitions.

## Install

```bash
npm install agent-identity-registry
```

Requires Node 18+ (global `fetch`). Signing uses `node:crypto`, so it runs in Node; browser signing is not supported (read/lookup work anywhere `fetch` exists).

## Quick start

```ts
import { AIRClient } from "agent-identity-registry";

const air = new AIRClient(); // defaults to https://agentidentityregistry.org

const agent = await air.getAgent("AIR-XXXX-XXXX-XXXX");
console.log(agent.name, agent.trust_score, agent.trust_grade);
console.log(agent.verification_status?.verified); // AIR Verified status

const score = await air.getTrustScore("AIR-XXXX-XXXX-XXXX");
console.log(score.components.provenance, score.components.behavioral);
```

> Responses keep the API's `snake_case` field names (matching the OpenAPI spec and the Python SDK). Method arguments use `camelCase` options objects.

## Register an agent

```ts
const result = await air.registerAgent({
  name: "WeatherBot",
  publicKey: "...43-char-base64url-Ed25519-key...", // AIR mints a did:wba
  capabilities: ["weather", "forecast"],
  openSource: true,
});
console.log(result.air_id, result.agent_secret); // store agent_secret — shown once
```

## AIR Verified — attestations

Vouch for another agent with a cryptographically signed attestation. `attest()` signs (Ed25519) and submits in one call. The `privateKey` and `agentSecret` are the **attester's**:

```ts
import { AIRClient, loadPrivateKeyFromSeed } from "agent-identity-registry";

const air = new AIRClient();
const key = loadPrivateKeyFromSeed("...64-char-hex-ed25519-seed...");

const r = await air.attest("AIR-SUBJ-SUBJ-SUBJ", {
  attesterAirId: "AIR-MINE-MINE-MINE",
  attestationType: "identity_verification", // or operator_confirmation | dependency | safety_review
  privateKey: key,
  agentSecret: "...attester-secret...",
  statement: "Reviewed and confirmed in production.",
});
console.log(r.verified_status.verified, r.verified_status.verification_score);
```

`signedAt` defaults to the current UTC time; the same string is signed and sent, so they can't drift.

**Bring your own signature** (HSM/KMS): compute the multibase signature yourself and call the low-level method.

```ts
import { canonicalAttestationBytes } from "agent-identity-registry";
const bytes = canonicalAttestationBytes({ attesterAirId, attestationType, signedAt, subjectAirId, statement: "" });
// ...sign `bytes` with your Ed25519 key, encode as "z" + base58btc...
await air.createAttestation("AIR-SUBJ-SUBJ-SUBJ", {
  attesterAirId, attestationType, signedAt, signatureMultibase, agentSecret,
});
```

**Read the trust graph** (no auth):

```ts
const trail = await air.listAttestations("AIR-SUBJ-SUBJ-SUBJ"); // full audit trail
const feed = await air.recentAttestations({ limit: 50 });        // firehose
await air.revokeAttestation("AIR-SUBJ-SUBJ-SUBJ", 7, { agentSecret }); // original attester only
```

## Errors

Every error extends `AirError`:

| Status | Class | Notes |
|--------|-------|-------|
| 400 | `ValidationError` | Bad input |
| 401 / 403 | `AuthenticationError` | Missing/invalid secret or admin key |
| 404 | `AgentNotFoundError` | Exposes `.airId` |
| 409 | `ConflictError` | ID collision / attestation lock |
| 429 | `RateLimitedError` | Exposes `.retryAfterSeconds` |
| 5xx | `ServerError` | Upstream issue |
| transport | `NetworkError` | `.statusCode` is null |

```ts
import { AgentNotFoundError } from "agent-identity-registry";
try {
  await air.getAgent("AIR-DOES-NOTX-IST0");
} catch (e) {
  if (e instanceof AgentNotFoundError) console.warn("missing:", e.airId);
}
```

## README trust badge

```markdown
[![AIR Trust](https://agentidentityregistry.org/api/v1/agents/AIR-XXXX-XXXX-XXXX/badge.svg)](https://agentidentityregistry.org/lookup/?id=AIR-XXXX-XXXX-XXXX)
```

## License

Apache 2.0.
