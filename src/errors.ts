/**
 * Error hierarchy — mirrors the Python SDK so behavior is identical across
 * languages. Every thrown error extends {@link AirError}; catch that to handle
 * anything the SDK raises.
 */

export interface ErrorEnvelope {
  error: string;
  message?: string;
  air_id?: string;
  hint?: string;
  retry_after_seconds?: number;
}

export interface AirErrorOptions {
  statusCode?: number | null;
  envelope?: ErrorEnvelope | null;
}

export class AirError extends Error {
  readonly statusCode: number | null;
  readonly envelope: ErrorEnvelope | null;

  constructor(message: string, opts: AirErrorOptions = {}) {
    super(message);
    this.name = new.target.name;
    this.statusCode = opts.statusCode ?? null;
    this.envelope = opts.envelope ?? null;
    // Keep `instanceof` working after TS downlevels to ES5-style classes.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 400 — request body or query rejected by the API. */
export class ValidationError extends AirError {}

/** 401 / 403 — missing or invalid X-Agent-Secret / X-Admin-Key. */
export class AuthenticationError extends AirError {}

/** 404 on an agent-scoped endpoint. Exposes `airId` for convenience. */
export class AgentNotFoundError extends AirError {
  readonly airId: string | null;
  constructor(message: string, opts: AirErrorOptions & { airId?: string | null } = {}) {
    super(message, opts);
    this.airId = opts.airId ?? null;
  }
}

/** 409 — ID collision or an attestation lock (e.g. shared WHOIS root). */
export class ConflictError extends AirError {}

/** 429 — rate limited. Exposes `retryAfterSeconds`. */
export class RateLimitedError extends AirError {
  readonly retryAfterSeconds: number | null;
  constructor(message: string, opts: AirErrorOptions & { retryAfterSeconds?: number | null } = {}) {
    super(message, opts);
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
  }
}

/** 5xx — upstream registry failure. */
export class ServerError extends AirError {}

/** Transport-layer failure (DNS, TLS, timeout, connection refused). statusCode is null. */
export class NetworkError extends AirError {}

/**
 * Throw the appropriate {@link AirError} subclass for a non-2xx response.
 * Hybrid: exact-match the special codes (404, 409, 429, 401/403), range-fallback
 * the rest. Prefers the server's human-readable message over a generic one.
 */
export function raiseForStatus(
  status: number,
  envelope: ErrorEnvelope | null,
  airId?: string | null,
): void {
  if (status < 400) return;
  const message = envelope?.error || `HTTP ${status}`;

  if (status === 404) throw new AgentNotFoundError(message, { statusCode: 404, envelope, airId });
  if (status === 409) throw new ConflictError(message, { statusCode: status, envelope });
  if (status === 429) {
    throw new RateLimitedError(message, {
      statusCode: status,
      envelope,
      retryAfterSeconds: envelope?.retry_after_seconds ?? null,
    });
  }
  if (status === 401 || status === 403) {
    throw new AuthenticationError(message, { statusCode: status, envelope });
  }
  if (status >= 400 && status < 500) {
    throw new ValidationError(message, { statusCode: status, envelope });
  }
  throw new ServerError(message, { statusCode: status, envelope });
}
