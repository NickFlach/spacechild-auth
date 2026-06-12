/**
 * Flux Publisher
 *
 * Optional bridge from the local auth event bus to a Flux world-state engine
 * (event-sourced state engine, HTTP ingestion at POST /api/events).
 *
 * Enabled only when FLUX_URL is set — when unset there is zero behavior change.
 *
 * Environment:
 *   FLUX_URL        e.g. https://api.flux-universe.com or http://localhost:3000
 *   FLUX_TOKEN      Flux namespace bearer token (required if the instance has
 *                   FLUX_AUTH_ENABLED=true)
 *   FLUX_NAMESPACE  Flux namespace for entity IDs (entity_id becomes
 *                   "<namespace>/auth-user-<id>"). Omit for internal/no-auth
 *                   Flux instances.
 *
 * Privacy: Flux reads are open even on auth-enabled instances, so published
 * properties deliberately exclude PII (no email, no IP) — only opaque user IDs
 * and event metadata are sent.
 */

import { onAuthEvent, AuthEvents } from "./events";

// ============================================
// TYPES
// ============================================

/** Flux event envelope (POST /api/events body) */
export interface FluxEvent {
  stream: string;
  source: string;
  timestamp: number;
  payload: {
    entity_id: string;
    properties: Record<string, unknown>;
  };
}

export interface FluxPublisherConfig {
  url: string;
  token?: string;
  namespace?: string;
}

/** Auth events forwarded to Flux */
export const FLUX_FORWARDED_EVENTS = [
  "auth:user.registered",
  "auth:user.login",
  "auth:token.refreshed",
] as const;

export type FluxForwardedEvent = (typeof FLUX_FORWARDED_EVENTS)[number];

const STREAM = "auth";
const SOURCE = "spacechild-auth";

// ============================================
// EVENT MAPPING (pure, unit-testable)
// ============================================

/**
 * Map an auth event to a Flux event envelope.
 *
 * Each user becomes a Flux entity ("auth-user-<id>") whose properties reflect
 * their latest auth activity. PII (email, IP) is intentionally not included.
 */
export function mapAuthEventToFluxEvent<K extends FluxForwardedEvent>(
  event: K,
  payload: AuthEvents[K],
  namespace?: string
): FluxEvent {
  const shortName = event.replace(/^auth:/, ""); // e.g. "user.login"
  const entityId = `auth-user-${payload.userId}`;

  const properties: Record<string, unknown> = {
    type: "auth-activity",
    user_id: payload.userId,
    last_event: shortName,
    last_event_at: payload.timestamp.toISOString(),
  };

  if (event === "auth:user.login") {
    properties.last_login_method = (payload as AuthEvents["auth:user.login"]).method;
    properties.last_login_at = payload.timestamp.toISOString();
  }

  if (event === "auth:user.registered") {
    properties.registered_at = payload.timestamp.toISOString();
  }

  return {
    stream: STREAM,
    source: SOURCE,
    timestamp: payload.timestamp.getTime(),
    payload: {
      entity_id: namespace ? `${namespace}/${entityId}` : entityId,
      properties,
    },
  };
}

// ============================================
// PUBLISHER
// ============================================

export class FluxPublisher {
  private readonly url: string;
  private readonly token?: string;
  private readonly namespace?: string;
  private unsubscribers: Array<() => void> = [];

  constructor(config: FluxPublisherConfig) {
    this.url = config.url.replace(/\/+$/, "");
    this.token = config.token;
    this.namespace = config.namespace;
  }

  /** Subscribe to the auth event bus and forward selected events to Flux. */
  start(): void {
    for (const event of FLUX_FORWARDED_EVENTS) {
      this.unsubscribers.push(
        onAuthEvent(event, (payload) => {
          this.publish(mapAuthEventToFluxEvent(event, payload, this.namespace));
        })
      );
    }
  }

  /** Unsubscribe from the auth event bus. */
  stop(): void {
    for (const unsubscribe of this.unsubscribers) {
      unsubscribe();
    }
    this.unsubscribers = [];
  }

  /** Fire-and-forget POST to Flux. Failures are logged, never thrown. */
  publish(event: FluxEvent): void {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    fetch(`${this.url}/api/events`, {
      method: "POST",
      headers,
      body: JSON.stringify(event),
    })
      .then((res) => {
        if (!res.ok) {
          console.warn(`⚠️ Flux publish failed: HTTP ${res.status} (${event.payload.entity_id})`);
        }
      })
      .catch((error) => {
        console.warn(`⚠️ Flux publish error: ${error?.message || error}`);
      });
  }
}

// ============================================
// INITIALIZATION
// ============================================

/**
 * Initialize the Flux publisher from environment variables.
 * Returns null (and changes nothing) when FLUX_URL is not set.
 */
export function initFluxPublisher(): FluxPublisher | null {
  const url = process.env.FLUX_URL;
  if (!url) {
    return null;
  }

  const publisher = new FluxPublisher({
    url,
    token: process.env.FLUX_TOKEN,
    namespace: process.env.FLUX_NAMESPACE,
  });
  publisher.start();
  console.log(`🌊 Flux publisher enabled → ${url} (namespace: ${process.env.FLUX_NAMESPACE || "none"})`);
  return publisher;
}
