/**
 * Flux Publisher Tests
 *
 * Tests the auth-event → Flux-event mapping and the opt-in behavior.
 * No live Flux instance required.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  mapAuthEventToFluxEvent,
  initFluxPublisher,
  FluxPublisher,
  FLUX_FORWARDED_EVENTS,
} from '../src/flux-publisher';

const TS = new Date('2026-06-12T10:00:00.000Z');

describe('mapAuthEventToFluxEvent', () => {
  it('maps user.registered to a Flux event envelope', () => {
    const event = mapAuthEventToFluxEvent('auth:user.registered', {
      userId: 'u-123',
      email: 'nick@example.com',
      firstName: 'Nick',
      timestamp: TS,
    });

    expect(event).toEqual({
      stream: 'auth',
      source: 'spacechild-auth',
      timestamp: TS.getTime(),
      payload: {
        entity_id: 'auth-user-u-123',
        properties: {
          type: 'auth-activity',
          user_id: 'u-123',
          last_event: 'user.registered',
          last_event_at: TS.toISOString(),
          registered_at: TS.toISOString(),
        },
      },
    });
  });

  it('maps user.login with method', () => {
    const event = mapAuthEventToFluxEvent('auth:user.login', {
      userId: 'u-123',
      email: 'nick@example.com',
      method: 'zkp',
      ip: '10.0.0.1',
      timestamp: TS,
    });

    expect(event.payload.properties.last_event).toBe('user.login');
    expect(event.payload.properties.last_login_method).toBe('zkp');
    expect(event.payload.properties.last_login_at).toBe(TS.toISOString());
  });

  it('maps token.refreshed', () => {
    const event = mapAuthEventToFluxEvent('auth:token.refreshed', {
      userId: 'u-456',
      timestamp: TS,
    });

    expect(event.payload.entity_id).toBe('auth-user-u-456');
    expect(event.payload.properties.last_event).toBe('token.refreshed');
    expect(event.payload.properties).not.toHaveProperty('last_login_method');
  });

  it('never includes PII (email, ip) in published properties', () => {
    for (const name of FLUX_FORWARDED_EVENTS) {
      const event = mapAuthEventToFluxEvent(name, {
        userId: 'u-789',
        email: 'secret@example.com',
        ip: '192.168.1.1',
        method: 'password',
        timestamp: TS,
      } as any);

      const serialized = JSON.stringify(event);
      expect(serialized).not.toContain('secret@example.com');
      expect(serialized).not.toContain('192.168.1.1');
      expect(event.payload.properties).not.toHaveProperty('email');
      expect(event.payload.properties).not.toHaveProperty('ip');
    }
  });

  it('prefixes entity_id with namespace when provided', () => {
    const event = mapAuthEventToFluxEvent(
      'auth:user.login',
      { userId: 'u-1', email: 'a@b.c', method: 'sso', timestamp: TS },
      'spacechild'
    );
    expect(event.payload.entity_id).toBe('spacechild/auth-user-u-1');
  });
});

describe('initFluxPublisher', () => {
  afterEach(() => {
    delete process.env.FLUX_URL;
    delete process.env.FLUX_TOKEN;
    delete process.env.FLUX_NAMESPACE;
    vi.unstubAllGlobals();
  });

  it('returns null and changes nothing when FLUX_URL is unset', () => {
    delete process.env.FLUX_URL;
    expect(initFluxPublisher()).toBeNull();
  });

  it('returns a started publisher when FLUX_URL is set', () => {
    process.env.FLUX_URL = 'http://localhost:3000';
    const publisher = initFluxPublisher();
    expect(publisher).toBeInstanceOf(FluxPublisher);
    publisher!.stop();
  });
});

describe('FluxPublisher.publish', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('POSTs the event to <url>/api/events with bearer token', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal('fetch', fetchMock);

    const publisher = new FluxPublisher({
      url: 'http://localhost:3000/',
      token: 'test-token',
      namespace: 'spacechild',
    });

    const event = mapAuthEventToFluxEvent(
      'auth:user.login',
      { userId: 'u-1', email: 'a@b.c', method: 'password', timestamp: TS },
      'spacechild'
    );
    publisher.publish(event);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe('http://localhost:3000/api/events');
    expect(opts.method).toBe('POST');
    expect(opts.headers['Content-Type']).toBe('application/json');
    expect(opts.headers['Authorization']).toBe('Bearer test-token');
    expect(JSON.parse(opts.body)).toEqual(event);
  });

  it('omits Authorization header when no token configured', () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal('fetch', fetchMock);

    const publisher = new FluxPublisher({ url: 'http://localhost:3000' });
    publisher.publish(
      mapAuthEventToFluxEvent('auth:token.refreshed', { userId: 'u-1', timestamp: TS })
    );

    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.headers).not.toHaveProperty('Authorization');
  });

  it('never throws on network failure', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    vi.stubGlobal('fetch', fetchMock);

    const publisher = new FluxPublisher({ url: 'http://localhost:3000' });
    expect(() =>
      publisher.publish(
        mapAuthEventToFluxEvent('auth:token.refreshed', { userId: 'u-1', timestamp: TS })
      )
    ).not.toThrow();
    // Allow the rejected promise's catch handler to run (no unhandled rejection)
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('forwards live auth bus events end-to-end (in-process)', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal('fetch', fetchMock);

    const publisher = new FluxPublisher({ url: 'http://localhost:3000' });
    publisher.start();

    const { authEvents } = await import('../src/events');
    authEvents.userLogin({ userId: 'u-live', email: 'a@b.c', method: 'password' });

    // emitAsync uses setImmediate
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    publisher.stop();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.payload.entity_id).toBe('auth-user-u-live');
    expect(body.payload.properties.last_event).toBe('user.login');
  });
});
