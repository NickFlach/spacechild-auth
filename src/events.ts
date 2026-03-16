/**
 * SpaceChild Auth Events
 * 
 * Simple Node.js EventEmitter-based event system.
 * Maintains the same event names and payload shapes as the original.
 */

import { EventEmitter } from 'events';

// ============================================
// EVENT TYPES
// ============================================

export interface AuthEvents {
  'auth:user.registered': {
    userId: string;
    email: string;
    firstName?: string;
    lastName?: string;
    timestamp: Date;
  };

  'auth:user.login': {
    userId: string;
    email: string;
    method: 'password' | 'zkp' | 'sso';
    ip?: string;
    timestamp: Date;
  };

  'auth:user.logout': {
    userId: string;
    timestamp: Date;
  };

  'auth:user.verified': {
    userId: string;
    email: string;
    timestamp: Date;
  };

  'auth:password.reset': {
    userId: string;
    email: string;
    timestamp: Date;
  };

  'auth:mfa.enabled': {
    userId: string;
    method: string;
    timestamp: Date;
  };

  'auth:mfa.disabled': {
    userId: string;
    method: string;
    timestamp: Date;
  };

  'auth:mfa.verified': {
    userId: string;
    method: string;
    timestamp: Date;
  };

  'auth:token.refreshed': {
    userId: string;
    timestamp: Date;
  };

  'auth:token.revoked': {
    userId: string;
    revokedBy: 'user' | 'admin' | 'system';
    timestamp: Date;
  };
}

// ============================================
// EVENT EMITTER
// ============================================

class AuthEventBus extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(50); // Allow more listeners for multiple subscribers
  }

  /**
   * Emit an async event (non-blocking)
   */
  emitAsync<K extends keyof AuthEvents>(event: K, payload: AuthEvents[K]): void {
    // Use setImmediate to make it truly async
    setImmediate(() => {
      try {
        this.emit(event, payload);
      } catch (error) {
        console.error(`Error in event handler for ${event}:`, error);
      }
    });
  }

  /**
   * Subscribe to auth events with proper typing
   */
  onAuthEvent<K extends keyof AuthEvents>(
    event: K,
    handler: (payload: AuthEvents[K]) => void | Promise<void>
  ): () => void {
    const wrappedHandler = async (payload: AuthEvents[K]) => {
      try {
        await handler(payload);
      } catch (error) {
        console.error(`Error in auth event handler for ${event}:`, error);
      }
    };

    this.on(event, wrappedHandler);

    // Return unsubscribe function
    return () => {
      this.off(event, wrappedHandler);
    };
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

const eventBus = new AuthEventBus();

/**
 * Emit auth events with proper typing
 */
export const authEvents = {
  /**
   * Emit when a new user registers
   */
  userRegistered(data: Omit<AuthEvents['auth:user.registered'], 'timestamp'>) {
    eventBus.emitAsync('auth:user.registered', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when a user logs in
   */
  userLogin(data: Omit<AuthEvents['auth:user.login'], 'timestamp'>) {
    eventBus.emitAsync('auth:user.login', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when a user logs out
   */
  userLogout(data: Omit<AuthEvents['auth:user.logout'], 'timestamp'>) {
    eventBus.emitAsync('auth:user.logout', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when a user verifies their email
   */
  userVerified(data: Omit<AuthEvents['auth:user.verified'], 'timestamp'>) {
    eventBus.emitAsync('auth:user.verified', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when a user resets their password
   */
  passwordReset(data: Omit<AuthEvents['auth:password.reset'], 'timestamp'>) {
    eventBus.emitAsync('auth:password.reset', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when MFA is enabled for a user
   */
  mfaEnabled(data: Omit<AuthEvents['auth:mfa.enabled'], 'timestamp'>) {
    eventBus.emitAsync('auth:mfa.enabled', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when MFA is disabled for a user
   */
  mfaDisabled(data: Omit<AuthEvents['auth:mfa.disabled'], 'timestamp'>) {
    eventBus.emitAsync('auth:mfa.disabled', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when MFA verification succeeds
   */
  mfaVerified(data: Omit<AuthEvents['auth:mfa.verified'], 'timestamp'>) {
    eventBus.emitAsync('auth:mfa.verified', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when a token is refreshed
   */
  tokenRefreshed(data: Omit<AuthEvents['auth:token.refreshed'], 'timestamp'>) {
    eventBus.emitAsync('auth:token.refreshed', {
      ...data,
      timestamp: new Date(),
    });
  },

  /**
   * Emit when tokens are revoked
   */
  tokenRevoked(data: Omit<AuthEvents['auth:token.revoked'], 'timestamp'>) {
    eventBus.emitAsync('auth:token.revoked', {
      ...data,
      timestamp: new Date(),
    });
  },
};

/**
 * Subscribe to auth events
 */
export function onAuthEvent<K extends keyof AuthEvents>(
  event: K,
  handler: (payload: AuthEvents[K]) => void | Promise<void>
): () => void {
  return eventBus.onAuthEvent(event, handler);
}

/**
 * Export the event bus for advanced usage
 */
export { eventBus };