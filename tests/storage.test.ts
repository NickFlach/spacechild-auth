/**
 * Storage Tests
 * 
 * Basic tests for the storage layer functionality.
 * Uses either a real database connection or mocked pool.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { Pool } from 'mysql2/promise';
import { Storage } from '../src/storage';

// Mock pool for testing without database
const createMockPool = (): Pool => {
  const mockConnection = {
    execute: async (sql: string, values?: any[]) => {
      // Simulate successful queries
      if (sql.includes('INSERT')) {
        return [{ insertId: 1, affectedRows: 1 }, []];
      }
      if (sql.includes('SELECT')) {
        return [[], []]; // Empty results
      }
      return [{ affectedRows: 1 }, []];
    },
    release: () => {},
  };

  return {
    execute: mockConnection.execute,
    getConnection: async () => mockConnection,
    end: async () => {},
  } as any;
};

describe('Storage Layer', () => {
  let storage: Storage;
  let mockPool: Pool;

  beforeAll(async () => {
    mockPool = createMockPool();
    storage = new Storage(mockPool);
  });

  beforeEach(() => {
    // Reset any state if needed
  });

  describe('User Operations', () => {
    it('should create a user with upsertUser', async () => {
      const userData = {
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        passwordHash: 'hashedpassword',
        isEmailVerified: false,
      };

      // This will use the mock - in real tests, would use actual DB
      await expect(storage.upsertUser(userData)).resolves.toBeDefined();
    });

    it('should get user by email', async () => {
      await expect(storage.getUserByEmail('test@example.com')).resolves.toBeUndefined();
    });

    it('should get user by ID', async () => {
      await expect(storage.getUser('user-id')).resolves.toBeUndefined();
    });

    it('should update user data', async () => {
      const updateData = {
        firstName: 'Updated',
        lastName: 'Name',
      };

      await expect(storage.updateUser('user-id', updateData)).resolves.toBeUndefined();
    });
  });

  describe('Token Operations', () => {
    it('should create refresh token', async () => {
      const tokenData = {
        userId: 'user-id',
        tokenHash: 'hashed-token',
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      };

      await expect(storage.createRefreshToken(tokenData)).resolves.toBeDefined();
    });

    it('should get refresh tokens by user', async () => {
      await expect(storage.getRefreshTokensByUser('user-id')).resolves.toEqual([]);
    });

    it('should revoke refresh token', async () => {
      await expect(storage.revokeRefreshToken(1)).resolves.toBeUndefined();
    });

    it('should revoke all user refresh tokens', async () => {
      await expect(storage.revokeAllUserRefreshTokens('user-id')).resolves.toBeUndefined();
    });
  });

  describe('Email Verification', () => {
    it('should create email verification token', async () => {
      const tokenData = {
        userId: 'user-id',
        tokenHash: 'hashed-token',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      await expect(storage.createEmailVerificationToken(tokenData)).resolves.toBeDefined();
    });

    it('should consume email verification token', async () => {
      await expect(storage.consumeEmailVerificationToken(1)).resolves.toBeUndefined();
    });

    it('should invalidate user verification tokens', async () => {
      await expect(storage.invalidateUserVerificationTokens('user-id')).resolves.toBeUndefined();
    });
  });

  describe('Password Reset', () => {
    it('should create password reset token', async () => {
      const tokenData = {
        userId: 'user-id', 
        tokenHash: 'hashed-token',
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      };

      await expect(storage.createPasswordResetToken(tokenData)).resolves.toBeDefined();
    });

    it('should consume password reset token', async () => {
      await expect(storage.consumePasswordResetToken(1)).resolves.toBeUndefined();
    });
  });

  describe('ZK Credentials', () => {
    it('should create ZK credential', async () => {
      const credentialData = {
        userId: 'user-id',
        publicCommitment: 'commitment-hash',
        credentialHash: 'credential-hash',
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      };

      await expect(storage.createZkCredential(credentialData)).resolves.toBeDefined();
    });

    it('should get ZK credentials by user', async () => {
      await expect(storage.getZkCredentialsByUser('user-id')).resolves.toEqual([]);
    });

    it('should get ZK credential by commitment', async () => {
      await expect(storage.getZkCredentialByCommitment('commitment')).resolves.toBeUndefined();
    });
  });

  describe('Proof Sessions', () => {
    it('should create proof session', async () => {
      const sessionData = {
        sessionId: 'session-123',
        challenge: 'challenge-data',
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      };

      await expect(storage.createProofSession(sessionData)).resolves.toBeDefined();
    });

    it('should get proof session', async () => {
      await expect(storage.getProofSession('session-123')).resolves.toBeUndefined();
    });
  });

  describe('MFA Operations', () => {
    it('should create MFA method', async () => {
      const methodData = {
        userId: 'user-id',
        type: 'totp',
        name: 'Authenticator App',
        isEnabled: true,
      };

      await expect(storage.createMfaMethod(methodData)).resolves.toBeDefined();
    });

    it('should get MFA methods by user', async () => {
      await expect(storage.getMfaMethodsByUser('user-id')).resolves.toEqual([]);
    });

    it('should create TOTP secret', async () => {
      const secretData = {
        userId: 'user-id',
        encryptedSecret: 'encrypted-secret',
        backupCodes: ['code1', 'code2'],
        backupCodesUsed: [],
      };

      await expect(storage.createTotpSecret(secretData)).resolves.toBeDefined();
    });
  });
});

// Integration tests (require actual database)
describe.skip('Storage Integration Tests', () => {
  // These tests would run against a real database
  // Skip by default but can be enabled for full integration testing

  it('should perform full user lifecycle', async () => {
    // Create user -> verify email -> login -> create tokens -> cleanup
  });

  it('should handle concurrent token operations', async () => {
    // Test race conditions and locking
  });

  it('should enforce database constraints', async () => {
    // Test foreign key constraints, unique indexes, etc.
  });
});