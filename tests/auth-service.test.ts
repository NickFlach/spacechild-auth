/**
 * Auth Service Tests
 * 
 * Tests for the core authentication service functionality.
 * Focuses on business logic rather than database operations.
 */

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { AuthService } from '../src/auth-service';

// Mock the storage module
const mockStorage = {
  getUserByEmail: vi.fn(),
  getUser: vi.fn(),
  upsertUser: vi.fn(),
  updateUser: vi.fn(),
  createZkCredential: vi.fn(),
  getZkCredentialByCommitment: vi.fn(),
  createEmailVerificationToken: vi.fn(),
  consumeEmailVerificationToken: vi.fn(),
  invalidateUserVerificationTokens: vi.fn(),
  createPasswordResetToken: vi.fn(),
  consumePasswordResetToken: vi.fn(),
  invalidateUserPasswordResetTokens: vi.fn(),
  findActiveVerificationTokens: vi.fn(),
  findActiveResetTokens: vi.fn(),
  createRefreshToken: vi.fn(),
  getRefreshTokensByUser: vi.fn(),
  revokeRefreshToken: vi.fn(),
  revokeAllUserRefreshTokens: vi.fn(),
  createProofSession: vi.fn(),
  getProofSession: vi.fn(),
  updateProofSession: vi.fn(),
  getAllUsers: vi.fn(),
  getZkCredentialsByUser: vi.fn(),
  getSubdomainAccess: vi.fn(),
  createSubdomainAccess: vi.fn(),
  updateSubdomainLastAccess: vi.fn(),
  getNotificationPreferences: vi.fn(),
  upsertNotificationPreferences: vi.fn(),
};

// Mock the email module
const mockEmail = {
  sendVerificationEmail: vi.fn().mockResolvedValue(true),
  sendPasswordResetEmail: vi.fn().mockResolvedValue(true),
  sendWelcomeEmail: vi.fn().mockResolvedValue(true),
};

// Mock the events module
const mockAuthEvents = {
  userRegistered: vi.fn(),
  userLogin: vi.fn(),
  userLogout: vi.fn(),
  userVerified: vi.fn(),
  passwordReset: vi.fn(),
  tokenRefreshed: vi.fn(),
  tokenRevoked: vi.fn(),
  mfaEnabled: vi.fn(),
  mfaDisabled: vi.fn(),
  mfaVerified: vi.fn(),
};

// Mock modules
vi.mock('../src/storage', () => ({
  storage: mockStorage,
}));

vi.mock('../src/email', () => mockEmail);

vi.mock('../src/events', () => ({
  authEvents: mockAuthEvents,
}));

// Mock circomlibjs to avoid ARM compatibility issues
vi.mock('circomlibjs', () => ({
  buildPoseidon: vi.fn().mockRejectedValue(new Error('circomlibjs not available')),
}));

describe('AuthService', () => {
  let authService: AuthService;

  beforeAll(() => {
    // Set required environment variable
    process.env.SESSION_SECRET = 'test-secret-key-minimum-32-characters-long';
    authService = AuthService.getInstance();
  });

  beforeEach(() => {
    // Reset all mocks before each test
    vi.clearAllMocks();
  });

  describe('Password Operations', () => {
    it('should hash passwords securely', async () => {
      const password = 'testpassword123';
      const hash = await authService.hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50); // bcrypt hashes are long
    });

    it('should verify passwords correctly', async () => {
      const password = 'testpassword123';
      const hash = await authService.hashPassword(password);
      
      const isValid = await authService.verifyPassword(password, hash);
      expect(isValid).toBe(true);
      
      const isInvalid = await authService.verifyPassword('wrongpassword', hash);
      expect(isInvalid).toBe(false);
    });
  });

  describe('User Registration', () => {
    it('should register a new user successfully', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        passwordHash: 'hashed-password',
        zkCredentialHash: null,
        isEmailVerified: false,
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null,
        profileImageUrl: null,
      };

      mockStorage.getUserByEmail.mockResolvedValue(null); // User doesn't exist
      mockStorage.upsertUser.mockResolvedValue(mockUser);
      mockStorage.createEmailVerificationToken.mockResolvedValue({});

      const result = await authService.register(
        'test@example.com',
        'password123',
        'Test',
        'User'
      );

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.requiresVerification).toBe(true);
      expect(mockStorage.getUserByEmail).toHaveBeenCalledWith('test@example.com');
      expect(mockStorage.upsertUser).toHaveBeenCalled();
      expect(mockEmail.sendVerificationEmail).toHaveBeenCalled();
      expect(mockAuthEvents.userRegistered).toHaveBeenCalled();
    });

    it('should reject registration for existing email', async () => {
      const existingUser = {
        id: 'existing-user',
        email: 'test@example.com',
        firstName: 'Existing',
        lastName: 'User',
        passwordHash: 'hashed-password',
        zkCredentialHash: null,
        isEmailVerified: true,
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null,
        profileImageUrl: null,
      };

      mockStorage.getUserByEmail.mockResolvedValue(existingUser);

      const result = await authService.register(
        'test@example.com',
        'password123',
        'Test',
        'User'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Email already registered');
      expect(mockStorage.upsertUser).not.toHaveBeenCalled();
    });
  });

  describe('User Login', () => {
    it('should login user with valid credentials', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        passwordHash: await authService.hashPassword('password123'),
        zkCredentialHash: null,
        isEmailVerified: true,
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null,
        profileImageUrl: null,
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);
      mockStorage.updateUser.mockResolvedValue(mockUser);
      mockStorage.createRefreshToken.mockResolvedValue({});

      const result = await authService.login('test@example.com', 'password123');

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(mockAuthEvents.userLogin).toHaveBeenCalled();
    });

    it('should reject login for non-existent user', async () => {
      mockStorage.getUserByEmail.mockResolvedValue(null);

      const result = await authService.login('nonexistent@example.com', 'password123');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid email or password');
    });

    it('should reject login for invalid password', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        passwordHash: await authService.hashPassword('correctpassword'),
        isEmailVerified: true,
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);

      const result = await authService.login('test@example.com', 'wrongpassword');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid email or password');
    });

    it('should reject login for unverified user', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        passwordHash: await authService.hashPassword('password123'),
        isEmailVerified: false,
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);

      const result = await authService.login('test@example.com', 'password123');

      expect(result.success).toBe(false);
      expect(result.error).toContain('verify your email');
      expect(result.requiresVerification).toBe(true);
    });
  });

  describe('Token Operations', () => {
    it('should generate valid JWT tokens', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
      };

      mockStorage.createRefreshToken.mockResolvedValue({});

      const tokens = await authService.generateTokens(mockUser);

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(typeof tokens.accessToken).toBe('string');
      expect(typeof tokens.refreshToken).toBe('string');
    });

    it('should verify valid access tokens', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
      };

      mockStorage.createRefreshToken.mockResolvedValue({});

      const tokens = await authService.generateTokens(mockUser);
      const payload = await authService.verifyAccessToken(tokens.accessToken);

      expect(payload).toBeDefined();
      expect(payload?.userId).toBe('user-123');
      expect(payload?.email).toBe('test@example.com');
      expect(payload?.type).toBe('access');
    });

    it('should reject invalid access tokens', async () => {
      const payload = await authService.verifyAccessToken('invalid-token');
      expect(payload).toBeNull();
    });
  });

  describe('Email Verification', () => {
    it('should resend verification email', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isEmailVerified: false,
        firstName: 'Test',
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);
      mockStorage.invalidateUserVerificationTokens.mockResolvedValue(undefined);
      mockStorage.createEmailVerificationToken.mockResolvedValue({});

      const result = await authService.resendVerificationEmail('test@example.com');

      expect(result.success).toBe(true);
      expect(mockEmail.sendVerificationEmail).toHaveBeenCalled();
    });

    it('should not resend for already verified email', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        isEmailVerified: true,
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);

      const result = await authService.resendVerificationEmail('test@example.com');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Email is already verified');
    });
  });

  describe('Password Reset', () => {
    it('should initiate password reset', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
      };

      mockStorage.getUserByEmail.mockResolvedValue(mockUser);
      mockStorage.invalidateUserPasswordResetTokens.mockResolvedValue(undefined);
      mockStorage.createPasswordResetToken.mockResolvedValue({});

      const result = await authService.requestPasswordReset('test@example.com');

      expect(result.success).toBe(true);
      expect(mockEmail.sendPasswordResetEmail).toHaveBeenCalled();
    });

    it('should silently succeed for non-existent email', async () => {
      mockStorage.getUserByEmail.mockResolvedValue(null);

      const result = await authService.requestPasswordReset('nonexistent@example.com');

      expect(result.success).toBe(true);
      expect(mockEmail.sendPasswordResetEmail).not.toHaveBeenCalled();
    });
  });

  describe('Authorization Codes (SSO)', () => {
    it('should generate authorization code', async () => {
      const code = await authService.generateAuthorizationCode('user-123', 'test-subdomain');

      expect(code).toBeDefined();
      expect(typeof code).toBe('string');
      expect(code.length).toBeGreaterThan(30);
    });

    it('should exchange valid authorization code', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
      };

      mockStorage.getUser.mockResolvedValue(mockUser);
      mockStorage.createRefreshToken.mockResolvedValue({});

      const code = await authService.generateAuthorizationCode('user-123', 'test-subdomain');
      const result = await authService.exchangeAuthorizationCode(code, 'test-subdomain');

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should reject invalid authorization code', async () => {
      const result = await authService.exchangeAuthorizationCode('invalid-code', 'test-subdomain');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid or expired');
    });
  });

  describe('ZK Proof Operations', () => {
    it('should create ZK proof request', async () => {
      mockStorage.createProofSession.mockResolvedValue({
        id: 1,
        sessionId: 'session-123',
        challenge: 'challenge-data',
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      const request = await authService.createZkProofRequest();

      expect(request.sessionId).toBeDefined();
      expect(request.challenge).toBeDefined();
      expect(request.expiresAt).toBeDefined();
      expect(mockStorage.createProofSession).toHaveBeenCalled();
    });

    it('should handle ZK proof operations gracefully when circomlibjs unavailable', async () => {
      // circomlibjs is mocked to fail, so ZKP should be disabled
      const proofResponse = {
        sessionId: 'session-123',
        proof: {
          commitment: 'test-commitment',
          response: 'test-response',
          publicSignals: [],
        },
      };

      const result = await authService.verifyZkProof(proofResponse);

      expect(result.success).toBe(false);
      expect(result.error).toContain('ZK proof functionality is not available');
    });
  });
});