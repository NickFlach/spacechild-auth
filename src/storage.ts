/**
 * Storage Layer
 * 
 * Implements all storage methods using raw MySQL queries with parameterized statements.
 * Provides CRUD operations for all auth-related data.
 */

import type { Pool, PoolConnection, RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import { pool } from './db';
import type {
  User, UpsertUser, InsertZkCredential, ZkCredential, ProofSession, InsertProofSession,
  RefreshToken, InsertRefreshToken, SubdomainAccess, InsertSubdomainAccess,
  EmailVerificationToken, InsertEmailVerificationToken, PasswordResetToken, InsertPasswordResetToken,
  MfaMethod, InsertMfaMethod, TotpSecret, InsertTotpSecret, WebauthnCredential, InsertWebauthnCredential,
  MfaChallenge, InsertMfaChallenge, MfaPendingLogin, InsertMfaPendingLogin,
  NotificationPreferences, InsertNotificationPreferences
} from './types';

/**
 * Storage implementation with raw MySQL queries
 */
export class Storage {
  private pool: Pool;

  constructor(dbPool: Pool) {
    this.pool = dbPool;
  }

  // ============================================
  // USERS
  // ============================================

  async getUser(id: string): Promise<User | undefined> {
    const [rows] = await this.pool.execute(
      'SELECT * FROM users WHERE id = ?',
      [id]
    ) as [RowDataPacket[], any];
    return rows[0] as User | undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    return rows[0] as User | undefined;
  }

  async getAllUsers(): Promise<User[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM users ORDER BY created_at DESC'
    );
    return rows as User[];
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const {
      id,
      email,
      firstName,
      lastName,
      profileImageUrl,
      passwordHash,
      zkCredentialHash,
      isEmailVerified,
      role,
      lastLoginAt
    } = userData;

    if (id) {
      // Update existing user
      await this.pool.execute(
        `UPDATE users SET 
         email = ?, first_name = ?, last_name = ?, profile_image_url = ?,
         password_hash = ?, zk_credential_hash = ?, is_email_verified = ?,
         role = ?, last_login_at = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [email, firstName, lastName, profileImageUrl, passwordHash, zkCredentialHash,
         isEmailVerified, role, lastLoginAt, id]
      );
      
      const user = await this.getUser(id);
      if (!user) throw new Error('User not found after update');
      return user;
    } else {
      // Insert new user
      const [result] = await this.pool.execute(
        `INSERT INTO users (id, email, first_name, last_name, profile_image_url, 
         password_hash, zk_credential_hash, is_email_verified, role, last_login_at)
         VALUES (UUID(), ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [email, firstName, lastName, profileImageUrl, passwordHash, zkCredentialHash,
         isEmailVerified, role, lastLoginAt]
      ) as [ResultSetHeader, any];

      // Get the inserted user
      const [rows] = await this.pool.execute<RowDataPacket[]>(
        'SELECT * FROM users WHERE id = (SELECT id FROM users ORDER BY created_at DESC LIMIT 1)'
      );
      return rows[0] as User;
    }
  }

  async updateUser(id: string, data: Partial<UpsertUser>): Promise<User | undefined> {
    const fields = [];
    const values = [];

    if (data.email !== undefined) {
      fields.push('email = ?');
      values.push(data.email);
    }
    if (data.firstName !== undefined) {
      fields.push('first_name = ?');
      values.push(data.firstName);
    }
    if (data.lastName !== undefined) {
      fields.push('last_name = ?');
      values.push(data.lastName);
    }
    if (data.profileImageUrl !== undefined) {
      fields.push('profile_image_url = ?');
      values.push(data.profileImageUrl);
    }
    if (data.passwordHash !== undefined) {
      fields.push('password_hash = ?');
      values.push(data.passwordHash);
    }
    if (data.zkCredentialHash !== undefined) {
      fields.push('zk_credential_hash = ?');
      values.push(data.zkCredentialHash);
    }
    if (data.isEmailVerified !== undefined) {
      fields.push('is_email_verified = ?');
      values.push(data.isEmailVerified);
    }
    if (data.role !== undefined) {
      fields.push('role = ?');
      values.push(data.role);
    }
    if (data.lastLoginAt !== undefined) {
      fields.push('last_login_at = ?');
      values.push(data.lastLoginAt);
    }

    if (fields.length === 0) {
      return await this.getUser(id);
    }

    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);

    await this.pool.execute(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      values.filter(v => v !== undefined)
    );

    return await this.getUser(id);
  }

  // ============================================
  // ZK CREDENTIALS
  // ============================================

  async getZkCredential(id: number): Promise<ZkCredential | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM zk_credentials WHERE id = ?',
      [id]
    );
    return rows[0] as ZkCredential | undefined;
  }

  async getZkCredentialsByUser(userId: string): Promise<ZkCredential[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM zk_credentials WHERE user_id = ?',
      [userId]
    );
    return rows as ZkCredential[];
  }

  async getZkCredentialByCommitment(commitment: string): Promise<ZkCredential | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM zk_credentials WHERE public_commitment = ?',
      [commitment]
    );
    return rows[0] as ZkCredential | undefined;
  }

  async createZkCredential(credential: InsertZkCredential): Promise<ZkCredential> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO zk_credentials (user_id, credential_type, public_commitment, 
       credential_hash, expires_at, is_revoked, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        credential.userId,
        credential.credentialType || 'space_child_identity',
        credential.publicCommitment,
        credential.credentialHash,
        credential.expiresAt,
        credential.isRevoked || false,
        credential.metadata ? JSON.stringify(credential.metadata) : null
      ]
    );

    const newCredential = await this.getZkCredential(result.insertId);
    if (!newCredential) throw new Error('Failed to create ZK credential');
    return newCredential;
  }

  async revokeZkCredential(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE zk_credentials SET is_revoked = 1 WHERE id = ?',
      [id]
    );
  }

  // ============================================
  // PROOF SESSIONS
  // ============================================

  async getProofSession(sessionId: string): Promise<ProofSession | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM proof_sessions WHERE session_id = ?',
      [sessionId]
    );
    return rows[0] as ProofSession | undefined;
  }

  async createProofSession(session: InsertProofSession): Promise<ProofSession> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO proof_sessions (session_id, user_id, challenge, proof_type, 
       status, expires_at, verified_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        session.sessionId,
        session.userId || null,
        session.challenge,
        session.proofType || 'auth',
        session.status || 'pending',
        session.expiresAt,
        session.verifiedAt || null
      ]
    );

    const newSession = await this.getProofSession(session.sessionId);
    if (!newSession) throw new Error('Failed to create proof session');
    return newSession;
  }

  async updateProofSession(id: number, data: Partial<InsertProofSession>): Promise<ProofSession | undefined> {
    const fields = [];
    const values = [];

    if (data.status !== undefined) {
      fields.push('status = ?');
      values.push(data.status);
    }
    if (data.userId !== undefined) {
      fields.push('user_id = ?');
      values.push(data.userId);
    }
    if (data.verifiedAt !== undefined) {
      fields.push('verified_at = ?');
      values.push(data.verifiedAt);
    }

    if (fields.length === 0) {
      const [rows] = await this.pool.execute<RowDataPacket[]>(
        'SELECT * FROM proof_sessions WHERE id = ?',
        [id]
      );
      return rows[0] as ProofSession | undefined;
    }

    values.push(id);

    await this.pool.execute(
      `UPDATE proof_sessions SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM proof_sessions WHERE id = ?',
      [id]
    );
    return rows[0] as ProofSession | undefined;
  }

  // ============================================
  // REFRESH TOKENS
  // ============================================

  async getRefreshToken(tokenHash: string): Promise<RefreshToken | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM refresh_tokens WHERE token_hash = ?',
      [tokenHash]
    );
    return rows[0] as RefreshToken | undefined;
  }

  async getRefreshTokensByUser(userId: string): Promise<RefreshToken[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    return rows as RefreshToken[];
  }

  async createRefreshToken(token: InsertRefreshToken): Promise<RefreshToken> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO refresh_tokens (user_id, token_hash, device_info, subdomain, 
       expires_at, is_revoked)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        token.userId,
        token.tokenHash,
        token.deviceInfo || null,
        token.subdomain || null,
        token.expiresAt,
        token.isRevoked || false
      ]
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM refresh_tokens WHERE id = ?',
      [result.insertId]
    );
    return rows[0] as RefreshToken;
  }

  async revokeRefreshToken(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?',
      [id]
    );
  }

  async revokeAllUserRefreshTokens(userId: string): Promise<void> {
    await this.pool.execute(
      'UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?',
      [userId]
    );
  }

  // ============================================
  // SUBDOMAIN ACCESS
  // ============================================

  async getSubdomainAccess(userId: string, subdomain: string): Promise<SubdomainAccess | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM subdomain_access WHERE user_id = ? AND subdomain = ?',
      [userId, subdomain]
    );
    return rows[0] as SubdomainAccess | undefined;
  }

  async createSubdomainAccess(access: InsertSubdomainAccess): Promise<SubdomainAccess> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO subdomain_access (user_id, subdomain, last_access_at, access_level)
       VALUES (?, ?, ?, ?)`,
      [
        access.userId,
        access.subdomain,
        access.lastAccessAt || null,
        access.accessLevel || 'user'
      ]
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM subdomain_access WHERE id = ?',
      [result.insertId]
    );
    return rows[0] as SubdomainAccess;
  }

  async updateSubdomainLastAccess(userId: string, subdomain: string): Promise<void> {
    await this.pool.execute(
      'UPDATE subdomain_access SET last_access_at = CURRENT_TIMESTAMP WHERE user_id = ? AND subdomain = ?',
      [userId, subdomain]
    );
  }

  // ============================================
  // EMAIL VERIFICATION TOKENS
  // ============================================

  async createEmailVerificationToken(token: InsertEmailVerificationToken): Promise<EmailVerificationToken> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, consumed_at)
       VALUES (?, ?, ?, ?)`,
      [token.userId, token.tokenHash, token.expiresAt, token.consumedAt || null]
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM email_verification_tokens WHERE id = ?',
      [result.insertId]
    );
    return rows[0] as EmailVerificationToken;
  }

  async getEmailVerificationTokenByUser(userId: string): Promise<EmailVerificationToken | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT * FROM email_verification_tokens 
       WHERE user_id = ? AND consumed_at IS NULL AND expires_at > NOW()
       ORDER BY sent_at DESC LIMIT 1`,
      [userId]
    );
    return rows[0] as EmailVerificationToken | undefined;
  }

  async consumeEmailVerificationToken(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE email_verification_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );
  }

  async invalidateUserVerificationTokens(userId: string): Promise<void> {
    await this.pool.execute(
      'UPDATE email_verification_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE user_id = ?',
      [userId]
    );
  }

  async findActiveVerificationTokens(): Promise<EmailVerificationToken[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM email_verification_tokens WHERE consumed_at IS NULL AND expires_at > NOW()'
    );
    return rows as EmailVerificationToken[];
  }

  // ============================================
  // PASSWORD RESET TOKENS
  // ============================================

  async createPasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, consumed_at)
       VALUES (?, ?, ?, ?)`,
      [token.userId, token.tokenHash, token.expiresAt, token.consumedAt || null]
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM password_reset_tokens WHERE id = ?',
      [result.insertId]
    );
    return rows[0] as PasswordResetToken;
  }

  async getPasswordResetTokenByUser(userId: string): Promise<PasswordResetToken | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT * FROM password_reset_tokens 
       WHERE user_id = ? AND consumed_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );
    return rows[0] as PasswordResetToken | undefined;
  }

  async consumePasswordResetToken(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE password_reset_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );
  }

  async invalidateUserPasswordResetTokens(userId: string): Promise<void> {
    await this.pool.execute(
      'UPDATE password_reset_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE user_id = ?',
      [userId]
    );
  }

  async findActiveResetTokens(): Promise<PasswordResetToken[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM password_reset_tokens WHERE consumed_at IS NULL AND expires_at > NOW()'
    );
    return rows as PasswordResetToken[];
  }

  // ============================================
  // MFA METHODS
  // ============================================

  async getMfaMethodsByUser(userId: string): Promise<MfaMethod[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM mfa_methods WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    return rows as MfaMethod[];
  }

  async createMfaMethod(method: InsertMfaMethod): Promise<MfaMethod> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      'INSERT INTO mfa_methods (user_id, type, name, is_enabled, last_used_at) VALUES (?, ?, ?, ?, ?)',
      [method.userId, method.type, method.name, method.isEnabled ?? true, method.lastUsedAt || null]
    );

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM mfa_methods WHERE id = ?',
      [result.insertId]
    );
    return rows[0] as MfaMethod;
  }

  async updateMfaMethodLastUsed(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE mfa_methods SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );
  }

  async disableMfaMethod(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE mfa_methods SET is_enabled = 0 WHERE id = ?',
      [id]
    );
  }

  async deleteMfaMethod(id: number): Promise<void> {
    await this.pool.execute('DELETE FROM mfa_methods WHERE id = ?', [id]);
  }

  // ============================================
  // TOTP SECRETS
  // ============================================

  async getTotpSecret(userId: string): Promise<TotpSecret | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM totp_secrets WHERE user_id = ?',
      [userId]
    );
    return rows[0] as TotpSecret | undefined;
  }

  async createTotpSecret(secret: InsertTotpSecret): Promise<TotpSecret> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, backup_codes_used)
       VALUES (?, ?, ?, ?)`,
      [
        secret.userId,
        secret.encryptedSecret,
        JSON.stringify(secret.backupCodes || []),
        JSON.stringify(secret.backupCodesUsed || [])
      ]
    );

    const newSecret = await this.getTotpSecret(secret.userId);
    if (!newSecret) throw new Error('Failed to create TOTP secret');
    return newSecret;
  }

  async deleteTotpSecret(userId: string): Promise<void> {
    await this.pool.execute('DELETE FROM totp_secrets WHERE user_id = ?', [userId]);
  }

  // ============================================
  // WEBAUTHN CREDENTIALS
  // ============================================

  async getWebauthnCredentials(userId: string): Promise<WebauthnCredential[]> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    return rows as WebauthnCredential[];
  }

  async getWebauthnCredentialById(credentialId: string): Promise<WebauthnCredential | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM webauthn_credentials WHERE credential_id = ?',
      [credentialId]
    );
    return rows[0] as WebauthnCredential | undefined;
  }

  async createWebauthnCredential(credential: InsertWebauthnCredential): Promise<WebauthnCredential> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, 
       transports, aaguid, device_type, backed_up, name, last_used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        credential.userId,
        credential.credentialId,
        credential.publicKey,
        credential.counter || 0,
        JSON.stringify(credential.transports || []),
        credential.aaguid || null,
        credential.deviceType || null,
        credential.backedUp || false,
        credential.name,
        credential.lastUsedAt || null
      ]
    );

    const newCredential = await this.getWebauthnCredentialById(credential.credentialId);
    if (!newCredential) throw new Error('Failed to create WebAuthn credential');
    return newCredential;
  }

  async updateWebauthnCounter(credentialId: string, counter: number): Promise<void> {
    await this.pool.execute(
      'UPDATE webauthn_credentials SET counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?',
      [counter, credentialId]
    );
  }

  async deleteWebauthnCredential(id: number): Promise<void> {
    await this.pool.execute('DELETE FROM webauthn_credentials WHERE id = ?', [id]);
  }

  // ============================================
  // MFA CHALLENGES
  // ============================================

  async getMfaChallenge(id: number): Promise<MfaChallenge | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM mfa_challenges WHERE id = ?',
      [id]
    );
    return rows[0] as MfaChallenge | undefined;
  }

  async createMfaChallenge(challenge: InsertMfaChallenge): Promise<MfaChallenge> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      'INSERT INTO mfa_challenges (user_id, challenge, type, expires_at, used_at) VALUES (?, ?, ?, ?, ?)',
      [challenge.userId, challenge.challenge, challenge.type, challenge.expiresAt, challenge.usedAt || null]
    );

    const newChallenge = await this.getMfaChallenge(result.insertId);
    if (!newChallenge) throw new Error('Failed to create MFA challenge');
    return newChallenge;
  }

  async consumeMfaChallenge(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE mfa_challenges SET used_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );
  }

  // ============================================
  // MFA PENDING LOGINS
  // ============================================

  async getMfaPendingLogin(partialToken: string): Promise<MfaPendingLogin | undefined> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT * FROM mfa_pending_logins WHERE partial_token = ?',
      [partialToken]
    );
    return rows[0] as MfaPendingLogin | undefined;
  }

  async createMfaPendingLogin(pendingLogin: InsertMfaPendingLogin): Promise<MfaPendingLogin> {
    const [result] = await this.pool.execute<ResultSetHeader>(
      `INSERT INTO mfa_pending_logins (user_id, partial_token, required_methods, 
       expires_at, completed_at) VALUES (?, ?, ?, ?, ?)`,
      [
        pendingLogin.userId,
        pendingLogin.partialToken,
        JSON.stringify(pendingLogin.requiredMethods),
        pendingLogin.expiresAt,
        pendingLogin.completedAt || null
      ]
    );

    const newPendingLogin = await this.getMfaPendingLogin(pendingLogin.partialToken);
    if (!newPendingLogin) throw new Error('Failed to create MFA pending login');
    return newPendingLogin;
  }

  async completeMfaPendingLogin(id: number): Promise<void> {
    await this.pool.execute(
      'UPDATE mfa_pending_logins SET completed_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );
  }

  // ============================================
  // NOTIFICATION PREFERENCES
  // ============================================

  async getNotificationPreferences(userId: string): Promise<NotificationPreferences | undefined> {
    // This table doesn't exist in our schema, so we'll create a simple implementation
    // or return default values
    return {
      userId,
      notificationEmail: null,
      newAppsEnabled: true,
      updatesEnabled: true,
      marketingEnabled: false
    };
  }

  async upsertNotificationPreferences(prefs: InsertNotificationPreferences): Promise<NotificationPreferences> {
    // For now, just return the input as we don't have this table in our schema
    return {
      userId: prefs.userId,
      notificationEmail: prefs.notificationEmail || null,
      newAppsEnabled: prefs.newAppsEnabled ?? true,
      updatesEnabled: prefs.updatesEnabled ?? true,
      marketingEnabled: prefs.marketingEnabled ?? false
    };
  }
}

// Export singleton instance
export const storage = new Storage(pool);