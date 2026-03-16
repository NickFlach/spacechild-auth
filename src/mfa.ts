/**
 * MFA Service - TOTP Implementation
 *
 * Provides TOTP (Time-based One-Time Password) functionality for multi-factor authentication.
 * Uses RFC 6238 compliant TOTP with 30-second time steps.
 * Ported from space-child-dream with storage layer rewired.
 */

import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import { storage } from "./storage";
import { authEvents } from "./events";
import type { User, MfaMethod, TotpSecret, MfaPendingLogin, PendingLoginResult } from "./types";

// TOTP Configuration
const TOTP_ISSUER = "SpaceChild Auth";
const TOTP_ALGORITHM = "SHA1";
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30; // seconds
const TOTP_WINDOW = 1; // Allow 1 period before/after for clock skew

// Backup Codes Configuration
const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LENGTH = 8;

// Pending Login Configuration
const PENDING_LOGIN_EXPIRY = 5 * 60 * 1000; // 5 minutes

// Encryption for TOTP secrets (using SESSION_SECRET as key)
const ENCRYPTION_ALGORITHM = "aes-256-gcm";

function deriveEncryptionKey(salt: Buffer): Buffer {
  const secret = process.env.SESSION_SECRET || "";
  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters for MFA encryption");
  }
  return crypto.scryptSync(secret, salt, 32);
}

function encryptSecret(plaintext: string): string {
  const salt = crypto.randomBytes(16);
  const key = deriveEncryptionKey(salt);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");

  const authTag = cipher.getAuthTag();

  // Return: salt:iv:authTag:encrypted (all hex)
  return `${salt.toString("hex")}:${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
}

function decryptSecret(encryptedData: string): string {
  const parts = encryptedData.split(":");
  if (parts.length !== 4) {
    throw new Error("Invalid encrypted data format");
  }

  const salt = Buffer.from(parts[0], "hex");
  const iv = Buffer.from(parts[1], "hex");
  const authTag = Buffer.from(parts[2], "hex");
  const encrypted = parts[3];

  const key = deriveEncryptionKey(salt);
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

function generateBackupCodes(): string[] {
  const codes = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    codes.push(crypto.randomBytes(BACKUP_CODE_LENGTH).toString("hex").toUpperCase());
  }
  return codes;
}

async function hashBackupCodes(codes: string[]): Promise<string[]> {
  return Promise.all(codes.map(code => bcrypt.hash(code, 10)));
}

class MfaService {
  private static instance: MfaService;

  private constructor() {}

  static getInstance(): MfaService {
    if (!MfaService.instance) {
      MfaService.instance = new MfaService();
    }
    return MfaService.instance;
  }

  // ============================================
  // MFA STATUS
  // ============================================

  async userRequiresMfa(userId: string): Promise<boolean> {
    const methods = await storage.getMfaMethodsByUser(userId);
    return methods.some(method => method.isEnabled);
  }

  async getMfaStatus(userId: string): Promise<{
    hasMfa: boolean;
    methods: MfaMethod[];
    hasTotp: boolean;
    hasWebauthn: boolean;
    webauthnCredentialCount: number;
  }> {
    const methods = await storage.getMfaMethodsByUser(userId);
    const webauthnCredentials = await storage.getWebauthnCredentials(userId);

    return {
      hasMfa: methods.some(method => method.isEnabled),
      methods,
      hasTotp: methods.some(method => method.type === "totp" && method.isEnabled),
      hasWebauthn: methods.some(method => method.type === "webauthn" && method.isEnabled),
      webauthnCredentialCount: webauthnCredentials.length,
    };
  }

  // ============================================
  // TOTP SETUP
  // ============================================

  async setupTotp(userId: string): Promise<{
    secret: string;
    otpauthUri: string;
    qrCodeUrl: string;
    backupCodes: string[];
  }> {
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error("User not found");
    }

    // Check if TOTP is already enabled
    const existingSecret = await storage.getTotpSecret(userId);
    if (existingSecret) {
      throw new Error("TOTP is already enabled for this user");
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: user.email || user.id,
      issuer: TOTP_ISSUER,
      length: 32,
    });

    // Generate backup codes
    const backupCodes = generateBackupCodes();
    const hashedBackupCodes = await hashBackupCodes(backupCodes);

    // Encrypt and store secret
    const encryptedSecret = encryptSecret(secret.base32!);
    await storage.createTotpSecret({
      userId,
      encryptedSecret,
      backupCodes: hashedBackupCodes,
      backupCodesUsed: [],
    });

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url!);

    return {
      secret: secret.base32!,
      otpauthUri: secret.otpauth_url!,
      qrCodeUrl,
      backupCodes,
    };
  }

  async verifyTotpSetup(userId: string, token: string): Promise<boolean> {
    const totpSecret = await storage.getTotpSecret(userId);
    if (!totpSecret) {
      throw new Error("TOTP secret not found");
    }

    const secret = decryptSecret(totpSecret.encryptedSecret);

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: TOTP_WINDOW,
    });

    if (verified) {
      // Enable TOTP method
      await storage.createMfaMethod({
        userId,
        type: "totp",
        name: "Authenticator App",
        isEnabled: true,
      });

      // Emit MFA enabled event
      authEvents.mfaEnabled({
        userId,
        method: "totp",
      });
    }

    return verified;
  }

  async verifyTotpToken(userId: string, token: string): Promise<boolean> {
    // First try regular TOTP token
    const totpSecret = await storage.getTotpSecret(userId);
    if (!totpSecret) {
      return false;
    }

    const secret = decryptSecret(totpSecret.encryptedSecret);

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: TOTP_WINDOW,
    });

    if (verified) {
      // Update last used timestamp
      const methods = await storage.getMfaMethodsByUser(userId);
      const totpMethod = methods.find(m => m.type === "totp");
      if (totpMethod) {
        await storage.updateMfaMethodLastUsed(totpMethod.id);
      }

      return true;
    }

    // Try backup code
    return this.verifyBackupCode(userId, token);
  }

  private async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const totpSecret = await storage.getTotpSecret(userId);
    if (!totpSecret) {
      return false;
    }

    for (let i = 0; i < totpSecret.backupCodes.length; i++) {
      if (totpSecret.backupCodesUsed.includes(i)) {
        continue; // Already used
      }

      const isMatch = await bcrypt.compare(code.toUpperCase(), totpSecret.backupCodes[i]);
      if (isMatch) {
        // Mark backup code as used
        const usedCodes = [...totpSecret.backupCodesUsed, i];
        await storage.createTotpSecret({
          userId,
          encryptedSecret: totpSecret.encryptedSecret,
          backupCodes: totpSecret.backupCodes,
          backupCodesUsed: usedCodes,
        });

        return true;
      }
    }

    return false;
  }

  async disableTotp(userId: string): Promise<void> {
    // Remove TOTP secret
    await storage.deleteTotpSecret(userId);

    // Disable TOTP method
    const methods = await storage.getMfaMethodsByUser(userId);
    const totpMethod = methods.find(m => m.type === "totp");
    if (totpMethod) {
      await storage.disableMfaMethod(totpMethod.id);
    }

    // Emit MFA disabled event
    authEvents.mfaDisabled({
      userId,
      method: "totp",
    });
  }

  // ============================================
  // PENDING LOGIN MANAGEMENT
  // ============================================

  async createPendingLogin(user: User): Promise<PendingLoginResult> {
    const methods = await storage.getMfaMethodsByUser(user.id);
    const enabledMethods = methods.filter(m => m.isEnabled);

    if (enabledMethods.length === 0) {
      throw new Error("No MFA methods enabled for user");
    }

    const partialToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: "partial_auth",
      },
      process.env.SESSION_SECRET!,
      {
        expiresIn: "5m",
        issuer: "spacechild-auth",
      }
    );

    const availableMethods = enabledMethods.map(m => m.type);
    const expiresAt = new Date(Date.now() + PENDING_LOGIN_EXPIRY);

    await storage.createMfaPendingLogin({
      userId: user.id,
      partialToken,
      requiredMethods: availableMethods,
      expiresAt,
    });

    return {
      partialToken,
      requiresMfa: true,
      availableMethods,
      expiresAt,
    };
  }

  async completeMfaLogin(partialToken: string, method: string, token: string): Promise<{
    success: boolean;
    error?: string;
    user?: User;
  }> {
    try {
      // Verify partial token
      const payload = jwt.verify(partialToken, process.env.SESSION_SECRET!, {
        issuer: "spacechild-auth",
      }) as any;

      if (payload.type !== "partial_auth") {
        return { success: false, error: "Invalid token type" };
      }

      // Get pending login
      const pendingLogin = await storage.getMfaPendingLogin(partialToken);
      if (!pendingLogin) {
        return { success: false, error: "Pending login not found" };
      }

      if (new Date() > pendingLogin.expiresAt) {
        return { success: false, error: "MFA login expired" };
      }

      if (pendingLogin.completedAt) {
        return { success: false, error: "MFA already completed" };
      }

      // Verify MFA token
      let verified = false;
      if (method === "totp") {
        verified = await this.verifyTotpToken(payload.userId, token);
      } else if (method === "webauthn") {
        // WebAuthn verification would be handled separately
        return { success: false, error: "WebAuthn not implemented in this service" };
      }

      if (!verified) {
        return { success: false, error: "Invalid MFA token" };
      }

      // Complete pending login
      await storage.completeMfaPendingLogin(pendingLogin.id);

      // Get user
      const user = await storage.getUser(payload.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      // Emit MFA verification event
      authEvents.mfaVerified({
        userId: user.id,
        method,
      });

      return { success: true, user };
    } catch (error: any) {
      console.error("MFA completion error:", error);
      return { success: false, error: error.message || "MFA completion failed" };
    }
  }

  // ============================================
  // BACKUP CODE MANAGEMENT
  // ============================================

  async generateNewBackupCodes(userId: string): Promise<string[]> {
    const totpSecret = await storage.getTotpSecret(userId);
    if (!totpSecret) {
      throw new Error("TOTP not enabled for this user");
    }

    const backupCodes = generateBackupCodes();
    const hashedBackupCodes = await hashBackupCodes(backupCodes);

    // Update with new backup codes (reset used codes)
    await storage.createTotpSecret({
      userId,
      encryptedSecret: totpSecret.encryptedSecret,
      backupCodes: hashedBackupCodes,
      backupCodesUsed: [],
    });

    return backupCodes;
  }

  async getRemainingBackupCodes(userId: string): Promise<number> {
    const totpSecret = await storage.getTotpSecret(userId);
    if (!totpSecret) {
      return 0;
    }

    return totpSecret.backupCodes.length - totpSecret.backupCodesUsed.length;
  }
}

// Export singleton instance
export const mfaService = MfaService.getInstance();

// Export class for testing
export { MfaService };