/**
 * WebAuthn Service - Passkey Implementation
 *
 * Basic WebAuthn/FIDO2 functionality for passwordless and second-factor authentication.
 * This is a simplified version - full WebAuthn implementation would require @simplewebauthn/server.
 */

import { v4 as uuidv4 } from "uuid";
import { storage } from "./storage";
import { authEvents } from "./events";
import type { User, WebauthnCredential, MfaChallenge } from "./types";

// WebAuthn Configuration
const RP_NAME = "SpaceChild Auth";
const RP_ID = process.env.WEBAUTHN_RP_ID || "localhost";
const ORIGIN = process.env.WEBAUTHN_ORIGIN || `https://${RP_ID}`;

// Challenge expiry
const CHALLENGE_EXPIRY = 5 * 60 * 1000; // 5 minutes

export interface RegistrationOptionsResult {
  options: any; // PublicKeyCredentialCreationOptions
  challengeId: number;
}

export interface AuthenticationOptionsResult {
  options: any; // PublicKeyCredentialRequestOptions  
  challengeId: number;
}

export interface CredentialInfo {
  id: number;
  credentialId: string;
  name: string;
  deviceType: string | null;
  backedUp: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

/**
 * WebAuthn Service - Simplified Implementation
 * 
 * Note: This is a basic implementation for project structure.
 * For production use, implement with @simplewebauthn/server and proper attestation verification.
 */
export class WebauthnService {
  private static instance: WebauthnService;

  private constructor() {}

  static getInstance(): WebauthnService {
    if (!WebauthnService.instance) {
      WebauthnService.instance = new WebauthnService();
    }
    return WebauthnService.instance;
  }

  /**
   * Get current RP ID and Origin based on environment
   */
  private getRpConfig(): { rpId: string; expectedOrigin: string } {
    return {
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
    };
  }

  // ============================================
  // Registration Methods
  // ============================================

  /**
   * Generate registration options for WebAuthn credential creation
   * Note: This is a stub implementation. Full implementation requires @simplewebauthn/server
   */
  async generateRegistrationOptions(
    user: User,
    authenticatorAttachment?: "platform" | "cross-platform"
  ): Promise<RegistrationOptionsResult> {
    console.warn("⚠️ WebAuthn registration options: Stub implementation. Use @simplewebauthn/server for production.");
    
    // Create a challenge for tracking
    const challenge = await storage.createMfaChallenge({
      userId: user.id,
      challenge: uuidv4(),
      type: "webauthn_register", 
      expiresAt: new Date(Date.now() + CHALLENGE_EXPIRY),
    });

    // Return a basic structure that matches the expected interface
    return {
      options: {
        rp: { name: RP_NAME, id: RP_ID },
        user: {
          id: user.id,
          name: user.email || user.id,
          displayName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : user.email || "User",
        },
        challenge: challenge.challenge,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        timeout: CHALLENGE_EXPIRY,
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
          ...(authenticatorAttachment ? { authenticatorAttachment } : {}),
        },
        attestation: "none",
      },
      challengeId: challenge.id,
    };
  }

  /**
   * Verify registration response and store credential
   * Note: This is a stub implementation
   */
  async verifyRegistration(
    userId: string,
    response: any,
    credentialName?: string
  ): Promise<{ success: boolean; credentialId?: string; error?: string }> {
    console.warn("⚠️ WebAuthn registration verification: Stub implementation. Use @simplewebauthn/server for production.");
    
    return {
      success: false,
      error: "WebAuthn registration not implemented. Use @simplewebauthn/server for production deployment."
    };
  }

  // ============================================
  // Authentication Methods  
  // ============================================

  /**
   * Generate authentication options for WebAuthn assertion
   * Note: This is a stub implementation
   */
  async generateAuthenticationOptions(
    userId?: string
  ): Promise<AuthenticationOptionsResult> {
    console.warn("⚠️ WebAuthn authentication options: Stub implementation. Use @simplewebauthn/server for production.");

    // Create a challenge for tracking
    const challenge = await storage.createMfaChallenge({
      userId: userId || "anonymous",
      challenge: uuidv4(),
      type: "webauthn_authenticate",
      expiresAt: new Date(Date.now() + CHALLENGE_EXPIRY),
    });

    return {
      options: {
        challenge: challenge.challenge,
        rpId: RP_ID,
        timeout: CHALLENGE_EXPIRY,
        userVerification: "preferred",
      },
      challengeId: challenge.id,
    };
  }

  /**
   * Verify authentication response
   * Note: This is a stub implementation
   */
  async verifyAuthentication(
    response: any,
    userId?: string
  ): Promise<{ success: boolean; userId?: string; credentialId?: string; error?: string }> {
    console.warn("⚠️ WebAuthn authentication verification: Stub implementation. Use @simplewebauthn/server for production.");
    
    return {
      success: false,
      error: "WebAuthn authentication not implemented. Use @simplewebauthn/server for production deployment."
    };
  }

  // ============================================
  // Credential Management
  // ============================================

  /**
   * Get user's WebAuthn credentials
   */
  async getUserCredentials(userId: string): Promise<CredentialInfo[]> {
    const credentials = await storage.getWebauthnCredentials(userId);
    return credentials.map(cred => ({
      id: cred.id,
      credentialId: cred.credentialId,
      name: cred.name,
      deviceType: cred.deviceType,
      backedUp: cred.backedUp,
      createdAt: cred.createdAt,
      lastUsedAt: cred.lastUsedAt,
    }));
  }

  /**
   * Delete a WebAuthn credential
   */
  async deleteCredential(userId: string, credentialId: number): Promise<void> {
    const credentials = await storage.getWebauthnCredentials(userId);
    const credential = credentials.find(c => c.id === credentialId);
    
    if (!credential) {
      throw new Error("Credential not found");
    }

    await storage.deleteWebauthnCredential(credentialId);

    // If this was the last WebAuthn credential, disable the MFA method
    const remaining = await storage.getWebauthnCredentials(userId);
    if (remaining.length === 0) {
      const methods = await storage.getMfaMethodsByUser(userId);
      const webauthnMethod = methods.find(m => m.type === "webauthn");
      if (webauthnMethod) {
        await storage.disableMfaMethod(webauthnMethod.id);
        
        // Emit MFA disabled event
        authEvents.mfaDisabled({
          userId,
          method: "webauthn",
        });
      }
    }
  }

  /**
   * Generate a user-friendly name for a credential
   */
  private generateCredentialName(deviceType?: string | null, backedUp?: boolean): string {
    if (backedUp) {
      return "Passkey (Synced)";
    }
    
    switch (deviceType) {
      case "singleDevice":
        return "Security Key";
      case "multiDevice":
        return "Passkey";
      default:
        return "Security Key";
    }
  }

  /**
   * Check if WebAuthn is supported (always return false in this stub)
   */
  isWebAuthnSupported(): boolean {
    return false; // Since this is a stub implementation
  }
}

// Export singleton instance
export const webauthnService = WebauthnService.getInstance();

// Export class for testing
export { WebauthnService };