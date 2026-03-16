/**
 * Auth Middleware
 *
 * Express middleware for authentication and authorization.
 * Ported from space-child-dream auth module.
 */

import type { Request, Response, NextFunction } from "express";
import { authService } from "./auth-service";
import { storage } from "./storage";
import type { RateLimitEntry, RateLimitResult } from "./types";

// ============================================
// RATE LIMITING
// ============================================

const authRateLimits = new Map<string, RateLimitEntry>();
const AUTH_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const AUTH_MAX_ATTEMPTS = 5;
const AUTH_BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes block after max attempts

/**
 * Check rate limit for authentication attempts
 */
export function checkAuthRateLimit(identifier: string): RateLimitResult {
  const now = Date.now();
  const entry = authRateLimits.get(identifier);

  // Clean up old entries periodically
  if (authRateLimits.size > 10000) {
    const keysToDelete: string[] = [];
    authRateLimits.forEach((val, key) => {
      if (now - val.firstAttempt > AUTH_RATE_LIMIT_WINDOW_MS * 2) {
        keysToDelete.push(key);
      }
    });
    keysToDelete.forEach(key => authRateLimits.delete(key));
  }

  if (!entry) {
    authRateLimits.set(identifier, { attempts: 1, firstAttempt: now });
    return { allowed: true, attemptsLeft: AUTH_MAX_ATTEMPTS - 1 };
  }

  // Check if currently blocked
  if (entry.blockedUntil && now < entry.blockedUntil) {
    const remainingSeconds = Math.ceil((entry.blockedUntil - now) / 1000);
    return { allowed: false, remainingSeconds };
  }

  // Reset if window has passed
  if (now - entry.firstAttempt > AUTH_RATE_LIMIT_WINDOW_MS) {
    authRateLimits.set(identifier, { attempts: 1, firstAttempt: now });
    return { allowed: true, attemptsLeft: AUTH_MAX_ATTEMPTS - 1 };
  }

  // Increment attempts
  entry.attempts++;

  if (entry.attempts > AUTH_MAX_ATTEMPTS) {
    entry.blockedUntil = now + AUTH_BLOCK_DURATION_MS;
    const remainingSeconds = Math.ceil(AUTH_BLOCK_DURATION_MS / 1000);
    return { allowed: false, remainingSeconds };
  }

  return { allowed: true, attemptsLeft: AUTH_MAX_ATTEMPTS - entry.attempts };
}

/**
 * Clear rate limit on successful authentication
 */
export function clearAuthRateLimit(identifier: string): void {
  authRateLimits.delete(identifier);
}

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

/**
 * Require authentication - returns 401 if not authenticated
 */
export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // Check if already authenticated (e.g., by previous middleware)
    if ((req as any).user) {
      return next();
    }
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  authService.verifyAccessToken(token).then((payload) => {
    if (!payload) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    (req as any).user = {
      claims: {
        sub: payload.userId,
        email: payload.email,
        first_name: payload.firstName,
        last_name: payload.lastName,
      },
    };
    next();
  }).catch(() => {
    res.status(401).json({ message: "Token verification failed" });
  });
}

/**
 * Optional authentication - sets req.user if token is present
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }

  const token = authHeader.split(" ")[1];

  authService.verifyAccessToken(token).then((payload) => {
    if (payload) {
      (req as any).user = {
        claims: {
          sub: payload.userId,
          email: payload.email,
          first_name: payload.firstName,
          last_name: payload.lastName,
        },
      };
    }
    next();
  }).catch(() => {
    next();
  });
}

// ============================================
// AUTHORIZATION MIDDLEWARE
// ============================================

/**
 * Require admin role
 */
export async function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const claims = (req as any).user?.claims;
  if (!claims) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const user = await storage.getUser(claims.sub);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (user.role === "admin" || user.role === "super_admin") {
      (req as any).userRole = user.role;
      return next();
    }

    return res.status(403).json({ message: "Forbidden - Admin access required" });
  } catch (error) {
    console.error("Admin check error:", error);
    return res.status(500).json({ message: "Failed to verify admin access" });
  }
}

/**
 * Require specific role(s)
 */
export function requireRole(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const claims = (req as any).user?.claims;
    if (!claims) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const user = await storage.getUser(claims.sub);
      if (!user) {
        return res.status(401).json({ message: "User not found" });
      }

      if (roles.includes(user.role)) {
        (req as any).userRole = user.role;
        return next();
      }

      return res.status(403).json({ message: `Forbidden - Requires one of: ${roles.join(", ")}` });
    } catch (error) {
      console.error("Role check error:", error);
      return res.status(500).json({ message: "Failed to verify role" });
    }
  };
}

// ============================================
// SSO VALIDATION
// ============================================

const TRUSTED_SSO_DOMAINS = [
  "spacechild.love",
  "ninja-portal.com", 
  "localhost",
  "127.0.0.1",
];

/**
 * Validate SSO callback URL against trusted domains
 */
export function isValidSsoCallback(callbackUrl: string): boolean {
  try {
    const url = new URL(callbackUrl);
    const hostname = url.hostname.toLowerCase();

    return TRUSTED_SSO_DOMAINS.some(trusted => {
      if (trusted === "localhost" || trusted === "127.0.0.1") {
        return hostname === trusted;
      }
      return hostname === trusted || hostname.endsWith(`.${trusted}`);
    });
  } catch {
    return false;
  }
}

/**
 * Get client IP from request
 */
export function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}