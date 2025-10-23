import { prisma } from './db';
import { sha256 } from '@oslojs/crypto/sha2';
import { encodeHexLowerCase } from '@oslojs/encoding';

// Session configuration from environment
const SESSION_DURATION_DAYS = parseInt(process.env.SESSION_DURATION_DAYS || '30');
const SESSION_DURATION_MS = SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000;
const SESSION_REFRESH_THRESHOLD_MS = SESSION_DURATION_MS / 2; // Refresh at 50%

export interface Session {
  id: string;
  userId: string;
  expiresAt: Date;
  ipAddress: string;
  userAgent: string;
}

export interface SessionUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  emailVerified: boolean;
}

/**
 * Generate a cryptographically secure session token (160 bits)
 */
export function generateSessionToken(): string {
  const bytes = new Uint8Array(20); // 160 bits
  crypto.getRandomValues(bytes);
  return encodeHexLowerCase(bytes);
}

/**
 * Hash session token with SHA-256 for storage
 */
function hashToken(token: string): string {
  return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
}

/**
 * Create a new session
 */
export async function createSession(
  userId: string,
  ipAddress: string,
  userAgent: string
): Promise<{ session: Session; token: string }> {
  const token = generateSessionToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

  const session = await prisma.session.create({
    data: {
      userId,
      token: tokenHash,
      expiresAt,
      ipAddress,
      userAgent,
    },
  });

  return {
    session,
    token, // Return plaintext token to set in cookie
  };
}

/**
 * Validate session token and return session + user
 * Implements sliding window expiration
 */
export async function validateSession(
  token: string
): Promise<{ session: Session | null; user: SessionUser | null }> {
  const tokenHash = hashToken(token);

  const session = await prisma.session.findUnique({
    where: { token: tokenHash },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          emailVerified: true,
          isActive: true,
          lockedUntil: true,
        },
      },
    },
  });

  if (!session) {
    return { session: null, user: null };
  }

  // Check if expired
  if (Date.now() >= session.expiresAt.getTime()) {
    await prisma.session.delete({ where: { id: session.id } });
    return { session: null, user: null };
  }

  // Check if user is locked
  if (session.user.lockedUntil && Date.now() < session.user.lockedUntil.getTime()) {
    return { session: null, user: null };
  }

  // Check if user is inactive
  if (!session.user.isActive) {
    return { session: null, user: null };
  }

  // Sliding window: Refresh session if past threshold
  const shouldRefresh =
    Date.now() >= session.expiresAt.getTime() - SESSION_REFRESH_THRESHOLD_MS;

  if (shouldRefresh) {
    const newExpiresAt = new Date(Date.now() + SESSION_DURATION_MS);
    await prisma.session.update({
      where: { id: session.id },
      data: { expiresAt: newExpiresAt },
    });
    session.expiresAt = newExpiresAt;
  }

  const user: SessionUser = {
    id: session.user.id,
    email: session.user.email,
    firstName: session.user.firstName,
    lastName: session.user.lastName,
    role: session.user.role,
    emailVerified: session.user.emailVerified,
  };

  return { session, user };
}

/**
 * Invalidate a session
 */
export async function invalidateSession(sessionId: string): Promise<void> {
  await prisma.session.delete({ where: { id: sessionId } }).catch(() => {
    // Session may already be deleted
  });
}

/**
 * Invalidate all sessions for a user
 */
export async function invalidateUserSessions(userId: string): Promise<void> {
  await prisma.session.deleteMany({ where: { userId } });
}

/**
 * Clean up expired sessions (should be run periodically)
 */
export async function cleanupExpiredSessions(): Promise<number> {
  const result = await prisma.session.deleteMany({
    where: {
      expiresAt: {
        lt: new Date(),
      },
    },
  });
  return result.count;
}

/**
 * Clean up expired tokens (verification and password reset)
 */
export async function cleanupExpiredTokens(): Promise<{
  verificationTokens: number;
  passwordResetTokens: number;
}> {
  const now = new Date();

  const [verification, passwordReset] = await Promise.all([
    prisma.verificationToken.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
    prisma.passwordResetToken.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
  ]);

  return {
    verificationTokens: verification.count,
    passwordResetTokens: passwordReset.count,
  };
}
