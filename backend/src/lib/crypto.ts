import { sha256 } from '@oslojs/crypto/sha2';
import { encodeHexLowerCase, encodeBase32LowerCaseNoPadding } from '@oslojs/encoding';
import { prisma } from './db';

const TOKEN_LENGTH = 32; // 256 bits

/**
 * Generate a secure random token
 */
export function generateSecureToken(): string {
  const bytes = new Uint8Array(TOKEN_LENGTH);
  crypto.getRandomValues(bytes);
  return encodeBase32LowerCaseNoPadding(bytes);
}

/**
 * Hash a token with SHA-256
 */
export function hashToken(token: string): string {
  return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
}

/**
 * Generate email verification token
 */
export async function generateVerificationToken(
  userId: string,
  expiresInHours: number = 24
): Promise<string> {
  const token = generateSecureToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

  // Delete any existing verification tokens for this user
  await prisma.verificationToken.deleteMany({
    where: {
      userId,
      type: 'EMAIL_VERIFICATION',
    },
  });

  // Create new token
  await prisma.verificationToken.create({
    data: {
      userId,
      token: tokenHash,
      type: 'EMAIL_VERIFICATION',
      expiresAt,
    },
  });

  return token; // Return plaintext token to send via email
}

/**
 * Verify email verification token
 */
export async function verifyEmailToken(token: string): Promise<string | null> {
  const tokenHash = hashToken(token);

  const verificationToken = await prisma.verificationToken.findUnique({
    where: {
      token: tokenHash,
    },
  });

  if (!verificationToken) {
    return null;
  }

  // Check if expired
  if (Date.now() >= verificationToken.expiresAt.getTime()) {
    await prisma.verificationToken.delete({ where: { id: verificationToken.id } });
    return null;
  }

  // Check token type
  if (verificationToken.type !== 'EMAIL_VERIFICATION') {
    return null;
  }

  // Mark email as verified
  await prisma.user.update({
    where: { id: verificationToken.userId },
    data: {
      emailVerified: true,
      emailVerifiedAt: new Date(),
    },
  });

  // Delete the token
  await prisma.verificationToken.delete({ where: { id: verificationToken.id } });

  return verificationToken.userId;
}

/**
 * Generate password reset token
 */
export async function generatePasswordResetToken(
  userId: string,
  expiresInHours: number = 1
): Promise<string> {
  const token = generateSecureToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

  // Delete any existing password reset tokens for this user
  await prisma.passwordResetToken.deleteMany({
    where: { userId },
  });

  // Create new token
  await prisma.passwordResetToken.create({
    data: {
      userId,
      token: tokenHash,
      expiresAt,
    },
  });

  return token;
}

/**
 * Verify and consume password reset token
 */
export async function verifyPasswordResetToken(token: string): Promise<string | null> {
  const tokenHash = hashToken(token);

  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { token: tokenHash },
  });

  if (!resetToken) {
    return null;
  }

  // Check if expired
  if (Date.now() >= resetToken.expiresAt.getTime()) {
    await prisma.passwordResetToken.delete({ where: { id: resetToken.id } });
    return null;
  }

  // Check if already used
  if (resetToken.usedAt) {
    return null;
  }

  // Mark as used (but don't delete - keep for audit trail)
  await prisma.passwordResetToken.update({
    where: { id: resetToken.id },
    data: { usedAt: new Date() },
  });

  return resetToken.userId;
}
