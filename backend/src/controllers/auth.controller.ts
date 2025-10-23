import { Request, Response, NextFunction } from 'express';
import { hash, verify } from 'argon2';
import { prisma } from '../lib/db';
import { createSession, invalidateSession, invalidateUserSessions } from '../lib/session';
import {
  registerSchema,
  loginSchema,
  emailVerificationSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  changePasswordSchema,
  updateProfileSchema,
} from '../lib/validators';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
} from '../lib/email';
import {
  generateVerificationToken,
  verifyEmailToken,
  generatePasswordResetToken,
  verifyPasswordResetToken,
} from '../lib/crypto';

// Argon2 configuration (OWASP recommended)
const ARGON2_OPTIONS = {
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
};

// Configuration from environment
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
const LOCKOUT_DURATION_MINUTES = parseInt(process.env.LOCKOUT_DURATION_MINUTES || '15');
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION !== 'false';

export class AuthController {
  /**
   * Register a new user
   */
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = registerSchema.parse(req.body);

      // Check if user exists
      const existingUser = await prisma.user.findUnique({
        where: { email: data.email },
      });

      if (existingUser) {
        // Prevent email enumeration: return same success message
        // Optionally: send security notification email to existing user
        // (not implemented here to avoid spamming legitimate users)
        res.status(201).json({
          message: 'Registration successful! Please check your email to verify your account.',
        });
        return;
      }

      // Hash password with Argon2id
      const passwordHash = await hash(data.password, ARGON2_OPTIONS);

      // Create user
      const user = await prisma.user.create({
        data: {
          email: data.email,
          passwordHash,
          firstName: data.firstName,
          lastName: data.lastName,
        },
      });

      // Generate email verification token
      const verificationToken = await generateVerificationToken(user.id);

      // Send verification email
      await sendVerificationEmail(user.email, verificationToken);

      // Create session
      const ipAddress =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket.remoteAddress ||
        'unknown';
      const userAgent = req.headers['user-agent'] || 'unknown';

      const { token } = await createSession(user.id, ipAddress, userAgent);

      // Set cookie
      res.cookie('session', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          emailVerified: user.emailVerified,
        },
        message: 'Registration successful. Please check your email to verify your account.',
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Login
   */
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = loginSchema.parse(req.body);

      // Find user
      const user = await prisma.user.findUnique({
        where: { email: data.email },
      });

      if (!user) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      // Check if account is locked
      if (user.lockedUntil && Date.now() < user.lockedUntil.getTime()) {
        const minutesLeft = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
        res.status(423).json({
          error: `Account locked due to too many failed login attempts. Try again in ${minutesLeft} minutes.`,
        });
        return;
      }

      // Verify password with Argon2
      const isValidPassword = await verify(user.passwordHash, data.password);

      if (!isValidPassword) {
        // Increment failed attempts
        const failedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = failedAttempts >= MAX_LOGIN_ATTEMPTS;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: failedAttempts,
            lastFailedLoginAt: new Date(),
            lockedUntil: shouldLock
              ? new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000)
              : null,
          },
        });

        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      // Check if email verified (if required)
      if (REQUIRE_EMAIL_VERIFICATION && !user.emailVerified) {
        res.status(403).json({
          error: 'Please verify your email before logging in',
        });
        return;
      }

      // Reset failed attempts on successful login
      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lastFailedLoginAt: null,
          lastLoginAt: new Date(),
        },
      });

      // Session fixation prevention: Invalidate all existing sessions before creating new one
      // This ensures that any pre-existing sessions (even if compromised) are invalidated
      await prisma.session.deleteMany({
        where: { userId: user.id },
      });

      // Create session
      const ipAddress =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket.remoteAddress ||
        'unknown';
      const userAgent = req.headers['user-agent'] || 'unknown';

      const { token } = await createSession(user.id, ipAddress, userAgent);

      // Set cookie
      res.cookie('session', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });

      res.json({
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Logout
   */
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (req.session) {
        await invalidateSession(req.session.id);
      }

      res.clearCookie('session');
      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get current user
   */
  async me(req: Request, res: Response): Promise<void> {
    if (!req.user) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }

    res.json({ user: req.user });
  }

  /**
   * Verify email
   */
  async verifyEmail(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { token } = emailVerificationSchema.parse(req.body);

      const userId = await verifyEmailToken(token);

      if (!userId) {
        res.status(400).json({ error: 'Invalid or expired verification token' });
        return;
      }

      // Get user details
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, firstName: true },
      });

      if (user) {
        // Send welcome email
        await sendWelcomeEmail(user.email, user.firstName);
      }

      res.json({ message: 'Email verified successfully' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resend verification email
   */
  async resendVerification(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      if (req.user.emailVerified) {
        res.status(400).json({ error: 'Email already verified' });
        return;
      }

      // Generate new verification token
      const verificationToken = await generateVerificationToken(req.user.id);

      // Send verification email
      await sendVerificationEmail(req.user.email, verificationToken);

      res.json({ message: 'Verification email sent. Please check your inbox.' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { email } = passwordResetRequestSchema.parse(req.body);

      const user = await prisma.user.findUnique({
        where: { email },
      });

      // Always return success to prevent email enumeration
      if (!user) {
        res.json({
          message: 'If that email exists, a password reset link has been sent.',
        });
        return;
      }

      // Generate reset token
      const resetToken = await generatePasswordResetToken(user.id);

      // Send reset email
      await sendPasswordResetEmail(user.email, resetToken);

      res.json({
        message: 'If that email exists, a password reset link has been sent.',
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset password
   */
  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { token, password } = passwordResetSchema.parse(req.body);

      const userId = await verifyPasswordResetToken(token);

      if (!userId) {
        res.status(400).json({ error: 'Invalid or expired reset token' });
        return;
      }

      // Hash new password
      const passwordHash = await hash(password, ARGON2_OPTIONS);

      // Update password and invalidate all sessions
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash },
      });

      await invalidateUserSessions(userId);

      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Change password (requires current password)
   */
  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const { currentPassword, newPassword } = changePasswordSchema.parse(req.body);

      // Get user with password hash
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: { id: true, passwordHash: true },
      });

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Verify current password
      const validPassword = await verify(user.passwordHash, currentPassword);
      if (!validPassword) {
        res.status(400).json({ error: 'Current password is incorrect' });
        return;
      }

      // Hash new password
      const newPasswordHash = await hash(newPassword, ARGON2_OPTIONS);

      // Update password
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newPasswordHash },
      });

      // Invalidate all sessions except current one
      await invalidateUserSessions(user.id);

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update user profile (name only for now)
   */
  async updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const updateData = updateProfileSchema.parse(req.body);

      const user = await prisma.user.update({
        where: { id: req.user.id },
        data: updateData,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          emailVerified: true,
          createdAt: true,
        },
      });

      res.json({ user });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete account (requires password confirmation)
   */
  async deleteAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const { password } = req.body;

      if (!password) {
        res.status(400).json({ error: 'Password confirmation required' });
        return;
      }

      // Get user with password hash
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: { id: true, passwordHash: true },
      });

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Verify password
      const validPassword = await verify(user.passwordHash, password);
      if (!validPassword) {
        res.status(400).json({ error: 'Password is incorrect' });
        return;
      }

      // Delete all user sessions first
      await invalidateUserSessions(user.id);

      // Delete user (cascades to related records based on Prisma schema)
      await prisma.user.delete({
        where: { id: user.id },
      });

      // Clear session cookie
      res.clearCookie('session', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
      });

      res.json({ message: 'Account deleted successfully' });
    } catch (error) {
      next(error);
    }
  }
}
