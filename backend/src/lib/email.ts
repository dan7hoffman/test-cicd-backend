import nodemailer from 'nodemailer';

// Create transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'localhost',
  port: parseInt(process.env.SMTP_PORT || '1025'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: process.env.SMTP_USER
    ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      }
    : undefined,
});

const FROM_EMAIL = process.env.SMTP_FROM || 'noreply@example.com';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:4200';

/**
 * Send email verification email
 */
export async function sendVerificationEmail(
  email: string,
  token: string
): Promise<void> {
  const verificationUrl = `${FRONTEND_URL}/verify-email?token=${token}`;

  await transporter.sendMail({
    from: FROM_EMAIL,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <h1>Verify Your Email</h1>
      <p>Thank you for signing up! Please click the link below to verify your email address:</p>
      <p><a href="${verificationUrl}">Verify Email</a></p>
      <p>Or copy and paste this link into your browser:</p>
      <p>${verificationUrl}</p>
      <p>This link will expire in 24 hours.</p>
      <p>If you didn't create an account, please ignore this email.</p>
    `,
    text: `
      Verify Your Email

      Thank you for signing up! Please visit the link below to verify your email address:
      ${verificationUrl}

      This link will expire in 24 hours.

      If you didn't create an account, please ignore this email.
    `,
  });
}

/**
 * Send password reset email
 */
export async function sendPasswordResetEmail(
  email: string,
  token: string
): Promise<void> {
  const resetUrl = `${FRONTEND_URL}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: FROM_EMAIL,
    to: email,
    subject: 'Reset Your Password',
    html: `
      <h1>Reset Your Password</h1>
      <p>You requested to reset your password. Click the link below to create a new password:</p>
      <p><a href="${resetUrl}">Reset Password</a></p>
      <p>Or copy and paste this link into your browser:</p>
      <p>${resetUrl}</p>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request a password reset, please ignore this email.</p>
    `,
    text: `
      Reset Your Password

      You requested to reset your password. Visit the link below to create a new password:
      ${resetUrl}

      This link will expire in 1 hour.

      If you didn't request a password reset, please ignore this email.
    `,
  });
}

/**
 * Send welcome email (after email verification)
 */
export async function sendWelcomeEmail(
  email: string,
  firstName: string
): Promise<void> {
  await transporter.sendMail({
    from: FROM_EMAIL,
    to: email,
    subject: 'Welcome to Our Platform!',
    html: `
      <h1>Welcome, ${firstName}!</h1>
      <p>Your email has been verified and your account is now active.</p>
      <p>You can now log in and start using our platform.</p>
      <p><a href="${FRONTEND_URL}/login">Log In</a></p>
    `,
    text: `
      Welcome, ${firstName}!

      Your email has been verified and your account is now active.

      You can now log in and start using our platform at:
      ${FRONTEND_URL}/login
    `,
  });
}
