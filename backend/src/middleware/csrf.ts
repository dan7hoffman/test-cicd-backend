import { doubleCsrf } from 'csrf-csrf';
import { Request, Response, NextFunction } from 'express';

// CSRF protection configuration
const {
  generateToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'default-secret-change-in-production',
  cookieName: '__Host-csrf',
  cookieOptions: {
    sameSite: 'strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getTokenFromRequest: (req) => req.headers['x-csrf-token'] as string,
});

/**
 * CSRF protection middleware
 * Validates CSRF tokens for state-changing operations
 * Disabled in test environment for easier testing
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  // Skip CSRF in test environment
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  doubleCsrfProtection(req, res, next);
};

/**
 * Generate CSRF token endpoint
 * GET /api/csrf-token
 */
export const generateCsrfToken = (req: Request, res: Response) => {
  const token = generateToken(req, res);
  res.json({ csrfToken: token });
};
