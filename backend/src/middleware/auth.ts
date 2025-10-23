import { Request, Response, NextFunction } from 'express';
import { validateSession, SessionUser, Session } from '../lib/session';
import { logger } from '../lib/logger';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: SessionUser;
      session?: Session;
    }
  }
}

/**
 * Validate session and attach user to request
 * This middleware runs on ALL requests
 */
export async function authenticateRequest(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const sessionToken = req.cookies.session;

  if (!sessionToken) {
    req.user = undefined;
    req.session = undefined;
    return next();
  }

  try {
    const { session, user } = await validateSession(sessionToken);

    if (!session || !user) {
      res.clearCookie('session');
      req.user = undefined;
      req.session = undefined;
      return next();
    }

    req.session = session;
    req.user = user;
    next();
  } catch (error) {
    logger.error('Session validation error', { error });
    res.clearCookie('session');
    req.user = undefined;
    req.session = undefined;
    next();
  }
}

/**
 * Require authenticated user
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

/**
 * Require specific role(s)
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
      return;
    }

    next();
  };
}

/**
 * Require email verification
 */
export function requireEmailVerified(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  if (!req.user.emailVerified) {
    res.status(403).json({
      error: 'Email verification required',
      message: 'Please verify your email address to access this resource',
    });
    return;
  }

  next();
}
