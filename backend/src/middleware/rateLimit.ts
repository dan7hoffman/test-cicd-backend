import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for auth endpoints (login, register)
 * Stricter limits to prevent brute force attacks
 * Relaxed in test environment to allow rapid test execution
 */
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'test' ? 1000 : 5, // High limit for tests
  message: {
    error: 'Too many attempts',
    message: 'Too many login/register attempts. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
});

/**
 * Rate limiter for email-related endpoints
 * Prevents spam and abuse
 * Relaxed in test environment
 */
export const emailRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: process.env.NODE_ENV === 'test' ? 1000 : 3, // High limit for tests
  message: {
    error: 'Too many email requests',
    message: 'Too many email requests. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for password reset endpoints
 * Relaxed in test environment
 */
export const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: process.env.NODE_ENV === 'test' ? 1000 : 3, // High limit for tests
  message: {
    error: 'Too many password reset attempts',
    message: 'Too many password reset requests. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * General API rate limiter
 * More lenient for regular API usage
 * Even more lenient in test environment
 */
export const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'test' ? 10000 : 100, // Very high limit for tests
  message: {
    error: 'Too many requests',
    message: 'Too many requests. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
