import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { requireAuth } from '../middleware/auth';
import {
  authRateLimit,
  emailRateLimit,
  passwordResetRateLimit,
} from '../middleware/rateLimit';
import { csrfProtection, generateCsrfToken } from '../middleware/csrf';

const router = Router();
const authController = new AuthController();

// CSRF token endpoint (must be called before any POST requests)
router.get('/csrf-token', generateCsrfToken);

// Public routes with rate limiting and CSRF protection
router.post('/register', csrfProtection, authRateLimit, authController.register.bind(authController));
router.post('/login', csrfProtection, authRateLimit, authController.login.bind(authController));
router.post(
  '/verify-email',
  csrfProtection,
  emailRateLimit,
  authController.verifyEmail.bind(authController)
);
router.post(
  '/resend-verification',
  csrfProtection,
  requireAuth,
  emailRateLimit,
  authController.resendVerification.bind(authController)
);
router.post(
  '/request-password-reset',
  csrfProtection,
  passwordResetRateLimit,
  authController.requestPasswordReset.bind(authController)
);
router.post(
  '/reset-password',
  csrfProtection,
  passwordResetRateLimit,
  authController.resetPassword.bind(authController)
);

// Logout doesn't require auth (gracefully handles missing session)
router.post('/logout', csrfProtection, authController.logout.bind(authController));

// Protected routes
router.get('/me', requireAuth, authController.me.bind(authController));
router.post(
  '/change-password',
  csrfProtection,
  requireAuth,
  authRateLimit,
  authController.changePassword.bind(authController)
);
router.patch(
  '/profile',
  csrfProtection,
  requireAuth,
  authController.updateProfile.bind(authController)
);
router.delete(
  '/account',
  csrfProtection,
  authRateLimit, // Prevent abuse of account deletion
  requireAuth,
  authController.deleteAccount.bind(authController)
);

export default router;
