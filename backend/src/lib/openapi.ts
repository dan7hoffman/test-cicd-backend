import {
  OpenAPIRegistry,
  OpenApiGeneratorV3,
  extendZodWithOpenApi,
} from '@asteasolutions/zod-to-openapi';
import { z } from 'zod';
import {
  registerSchema,
  loginSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  emailVerificationSchema,
  updateProfileSchema,
  changePasswordSchema,
} from './validators';

// Extend Zod with OpenAPI methods
extendZodWithOpenApi(z);

// Create OpenAPI registry
const registry = new OpenAPIRegistry();

// Define common response schemas
const ErrorResponseSchema = z.object({
  error: z.string().openapi({ example: 'Error message' }),
  details: z.array(z.object({
    field: z.string(),
    message: z.string(),
  })).optional(),
});

const SuccessResponseSchema = z.object({
  message: z.string().openapi({ example: 'Operation successful' }),
});

const UserResponseSchema = z.object({
  id: z.string().openapi({ example: 'user_123abc' }),
  email: z.string().email().openapi({ example: 'user@example.com' }),
  firstName: z.string().openapi({ example: 'John' }),
  lastName: z.string().openapi({ example: 'Doe' }),
  role: z.enum(['USER', 'ADMIN', 'SUPER_ADMIN']).openapi({ example: 'USER' }),
  emailVerified: z.boolean().openapi({ example: true }),
  createdAt: z.string().datetime().openapi({ example: '2025-10-22T12:00:00Z' }),
});

const SessionResponseSchema = z.object({
  user: UserResponseSchema,
  expiresAt: z.string().datetime().openapi({ example: '2025-11-21T12:00:00Z' }),
});

// Register auth endpoints
registry.registerPath({
  method: 'post',
  path: '/api/auth/register',
  tags: ['Authentication'],
  summary: 'Register a new user',
  description: 'Create a new user account with email verification',
  request: {
    body: {
      content: {
        'application/json': {
          schema: registerSchema,
        },
      },
    },
  },
  responses: {
    201: {
      description: 'User registered successfully. Verification email sent.',
      content: {
        'application/json': {
          schema: z.object({
            message: z.string(),
            userId: z.string(),
          }),
        },
      },
    },
    400: {
      description: 'Validation error or email already exists',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    429: {
      description: 'Too many requests',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/login',
  tags: ['Authentication'],
  summary: 'Login user',
  description: 'Authenticate user and create session',
  request: {
    body: {
      content: {
        'application/json': {
          schema: loginSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Login successful. Session cookie set.',
      content: {
        'application/json': {
          schema: SessionResponseSchema,
        },
      },
    },
    401: {
      description: 'Invalid credentials or email not verified',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    429: {
      description: 'Too many login attempts',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/logout',
  tags: ['Authentication'],
  summary: 'Logout user',
  description: 'Invalidate current session',
  responses: {
    200: {
      description: 'Logged out successfully',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/verify-email',
  tags: ['Authentication'],
  summary: 'Verify email address',
  description: 'Verify user email with token from verification email',
  request: {
    body: {
      content: {
        'application/json': {
          schema: emailVerificationSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Email verified successfully',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    400: {
      description: 'Invalid or expired token',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/resend-verification',
  tags: ['Authentication'],
  summary: 'Resend verification email',
  description: 'Send a new verification email to user',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({ email: z.string().email() }),
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Verification email sent',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    400: {
      description: 'Email already verified or not found',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    429: {
      description: 'Too many requests',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/forgot-password',
  tags: ['Authentication'],
  summary: 'Request password reset',
  description: 'Send password reset email',
  request: {
    body: {
      content: {
        'application/json': {
          schema: passwordResetRequestSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Password reset email sent if account exists',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    429: {
      description: 'Too many requests',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/auth/reset-password',
  tags: ['Authentication'],
  summary: 'Reset password',
  description: 'Reset password using token from reset email',
  request: {
    body: {
      content: {
        'application/json': {
          schema: passwordResetSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Password reset successfully',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    400: {
      description: 'Invalid or expired token',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/auth/session',
  tags: ['Authentication'],
  summary: 'Get current session',
  description: 'Get current user session if authenticated',
  responses: {
    200: {
      description: 'Session retrieved',
      content: {
        'application/json': {
          schema: SessionResponseSchema,
        },
      },
    },
    401: {
      description: 'Not authenticated',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/auth/profile',
  tags: ['Profile'],
  summary: 'Get user profile',
  description: 'Get authenticated user profile',
  responses: {
    200: {
      description: 'Profile retrieved',
      content: {
        'application/json': {
          schema: UserResponseSchema,
        },
      },
    },
    401: {
      description: 'Not authenticated',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'put',
  path: '/api/auth/profile',
  tags: ['Profile'],
  summary: 'Update user profile',
  description: 'Update authenticated user profile',
  request: {
    body: {
      content: {
        'application/json': {
          schema: updateProfileSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Profile updated',
      content: {
        'application/json': {
          schema: UserResponseSchema,
        },
      },
    },
    400: {
      description: 'Validation error',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    401: {
      description: 'Not authenticated',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'put',
  path: '/api/auth/change-password',
  tags: ['Profile'],
  summary: 'Change password',
  description: 'Change authenticated user password',
  request: {
    body: {
      content: {
        'application/json': {
          schema: changePasswordSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Password changed successfully',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    400: {
      description: 'Validation error or incorrect current password',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    401: {
      description: 'Not authenticated',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/auth/account',
  tags: ['Profile'],
  summary: 'Delete account',
  description: 'Delete authenticated user account (requires password confirmation)',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            password: z.string(),
          }),
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Account deleted successfully',
      content: { 'application/json': { schema: SuccessResponseSchema } },
    },
    400: {
      description: 'Incorrect password',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
    401: {
      description: 'Not authenticated',
      content: { 'application/json': { schema: ErrorResponseSchema } },
    },
  },
});

// Generate OpenAPI document
function generateOpenAPIDocument() {
  const generator = new OpenApiGeneratorV3(registry.definitions);

  return generator.generateDocument({
    openapi: '3.1.0',
    info: {
      title: 'Backend API',
      version: '1.0.0',
      description: 'Modern authentication API with session-based auth, email verification, and password reset',
      contact: {
        name: 'API Support',
        email: 'support@example.com',
      },
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server',
      },
      {
        url: 'https://api.example.com',
        description: 'Production server',
      },
    ],
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication endpoints (register, login, logout, password reset)',
      },
      {
        name: 'Profile',
        description: 'User profile management endpoints',
      },
    ],
  });
}

export { registry, generateOpenAPIDocument };
