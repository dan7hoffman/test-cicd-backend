import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import morgan from 'morgan';
import addRequestId from 'express-request-id';
import swaggerUi from 'swagger-ui-express';
import { authenticateRequest } from './middleware/auth';
import { errorHandler, notFoundHandler } from './middleware/error';
import { apiRateLimit } from './middleware/rateLimit';
import { cleanupExpiredSessions, cleanupExpiredTokens } from './lib/session';
import { logger, morganStream } from './lib/logger';
import { generateOpenAPIDocument } from './lib/openapi';
import authRoutes from './routes/auth.routes';
import healthRoutes from './routes/health.routes';

// Load environment variables
dotenv.config();

// Validate required environment variables
function validateEnv(): void {
  const required = [
    'DATABASE_URL',
    'SESSION_SECRET',
    'CSRF_SECRET',
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_FROM',
    'FRONTEND_URL',
  ];

  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    logger.error('Missing required environment variables', { missing });
    logger.error('Please check your .env file and ensure all required variables are set');
    process.exit(1);
  }

  // Validate SESSION_SECRET length (should be at least 32 chars for security)
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) {
    logger.error('SESSION_SECRET must be at least 32 characters long');
    process.exit(1);
  }

  // Validate CSRF_SECRET length
  if (process.env.CSRF_SECRET && process.env.CSRF_SECRET.length < 32) {
    logger.error('CSRF_SECRET must be at least 32 characters long');
    process.exit(1);
  }

  logger.info('Environment variables validated successfully');
}

// Run validation immediately
validateEnv();

const app: Express = express();
const PORT = parseInt(process.env.PORT || '3000');
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:4200';

// CORS configuration
const corsOptions = {
  origin: FRONTEND_URL,
  credentials: true,
  optionsSuccessStatus: 200,
};

// Middleware
app.use(addRequestId()); // Add correlation IDs to all requests
app.use(cors(corsOptions));
app.use(morgan('combined', { stream: morganStream })); // HTTP request logging
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],                              // Default: only same-origin resources
      scriptSrc: ["'self'"],                               // Scripts: only from same origin
      styleSrc: ["'self'", "'unsafe-inline'"],             // Styles: same-origin + inline (required for many frameworks)
      imgSrc: ["'self'", "data:", "https:"],               // Images: same-origin, data URIs, and HTTPS
      fontSrc: ["'self'", "data:"],                        // Fonts: same-origin and data URIs
      connectSrc: ["'self'"],                              // AJAX/WebSocket: only same-origin
      frameSrc: ["'none'"],                                // Frames: disallow all (prevents clickjacking)
      objectSrc: ["'none'"],                               // Objects/Embeds: disallow all
      mediaSrc: ["'self'"],                                // Audio/Video: only same-origin
      formAction: ["'self'"],                              // Form submissions: only same-origin
      frameAncestors: ["'none'"],                          // Prevent embedding in frames (X-Frame-Options equivalent)
      baseUri: ["'self'"],                                 // Base tag: only same-origin
      upgradeInsecureRequests: [],                         // Upgrade HTTP to HTTPS automatically
    },
  },
  crossOriginEmbedderPolicy: false,                        // Allow embedding for better compatibility
  hsts: {
    maxAge: 31536000,                                      // 1 year HSTS
    includeSubDomains: true,                               // Apply to all subdomains
    preload: true,                                         // Allow browser preload lists
  },
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session authentication middleware (runs on all requests)
app.use(authenticateRequest);

// OpenAPI documentation (Swagger UI)
const openApiDocument = generateOpenAPIDocument();
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiDocument, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Backend API Documentation',
}));

// OpenAPI spec endpoints
app.get('/api-docs/json', (req, res) => {
  res.json(openApiDocument);
});

app.get('/api-docs/yaml', (req, res) => {
  const yaml = require('js-yaml');
  res.setHeader('Content-Type', 'text/yaml');
  res.send(yaml.dump(openApiDocument));
});

// Health check routes (no rate limiting)
app.use('/', healthRoutes);

// API routes with rate limiting
app.use('/api/auth', authRoutes);
app.use('/api', apiRateLimit); // Apply to all other API routes

// 404 handler
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

// Start server (skip during tests)
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    logger.info('Server started', {
      port: PORT,
      healthCheck: `http://localhost:${PORT}/health`,
      authEndpoints: `http://localhost:${PORT}/api/auth/*`,
      environment: process.env.NODE_ENV || 'development',
    });
  });

  // Session and token cleanup job - runs every hour
  const cleanupInterval = setInterval(async () => {
  try {
    const sessionsDeleted = await cleanupExpiredSessions();
    const tokensDeleted = await cleanupExpiredTokens();

    const totalCleaned = sessionsDeleted + tokensDeleted.verificationTokens + tokensDeleted.passwordResetTokens;
    if (totalCleaned > 0) {
      logger.info('Cleanup completed', {
        sessionsDeleted,
        verificationTokensDeleted: tokensDeleted.verificationTokens,
        passwordResetTokensDeleted: tokensDeleted.passwordResetTokens,
        totalDeleted: totalCleaned,
      });
    }
  } catch (error) {
    logger.error('Cleanup error', { error });
  }
  }, 60 * 60 * 1000); // 1 hour

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutdown signal received: cleaning up');
    clearInterval(cleanupInterval);

    // Final cleanup before shutdown
    try {
      const sessionsDeleted = await cleanupExpiredSessions();
      const tokensDeleted = await cleanupExpiredTokens();

      logger.info('Final cleanup completed', {
        sessionsDeleted,
        verificationTokensDeleted: tokensDeleted.verificationTokens,
        passwordResetTokensDeleted: tokensDeleted.passwordResetTokens,
      });
    } catch (error) {
      logger.error('Final cleanup error', { error });
    }

    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

export default app;
