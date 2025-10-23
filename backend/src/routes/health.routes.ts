import { Router, Request, Response } from 'express';
import { prisma } from '../lib/db';

const router = Router();

/**
 * Health check endpoint
 */
router.get('/health', async (req: Request, res: Response) => {
  try {
    // Check database connection
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: 'connected',
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * Readiness check (for Kubernetes)
 */
router.get('/ready', async (req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).send('OK');
  } catch (error) {
    res.status(503).send('Not Ready');
  }
});

/**
 * Liveness check (for Kubernetes)
 */
router.get('/live', (req: Request, res: Response) => {
  res.status(200).send('OK');
});

export default router;
