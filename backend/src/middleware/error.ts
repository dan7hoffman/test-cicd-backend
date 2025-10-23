import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '../lib/logger';

/**
 * Global error handler
 */
export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Log error for debugging
  logger.error('Error occurred', { error, path: req.path, method: req.method });

  // Zod validation errors
  if (error instanceof ZodError) {
    res.status(400).json({
      error: 'Validation error',
      details: error.errors.map((err) => ({
        field: err.path.join('.'),
        message: err.message,
      })),
    });
    return;
  }

  // Prisma errors
  if (error.constructor.name === 'PrismaClientKnownRequestError') {
    const prismaError = error as any;

    // Unique constraint violation
    if (prismaError.code === 'P2002') {
      res.status(409).json({
        error: 'Resource already exists',
        details: `A record with this ${prismaError.meta?.target?.[0] || 'field'} already exists`,
      });
      return;
    }

    // Foreign key constraint failed
    if (prismaError.code === 'P2003') {
      res.status(400).json({
        error: 'Invalid reference',
        details: 'Referenced record does not exist',
      });
      return;
    }

    // Record not found
    if (prismaError.code === 'P2025') {
      res.status(404).json({
        error: 'Not found',
        details: 'The requested record does not exist',
      });
      return;
    }
  }

  // Default error response
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'An unexpected error occurred',
  });
}

/**
 * 404 handler for undefined routes
 */
export function notFoundHandler(
  req: Request,
  res: Response
): void {
  res.status(404).json({
    error: 'Not found',
    message: `Route ${req.method} ${req.path} not found`,
  });
}
