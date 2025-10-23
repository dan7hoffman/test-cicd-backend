import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';

/**
 * Winston Logger Configuration
 *
 * Features:
 * - Structured JSON logging for production
 * - Daily log rotation (1GB max, 30 days retention)
 * - Separate files for errors and combined logs
 * - Console output in development
 * - Log levels: error, warn, info, http, debug
 */

// Log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Log colors for console
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(colors);

// Determine log level based on environment
const level = (): string => {
  const env = process.env.NODE_ENV || 'development';
  const isDevelopment = env === 'development';
  return isDevelopment ? 'debug' : 'info';
};

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Console format (human-readable for development)
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}${info.stack ? '\n' + info.stack : ''}`
  )
);

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');

// Transports
const transports: winston.transport[] = [];

// File transport for all logs (daily rotation)
transports.push(
  new DailyRotateFile({
    filename: path.join(logsDir, 'combined-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '1g', // 1GB max file size
    maxFiles: '30d', // Keep logs for 30 days
    format: logFormat,
  })
);

// File transport for error logs only
transports.push(
  new DailyRotateFile({
    level: 'error',
    filename: path.join(logsDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '1g',
    maxFiles: '30d',
    format: logFormat,
  })
);

// Console transport (development only, or when LOG_TO_CONSOLE=true)
if (process.env.NODE_ENV !== 'production' || process.env.LOG_TO_CONSOLE === 'true') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
    })
  );
}

// Create Winston logger
export const logger = winston.createLogger({
  level: level(),
  levels,
  format: logFormat,
  transports,
  // Don't exit on handled exceptions
  exitOnError: false,
});

// Create a stream for Morgan (HTTP request logging)
export const morganStream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

/**
 * Helper functions for common logging patterns
 */

export const logRequest = (method: string, path: string, statusCode: number, duration: number, userId?: string) => {
  logger.http('HTTP Request', {
    method,
    path,
    statusCode,
    duration: `${duration}ms`,
    userId: userId || 'anonymous',
  });
};

export const logError = (error: Error, context?: Record<string, any>) => {
  logger.error('Error occurred', {
    message: error.message,
    stack: error.stack,
    ...context,
  });
};

export const logAuth = (event: string, userId?: string, email?: string, success: boolean = true) => {
  logger.info('Auth Event', {
    event,
    userId,
    email,
    success,
  });
};

// Log startup message
logger.info('Logger initialized', {
  level: level(),
  environment: process.env.NODE_ENV || 'development',
  logsDir,
});
