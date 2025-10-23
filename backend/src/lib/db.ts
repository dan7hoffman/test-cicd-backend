import { PrismaClient } from '@prisma/client';

// Prisma Client singleton pattern
// Prevents multiple instances in development with hot reload

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

/**
 * Build DATABASE_URL with connection pool parameters
 * Connection pooling prevents database connection exhaustion under load
 */
function buildDatabaseUrl(): string {
  const baseUrl = process.env.DATABASE_URL || '';
  const connectionLimit = process.env.DB_CONNECTION_LIMIT || '10';
  const poolTimeout = process.env.DB_POOL_TIMEOUT || '20';

  try {
    const url = new URL(baseUrl);

    // Add connection pool parameters if not already present
    if (!url.searchParams.has('connection_limit')) {
      url.searchParams.set('connection_limit', connectionLimit);
    }
    if (!url.searchParams.has('pool_timeout')) {
      url.searchParams.set('pool_timeout', poolTimeout);
    }

    return url.toString();
  } catch (error) {
    // If URL parsing fails, return base URL (will be caught by env validation)
    return baseUrl;
  }
}

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['error', 'warn'] : ['error'],
    datasources: {
      db: {
        url: buildDatabaseUrl(),
      },
    },
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}
