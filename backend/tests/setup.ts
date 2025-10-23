import { prisma } from '../src/lib/db';
import { logger } from '../src/lib/logger';

// Setup runs before all tests
beforeAll(async () => {
  // Ensure test database is clean
  logger.info('Setting up test environment');
});

// Cleanup runs after all tests
afterAll(async () => {
  logger.info('Cleaning up test environment');

  // Clean up test data
  await prisma.passwordResetToken.deleteMany({});
  await prisma.verificationToken.deleteMany({});
  await prisma.session.deleteMany({});
  await prisma.user.deleteMany({});

  // Disconnect Prisma
  await prisma.$disconnect();
});
