import { PrismaClient } from '@prisma/client';
import { hash } from 'argon2';
import { logger } from '../src/lib/logger';

const prisma = new PrismaClient();

// Argon2 options (same as in auth controller)
const ARGON2_OPTIONS = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

async function main() {
  logger.info('Seeding database');

  // Create demo users
  const users = [
    {
      email: 'admin@example.com',
      password: 'Admin123!@#$',
      firstName: 'Admin',
      lastName: 'User',
      role: 'ADMIN',
      emailVerified: true,
    },
    {
      email: 'user@example.com',
      password: 'User123!@#$',
      firstName: 'Regular',
      lastName: 'User',
      role: 'USER',
      emailVerified: true,
    },
    {
      email: 'superadmin@example.com',
      password: 'SuperAdmin123!@#$',
      firstName: 'Super',
      lastName: 'Admin',
      role: 'SUPER_ADMIN',
      emailVerified: true,
    },
  ];

  for (const userData of users) {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: userData.email },
    });

    if (existingUser) {
      logger.info('User already exists, skipping', { email: userData.email });
      continue;
    }

    // Hash password
    const passwordHash = await hash(userData.password, ARGON2_OPTIONS);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: userData.email,
        passwordHash,
        firstName: userData.firstName,
        lastName: userData.lastName,
        role: userData.role as any,
        emailVerified: userData.emailVerified,
      },
    });

    logger.info('Created user', { email: user.email, role: user.role });
  }

  logger.info('Seeding completed successfully');
  logger.info('Demo credentials:', {
    admin: 'admin@example.com / Admin123!@#$',
    user: 'user@example.com / User123!@#$',
    superAdmin: 'superadmin@example.com / SuperAdmin123!@#$',
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    logger.error('Error seeding database', { error: e });
    await prisma.$disconnect();
    process.exit(1);
  });
