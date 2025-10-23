import request from 'supertest';
import { hash } from 'argon2';
import { prisma } from '../src/lib/db';
import app from '../src/index';

export const testUsers = {
  john: {
    email: 'john@example.com',
    password: 'Test1234!@#$',
    firstName: 'John',
    lastName: 'Doe',
  },
  jane: {
    email: 'jane@example.com',
    password: 'Test5678!@#$',
    firstName: 'Jane',
    lastName: 'Smith',
  },
};

/**
 * Create a test user in the database
 */
export async function createTestUser(userData: typeof testUsers.john) {
  const passwordHash = await hash(userData.password, {
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  return await prisma.user.create({
    data: {
      email: userData.email,
      passwordHash,
      firstName: userData.firstName,
      lastName: userData.lastName,
      emailVerified: true, // Pre-verified for testing
    },
  });
}

/**
 * Login a user and return the session cookie
 */
export async function loginUser(email: string, password: string): Promise<string> {
  const response = await request(app)
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);

  const cookies = response.headers['set-cookie'];
  if (!cookies || !Array.isArray(cookies)) {
    throw new Error('No session cookie returned');
  }

  return cookies[0];
}

/**
 * Extract session token from cookie string
 */
export function extractSessionToken(cookie: string): string {
  const match = cookie.match(/session=([^;]+)/);
  if (!match) {
    throw new Error('Could not extract session token from cookie');
  }
  return match[1];
}

/**
 * Clean up all test data
 */
export async function cleanupTestData() {
  await prisma.passwordResetToken.deleteMany({});
  await prisma.verificationToken.deleteMany({});
  await prisma.session.deleteMany({});
  await prisma.user.deleteMany({});
}
