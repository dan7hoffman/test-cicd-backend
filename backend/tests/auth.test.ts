import request from 'supertest';
import app from '../src/index';
import { prisma } from '../src/lib/db';
import {
  createTestUser,
  loginUser,
  cleanupTestData,
  testUsers,
} from './helpers';

describe('Auth API', () => {
  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send(testUsers.john)
        .expect(201);

      expect(response.body.user).toMatchObject({
        email: testUsers.john.email,
        firstName: testUsers.john.firstName,
        lastName: testUsers.john.lastName,
        emailVerified: false,
      });

      expect(response.body.message).toContain('verify');
      expect(response.headers['set-cookie']).toBeDefined();

      // Verify user in database
      const user = await prisma.user.findUnique({
        where: { email: testUsers.john.email },
      });
      expect(user).toBeTruthy();
      expect(user?.emailVerified).toBe(false);
    });

    it('should prevent email enumeration (duplicate email returns same response)', async () => {
      await createTestUser(testUsers.john);

      // Email enumeration prevention: return same success message for duplicate emails
      // This prevents attackers from discovering which emails are registered
      const response = await request(app)
        .post('/api/auth/register')
        .send(testUsers.john)
        .expect(201);

      expect(response.body.message).toBe(
        'Registration successful! Please check your email to verify your account.'
      );
    });

    it('should reject weak password', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({
          ...testUsers.john,
          password: 'weak',
        })
        .expect(400);
    });

    it('should reject invalid email', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({
          ...testUsers.john,
          email: 'invalid-email',
        })
        .expect(400);
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await createTestUser(testUsers.john);
    });

    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUsers.john.email,
          password: testUsers.john.password,
        })
        .expect(200);

      expect(response.body.user).toMatchObject({
        email: testUsers.john.email,
        firstName: testUsers.john.firstName,
        lastName: testUsers.john.lastName,
      });

      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should reject invalid password', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: testUsers.john.email,
          password: 'wrongpassword',
        })
        .expect(401);
    });

    it('should reject non-existent user', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: testUsers.john.password,
        })
        .expect(401);
    });

    it('should lock account after failed attempts', async () => {
      // Make 5 failed login attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({
            email: testUsers.john.email,
            password: 'wrongpassword',
          })
          .expect(401);
      }

      // 6th attempt should be locked
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUsers.john.email,
          password: 'wrongpassword',
        })
        .expect(423);

      expect(response.body.error).toContain('locked');
    });
  });

  describe('GET /api/auth/me', () => {
    it('should return current user when authenticated', async () => {
      await createTestUser(testUsers.john);
      const cookie = await loginUser(testUsers.john.email, testUsers.john.password);

      const response = await request(app)
        .get('/api/auth/me')
        .set('Cookie', cookie)
        .expect(200);

      expect(response.body.user).toMatchObject({
        email: testUsers.john.email,
        firstName: testUsers.john.firstName,
        lastName: testUsers.john.lastName,
      });
    });

    it('should reject unauthenticated request', async () => {
      await request(app).get('/api/auth/me').expect(401);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should logout authenticated user', async () => {
      await createTestUser(testUsers.john);
      const cookie = await loginUser(testUsers.john.email, testUsers.john.password);

      const response = await request(app)
        .post('/api/auth/logout')
        .set('Cookie', cookie)
        .expect(200);

      expect(response.body.message).toContain('Logged out');

      // Verify session is cleared
      const cookies = response.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies[0]).toContain('session=;');
    });

    it('should work even without valid session', async () => {
      await request(app).post('/api/auth/logout').expect(200);
    });
  });

  describe('POST /api/auth/request-password-reset', () => {
    it('should always return success to prevent email enumeration', async () => {
      // Non-existent email
      await request(app)
        .post('/api/auth/request-password-reset')
        .send({ email: 'nonexistent@example.com' })
        .expect(200);

      // Existing email
      await createTestUser(testUsers.john);
      await request(app)
        .post('/api/auth/request-password-reset')
        .send({ email: testUsers.john.email })
        .expect(200);
    });

    it('should create reset token for valid user', async () => {
      await createTestUser(testUsers.john);

      await request(app)
        .post('/api/auth/request-password-reset')
        .send({ email: testUsers.john.email })
        .expect(200);

      const user = await prisma.user.findUnique({
        where: { email: testUsers.john.email },
        include: { passwordResetTokens: true },
      });

      expect(user?.passwordResetTokens.length).toBeGreaterThan(0);
    });
  });

  describe('Health checks', () => {
    it('GET /health should return healthy status', async () => {
      const response = await request(app).get('/health').expect(200);

      expect(response.body).toMatchObject({
        status: 'healthy',
        database: 'connected',
      });
    });

    it('GET /ready should return OK', async () => {
      await request(app).get('/ready').expect(200);
    });

    it('GET /live should return OK', async () => {
      await request(app).get('/live').expect(200);
    });
  });
});
