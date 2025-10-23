# Backend API

Modern authentication backend built with Express, TypeScript, and Prisma.

## Features

- ✅ User registration with email verification
- ✅ Login with session-based authentication (Copenhagen Book pattern)
- ✅ Password reset flow
- ✅ Account locking after failed attempts
- ✅ Rate limiting on auth endpoints
- ✅ Role-based access control (USER, ADMIN, SUPER_ADMIN)
- ✅ Argon2id password hashing (OWASP recommended)
- ✅ SHA-256 token hashing
- ✅ Comprehensive test suite

## Tech Stack

- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: Session-based (HTTP-only cookies)
- **Password Hashing**: Argon2id
- **Token Hashing**: SHA-256 (@oslojs/crypto)
- **Validation**: Zod
- **Testing**: Jest + Supertest
- **Email**: Nodemailer

## Getting Started

### Prerequisites

- Node.js 18+
- PostgreSQL database (running via Docker)
- SMTP server for emails (MailHog for development)

### Installation

Dependencies are already installed. If needed:
```bash
npm install
```

### Database Setup

The database schema is already pushed. To reset:
```bash
npx prisma db push --accept-data-loss
```

### Seed Demo Users

```bash
npm run prisma:seed
```

Demo credentials:
- Admin: `admin@example.com` / `Admin123!@#$`
- User: `user@example.com` / `User123!@#$`
- Super Admin: `superadmin@example.com` / `SuperAdmin123!@#$`

### Development

```bash
npm run dev
```

Server runs on `http://localhost:3000`

### Testing

```bash
npm test
```

### Build

```bash
npm run build
```

### Production

```bash
npm start
```

## API Endpoints

### Health Checks
- `GET /health` - Health status with database check
- `GET /ready` - Readiness probe (Kubernetes)
- `GET /live` - Liveness probe (Kubernetes)

### Authentication
- `GET /api/auth/csrf-token` - Get CSRF token (call before POST requests)
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout (requires auth)
- `GET /api/auth/me` - Get current user (requires auth)
- `POST /api/auth/verify-email` - Verify email address
- `POST /api/auth/resend-verification` - Resend verification email (requires auth)
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (requires auth, current password)
- `PATCH /api/auth/profile` - Update profile (firstName, lastName) (requires auth)
- `DELETE /api/auth/account` - Delete account (requires auth, password confirmation)

## Security Features

- Helmet.js security headers (CSP, X-Frame-Options, HSTS, etc.)
- CSRF protection using double-submit cookie pattern (disabled in test env)
- Argon2id password hashing (19 MiB memory, 2 iterations)
- Session tokens: 160-bit random, SHA-256 hashed
- HTTP-only cookies with SameSite protection
- Account locking: 5 failed attempts → 15 minute lockout
- Rate limiting: 5 req/15min on auth endpoints
- Email enumeration prevention
- Password requirements: 12+ chars, upper, lower, number, special

## Environment Variables

See `.env.example` for all configuration options.

Key variables:
- `DATABASE_URL` - PostgreSQL connection string
- `SESSION_DURATION_DAYS` - Session lifetime (default: 30)
- `REQUIRE_EMAIL_VERIFICATION` - Enforce email verification (default: true)
- `MAX_LOGIN_ATTEMPTS` - Failed attempts before lockout (default: 5)
- `LOCKOUT_DURATION_MINUTES` - Lockout duration (default: 15)

## Project Structure

```
backend/
├── prisma/
│   ├── schema.prisma       # Database schema
│   └── seed.ts             # Demo data
├── src/
│   ├── controllers/        # Business logic
│   ├── lib/                # Utilities (session, crypto, email)
│   ├── middleware/         # Express middleware
│   ├── routes/             # API routes
│   └── index.ts            # App entry point
└── tests/                  # Integration tests
```

## License

MIT
