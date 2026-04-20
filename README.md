# FastAPI Authentication Backend with Security

A secure backend authentication system built with **FastAPI**, **SQLModel**, and **JWT**, featuring user signup, login, email verification via OTP, active session management, and layered security middleware.

---

## Features

### Authentication & Authorization
- User registration with strong password validation
- Secure password hashing (bcrypt via Passlib)
- JWT-based login with Bearer token authentication
- Protected routes using dependency-based authentication
- Email verification using time-bound OTP (1-minute expiry)

### Session & Device Management
- Multi-device session tracking with device fingerprinting (IP, OS, Browser, Device Type)
- View all active sessions across devices
- Revoke individual sessions or logout from all devices
- Passive cleanup of expired tokens on login

### Security Middleware
- **Global Rate Limiting** — sliding window rate limiter (60 req/min per IP)
- **Per-Endpoint Rate Limiting** — stricter limits on auth-sensitive routes (login, signup, OTP)
- **Request Logging** — logs method, path, status code, client IP, and response time
- **Security Headers** — X-Frame-Options, X-Content-Type-Options, HSTS, XSS Protection, Referrer-Policy
- **CORS** — configurable allowed origins

---

## Tech Stack

| Technology | Purpose |
|---|---|
| **FastAPI** | Web framework |
| **SQLModel** | ORM and data models |
| **SQLAlchemy (Async)** | Asynchronous database access (PostgreSQL via asyncpg) |
| **Passlib + bcrypt** | Password hashing |
| **python-jose** | JWT token encoding/decoding |
| **user-agents** | Device fingerprinting from User-Agent headers |
| **fastapi-mail** | Email delivery (OTP verification) |
| **Pydantic** | Request/response data validation |
| **Uvicorn** | ASGI server |

---

## Project Structure

```
FastAPI-Backend/
├── src/
│   ├── __init__.py        # Re-exports models and schemas
│   ├── auth_router.py     # Authentication & session routes
│   ├── database.py        # Async engine, session factory, DB init
│   ├── model.py           # SQLModel table definitions (User, Token, OTP)
│   ├── schema.py          # Pydantic request/response schemas
│   ├── utils.py           # Password hashing, JWT, OTP, token management
│   ├── email.py           # Email sending via fastapi-mail
│   ├── middleware.py       # Rate limiting, logging, security headers
│   ├── settings.py        # Pydantic Settings (env config)
│   └── loggings.py        # Logging configuration
│
├── main.py                # FastAPI app entry point & middleware setup
├── .env                   # Environment variables (not committed)
├── requirements.txt
└── README.md
```

---

## API Endpoints

### Authentication

| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| POST | `/auth/create` | ✗ | 3/min | Create a new user account |
| POST | `/auth/login` | ✗ | 5/min | Authenticate and receive JWT |
| POST | `/auth/logout` | ✓ | — | Logout current session |
| GET | `/auth/user-detail` | ✓ | — | Get current user profile |

### Email Verification

| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| POST | `/auth/get-email-otp` | ✓ | 3/min | Send OTP to registered email |
| POST | `/auth/verify-email` | ✓ | 5/min | Verify email with OTP |

### Session Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/auth/sessions` | ✓ | List all active sessions with device info |
| DELETE | `/auth/sessions/{session_id}` | ✓ | Revoke a specific session |
| DELETE | `/auth/sessions` | ✓ | Logout from all devices |

---

## Authentication Flow

1. User signs up via `POST /auth/create` with email and a strong password
2. Password is hashed (bcrypt) and stored in the database
3. User logs in via `POST /auth/login` and receives a JWT Bearer token
4. Device info (IP, OS, browser, device type) is captured and stored with the token
5. Expired tokens for the user are passively cleaned up during login
6. Authenticated user requests an email OTP via `POST /auth/get-email-otp`
7. A 6-digit OTP is sent to the user's email (1-minute expiry)
8. User submits the OTP via `POST /auth/verify-email`
9. Email is marked as verified and the OTP record is deleted

---

## Security Architecture

### Password Policy
- Minimum 8 characters
- At least one uppercase letter, one lowercase letter, one digit, and one special character
- Hashed with bcrypt — plain-text passwords are never stored

### Token Management
- JWT tokens with configurable expiry (default: 7 days)
- Tokens stored in database for server-side revocation
- Expired tokens are automatically cleaned up on login
- Invalid/expired tokens are deleted from DB when detected

### Rate Limiting
| Scope | Limit |
|-------|-------|
| Global (all endpoints) | 60 requests/min per IP |
| Login | 5 attempts/min per IP |
| Account creation | 3 attempts/min per IP |
| OTP request | 3 attempts/min per IP |
| Email verification | 5 attempts/min per IP |

### Security Headers
All responses include:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/CodeByFelix/FastAPI-Backend-with-SQLModel-and-Postgres.git
cd FastAPI-Backend-with-SQLModel-and-Postgres
```

### 2. Create and activate virtual environment
```bash
python -m venv myenv
myenv\Scripts\activate   # Windows
source myenv/bin/activate # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
Create a `.env` file at the project root:
```env
DB_HOST = your-database-host
DB_PORT = 5432
DB_DATABASE = postgres
DB_USER = your-db-user
DB_PASSWORD = your-db-password

SECRET_KEY = your-jwt-secret-key
ALGORITHM = HS256

MAIL_USERNAME = your-mail-username
MAIL_PASSWORD = your-mail-password
MAIL_FROM = your-email@example.com
MAIL_PORT = 2525
MAIL_SERVER = your-smtp-server

CORS_ORIGINS = *
```

### 5. Run the application
```bash
uvicorn main:app --reload
```

The API docs are available at `http://127.0.0.1:8000/docs`

---

## Notes

- This project is a starter authentication backend designed for extension into production systems
- Easily integrates with frontend applications (Web, Mobile, SPA)
- SSL verification is disabled for Supabase pooled connections — adjust `database.py` for your provider

---

## Possible Improvements

- Refresh token rotation
- Account lockout on repeated login failures
- Role-based access control (RBAC)
- Background tasks for email sending
- Unit and integration tests
- Redis-backed rate limiting for multi-process deployments