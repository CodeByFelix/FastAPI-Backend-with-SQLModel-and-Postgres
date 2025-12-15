# FastAPI Authentication Backend with Email OTP Verification

A sample backend authentication system built with **FastAPI**, **SQLModel**, and **JWT**, featuring secure user signup, login, and email verification using one-time passwords (OTP).

This project demonstrates best practices for modern Python backend development, including async database access, password hashing, token-based authentication, and dependency injection.

---

## Features

- User registration (signup)
- Secure password hashing (bcrypt via passlib)
- User login with JWT authentication
- Protected routes using dependency-based authentication
- Email verification using time-bound OTP
- Async database operations with SQLAlchemy / SQLModel
- Structured request and response validation with Pydantic
- Centralized logging and error handling

---

## Tech Stack

- **FastAPI** – Web framework
- **SQLModel** – ORM and data models
- **SQLAlchemy (Async)** – Asynchronous database access
- **Passlib + bcrypt** – Password hashing
- **JWT** – Authentication tokens
- **Pydantic** – Data validation
- **Uvicorn** – ASGI server

---

## Project Structure

FastAPI-Backend/
├── src/
│ ├── auth_router.py # Authentication routes
│ ├── database.py # Database session and connection handling
│ ├── schema.py # SQLModel & Pydantic schemas
│ ├── utils.py # Password hashing, JWT, OTP utilities
│ ├── email.py # Email sending logic
│ ├── loggings.py # Logging configuration
│ └── settings.py # Application settings and environment variables
│
├── main.py # FastAPI application entry point
├── requirements.txt
└── README.md

---

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|------|---------|------------|
| POST | `/auth/create` | Create a new user account |
| POST | `/auth/login` | Authenticate user and return JWT |
| GET | `/auth/logout` | Logout authenticated user |
| GET | `/auth/user_detail` | Get current authenticated user |

---

### Email Verification

| Method | Endpoint | Description |
|------|---------|------------|
| GET | `/auth/get_email_otp` | Send OTP to registered email |
| GET | `/auth/verify_email?otp=XXXXXX` | Verify email using OTP |

- OTP expires after **1 minute**
- OTP is invalidated after successful verification

---

## Authentication Flow

1. User signs up with email and password
2. Password is securely hashed and stored in the database
3. User logs in and receives a JWT access token
4. Authenticated user requests an email verification OTP
5. OTP is sent via email and stored with an expiration time
6. User verifies email using the OTP
7. Email is marked as verified and OTP is removed

---

## Password Security

- Passwords are hashed using **bcrypt**
- Plain-text passwords are never stored
- Secure comparison is used during verification
- Compatible versions of passlib and bcrypt are pinned

---

## Configuration (`settings.py`)

Application configuration is centralized in `src/settings.py` using Pydantic settings.

Typical settings include:

- Database connection URL
- JWT secret and expiry
- Email server credentials

Environment variables are loaded to avoid hardcoding sensitive values.

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
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
uvicorn main:app --reload
```


## Environment Variables

Create a .env file at the project root:
```python
DB_HOST = 
DB_PORT = 
DB_DATABASE = 
DB_USER = 
DB_PASSWORD = 

SECRET_KEY = 
ALGORITHM = 

MAIL_USERNAME = 
MAIL_PASSWORD = 
MAIL_FROM = 
MAIL_PORT = 
MAIL_SERVER = 
```

## Notes

 - This project is intended as a sample / starter authentication backend

 - Designed for extension into production systems

 - Easily integrates with frontend applications (Web, Mobile, SPA)



## Possible Improvements

 - Refresh token support

 - Rate limiting for OTP requests

 - Account lockout on repeated login failures

 - Role-based access control (RBAC)

 - Background tasks for email sending

 - Unit and integration tests