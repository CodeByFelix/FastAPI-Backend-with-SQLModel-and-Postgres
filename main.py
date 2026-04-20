from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from src.auth_router import auth_router
from src.database import init_db, engine
from src.middleware import RateLimitMiddleware, RequestLoggingMiddleware, SecurityHeadersMiddleware
from src.settings import settings
from src.loggings import logging


@asynccontextmanager
async def lifespan (app: FastAPI):
    await init_db ()
    logging.info ("Database initialised successfully")
    yield
    await engine.dispose ()
    logging.info ("Database connections closed")


app = FastAPI (lifespan=lifespan)

# --- CORS Middleware ---
app.add_middleware (
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Rate Limiting Middleware ---
app.add_middleware (RateLimitMiddleware)

# --- Request Logging Middleware ---
app.add_middleware (RequestLoggingMiddleware)

# --- Security Headers Middleware ---
app.add_middleware (SecurityHeadersMiddleware)

app.include_router (auth_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the full exception for developers including stack trace
    logging.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)

    # Return a clean, safe response to the user
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred. Please try again later."},
    )
