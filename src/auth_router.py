from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, update, delete
from src import (
    User, UserRead, UserReturn, EmailValidationOtp, Token,
    UserCreate, UserLogin, LoginReturn, VerifyEmailRequest, SessionResponse
)
from src.utils import hash_password, verify_password, get_current_user, create_token, generate_otp, oauth_schema, cleanup_expired_tokens
from src.database import get_session, DbConnectionError
from src.email import send_email
from src.middleware import (
    rate_limit_dependency, login_limiter, create_account_limiter,
    otp_request_limiter, otp_verify_limiter, get_client_ip
)
from datetime import datetime, timedelta, timezone
from user_agents import parse as parse_user_agent
from src.loggings import logging
import uuid

auth_router = APIRouter (prefix='/auth', tags=['auth'])


@auth_router.post(
    "/create", 
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
    description="Creates a new user account with a hashed password. Verifies that the email is not already in use.",
    responses={
        status.HTTP_409_CONFLICT: {"description": "Email already exists"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error or Account creation failed"}
    }
)
async def create_account (request: Request, user_in: UserCreate, session: AsyncSession = Depends (get_session),
                          _rate_limit = Depends (rate_limit_dependency (create_account_limiter))):
    """
    Registers a new user in the database.
    
    Args:
        user_in (UserCreate): The user's registration details (email, password, etc).
        session (AsyncSession): The database session.
        
    Returns:
        dict: A success message.
    """
    query = select (User).where (User.email == user_in.email)
    try:
        result = await session.execute (query)
        existing = result.one_or_none ()
    except Exception:
        logging.exception ("DB Error during email existence check")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")
    
    if existing:
        raise HTTPException (status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
    
    hashed_password = await hash_password (password=user_in.password)

    user = User (
        email=user_in.email,
        password=hashed_password,
        first_name=user_in.first_name,
        last_name=user_in.last_name
    )

    try:
        session.add (user)
        await session.commit ()
        await session.refresh (user)
        return {'message': f"Account {user.email} created successfully"}
    except Exception as e:
        logging.exception ("Error creating account")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Account creation failed")
    
@auth_router.post(
    "/login", 
    response_model=LoginReturn, 
    status_code=status.HTTP_200_OK,
    summary="Login to user account",
    description="Authenticates a user via email and password, returning a JWT token for subsequent requests.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Wrong Email or Password"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def login (request: Request, user_in: UserLogin, session: AsyncSession = Depends (get_session),
                 _rate_limit = Depends (rate_limit_dependency (login_limiter))):
    """
    Authenticates a user and generates a Bearer token.
    
    Args:
        user_in (UserLogin): The user's login credentials.
        session (AsyncSession): The database session.
        
    Returns:
        LoginReturn: The authenticated user profile and JWT token.
    """
    query = select(User).where(User.email == user_in.email)
    try:
        result = await session.execute (query)
        existing = result.one_or_none ()
    except Exception:
        logging.exception ("Database Error during user login lookup")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")
    
    if not existing:
        raise HTTPException (status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong Email or Password")
    
    user = User.model_validate (existing[0])

    if not await verify_password (plain_password=user_in.password, hashed_password=user.password):
        raise HTTPException (status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong Email or Password")
    
    user_return = UserReturn.model_validate (user)

    # Parse device info from User-Agent header
    ua_string = request.headers.get ("User-Agent", "")
    ua = parse_user_agent (ua_string)
    client_ip = get_client_ip (request)

    device_info = {
        "ip_address": client_ip,
        "os": f"{ua.os.family} {ua.os.version_string}".strip (),
        "browser": f"{ua.browser.family} {ua.browser.version_string}".strip (),
        "device_type": "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop",
    }

    # Passively clean up expired tokens for this user
    await cleanup_expired_tokens (user_id=str (user.id), session=session)

    token = await create_token (
        user_id=str (user.id), 
        expires=timedelta (hours=168), 
        session=session,
        **device_info
    )

    login_return = LoginReturn (
        user=user_return,
        token=token,
        token_type="Bearer",
        message=f"Login to {user.email} successful"
    )

    return login_return


@auth_router.post(
    "/logout", 
    status_code=status.HTTP_200_OK,
    summary="Logout user",
    description="Logs the current user out by permanently invalidating their active session token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def logout (session: AsyncSession = Depends (get_session),
                  user: UserRead = Depends (get_current_user),
                  credential: HTTPAuthorizationCredentials = Depends (oauth_schema)):
    """
    Logs out the authenticated user by deleting their access token from the database.
    
    Args:
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        credential (HTTPAuthorizationCredentials): The token payload from the request header.
    """
    token_str = credential.credentials
    query = select(Token).where(Token.token == token_str)
    
    try:
        result = await session.execute(query)
        token_record = result.scalar_one_or_none()
        
        if token_record:
            await session.delete(token_record)
            await session.commit()
            
    except Exception:
        logging.exception("DB Error during logout")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")
        
    return {"message": "Successfully logged out"}


@auth_router.post(
    "/get-email-otp", 
    status_code=status.HTTP_200_OK,
    summary="Request Email Verification OTP",
    description="Generates an OTP and sends it to the user's registered email address for verification.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Error storing or sending OTP"}
    }
)
async def get_email_otp (request: Request, session: AsyncSession = Depends (get_session),
                         user: UserRead = Depends (get_current_user),
                         _rate_limit = Depends (rate_limit_dependency (otp_request_limiter))):
    """
    Generates and sends a 6-digit OTP to the user's email.
    
    Args:
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        
    Returns:
        dict: A success message indicating the OTP was sent.
    """
    otp = await generate_otp (length=6)
    otp_data = EmailValidationOtp (
        user_id=user.id,
        email=user.email,
        otp=otp,
        expires_at=datetime.now (timezone.utc) + timedelta (minutes=1)
    )

    body = f"""
<p>
Hi {user.first_name},
\n\n
Use OTP to verify your Email.\n
{otp}
</p>
"""
    if await send_email (to_email=user.email, subject="Email Verification OTP", html_body=body):
        try:
            # Invalidate any previous OTPs for this user
            await session.execute (delete (EmailValidationOtp).where (EmailValidationOtp.user_id == user.id))
            session.add (otp_data)
            await session.commit ()

            return {"message": "Email Verification OTP sent"}
        except Exception as e:
            logging.exception ("Error occured while saving OTP to DB")
            raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error storing OTP")
    
    else:
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")

@auth_router.post(
    "/verify-email", 
    status_code=status.HTTP_200_OK,
    summary="Verify Email via OTP",
    description="Verifies the OTP sent to the user's email. If valid, marks the user's email as verified.",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Invalid OTP or OTP expired"},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def verify_email (request_body: VerifyEmailRequest, request: Request,
                        session: AsyncSession = Depends (get_session),
                        user: UserRead = Depends (get_current_user),
                        _rate_limit = Depends (rate_limit_dependency (otp_verify_limiter))):
    """
    Validates the submitted OTP against the database record to verify the user's email.
    
    Args:
        otp (str): The one-time password submitted by the user.
        session (AsyncSession): The database session.
        user (UserRead): The currently authenticated user.
        
    Returns:
        dict: A success message if verification passes.
    """
    query = select (EmailValidationOtp).where (EmailValidationOtp.user_id == user.id,
                                               EmailValidationOtp.otp == request_body.otp)
    
    try:
        result = await session.execute (query)
        otp_record = result.scalar_one_or_none ()
    except Exception as e:
        logging.exception ("Error reading from DB")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")
    
    if otp_record:
        #expired_at = otp_record.expires_at.replace(tzinfo=timezone.utc)
        if otp_record.expires_at < datetime.now (timezone.utc):
            try:
                await session.delete (otp_record)
                await session.commit ()
                #raise HTTPException (status_code=400, detail="OTP has expired")
            except Exception as e:
                logging.exception ("DB Read Write Error")
                raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")
            else:
                raise HTTPException (status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired")
        else:
            update_query = update (User).where(User.id == user.id).values (email_verified=True)
            try:
                await session.execute (update_query)
                await session.delete (otp_record)
                await session.commit ()
                return {'message': f"Email {user.email} verified successfully."}
            except Exception as e:
                logging.exception ("DB Read Write Error")
                raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")

    else:
        raise HTTPException (status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
    
@auth_router.get(
    "/user-detail", 
    response_model=UserReturn, 
    status_code=status.HTTP_200_OK,
    summary="Get user details",
    description="Retrieves the profile details of the currently authenticated user.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"}
    }
)
async def get_user_details (user: UserRead = Depends (get_current_user)):
    """
    Returns the authenticated user's profile information.
    
    Args:
        user (UserRead): The currently authenticated user.
        
    Returns:
        UserReturn: The user's detailed profile.
    """
    user_return = UserReturn.model_validate(user)
    return user_return


@auth_router.get(
    "/sessions",
    response_model=list[SessionResponse],
    status_code=status.HTTP_200_OK,
    summary="Get all active sessions",
    description="Returns a list of all active login sessions for the authenticated user, including device details.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def get_sessions (session: AsyncSession = Depends (get_session),
                        user: UserRead = Depends (get_current_user),
                        credential: HTTPAuthorizationCredentials = Depends (oauth_schema)):
    """
    Returns all active (non-expired) sessions for the current user.
    Marks the session matching the current token as `is_current_session`.
    """
    current_token = credential.credentials
    query = select (Token).where (
        Token.user_id == user.id,
        Token.exp > datetime.now (timezone.utc)
    ).order_by (Token.created_at.desc ())

    try:
        result = await session.execute (query)
        tokens = result.scalars ().all ()
    except Exception:
        logging.exception ("DB Error fetching sessions")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")

    sessions_list = []
    for t in tokens:
        sessions_list.append (SessionResponse (
            id=t.id,
            ip_address=t.ip_address,
            os=t.os,
            browser=t.browser,
            device_type=t.device_type,
            created_at=t.created_at,
            is_current_session=(t.token == current_token)
        ))

    return sessions_list


@auth_router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke a specific session",
    description="Logs out a specific device by deleting its session token. Cannot revoke the current session.",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Cannot revoke current session. Use /logout instead."},
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_404_NOT_FOUND: {"description": "Session not found"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def revoke_session (session_id: uuid.UUID,
                          session: AsyncSession = Depends (get_session),
                          user: UserRead = Depends (get_current_user),
                          credential: HTTPAuthorizationCredentials = Depends (oauth_schema)):
    """
    Revokes a specific session by its ID. Prevents revoking the current session
    to avoid accidental self-lockout — use /logout for that instead.
    """
    current_token = credential.credentials
    query = select (Token).where (Token.id == session_id, Token.user_id == user.id)

    try:
        result = await session.execute (query)
        token_record = result.scalar_one_or_none ()
    except Exception:
        logging.exception ("DB Error during session revocation")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")

    if not token_record:
        raise HTTPException (status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if token_record.token == current_token:
        raise HTTPException (status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot revoke current session. Use /logout instead.")

    try:
        await session.delete (token_record)
        await session.commit ()
    except Exception:
        logging.exception ("DB Error deleting session")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")

    return {"message": "Session revoked successfully"}


@auth_router.delete(
    "/sessions",
    status_code=status.HTTP_200_OK,
    summary="Logout from all devices",
    description="Revokes all active sessions for the authenticated user, including the current one. The user will need to log in again.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid token or Token expired"},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"description": "Database Error"}
    }
)
async def logout_all_devices (session: AsyncSession = Depends (get_session),
                              user: UserRead = Depends (get_current_user)):
    """
    Deletes all token records for the current user, effectively logging them
    out from every device and session.
    """
    try:
        await session.execute (delete (Token).where (Token.user_id == user.id))
        await session.commit ()
    except Exception:
        logging.exception ("DB Error during logout all")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database Error")

    return {"message": "Successfully logged out from all devices"}