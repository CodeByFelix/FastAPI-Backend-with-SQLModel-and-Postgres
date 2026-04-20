from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends
from datetime import datetime, timedelta, timezone
from sqlmodel import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from src.database import get_session
from src.model import User, UserRead, Token
from src.settings import settings
from src.loggings import logging
import random

password_context = CryptContext (schemes=['bcrypt'], deprecated='auto')
secret_key = settings.SECRET_KEY
algorithm = settings.ALGORITHM

oauth_schema = HTTPBearer ()


async def hash_password (password: str) -> str:
    return password_context.hash (password)

async def verify_password (plain_password: str, hashed_password: str) -> bool:
    return password_context.verify (plain_password, hashed_password)

async def create_token (user_id: str, expires: timedelta = None, session: AsyncSession = None,
                        ip_address: str = None, os: str = None, browser: str = None, 
                        device_type: str = None) -> str:
    ex = datetime.now (timezone.utc) + (expires or timedelta (hours=168))
    data = {'id': user_id, 'exp': ex}
    token = jwt.encode (claims=data, key=secret_key, algorithm=algorithm)
    token_entry = Token(
        user_id=user_id, 
        token=token, 
        exp=ex,
        ip_address=ip_address,
        os=os,
        browser=browser,
        device_type=device_type
    )
    try:
        session.add (token_entry)
        await session.commit ()
        return token
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")


async def cleanup_expired_tokens (user_id: str, session: AsyncSession) -> None:
    """Remove all expired tokens for the given user."""
    try:
        cleanup_query = delete (Token).where (
            Token.user_id == user_id,
            Token.exp < datetime.now (timezone.utc)
        )
        await session.execute (cleanup_query)
        await session.commit ()
    except:
        logging.exception ("Error cleaning up expired tokens")
    

async def delete_token_record (token_record: Token, session: AsyncSession = None):
    await session.delete (token_record)
    await session.commit ()

async def get_current_user (credential: HTTPAuthorizationCredentials = Depends (oauth_schema),
                            session: AsyncSession = Depends (get_session)) -> UserRead:
    token = credential.credentials
    credential_exception = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Invalid token",
                                          headers={'WWW-Authenticate': "Bearer"})
    credential_expired = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Token Expired",
                                         headers={'WWW-Authenticate': "Bearer"})
    
    query = select (Token).where (Token.token == token)
    try:
        result = await session.execute (query)
        token_record = result.scalar_one_or_none ()
        
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    else:
        if not token_record:
            raise credential_exception
        
        try:
            payload = jwt.decode (token=token, key=secret_key, algorithms=algorithm)
            user_id = payload.get ('id', None)
            
        except JWTError:
            await delete_token_record (token_record=token_record, session=session)
            raise credential_exception
        except ExpiredSignatureError:
            await delete_token_record (token_record=token_record, session=session)
            raise credential_expired
        else:
            if user_id is None:
                await delete_token_record (token_record=token_record, session=session)
                raise credential_exception
            
            try:
                query = select (User).where (User.id == user_id)
                result = await session.execute (query)
                user = result.one_or_none ()
            except:
                raise HTTPException (status_code=400, detail="DB Connection Error")
            if not user:
                raise credential_exception
            
            return UserRead.model_validate (user[0], from_attributes=True)


async def generate_otp (length: int = 6) -> str:
    return ''.join (str(random.randint(0, 9)) for _ in range (length))
