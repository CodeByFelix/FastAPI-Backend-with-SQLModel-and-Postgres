from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends
from datetime import datetime, timedelta, timezone
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.database import get_session
from src.schema import User, UserRead, Token
from src.settings import settings
from src.loggings import logging
import random

password_context = CryptContext (schemes=['bcrypt'], deprecated='auto')
secretKey = settings.SECRET_KEY
algorithm = settings.ALGORITHM

oauthSchema = HTTPBearer ()


async def hashPassword (password:str) -> str:
    return password_context.hash (password)

async def verifyPassword (plainPassword:str, hashedPassword:str) -> bool:
    return password_context.verify (plainPassword, hashedPassword)

async def createToken (user_id:str, expires: timedelta = None, session:AsyncSession = None) -> str:
    ex = datetime.now (timezone.utc) + (expires or timedelta (hours=168))
    data={'id': user_id, 'exp': ex}
    token = jwt.encode (claims=data, key=secretKey, algorithm=algorithm)
    tokenEntry = Token(user_id=user_id, token=token, exp=ex)
    try:
        session.add (tokenEntry)
        await session.commit ()
        return token
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    

async def deleteTokenRecord (tokenRecord:Token, session:AsyncSession = None):
    await session.delete (tokenRecord)
    await session.commit ()

async def getCurrentUser (credential:HTTPAuthorizationCredentials = Depends (oauthSchema),
                          session:AsyncSession = Depends (get_session)) -> UserRead:
    token = credential.credentials
    credentialException = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Invalid token",
                                         headers={'WWW.Authenticate': "Bearer"})
    credentialExpired = HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Token Expired",
                                         headers={'WWW.Authenticate': "Bearer"})
    
    query = select (Token).where (Token.token == token)
    try:
        result = await session.execute (query)
        tokenRecord = result.scalar_one_or_none ()
        
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    else:
        if not tokenRecord:
            raise credentialException
        
        try:
            payload = jwt.decode (token=token, key=secretKey, algorithms=algorithm)
            user_id = payload.get ('id', None)
            
        except JWTError:
            await deleteTokenRecord (tokenRecord=tokenRecord, session=session)
            raise credentialException
        except ExpiredSignatureError:
            await deleteTokenRecord (tokenRecord=tokenRecord, session=session)
            raise credentialExpired
        else:
            if id is None:
                await deleteTokenRecord (tokenRecord=tokenRecord, session=session)
                raise credentialException
            
            try:
                query = select (User).where (User.id == user_id)
                result = await session.execute (query)
                user = result.one_or_none ()
            except:
                raise HTTPException (status_code=400, detail="DB Connection Error")
            if not user:
                raise credentialException
            
            return UserRead.model_validate (user[0], from_attributes=True)

    


async def generate_OTP (length:int = 6) -> str:
    return ''.join (str(random.randint(0, 9)) for _ in range (length))
