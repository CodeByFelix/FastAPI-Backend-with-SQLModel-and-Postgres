from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, update
from src.schema import User, UserRead, UserCreate, UserLogin, UserReturn, LoginReturn, EmailRequest, EmailValidationOTP
from src.utils import hashPassword, verifyPassword, getCurrentUser, createToken, generate_OTP
from src.database import get_session, DB_Connection_Error
from src.email import sendEmail
from datetime import datetime, timedelta, timezone
from src.loggings import logging

auth_router = APIRouter (prefix='/auth', tags=['auth'])


@auth_router.post ("/create")
async def createAccount (user_in:UserCreate, session:AsyncSession = Depends (get_session)):
    query = select (User).where (User.email == user_in.email)
    try:
        result = await session.execute (query)
        existing = result.one_or_none ()
    except:
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    
    if existing:
        raise HTTPException (status_code=400, detail=f"Email address {user_in.email} already in use")
    
    hashedPassword = await hashPassword (password=user_in.password)

    user = User (
        email=user_in.email,
        password=hashedPassword,
        firstName=user_in.firstName,
        lastName=user_in.lastName
    )

    try:
        session.add (user)
        await session.commit ()
        await session.refresh (user)
        return {'message': f"Account {user.email} created successfully"}
    except Exception as e:
        logging.exception ("Error creating account")
        raise HTTPException (status_code=400, detail="Account creation failed")
    
@auth_router.post ("/login", response_model=LoginReturn)
async def login (user_in:UserLogin, session:AsyncSession = Depends (get_session)):
    query = select(User).where(User.email == user_in.email)
    try:
        result = await session.execute (query)
        existing = result.one_or_none ()
    except:
        logging.exception ("DB Error")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to Connect to the DB")
    
    if not existing:
        raise HTTPException (status_code=400, detail="Wrong Email or Password")
    
    user = User.model_validate (existing[0])

    if not await verifyPassword (plainPassword=user_in.password, hashedPassword=user.password):
        raise HTTPException (status_code=400, detail="Wrong Email or Password")
    
    userReturn = UserReturn.model_validate (user)

    #data = {'id': str (user.id)}
    token = await createToken (user_id=str(user.id), expires=timedelta(hours=168), session=session)

    loginReturn = LoginReturn (
        user= userReturn,
        token=token,
        token_type="Bearer",
        message=f"Login to {user.email} successful"
    )

    return loginReturn

# @auth_router.post ("/send_mail")
# async def sendMail (request:EmailRequest, 
#                     session:AsyncSession = Depends (get_session), 
#                     user:UserRead = Depends(getCurrentUser)):
#     body = f"<p>{request.msg}</p>"
#     if await sendEmail (to_email=user.email, subject="Email Test", html_body=body):
#         return {"message": "Email sent"}
#     else:
#         raise HTTPException (status_code=400, detail="Email not sent")


@auth_router.get ("/logout")
async def logout (session:AsyncSession = Depends (get_session),
                  user:UserRead = Depends (getCurrentUser)):
    pass


@auth_router.get ("/get_email_otp")
async def getEmailOTP (session:AsyncSession = Depends (get_session),
                       user:UserRead = Depends (getCurrentUser)):
    otp = await generate_OTP (length=6)
    otp_data = EmailValidationOTP (
        user_id=user.id,
        email=user.email,
        OTP=otp,
        expires_at = datetime.now (timezone.utc) + timedelta (minutes=1)
    )

    body = f"""
<p>
Hi {user.firstName},
\n\n
Use OTP to verify your Email.\n
{otp}
</p>
"""
    if await sendEmail (to_email=user.email, subject="Email Verification OTP", html_body=body):
        try:
            session.add (otp_data)
            await session.commit ()

            return {"message": "Email Verification OTP sent"}
        except Exception as e:
            logging.exception ("Error occured while saving OTP to DB")
            raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error storing OTP. Try again")
    
    else:
        raise HTTPException (status_code=400, detail="Error sending OTP. Try again")

@auth_router.get ("/verify_email")
async def verfyEmail (otp:str,
                      session:AsyncSession = Depends (get_session),
                      user:UserRead = Depends (getCurrentUser)):
    query = select (EmailValidationOTP).where (EmailValidationOTP.user_id == user.id,
                                               EmailValidationOTP.OTP == otp)
    
    try:
        result = await session.execute (query)
        OTP_record = result.scalar_one_or_none ()
    except Exception as e:
        logging.exception ("Error reading from DB")
        raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB Connection error")
    
    if OTP_record:
        #expired_at = OTP_record.expires_at.replace(tzinfo=timezone.utc)
        if OTP_record.expires_at < datetime.now (timezone.utc):
            try:
                await session.delete (OTP_record)
                await session.commit ()
                #raise HTTPException (status_code=400, detail="OTP has expired")
            except Exception as e:
                logging.exception ("DB Read Write Error")
                raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB Connection error")
            else:
                raise HTTPException (status_code=400, detail="OTP has expired")
        else:
            updateQuery = update (User).where(User.id == user.id).values (emailVerified=True)
            try:
                await session.execute (updateQuery)
                await session.delete (OTP_record)
                await session.commit ()
                return {'message' f"Email {user.email} verified successfully."}
            except Exception as e:
                logging.exception ("DB Read Write Error")
                raise HTTPException (status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB Connection error")

    else:
        raise HTTPException (status_code=400, detail="Invalid OTP")
    
@auth_router.get ("/user_deatil", response_model= UserReturn)
async def getUserDetails (user:UserRead = Depends (getCurrentUser)):
    userReturn = UserReturn.model_validate(user)
    return userReturn