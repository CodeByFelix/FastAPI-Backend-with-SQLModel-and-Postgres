from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType, NameEmail
from pydantic import BaseModel
from typing import List
from src.settings import settings
from src.loggings import logging


config = ConnectionConfig (
    MAIL_USERNAME = settings.MAIL_USERNAME,
    MAIL_PASSWORD = settings.MAIL_PASSWORD,
    MAIL_FROM = settings.MAIL_FROM,
    MAIL_PORT = settings.MAIL_PORT,
    MAIL_SERVER = settings.MAIL_SERVER,
    MAIL_STARTTLS = False,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

async def sendEmail (to_email:str, subject:str, html_body:str) -> bool:
    message = MessageSchema (
        subject=subject,
        recipients=[to_email],
        body=html_body,
        subtype=MessageType.html
    )
    try:
        fm = FastMail (config=config)
        await fm.send_message (message=message)
        return True
    except Exception as e:
        logging.exception ("Error sending mail")
        return False

