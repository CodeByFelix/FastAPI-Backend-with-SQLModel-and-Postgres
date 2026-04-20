from typing import Optional
from pydantic import BaseModel, EmailStr, Field, validator
from src.model import UserReturn, UserBase
import uuid
import re
from datetime import datetime

#-----User Schemas-----
class UserLogin (BaseModel):
    email: EmailStr
    password: str

class UserCreate (UserBase):
    password: str = Field(min_length=8, description="Password must be at least 8 characters long")

    @validator("password")
    def validate_password_strength(cls, value):
        """
        Validates that the password is strong:
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")

        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")

        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>/]", value):
            raise ValueError("Password must contain at least one special character")

        return value

class LoginReturn (BaseModel):
    user: UserReturn
    token: str
    token_type: str
    message: str

class VerifyEmailRequest (BaseModel):
    otp: str

class SessionResponse(BaseModel):
    id: uuid.UUID
    ip_address: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    device_type: Optional[str] = None
    created_at: datetime
    is_current_session: bool = False