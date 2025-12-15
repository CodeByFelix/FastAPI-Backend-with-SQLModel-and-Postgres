from typing import Optional
from sqlmodel import SQLModel, Field, Column, String, DateTime
from pydantic import EmailStr, validator, BaseModel, field_validator
from typing import List
import uuid
import re
from src.database import user_data
from datetime import datetime


class UserBase (SQLModel):
    email: EmailStr = Field (sa_column=Column(String, unique=True, index=True))
    firstName: Optional[str] = None
    lastName: Optional[str] = None

class User (UserBase, table=True):
    __tablename__ = "users"
    __table_args__ = {'schema': user_data}
    id:Optional[uuid.UUID] = Field (default_factory=uuid.uuid4, primary_key=True)
    password:str
    emailVerified: bool = Field(default=False)

class UserRead (UserBase):
    id:str
    emailVerified:bool

    @field_validator ('id', mode='before')
    def convert_uuid (cls, v):
        return str (v)

class UserReturn (UserBase):
    emailVerified:bool

class LoginReturn (BaseModel):
    user: UserReturn
    token: str
    token_type: str
    message: str

class UserCreate(UserBase):
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
    
class UserLogin (SQLModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Password must be at least 8 characters long")

class EmailRequest (SQLModel):
    msg: str



class EmailValidationOTP (SQLModel, table=True):
    __tablename__ = "email_validation_OTP"
    __table_args__ = {'schema': user_data}

    id:uuid.UUID = Field (default_factory=uuid.uuid4, primary_key=True)
    user_id: str
    email: str
    OTP: str
    expires_at: datetime = Field (sa_column=Column (DateTime(timezone=True)))

class Token (SQLModel, table=True):
    __tablename__ = "user_token"
    __table_args__ = {'schema': user_data}

    id:uuid.UUID = Field (default_factory=uuid.uuid4, primary_key=True)
    user_id: str
    token:str
    exp: datetime = Field (sa_column=Column (DateTime(timezone=True)))
