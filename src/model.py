from typing import Optional
from sqlmodel import SQLModel, Field, Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from pydantic import EmailStr
import uuid
from src.database import USER_DATA
from datetime import datetime, timezone


#-----User Models-----
class UserBase (SQLModel):
    email: EmailStr = Field (sa_column=Column(String, unique=True, index=True))
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class User (UserBase, table=True):
    __tablename__ = "users"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}
    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    password: str
    email_verified: bool = Field(default=False)

class UserRead (UserBase):
    id: uuid.UUID
    email_verified: bool


class UserReturn (UserBase):
    email_verified: bool


#-----OTP Models-----
class EmailValidationOtp (SQLModel, table=True):
    __tablename__ = "email_validation_OTP"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    user_id: uuid.UUID = Field (foreign_key=f"{USER_DATA}.users.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    email: str
    otp: str
    expires_at: datetime = Field (sa_column=Column (DateTime(timezone=True)))


class Token (SQLModel, table=True):
    __tablename__ = "user_token"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    user_id: uuid.UUID = Field (foreign_key=f"{USER_DATA}.users.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    token: str
    exp: datetime = Field (sa_column=Column (DateTime(timezone=True)))
    
    # Device and session tracking fields
    ip_address: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    device_type: Optional[str] = None
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))
