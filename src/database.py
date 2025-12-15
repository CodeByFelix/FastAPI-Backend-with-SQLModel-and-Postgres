from typing import AsyncGenerator
from sqlmodel import SQLModel, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from src.settings import settings

import ssl

class DB_Connection_Error (Exception):
    pass


user = settings.DB_USER
password = settings.DB_PASSWORD
host = settings.DB_HOST
port = settings.DB_PORT
database = settings.DB_DATABASE

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False   # important for Supabase pooled endpoints
ssl_context.verify_mode = ssl.CERT_NONE

DB_URL = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}"

#print (DB_URL)
engine = create_async_engine (url=DB_URL, echo=False, future=True, connect_args={"ssl": ssl_context})

AsyncSessionLocal = sessionmaker (
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

user_data = "test_data"

async def init_db () -> None:
    try:
        async with engine.begin () as conn:
            schemas = [user_data]
            for schema in schemas:
                await conn.execute (text (f"CREATE SCHEMA IF NOT EXISTS {schema}"))
                
            await conn.run_sync(SQLModel.metadata.create_all)
    except Exception as e:
        raise DB_Connection_Error (f"Error connecting to DB {e}") from e


async def get_session () -> AsyncGenerator [AsyncSession, None]:
    async with AsyncSessionLocal () as session:
        yield session