import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

load_dotenv()


def get_database_url() -> str:
    url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./deepsecure.db")
    # Convert standard postgres/postgresql URLs to asyncpg driver URLs for production
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


DATABASE_URL = get_database_url()
DB_ECHO = os.getenv("DB_ECHO", "false").lower() in ("true", "1", "yes")

engine_kwargs = {"echo": DB_ECHO}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_async_engine(
    DATABASE_URL,
    **engine_kwargs
)


class Base(DeclarativeBase):
    pass


AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    from app.models.user import User  # noqa: F401
    from app.models.scan import Scan  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)