import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.ai import router as ai_router
from app.api.auth import router as auth_router
from app.api.scanner import router as scanner_router
from app.core.database import engine, init_db
from app.models.user import User  # noqa: F401
from app.models.scan import Scan  # noqa: F401

load_dotenv()

# Configure production-safe logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("deepsecure")


def parse_cors_origins() -> list[str]:
    raw_origins = os.getenv("CORS_ORIGINS", "")
    if not raw_origins:
        return [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    return origins if origins else ["*"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing DeepSecure-X database...")
    await init_db()
    logger.info("DeepSecure-X database initialization complete.")
    yield


app = FastAPI(
    title="DeepSecure-X",
    description="Secure AI-powered application security platform",
    version="1.0.0",
    lifespan=lifespan
)

origins = parse_cors_origins()
logger.info(f"Configured CORS allowed origins: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: {exc}",
        exc_info=True
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."}
    )


app.include_router(auth_router)
app.include_router(ai_router)
app.include_router(scanner_router)


@app.get("/")
async def root():
    return {
        "message": "DeepSecure-X API is running",
        "status": "secure",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    db_status = "connected"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Health check database ping failed: {e}")
        db_status = "disconnected"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "version": "1.0.0"
    }