import logging
import httpx
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.core.enrichment.enricher import load_kev
from app.core.nist.mapper import seed_mappings
from app.db.init_db import init_db
from app.db.session import AsyncSessionLocal
from app.api.routes import auth, ingest, query, score, report, analyse, audit, metrics

log = logging.getLogger("ragscan")
logging.basicConfig(level=logging.INFO)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting up RAGScan...")
    try:
        log.info("Initializing database schema...")
        await init_db()
        log.info("Database schema ready.")

        log.info("Seeding control mappings...")
        async with AsyncSessionLocal() as session:
            await seed_mappings(session)
        log.info("Control mappings ready.")

        log.info("Loading KEV catalog...")
        async with httpx.AsyncClient() as client:
            await load_kev(client)
        log.info("KEV catalog ready.")
    except Exception:
        log.exception("Startup failed during initialization")
        raise
    log.info("Startup complete.")
    yield
    log.info("Shutting down.")


app = FastAPI(
    title="RAGScan",
    version="1.0.0",
    description="Retrieval-augmented vulnerability intelligence and compliance gap analysis.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth")
app.include_router(ingest.router, prefix="/ingest")
app.include_router(query.router, prefix="/query")
app.include_router(score.router, prefix="/score")
app.include_router(metrics.router, prefix="/metrics")
app.include_router(report.router, prefix="/report")
app.include_router(analyse.router, prefix="/analyse")
app.include_router(audit.router, prefix="/audit")


@app.get("/health")
async def health():
    return {"status": "ok", "version": app.version}
