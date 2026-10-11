from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sureshot.api.deps import get_runner, get_store
from sureshot.api.routers import findings, health, reports, scans


@asynccontextmanager
async def _lifespan(app: FastAPI):
    get_store()  # load persisted scans, mark interrupted ones failed
    yield
    get_runner().shutdown()


def create_app() -> FastAPI:
    app = FastAPI(title="SureShot API", version="0.1.0", lifespan=_lifespan)
    origins = os.environ.get("SURESHOT_CORS_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(CORSMiddleware, allow_origins=origins,
                       allow_methods=["*"], allow_headers=["*"])
    for router in (health.router, scans.router, findings.router, reports.router):
        app.include_router(router, prefix="/api")
    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("sureshot.api.main:app",
                host=os.environ.get("SURESHOT_API_HOST", "127.0.0.1"),
                port=int(os.environ.get("SURESHOT_API_PORT", "8787")))
