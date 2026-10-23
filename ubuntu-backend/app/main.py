"""CarThing SOC read-only REST API plus an optional browser preview."""
from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .collectors import auth_failures, docker_status, server_status, tailscale_status, wazuh_alerts
from .config import Settings
from .ai_investigate import InvestigationJobs, JobError


class Cache:
    def __init__(self, seconds: int):
        self.seconds = seconds
        self._values: dict[str, tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def get(self, key: str, get_data: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            cached = self._values.get(key)
            if cached and (now - cached[0]) < self.seconds:
                return cached[1]
            result = get_data()
            self._values[key] = (time.monotonic(), result)
            return result


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.validate()
    app = FastAPI(title="CarThing SOC Backend", version="1.1.0", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.cache = Cache(settings.cache_seconds)
    app.state.ai_jobs = InvestigationJobs(settings)

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                           allow_methods=["GET"], allow_headers=["X-API-Key"], allow_credentials=False)

    def authorized(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
        if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")

    def cached(key: str, collector: Callable[[], Any]) -> Any:
        return app.state.cache.get(key, collector)

    @app.get("/", include_in_schema=False)
    def preview() -> FileResponse:
        return FileResponse(Path(__file__).resolve().parent / "static" / "index.html",
                            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "alive", "service": "carthing-soc", "version": "1.1.0"}

    @app.get("/api/v1/server", dependencies=[Depends(authorized)])
    def server() -> dict[str, Any]:
        return cached("server", lambda: server_status(settings))

    @app.get("/api/v1/docker", dependencies=[Depends(authorized)])
    def docker() -> dict[str, Any]:
        return cached("docker", lambda: docker_status(settings))

    @app.get("/api/v1/tailscale", dependencies=[Depends(authorized)])
    def tailscale() -> dict[str, Any]:
        return cached("tailscale", lambda: tailscale_status(settings))

    @app.get("/api/v1/alerts", dependencies=[Depends(authorized)])
    def alerts(limit: int = Query(default=15, ge=1, le=50)) -> dict[str, Any]:
        return cached(f"wazuh_{limit}", lambda: wazuh_alerts(settings, limit))

    @app.get("/api/v1/auth", dependencies=[Depends(authorized)])
    def auth() -> dict[str, Any]:
        return cached("auth", lambda: auth_failures(settings))

    @app.get("/api/v1/overview", dependencies=[Depends(authorized)])
    def overview() -> dict[str, Any]:
        # A single compact endpoint for the Car Thing's limited resources.
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "server": cached("server", lambda: server_status(settings)),
            "docker": cached("docker", lambda: docker_status(settings)),
            "tailscale": cached("tailscale", lambda: tailscale_status(settings)),
            "wazuh": cached("wazuh_15", lambda: wazuh_alerts(settings, 15)),
            "auth": cached("auth", lambda: auth_failures(settings)),
        }

    @app.post("/api/v1/ai/investigate", dependencies=[Depends(authorized)])
    def start_ai_investigation(body: dict[str, Any]) -> dict[str, Any]:
        # On-demand only. No automated or scheduled LLM requests.
        try:
            return app.state.ai_jobs.submit(body.get("alert_id"))
        except JobError as exc:
            raise HTTPException(status_code=exc.code, detail=str(exc)) from exc

    @app.get("/api/v1/ai/investigate/{job_id}", dependencies=[Depends(authorized)])
    def get_ai_investigation(job_id: str) -> dict[str, Any]:
        try:
            return app.state.ai_jobs.get(job_id)
        except JobError as exc:
            raise HTTPException(status_code=exc.code, detail=str(exc)) from exc

    return app


# Deliberately fails fast if the API key hasn't been generated.
app = create_app()
