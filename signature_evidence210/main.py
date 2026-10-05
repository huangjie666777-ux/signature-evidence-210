"""FastAPI HTTP layer for the RFC 3161 TSA service."""

from __future__ import annotations

import asyncio

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse

from .config import Settings, load_settings
from .pki import ensure_pki
from .rfc3161 import issue
from .store import ReceiptStore

QUERY_MEDIA_TYPE = "application/timestamp-query"
REPLY_MEDIA_TYPE = "application/timestamp-reply"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    ensure_pki(settings)  # raises on missing/mismatched keys -> no startup
    store = ReceiptStore(settings.db_path)
    semaphore = asyncio.Semaphore(settings.max_concurrency)

    app = FastAPI(title="Archive TSA", version="0.1.0")
    app.state.settings = settings
    app.state.store = store

    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        if request.method == "POST":
            declared = request.headers.get("content-length")
            if declared is not None and declared.isdigit():
                if int(declared) > settings.max_request_bytes:
                    return PlainTextResponse("request too large", status_code=413)
        return await call_next(request)

    @app.post("/tsa")
    async def timestamp(request: Request) -> Response:
        if request.headers.get("content-type", "").split(";")[0].strip() != QUERY_MEDIA_TYPE:
            return PlainTextResponse("unsupported media type", status_code=415)
        body = await request.body()
        if len(body) > settings.max_request_bytes:
            return PlainTextResponse("request too large", status_code=413)
        if not body:
            return PlainTextResponse("empty request", status_code=400)
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=settings.sign_timeout_seconds)
        except asyncio.TimeoutError:
            return PlainTextResponse("server busy", status_code=503)
        try:
            reply = await asyncio.to_thread(issue, body, settings, store)
        finally:
            semaphore.release()
        return Response(content=reply, media_type=REPLY_MEDIA_TYPE)

    @app.get("/tsa/cert")
    async def tsa_certificate() -> Response:
        return Response(
            content=settings.tsa_cert_path.read_bytes(), media_type="application/x-pem-file"
        )

    @app.get("/tsa/chain")
    async def chain() -> Response:
        pem = settings.tsa_cert_path.read_bytes() + settings.ca_cert_path.read_bytes()
        return Response(content=pem, media_type="application/x-pem-file")

    @app.get("/tsa/receipt/{serial}")
    async def receipt(serial: int) -> Response:
        if serial <= 0:
            return PlainTextResponse("serial must be positive", status_code=400)
        data = store.get_receipt(serial)
        if data is None:
            return PlainTextResponse("unknown serial", status_code=404)
        return Response(content=data, media_type=REPLY_MEDIA_TYPE)

    return app


app = create_app()
