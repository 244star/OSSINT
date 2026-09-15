from __future__ import annotations
import asyncio
import base64
import binascii
import hmac
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ossint.__main__ import coerce
from ossint.__main__ import MAX_IDENTIFIER_LENGTH
from ossint.models import Identifier, IdentifierType
from ossint.normalizers import normalize_email, normalize_phone
from ossint.orchestrator import Orchestrator
from ossint.reporting import graph_dict_to_gml

from .pdf_export import render_report_pdf
from .store import ReportStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent


def _basic_auth_valid(header: str | None, username: str, password: str) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    supplied_user, separator, supplied_password = decoded.partition(":")
    return bool(separator) and hmac.compare_digest(supplied_user, username) and \
        hmac.compare_digest(supplied_password, password)


class RequestRateLimiter:
    def __init__(self, limit: int = 20, window: float = 60.0):
        if limit < 1 or window <= 0:
            raise ValueError("rate limiter limit and window must be positive")
        self.limit = limit
        self.window = window
        self._requests: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        requests = self._requests[key]
        while requests and current - requests[0] >= self.window:
            requests.popleft()
        if len(requests) >= self.limit:
            return False
        requests.append(current)
        return True


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Optional protection for deployments that expose the web app remotely."""

    async def dispatch(self, request: Request, call_next):
        username = os.environ.get("OSSINT_WEB_USERNAME")
        password = os.environ.get("OSSINT_WEB_PASSWORD")
        if not username and not password:
            return await call_next(request)
        if not username or not password:
            return Response("Web authentication is misconfigured", status_code=503)
        if not _basic_auth_valid(request.headers.get("Authorization"), username, password):
            return Response(
                "Authentication required", status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="OSSINT"'})
        return await call_next(request)


class SearchGuardMiddleware(BaseHTTPMiddleware):
    """Bound inbound search volume and simultaneous search executions."""

    def __init__(self, app, limit: int = 20, window: float = 60.0,
                 max_concurrent: int = 4):
        super().__init__(app)
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be positive")
        self.rate_limiter = RequestRateLimiter(limit, window)
        self._active = 0
        self._max_concurrent = max_concurrent
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST" or request.url.path != "/search":
            return await call_next(request)
        client_key = request.client.host if request.client else "unknown"
        if not self.rate_limiter.allow(client_key):
            return Response("Too many search requests", status_code=429,
                            headers={"Retry-After": "60"})
        async with self._lock:
            if self._active >= self._max_concurrent:
                return Response("Too many searches in progress", status_code=429,
                                headers={"Retry-After": "10"})
            self._active += 1
        try:
            return await call_next(request)
        finally:
            async with self._lock:
                self._active -= 1


app = FastAPI(title="OSSINT Web", docs_url=None, redoc_url=None)
app.add_middleware(BasicAuthMiddleware)
app.add_middleware(
    SearchGuardMiddleware,
    limit=int(os.environ.get("OSSINT_WEB_RATE_LIMIT", "20")),
    window=float(os.environ.get("OSSINT_WEB_RATE_WINDOW", "60")),
    max_concurrent=int(os.environ.get("OSSINT_WEB_MAX_CONCURRENT", "4")),
)
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
store = ReportStore(ROOT / "reports")

ORDER = ["email", "phone", "username", "name", "domain"]
PLATFORMS = {
    "linkedin.com": "LinkedIn", "x.com": "X", "instagram.com": "Instagram",
    "facebook.com": "Facebook", "tiktok.com": "TikTok", "github.com": "GitHub",
    "medium.com": "Medium", "pinterest.com": "Pinterest",
    "youtube.com": "YouTube", "reddit.com": "Reddit", "threads.net": "Threads",
    "bsky.app": "Bluesky", "twitch.tv": "Twitch", "snapchat.com": "Snapchat",
    "t.me": "Telegram", "tumblr.com": "Tumblr", "soundcloud.com": "SoundCloud",
    "kick.com": "Kick", "substack.com": "Substack",
}


def prepare_report(data: dict) -> dict:
    """Turn a stored report dict into template-ready view data."""
    graph = data["graph"]
    lookup = {i["key"]: i for i in graph["identifiers"]}

    groups: dict = {}
    for i in graph["identifiers"]:
        groups.setdefault(i["type"], []).append(i)
    groups = {k: sorted(v, key=lambda x: -x["score"]) for k, v in groups.items()}
    groups = {k: groups[k] for k in sorted(groups, key=lambda t: ORDER.index(t) if t in ORDER else 99)}

    findings = []
    for f in graph["findings"]:
        details = f.get("details") or {}
        breaches = details.get("breaches") if isinstance(details, dict) else None
        if isinstance(breaches, list):
            summary = ", ".join(str(b) for b in breaches[:8])
        elif isinstance(details, dict):
            summary = " — ".join(str(v) for v in (details.get("title"), details.get("snippet")) if v)
        else:
            summary = ""
        findings.append({
            "identifier": f["identifier"]["value"],
            "source": f["source"],
            "confidence": f["confidence"],
            "url": f.get("url"),
            "details_summary": summary,
            "details": details,
        })
    findings.sort(key=lambda x: ("verified", "likely", "unsure").index(x["confidence"])
                  if x["confidence"] in ("verified", "likely", "unsure") else 3)

    pivots = []
    for p in graph["pivots"]:
        a = lookup.get(p["from"])
        b = lookup.get(p["to"])
        pivots.append({"from": a["value"] if a else p["from"],
                       "to": b["value"] if b else p["to"],
                       "weight": p["weight"]})

    return {
        "id": data["id"],
        "seed": data["seed"],
        "when": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data["created"])),
        "groups": groups,
        "findings": findings,
        "total": len(findings),
        "source_stats": data.get("source_stats") or {},
        "shows_details": any(f.get("details_summary") for f in findings),
        "pivots": pivots,
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html",
                                      context={"request": request,
                                               "recent": store.list_recent()})


@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    return templates.TemplateResponse(request=request, name="history.html",
                                      context={"request": request,
                                               "items": store.list_all()})


@app.get("/platforms", response_class=HTMLResponse)
async def platforms(request: Request):
    return templates.TemplateResponse(request=request, name="platforms.html",
                                      context={"request": request,
                                               "platforms": PLATFORMS})


def coerce_as(raw: str, identifier_type: str) -> Identifier:
    """Parse an input from a type-specific search form."""
    raw = raw.strip()
    if not raw:
        raise ValueError("identifier cannot be empty")
    if len(raw) > MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"identifier cannot exceed {MAX_IDENTIFIER_LENGTH} characters")
    try:
        kind = IdentifierType(identifier_type)
    except ValueError as exc:
        raise ValueError("unknown search type") from exc
    if kind == IdentifierType.EMAIL:
        return normalize_email(raw)
    if kind == IdentifierType.PHONE:
        return normalize_phone(raw)
    if kind == IdentifierType.NAME:
        if not raw or not any(char.isalpha() for char in raw):
            raise ValueError("enter a name")
        return Identifier(kind, raw.title())
    if kind == IdentifierType.USERNAME:
        if not raw or any(char.isspace() for char in raw):
            raise ValueError("enter a username without spaces")
        return Identifier(kind, raw.lower())
    return Identifier(kind, raw.lower())


@app.post("/search")
async def search(q: str = Form(...), search_type: str = Form("auto"), proxy: str = Form(""),
                 platform: str = Form("")):
    q = q.strip()
    try:
        ident = coerce(q) if search_type == "auto" else coerce_as(q, search_type)
    except ValueError as exc:
        return HTMLResponse(f"<p>Invalid input: {exc}</p><p><a href='/'>Back</a></p>",
                            status_code=400)
    if platform and platform not in PLATFORMS:
        return HTMLResponse("<p>Unknown platform.</p><p><a href='/platforms'>Back</a></p>",
                            status_code=400)
    orchestrator = Orchestrator(max_depth=2, proxy=proxy.strip() or None,
                                platform=platform or None)
    graph = await orchestrator.run(ident)
    rid = store.create(ident, graph, orchestrator.source_stats)
    return RedirectResponse(f"/report/{rid}", status_code=303)


@app.get("/report/{rid}", response_class=HTMLResponse)
async def report(request: Request, rid: str):
    data = store.load(rid)
    if not data:
        return HTMLResponse("<p>Report not found.</p><p><a href='/'>Back</a></p>", status_code=404)
    return templates.TemplateResponse(request=request, name="report.html",
                                      context={"request": request, **prepare_report(data)})


@app.post("/report/{rid}/delete")
async def delete_report(rid: str):
    if not store.delete(rid):
        return HTMLResponse("Report not found", status_code=404)
    return RedirectResponse("/history", status_code=303)


@app.get("/report/{rid}/pdf")
async def report_pdf(rid: str):
    data = store.load(rid)
    if not data:
        return Response("Report not found", status_code=404)
    prepared = prepare_report(data)
    pdf_bytes = render_report_pdf(prepared)
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="ossint_report_{rid}.pdf"'})


@app.get("/report/{rid}/gml")
async def report_gml(rid: str):
    data = store.load(rid)
    if not data:
        return Response("Report not found", status_code=404)
    gml = data.get("gml") or graph_dict_to_gml(data.get("graph") or {})
    if not gml.strip():
        return Response("Graph unavailable for this report", status_code=404)
    return Response(content=gml, media_type="application/octet-stream",
                    headers={"Content-Disposition":
                             f'attachment; filename="ossint_graph_{rid}.gml"'})
