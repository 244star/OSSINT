from __future__ import annotations
import logging
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

from osint.__main__ import coerce
from osint.models import Identifier, IdentifierType
from osint.normalizers import normalize_email, normalize_phone
from osint.orchestrator import Orchestrator
from osint.reporting import graph_dict_to_gml

from .pdf_export import render_report_pdf
from .store import ReportStore

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

app = FastAPI(title="OSINT Web", docs_url=None, redoc_url=None)
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

    confidence_counts = {level: sum(1 for f in findings if f["confidence"] == level)
                         for level in ("verified", "likely", "unsure")}
    source_names = sorted({f["source"] for f in findings})

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
        "confidence_counts": confidence_counts,
        "source_names": source_names,
        "source_count": len(source_names),
        "identifier_count": len(graph["identifiers"]),
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
    graph = await Orchestrator(max_depth=2, proxy=proxy.strip() or None,
                               platform=platform or None).run(ident)
    rid = store.create(ident, graph)
    return RedirectResponse(f"/report/{rid}", status_code=303)


@app.get("/report/{rid}", response_class=HTMLResponse)
async def report(request: Request, rid: str):
    data = store.load(rid)
    if not data:
        return HTMLResponse("<p>Report not found.</p><p><a href='/'>Back</a></p>", status_code=404)
    return templates.TemplateResponse(request=request, name="report.html",
                                      context={"request": request, **prepare_report(data)})


@app.get("/report/{rid}/pdf")
async def report_pdf(rid: str):
    data = store.load(rid)
    if not data:
        return Response("Report not found", status_code=404)
    prepared = prepare_report(data)
    pdf_bytes = render_report_pdf(prepared)
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="osint_report_{rid}.pdf"'})


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
                             f'attachment; filename="osint_graph_{rid}.gml"'})
