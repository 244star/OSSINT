"""python build_pdf.py -> OSINT_Blueprint.pdf (blueprint + all source files)"""
from pathlib import Path

from fpdf import FPDF

CORE = ["osint/models.py", "osint/normalizers.py", "osint/graph.py",
    "osint/confidence.py", "osint/reporting.py", "osint/orchestrator.py",
    "osint/__main__.py"]
SRC = ["osint/sources/base.py", "osint/sources/native.py",
       "osint/sources/wrappers.py", "osint/sources/dorks.py",
       "osint/sources/telegram_phone.py", "osint/sources/breaches.py"]
WEB = ["run_web.py", "webapp/server.py", "webapp/store.py", "webapp/pdf_export.py",
       "webapp/templates/index.html", "webapp/templates/report.html",
       "webapp/templates/history.html", "webapp/static/style.css"]

BLUEPRINT = """OSINT PRODUCT BLUEPRINT
========================

PIPELINE: identifier -> normalize -> parallel source queries -> correlation graph -> confidence -> report
PIVOTING: every finding seeds new queries (email -> username -> name -> phone), max_depth=2.

TECHNIQUE MATRIX
- Email: registration enumeration (user-scanner / socialscan), breaches (HIBP, DeHashed),
  Gravatar JSON, Google-account surface (Epieos/GHunt)
- Phone: E.164 + carrier/line-type (phonenumbers), enrichment (Twilio Lookup, Numverify),
  WhatsApp/Telegram presence, breach records
- Name: search-engine x-ray (Serper, site: dorks), people-data APIs (PDL/Apollo)
- Username: Maigret (3000+ sites), Sherlock, Blackbird

BREACHES: HIBP v3 via hibp-api-key (free at haveibeenpwned.com). 200 = breaches found,
404 = clean. Add more engines (DeHashed/Snusbase/IntelX) behind the same Source API.

WEB APP (FastAPI + Jinja2)
  python run_web.py          -> http://127.0.0.1:8000  (opens browser automatically)
  POST /search               -> runs the pipeline, saves report, redirects to result page
                               (optional proxy field, or OSINT_PROXY env var)
  GET  /history              -> every saved search (open / pdf / gml links)
  GET  /report/{id}          -> results page (identifiers, findings, confidence, pivots)
  GET  /report/{id}/pdf      -> server-generated PDF download
  GET  /report/{id}/gml      -> correlation graph as GML (opens in Gephi / yEd)
  Browser Print / Save-as-PDF -> printable layout via print CSS
  Reports persist as JSON+GML under reports/ (recent on home page, full history page).

PROXY: per-request field on the search form, or OSINT_PROXY=http://user:pass@host:port
environment variable. Applies to every httpx-backed live source via the shared client.
Subprocess-only sources (maigret, socialscan) bypass it; run those over a system/WSL proxy.

CONFIDENCE MODEL
VERIFIED  - target server explicitly confirmed (HTTP 200 profile, reset-flow response)
LIKELY    - corroborated search hit / single source
UNSURE    - collision-prone (esp. names)

ENGINEERING: async httpx + per-source rate limits, proxy rotation, module health-checks
(module rot is the #1 failure mode), graph persistence (JSON + GML), Redis caching.

COMPLIANCE: GDPR/CCPA controller duties, FCRA ToS prohibition on employment/credit/
tenant screening, platform-ToS review of enumeration modules. For authorized use only.

USAGE
  pip install -r requirements.txt
  pipx install maigret                 # optional username sweep (3000+ sites)
  set HIBP_API_KEY=...                 # optional breach module
  set SERPER_API_KEY=...               # optional search x-ray
    set OSINT_PROXY=http://user:pass@host:port   # optional proxy for live lookups
  python run_web.py                    # start the web app
    python -m osint "john.doe@gmail.com"  # or CLI mode
  python build_pdf.py                  # regenerate this document
"""

HEADER = "OSINT Blueprint - privileged/internal"


class Doc(FPDF):
    def header(self):
        self.set_font("Courier", size=7)
        self.cell(0, 4, HEADER, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)


def code_block(pdf: FPDF, text: str):
    pdf.set_font("Courier", size=7)
    pdf.set_fill_color(245, 245, 245)
    for line in text.splitlines():
        if pdf.get_y() > 270:
            pdf.add_page()
        safe = line[:150].encode("latin-1", "replace").decode("latin-1")
        pdf.cell(0, 3.4, safe, fill=True, new_x="LMARGIN", new_y="NEXT")


def main() -> None:
    pdf = Doc(unit="mm", format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "OSINT Blueprint", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    code_block(pdf, BLUEPRINT)

    for path in CORE + SRC + WEB + ["requirements.txt", "build_pdf.py"]:
        p = Path(path)
        if not p.exists():
            continue
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, path.encode("latin-1", "replace").decode("latin-1"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        code_block(pdf, p.read_text(encoding="utf-8"))

    pdf.output("OSINT_Blueprint.pdf")
    print("[+] wrote OSINT_Blueprint.pdf")


if __name__ == "__main__":
    main()
