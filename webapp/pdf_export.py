from __future__ import annotations

from fpdf import FPDF

ORDER = ["email", "phone", "username", "name", "domain"]
MINT = (78, 155, 124)
INK = (24, 31, 31)
MUTED = (91, 105, 103)
LINE = (215, 224, 220)
PALE = (241, 247, 244)


def _safe(value) -> str:
    """Keep the built-in PDF fonts safe for arbitrary source text."""
    return (str(value) if value is not None else "").encode("cp1252", "replace").decode("cp1252")


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, "OSINT  /  INVESTIGATION BRIEF", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LINE)
        self.line(self.l_margin, 13, self.w - self.r_margin, 13)
        self.set_text_color(*INK)

    def footer(self):
        self.set_y(-14)
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "Authorized investigations only  |  Public-source observations", align="L")
        self.cell(0, 8, f"Page {self.page_no()}", align="R")


def _section(pdf: ReportPDF, number: str, title: str, caption: str = "") -> None:
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*MINT)
    pdf.cell(12, 6, number)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
    if caption:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 5, caption, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _metric(pdf: ReportPDF, x: float, label: str, value: str, note: str) -> None:
    y = pdf.get_y()
    pdf.set_fill_color(*PALE)
    pdf.set_draw_color(*LINE)
    pdf.rect(x, y, 42.5, 23, style="DF")
    pdf.set_xy(x + 3, y + 3)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*MUTED)
    pdf.cell(36, 4, _safe(label).upper())
    pdf.set_xy(x + 3, y + 8)
    pdf.set_font("Helvetica", "", 18)
    pdf.set_text_color(*INK)
    pdf.cell(36, 8, _safe(value))
    pdf.set_xy(x + 3, y + 17)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*MUTED)
    pdf.cell(36, 3, _safe(note))


def _finding(pdf: ReportPDF, finding: dict) -> None:
    if pdf.get_y() > 245:
        pdf.add_page()
    y = pdf.get_y()
    pdf.set_fill_color(248, 250, 249)
    pdf.set_draw_color(*LINE)
    pdf.rect(pdf.l_margin, y, 180, 11, style="DF")
    pdf.set_xy(pdf.l_margin + 4, y + 3)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*INK)
    pdf.cell(57, 5, _safe(finding["identifier"]))
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(55, 5, _safe(finding["source"]))
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*MINT if finding["confidence"] == "verified" else (173, 128, 42))
    pdf.cell(55, 5, _safe(finding["confidence"]).upper())
    pdf.set_xy(pdf.l_margin + 4, y + 14)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*INK)
    detail = finding.get("details_summary") or "No additional source metadata."
    pdf.multi_cell(172, 4, _safe(detail), new_x="LMARGIN", new_y="NEXT")
    if finding.get("url"):
        pdf.set_text_color(*MINT)
        pdf.cell(0, 4, _safe(finding["url"]), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)


def render_report_pdf(prepared: dict) -> bytes:
    pdf = ReportPDF()
    pdf.set_auto_page_break(True, margin=18)
    pdf.set_margins(15, 18, 15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*INK)
    pdf.cell(0, 12, "Public-source findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 6, f"Seed identifier: {_safe(prepared['seed'])}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Generated: {_safe(prepared['when'])}  |  Report: {_safe(prepared['id'])}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    counts = prepared.get("confidence_counts", {})
    metrics = [("Findings", str(prepared["total"]), "observations"),
               ("Identifiers", str(prepared.get("identifier_count", 0)), "linked nodes"),
               ("Sources", str(prepared.get("source_count", 0)), "distinct providers"),
               ("Verified", str(counts.get("verified", 0)), "explicit confirmations")]
    start_x = pdf.l_margin
    for index, (label, value, note) in enumerate(metrics):
        _metric(pdf, start_x + index * 45, label, value, note)
    pdf.set_y(pdf.get_y() + 29)

    pdf.set_fill_color(*PALE)
    pdf.set_draw_color(*MINT)
    pdf.rect(pdf.l_margin, pdf.get_y(), 180, 17, style="DF")
    pdf.set_xy(pdf.l_margin + 4, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*INK)
    pdf.cell(33, 5, "ASSESSMENT SCOPE")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(140, 4, "Public-source observations available at scan time. A finding is not proof of identity; review the linked source before acting on it.", new_x="LMARGIN", new_y="NEXT")

    _section(pdf, "01", "Evidence posture", f"{prepared.get('source_count', 0)} source providers queried")
    posture = [("VERIFIED", counts.get("verified", 0), "explicit server confirmation"),
               ("LIKELY", counts.get("likely", 0), "credible source or search hit"),
               ("UNSURE", counts.get("unsure", 0), "collision or weak signal")]
    for index, (label, value, note) in enumerate(posture):
        x = pdf.l_margin + index * 60
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*MINT if label == "VERIFIED" else (173, 128, 42) if label == "LIKELY" else MUTED)
        pdf.set_xy(x, pdf.get_y())
        pdf.cell(22, 6, label)
        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(*INK)
        pdf.cell(12, 6, str(value))
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(x, pdf.get_y() + 7)
        pdf.multi_cell(52, 3, note)
    pdf.ln(7)

    source_names = prepared.get("source_names", [])
    if source_names:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(30, 5, "SOURCE COVERAGE")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*INK)
        pdf.multi_cell(145, 5, _safe("  |  ".join(source_names)), new_x="LMARGIN", new_y="NEXT")

    _section(pdf, "02", "Identifier map", "Ranked by corroboration")
    for identifier_type in ORDER:
        items = prepared["groups"].get(identifier_type)
        if not items:
            continue
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*MINT)
        pdf.cell(30, 6, identifier_type.upper())
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*INK)
        for item in items:
            pdf.cell(112, 6, _safe(item["value"]))
            pdf.set_text_color(*MUTED)
            pdf.cell(0, 6, f"corroboration {item['score']}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*INK)

    _section(pdf, "03", "Evidence ledger", f"{prepared['total']} observation(s), ordered by confidence")
    if prepared["findings"]:
        for finding in prepared["findings"]:
            _finding(pdf, finding)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(0, 5, "No findings were returned for this identifier.")

    if prepared.get("pivots"):
        _section(pdf, "04", "Pivot trail", "Linked identifiers discovered during collection")
        for pivot in prepared["pivots"]:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*INK)
            pdf.cell(0, 6, f"{_safe(pivot['from'])}  ->  {_safe(pivot['to'])}")
            pdf.set_text_color(*MUTED)
            pdf.cell(0, 6, f"  weight {pivot['weight']}", new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())