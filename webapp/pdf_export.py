from __future__ import annotations

from fpdf import FPDF

ORDER = ["email", "phone", "username", "name", "domain"]


def _safe(value) -> str:
    """cp1252-safe text so non-ASCII names don't crash the core-font PDF."""
    return (str(value) if value is not None else "").encode("cp1252", "replace").decode("cp1252")


def render_report_pdf(prepared: dict) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "OSSINT Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 6, f"Seed: {_safe(prepared['seed'])}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Generated: {_safe(prepared['when'])}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    groups = prepared["groups"]
    for t in ORDER:
        items = groups.get(t)
        if not items:
            continue
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"{t.upper()} ({len(items)})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for it in items:
            pdf.cell(0, 6, f"  {_safe(it['value'])}   (corroboration {it['score']})",
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"FINDINGS ({len(prepared['findings'])})", new_x="LMARGIN", new_y="NEXT")

    headers = ["Identifier", "Source", "Confidence", "Link", "Details"]
    widths = [50, 40, 28, 28, 44]
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, h, border=1, fill=True)
    pdf.ln()

    pdf.set_font("Helvetica", "", 9)
    for f in prepared["findings"]:
        row = [_safe(f["identifier"]), _safe(f["source"]), _safe(f["confidence"]),
               _safe(f.get("url") or "-"), _safe(f.get("details_summary") or "-")]
        for c, w in zip(row, widths):
            pdf.cell(w, 7, c[:70], border=1)
        pdf.ln()
        if pdf.get_y() > 260:
            pdf.add_page()

    return bytes(pdf.output())
