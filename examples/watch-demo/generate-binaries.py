#!/usr/bin/env python3
"""
generate-binaries.py — build valid binary demo fixtures for the folder-watch demo.

Produces three files next to this script that exercise Verity's Tier-1 extraction
(crates/verity-server/src/extract.rs): calamine (.xlsx), zip+quick-xml (.pptx),
pdf-extract (.pdf). All content stays coherent with the Acme Freight sample cast
(account:acme-freight, user:jordan / group:sales, renewal risk, $48k -> $61k,
$52k competitor, $58k deal-desk floor).

  .xlsx  -> openpyxl (a real dependency; `pip install openpyxl`)
  .pptx  -> hand-built OOXML zip (stdlib only: zipfile + string templates)
  .pdf   -> hand-built PDF 1.4 with a text stream (stdlib only)

Run:
    python3 generate-binaries.py

If openpyxl is missing, the .xlsx is skipped with a clear message; the plain-text
fixtures (acme-renewal-risk.md, acme-notes.txt, acme-fleet.csv) always work, so the
demo never depends on this script succeeding.
"""

import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- xlsx
def build_xlsx(path):
    try:
        from openpyxl import Workbook
    except ImportError:
        print("  [skip] .xlsx — openpyxl not installed (pip install openpyxl). "
              "acme-fleet.csv is the plain-text stand-in.")
        return False
    wb = Workbook()
    ws = wb.active
    ws.title = "Renewal Pricing"
    rows = [
        ["Acme Freight Co — Renewal Pricing Sheet", "", "", ""],
        ["Account", "account:acme-freight", "CSM", "user:jordan (group:sales)"],
        ["", "", "", ""],
        ["Line item", "Amount (USD)", "Basis", "Note"],
        ["Prior annual quote", 48000, "annual", "original renewal quote"],
        ["Revised annual quote", 61000, "annual", "after pricing review"],
        ["Competitor quote (rumored)", 52000, "annual", "undercuts our revised number"],
        ["Deal-desk floor", 58000, "annual", "do not commit below this"],
        ["", "", "", ""],
        ["Renewal stage", "negotiation", "", "decision expected this quarter"],
        ["Renewal risk", "HIGH", "", "price gap + active competitor"],
        ["Recommended play", "multi-year term", "",
         "bridge the gap without discounting below the floor"],
    ]
    for r in rows:
        ws.append(r)
    wb.save(path)
    print(f"  [ok]  {os.path.basename(path)}")
    return True


# --------------------------------------------------------------------------- pptx
PPTX_SLIDE_LINES = [
    "Acme Freight — Renewal Review (sample)",
    "Account: account:acme-freight  |  CSM: user:jordan  |  Team: group:sales",
    "Stage: negotiation — decision expected this quarter.",
    "Revised annual quote: $61k (up from $48k after the pricing review).",
    "Competitor rumored at $52k. Deal-desk floor is $58k/yr.",
    "Renewal risk: HIGH — price gap plus an active competitor.",
    "Play: lead with the dispatch integration and 95% tracking SLA; "
    "bridge price with a multi-year term.",
]


def _pptx_paragraph(text):
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    return (
        "<a:p><a:r><a:rPr lang=\"en-US\" dirty=\"0\"/>"
        f"<a:t>{text}</a:t></a:r></a:p>"
    )


def build_pptx(path):
    paragraphs = "".join(_pptx_paragraph(t) for t in PPTX_SLIDE_LINES)
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
        '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        '</Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
        '</Relationships>'
    )
    presentation = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>'
        '<p:sldSz cx="9144000" cy="6858000"/></p:presentation>'
    )
    presentation_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>'
        '</Relationships>'
    )
    slide = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr/>'
        '<p:sp><p:nvSpPr><p:cNvPr id="2" name="TextBox"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
        '<p:spPr><a:xfrm><a:off x="457200" y="457200"/><a:ext cx="8229600" cy="5943600"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        f'<p:txBody><a:bodyPr/><a:lstStyle/>{paragraphs}</p:txBody></p:sp>'
        '</p:spTree></p:cSld><p:clrMapOvr><a:overrideClrMapping '
        'bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
        'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" '
        'hlink="hlink" folHlink="folHlink"/></p:clrMapOvr></p:sld>'
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("ppt/presentation.xml", presentation)
        z.writestr("ppt/_rels/presentation.xml.rels", presentation_rels)
        z.writestr("ppt/slides/slide1.xml", slide)
    print(f"  [ok]  {os.path.basename(path)}")
    return True


# --------------------------------------------------------------------------- pdf
PDF_LINES = [
    "Acme Freight - Renewal Risk (sample)",
    "Account: account:acme-freight   CSM: user:jordan   Team: group:sales",
    "Stage: negotiation - decision expected this quarter.",
    "Revised annual quote is $61k, up from $48k after the pricing review.",
    "A competitor is rumored at $52k. The deal-desk floor is $58k per year.",
    "Renewal risk: HIGH - price gap plus an active competitor.",
    "Play: lead with the dispatch integration and the 95% tracking SLA;",
    "bridge the price gap with a multi-year term, not a discount below the floor.",
]


def _pdf_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(path):
    # Build a simple single-page PDF 1.4 with a Helvetica text block.
    lines_ops = ["BT", "/F1 12 Tf", "14 TL", "72 720 Td"]
    for ln in PDF_LINES:
        lines_ops.append(f"({_pdf_escape(ln)}) Tj")
        lines_ops.append("T*")
    lines_ops.append("ET")
    stream = "\n".join(lines_ops).encode("latin-1")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    objects.append(
        b"<< /Length " + str(len(stream)).encode("latin-1") + b" >>\nstream\n"
        + stream + b"\nendstream"
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode("latin-1") + obj + b"\nendobj\n"
    xref_pos = len(out)
    n = len(objects) + 1
    out += f"xref\n0 {n}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode("latin-1")
    out += (
        f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    ).encode("latin-1")
    with open(path, "wb") as f:
        f.write(out)
    print(f"  [ok]  {os.path.basename(path)}")
    return True


def main():
    print("Generating binary demo fixtures in", HERE)
    build_xlsx(os.path.join(HERE, "acme-renewal-pricing.xlsx"))
    build_pptx(os.path.join(HERE, "acme-renewal-review.pptx"))
    build_pdf(os.path.join(HERE, "acme-renewal-risk.pdf"))
    print("Done.")


if __name__ == "__main__":
    sys.exit(main())
