//! Tier-1 binary file extraction: PDF, PPTX, XLS(X) → plain text.
//!
//! The honesty rules here are load-bearing (founder directive, Tier 1):
//!
//! * **Rust-native and deterministic.** No LLM, no OCR, no external process.
//!   The same bytes always yield the same text.
//! * **Never silently empty.** Every call returns either extracted text with
//!   its method + truncation flag, a *typed* failure reason (encrypted PDF,
//!   scanned/image PDF, parse failure, unrecognized format), or an explicit
//!   `NotHandled` so the caller can run its existing text-like/store-only
//!   logic. A caller can always disclose exactly what happened.
//! * **A hostile file never kills the server.** The PDF path is wrapped in
//!   `catch_unwind` because pdf crates are known to panic on malformed input.
//! * **Honest limits.** Extraction is capped at [`MAX_EXTRACT_CHARS`] with a
//!   disclosed `truncated` flag; scanned PDFs are declined with an explicit
//!   "OCR is a later tier" reason, not returned as empty text.
//!
//! Dependency choices (also noted in the workspace Cargo.toml):
//!
//! * **calamine** — pure-Rust xlsx/xls/xlsb/ods reader with its own magic-byte
//!   autodetection (`open_workbook_auto_from_rs`), so legacy `.xls` (OLE2) and
//!   modern `.xlsx` (zip) share one code path.
//! * **zip + quick-xml** — a pptx is a zip of XML; slide text is just the
//!   `<a:t>` runs in `ppt/slides/slideN.xml` plus the notes slides reachable
//!   through each slide's `.rels`. A streaming XML pull is all that's needed.
//! * **pdf-extract over raw lopdf** — pdf-extract implements the actual
//!   text-run decoding (font encodings, ToUnicode CMaps, ordering) on top of
//!   lopdf; with lopdf alone we would have to reimplement all of that. The
//!   cost is that pdf-extract panics on some malformed files — accepted and
//!   contained via `catch_unwind`, never allowed to unwind into the handler.

use std::io::{Cursor, Read};

use calamine::Reader as _;

/// Hard cap on extracted text, in chars (~200 KB). Disclosed via
/// `Extraction::truncated` — a capped extraction is never passed off as the
/// whole document.
pub(crate) const MAX_EXTRACT_CHARS: usize = 200_000;

/// A successful extraction: the text, how it was produced, and whether the
/// [`MAX_EXTRACT_CHARS`] cap cut it short.
#[derive(Debug)]
pub(crate) struct Extraction {
    pub(crate) text: String,
    /// "calamine" | "pptx-xml" | "pdf-text" — recorded into provenance.
    pub(crate) method: &'static str,
    pub(crate) truncated: bool,
}

/// Typed failure reasons. `reason()` strings are part of the disclosed API
/// (they land in episode payloads, HTTP responses, and UI receipts) — change
/// them deliberately.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExtractFailure {
    EncryptedPdf,
    /// Parsed fine but produced (approximately) no text: an image-only scan.
    ScannedPdf,
    PdfParse(String),
    SheetParse(String),
    PptxParse(String),
    /// The filename claimed one of our formats but the bytes don't match
    /// (magic wins), or the connector sent bytes we have no extractor for.
    UnrecognizedFormat,
    /// Parsed fine but the document simply contains no text (e.g. an empty
    /// workbook or an all-images deck).
    NoText,
}

impl ExtractFailure {
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::EncryptedPdf => "encrypted PDF".into(),
            Self::ScannedPdf => "scanned/image PDF — no text layer (OCR is a later tier)".into(),
            Self::PdfParse(e) => format!("PDF parse failure: {e}"),
            Self::SheetParse(e) => format!("spreadsheet parse failure: {e}"),
            Self::PptxParse(e) => format!("PPTX parse failure: {e}"),
            Self::UnrecognizedFormat => "unrecognized format".into(),
            Self::NoText => "file parsed but contains no extractable text".into(),
        }
    }
}

/// What [`extract`] decided about the bytes.
#[derive(Debug)]
pub(crate) enum ExtractOutcome {
    /// Not one of ours (not PDF/PPTX/XLS(X) by magic or claim) — the caller
    /// applies its existing text-like / store-only handling.
    NotHandled,
    Extracted(Extraction),
    Failed(ExtractFailure),
}

// ---------------------------------------------------------------------------
// Detection: magic bytes AND filename, magic wins.
// ---------------------------------------------------------------------------

/// Format claimed by the file extension alone. Used only as a tiebreak/claim:
/// when the magic bytes disagree with the claim, magic wins and the claim
/// makes the mismatch a *typed* failure instead of a silent store-only.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Claim {
    Pdf,
    Xlsx,
    Pptx,
    Xls,
}

fn claim_from_name(filename: Option<&str>) -> Option<Claim> {
    let lower = filename?.to_ascii_lowercase();
    if lower.ends_with(".pdf") {
        Some(Claim::Pdf)
    } else if lower.ends_with(".xlsx") || lower.ends_with(".xlsm") {
        Some(Claim::Xlsx)
    } else if lower.ends_with(".pptx") {
        Some(Claim::Pptx)
    } else if lower.ends_with(".xls") {
        Some(Claim::Xls)
    } else {
        None
    }
}

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The PDF spec allows up to 1024 bytes of junk before `%PDF-`.
fn looks_like_pdf(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(1024)];
    window.windows(5).any(|w| w == b"%PDF-")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Route bytes to the right Tier-1 extractor. Detection is by magic bytes AND
/// filename — magic wins. `NotHandled` means "not our format"; the caller
/// keeps its existing behavior for those.
pub(crate) fn extract(bytes: &[u8], filename: Option<&str>) -> ExtractOutcome {
    extract_with_cap(bytes, filename, MAX_EXTRACT_CHARS)
}

/// Cap-parameterized worker so tests can exercise truncation without
/// megabyte fixtures. Production callers use [`extract`].
fn extract_with_cap(bytes: &[u8], filename: Option<&str>, cap: usize) -> ExtractOutcome {
    let claim = claim_from_name(filename);
    if looks_like_pdf(bytes) {
        return finish(extract_pdf(bytes, cap));
    }
    if bytes.starts_with(ZIP_MAGIC) {
        // Zip container: xlsx and pptx are both zips — tell them apart by the
        // package structure (magic-level truth), not the extension.
        return match zip_office_kind(bytes) {
            Ok(Some(Claim::Xlsx)) => finish(extract_sheet(bytes, cap)),
            Ok(Some(Claim::Pptx)) => finish(extract_pptx(bytes, cap)),
            // A zip that isn't an office package: ours only if the name
            // claimed so (then the claim is wrong — typed, magic wins).
            Ok(_) => match claim {
                Some(Claim::Xlsx) | Some(Claim::Pptx) | Some(Claim::Xls) | Some(Claim::Pdf) => {
                    ExtractOutcome::Failed(ExtractFailure::UnrecognizedFormat)
                }
                None => ExtractOutcome::NotHandled,
            },
            Err(e) => match claim {
                Some(Claim::Pptx) => ExtractOutcome::Failed(ExtractFailure::PptxParse(e)),
                Some(Claim::Xlsx) | Some(Claim::Xls) => {
                    ExtractOutcome::Failed(ExtractFailure::SheetParse(e))
                }
                Some(Claim::Pdf) => ExtractOutcome::Failed(ExtractFailure::UnrecognizedFormat),
                None => ExtractOutcome::NotHandled,
            },
        };
    }
    if bytes.starts_with(OLE2_MAGIC) {
        // Legacy OLE2 container: could be .xls, but also .doc/.ppt (not Tier
        // 1). calamine autodetects; if it can't read it as a workbook and the
        // name claimed .xls, that's a typed failure — otherwise not ours.
        return match extract_sheet(bytes, cap) {
            Ok(ex) => finish(Ok(ex)),
            Err(f) => match claim {
                Some(Claim::Xls) | Some(Claim::Xlsx) => ExtractOutcome::Failed(f),
                _ => ExtractOutcome::NotHandled,
            },
        };
    }
    // No magic matched. If the name claimed one of ours, the bytes lie —
    // typed failure (never silently store a "pdf" that isn't one). Otherwise
    // this simply isn't our job.
    match claim {
        Some(_) => ExtractOutcome::Failed(ExtractFailure::UnrecognizedFormat),
        None => ExtractOutcome::NotHandled,
    }
}

/// Fold `Ok(empty)` into the typed `NoText` failure — extraction NEVER
/// returns silently-empty text.
fn finish(res: Result<Extraction, ExtractFailure>) -> ExtractOutcome {
    match res {
        Ok(ex) if ex.text.trim().is_empty() => ExtractOutcome::Failed(ExtractFailure::NoText),
        Ok(ex) => ExtractOutcome::Extracted(ex),
        Err(f) => ExtractOutcome::Failed(f),
    }
}

/// Peek inside a zip to classify it as xlsx / pptx / other. Errors are the
/// stringified zip failure (corrupt archive etc.).
fn zip_office_kind(bytes: &[u8]) -> Result<Option<Claim>, String> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let names: Vec<&str> = archive.file_names().collect();
    if names.contains(&"xl/workbook.xml") {
        return Ok(Some(Claim::Xlsx));
    }
    if names.contains(&"ppt/presentation.xml") {
        return Ok(Some(Claim::Pptx));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Char-budgeted output assembly (shared truncation semantics)
// ---------------------------------------------------------------------------

struct Budget {
    out: String,
    remaining: usize,
    truncated: bool,
}

impl Budget {
    fn new(cap: usize) -> Self {
        Self {
            out: String::new(),
            remaining: cap,
            truncated: false,
        }
    }

    /// Append `s`; if the budget runs out mid-string, cut at a char boundary
    /// and mark truncated. Returns false once the budget is exhausted so
    /// producers can stop early instead of materializing unbounded text.
    fn push(&mut self, s: &str) -> bool {
        if self.truncated {
            return false;
        }
        let n = s.chars().count();
        if n <= self.remaining {
            self.out.push_str(s);
            self.remaining -= n;
            true
        } else {
            let cut = s
                .char_indices()
                .nth(self.remaining)
                .map(|(i, _)| i)
                .unwrap_or(s.len());
            self.out.push_str(&s[..cut]);
            self.remaining = 0;
            self.truncated = true;
            false
        }
    }

    fn into_extraction(self, method: &'static str) -> Extraction {
        Extraction {
            text: self.out,
            method,
            truncated: self.truncated,
        }
    }
}

// ---------------------------------------------------------------------------
// XLSX / XLS via calamine
// ---------------------------------------------------------------------------

/// Per-sheet text: the sheet name as a heading, rows as lines with cells
/// tab-joined, empty rows skipped. Sheets are separated by a blank line so
/// the paragraph chunker keeps them apart.
fn extract_sheet(bytes: &[u8], cap: usize) -> Result<Extraction, ExtractFailure> {
    let mut workbook = calamine::open_workbook_auto_from_rs(Cursor::new(bytes))
        .map_err(|e| ExtractFailure::SheetParse(e.to_string()))?;
    let mut budget = Budget::new(cap);
    // Headings alone are not content: an all-empty workbook must fold to the
    // typed NoText failure, not ship a text of bare "Sheet:" lines.
    let mut wrote_cells = false;
    'sheets: for name in workbook.sheet_names().to_owned() {
        let range = match workbook.worksheet_range(&name) {
            Ok(r) => r,
            Err(e) => return Err(ExtractFailure::SheetParse(e.to_string())),
        };
        if !budget.push(&format!("Sheet: {name}\n")) {
            break;
        }
        for row in range.rows() {
            let mut line = row
                .iter()
                .map(|c| match c {
                    calamine::Data::Empty => String::new(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join("\t");
            while line.ends_with('\t') {
                line.pop();
            }
            if line.trim().is_empty() {
                continue;
            }
            line.push('\n');
            wrote_cells = true;
            if !budget.push(&line) {
                break 'sheets;
            }
        }
        if !budget.push("\n") {
            break;
        }
    }
    if !wrote_cells {
        return Ok(Extraction {
            text: String::new(), // folded to ExtractFailure::NoText by finish()
            method: "calamine",
            truncated: false,
        });
    }
    Ok(budget.into_extraction("calamine"))
}

// ---------------------------------------------------------------------------
// PPTX via zip + quick-xml
// ---------------------------------------------------------------------------

/// Slide text runs (`<a:t>`) in slide order, with "Slide N:" headings, plus
/// each slide's speaker notes (resolved through the slide's `.rels` — notes
/// slide numbering does NOT reliably match slide numbering, so we follow the
/// relationship instead of guessing).
fn extract_pptx(bytes: &[u8], cap: usize) -> Result<Extraction, ExtractFailure> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ExtractFailure::PptxParse(e.to_string()))?;
    // ppt/slides/slideN.xml, ordered numerically by N (lexicographic would put
    // slide10 before slide2).
    let mut slides: Vec<(u32, String)> = archive
        .file_names()
        .filter_map(|n| {
            let num = n
                .strip_prefix("ppt/slides/slide")?
                .strip_suffix(".xml")?
                .parse::<u32>()
                .ok()?;
            Some((num, n.to_string()))
        })
        .collect();
    slides.sort_unstable();
    if slides.is_empty() {
        return Err(ExtractFailure::PptxParse(
            "no ppt/slides/slideN.xml entries".into(),
        ));
    }

    let mut budget = Budget::new(cap);
    // Same rule as sheets: "Slide N:" headings alone are not content — an
    // all-images deck folds to the typed NoText failure.
    let mut wrote_runs = false;
    for (num, slide_path) in slides {
        let slide_xml =
            read_zip_entry(&mut archive, &slide_path).map_err(ExtractFailure::PptxParse)?;
        let body = drawingml_text(&slide_xml).map_err(ExtractFailure::PptxParse)?;
        if !budget.push(&format!("Slide {num}:\n")) {
            break;
        }
        if !body.is_empty() {
            wrote_runs = true;
            if !budget.push(&format!("{body}\n")) {
                break;
            }
        }
        // Speaker notes, via the slide's relationships part.
        let rels_path = format!("ppt/slides/_rels/slide{num}.xml.rels");
        if let Ok(rels_xml) = read_zip_entry(&mut archive, &rels_path) {
            if let Some(target) = notes_target(&rels_xml) {
                if let Ok(notes_xml) = read_zip_entry(&mut archive, &target) {
                    let notes = drawingml_text(&notes_xml).map_err(ExtractFailure::PptxParse)?;
                    if !notes.is_empty() {
                        wrote_runs = true;
                        if !budget.push(&format!("Notes:\n{notes}\n")) {
                            break;
                        }
                    }
                }
            }
        }
        if !budget.push("\n") {
            break;
        }
    }
    if !wrote_runs {
        return Ok(Extraction {
            text: String::new(), // folded to ExtractFailure::NoText by finish()
            method: "pptx-xml",
            truncated: false,
        });
    }
    Ok(budget.into_extraction("pptx-xml"))
}

fn read_zip_entry(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<String, String> {
    let mut file = archive.by_name(name).map_err(|e| e.to_string())?;
    let mut s = String::new();
    file.read_to_string(&mut s).map_err(|e| e.to_string())?;
    Ok(s)
}

/// Pull the visible text out of a DrawingML part: `<a:t>` runs joined in
/// document order, with a newline at each paragraph (`</a:p>`). The `a:`
/// prefix is fixed by convention in every real-world pptx; a streaming match
/// on the qualified name is deterministic and dependency-light.
fn drawingml_text(xml: &str) -> Result<String, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut out = String::new();
    let mut in_text_run = false;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) if e.name().as_ref() == b"a:t" => in_text_run = true,
            Event::End(e) if e.name().as_ref() == b"a:t" => in_text_run = false,
            Event::End(e) if e.name().as_ref() == b"a:p" => {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
            }
            Event::Text(t) if in_text_run => {
                out.push_str(&t.decode().map_err(|e| e.to_string())?);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out.trim_end().to_string())
}

/// Find the notesSlide relationship target in a slide's `.rels` part and
/// resolve it against `ppt/slides/` (targets look like
/// `../notesSlides/notesSlide1.xml`).
fn notes_target(rels_xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(rels_xml);
    loop {
        match reader.read_event().ok()? {
            Event::Empty(e) | Event::Start(e) if e.name().as_ref() == b"Relationship" => {
                let mut rel_type = String::new();
                let mut target = String::new();
                for attr in e.attributes().flatten() {
                    let key = attr.key.as_ref().to_vec();
                    let val = attr
                        .decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            reader.decoder(),
                        )
                        .ok()?
                        .into_owned();
                    match key.as_slice() {
                        b"Type" => rel_type = val,
                        b"Target" => target = val,
                        _ => {}
                    }
                }
                if rel_type.ends_with("/notesSlide") {
                    return Some(
                        target
                            .strip_prefix("../")
                            .map(|t| format!("ppt/{t}"))
                            .unwrap_or_else(|| format!("ppt/slides/{target}")),
                    );
                }
            }
            Event::Eof => return None,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// PDF via pdf-extract (text layer only — no OCR in Tier 1)
// ---------------------------------------------------------------------------

fn extract_pdf(bytes: &[u8], cap: usize) -> Result<Extraction, ExtractFailure> {
    // Encryption check FIRST, on the raw bytes: the `/Encrypt` key legitimately
    // appears only in the trailer dictionary. A false positive would require
    // the literal token in an *uncompressed* content stream — vanishingly rare
    // since streams are Flate-compressed — and errs on the refusing side.
    // Attempting decryption (even empty-password RC4) is out of Tier-1 scope:
    // we decline with a typed reason rather than half-support it.
    if bytes.windows(8).any(|w| w == b"/Encrypt") {
        return Err(ExtractFailure::EncryptedPdf);
    }
    // pdf-extract panics on some malformed files; a hostile upload must never
    // unwind into the handler, so the whole call is fenced with catch_unwind.
    let extracted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pdf_extract::extract_text_from_mem(bytes)
    }));
    let text = match extracted {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => return Err(ExtractFailure::PdfParse(e.to_string())),
        Err(_) => {
            return Err(ExtractFailure::PdfParse(
                "parser panicked on malformed input (contained)".into(),
            ))
        }
    };
    if text.trim().is_empty() {
        // Parsed fine, ~no text: an image-only/scanned PDF. Tier 1 has no OCR
        // — disclose that instead of indexing nothing silently.
        return Err(ExtractFailure::ScannedPdf);
    }
    let mut budget = Budget::new(cap);
    budget.push(text.trim());
    Ok(budget.into_extraction("pdf-text"))
}

// ---------------------------------------------------------------------------
// Programmatic fixtures (tests only): tiny valid files, no binaries in-repo.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod fixtures {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    fn build_zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, body) in entries {
                w.start_file(*name, opts).expect("zip entry");
                w.write_all(body.as_bytes()).expect("zip body");
            }
            w.finish().expect("zip finish");
        }
        cursor.into_inner()
    }

    fn worksheet_xml(rows: &[&[&str]]) -> String {
        let mut body = String::from(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
        );
        for (r, row) in rows.iter().enumerate() {
            body.push_str(&format!(r#"<row r="{}">"#, r + 1));
            for (c, cell) in row.iter().enumerate() {
                let col = (b'A' + c as u8) as char;
                body.push_str(&format!(
                    r#"<c r="{col}{}" t="inlineStr"><is><t>{cell}</t></is></c>"#,
                    r + 1
                ));
            }
            body.push_str("</row>");
        }
        body.push_str("</sheetData></worksheet>");
        body
    }

    /// A minimal but valid two-sheet xlsx with known cell text.
    pub(crate) fn xlsx_two_sheets(rows1: &[&[&str]], rows2: &[&[&str]]) -> Vec<u8> {
        build_zip(&[
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#,
            ),
            (
                "_rels/.rels",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#,
            ),
            (
                "xl/workbook.xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Pipeline" sheetId="1" r:id="rId1"/><sheet name="Forecast" sheetId="2" r:id="rId2"/></sheets>
</workbook>"#,
            ),
            (
                "xl/_rels/workbook.xml.rels",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"#,
            ),
            ("xl/worksheets/sheet1.xml", &worksheet_xml(rows1)),
            ("xl/worksheets/sheet2.xml", &worksheet_xml(rows2)),
        ])
    }

    fn slide_xml(paras: &[&str]) -> String {
        let runs: String = paras
            .iter()
            .map(|p| format!("<a:p><a:r><a:t>{p}</a:t></a:r></a:p>"))
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:sp><p:txBody>{runs}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#
        )
    }

    /// A minimal two-slide pptx; slide 1 carries speaker notes wired through
    /// its .rels part (as real generators do).
    pub(crate) fn pptx_two_slides(slide1: &[&str], slide2: &[&str], notes1: &str) -> Vec<u8> {
        build_zip(&[
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
</Types>"#,
            ),
            (
                "_rels/.rels",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>"#,
            ),
            (
                "ppt/presentation.xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>"#,
            ),
            ("ppt/slides/slide1.xml", &slide_xml(slide1)),
            ("ppt/slides/slide2.xml", &slide_xml(slide2)),
            (
                "ppt/slides/_rels/slide1.xml.rels",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide1.xml"/>
</Relationships>"#,
            ),
            ("ppt/notesSlides/notesSlide1.xml", &slide_xml(&[notes1])),
        ])
    }

    /// A minimal single-page text PDF with correct xref offsets, authored
    /// programmatically (WinAnsi/Helvetica, one text-showing operator per
    /// sentence). No downloads, no checked-in binaries.
    pub(crate) fn text_pdf(sentences: &[&str]) -> Vec<u8> {
        let mut content = String::from("BT /F1 12 Tf 72 720 Td 14 TL\n");
        for s in sentences {
            let escaped = s
                .replace('\\', r"\\")
                .replace('(', r"\(")
                .replace(')', r"\)");
            content.push_str(&format!("({escaped}) Tj T*\n"));
        }
        content.push_str("ET\n");

        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
            format!("<< /Length {} >>\nstream\n{content}endstream", content.len()),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
                .to_string(),
        ];

        let mut pdf = String::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.push_str(&format!("{} 0 obj\n{obj}\nendobj\n", i + 1));
        }
        let xref_at = pdf.len();
        pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
        pdf.push_str("0000000000 65535 f \n");
        for off in offsets {
            pdf.push_str(&format!("{off:010} 00000 n \n"));
        }
        pdf.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        ));
        pdf.into_bytes()
    }

    /// A structurally-plausible PDF whose trailer names an /Encrypt dict —
    /// the typed encrypted-PDF refusal path. (Tier 1 declines encryption
    /// outright; we don't need real RC4/AES material to prove the refusal.)
    pub(crate) fn encrypted_pdf() -> Vec<u8> {
        let mut pdf = String::from_utf8(text_pdf(&["irrelevant"])).unwrap();
        pdf = pdf.replace("/Root 1 0 R", "/Root 1 0 R /Encrypt 9 0 R");
        pdf.into_bytes()
    }

    /// A valid PDF with one empty page — parses fine, zero text ops. The
    /// stand-in for a scanned/image-only document.
    pub(crate) fn image_only_pdf() -> Vec<u8> {
        text_pdf(&[])
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_extracted(outcome: ExtractOutcome) -> Extraction {
        match outcome {
            ExtractOutcome::Extracted(ex) => ex,
            other => panic!("expected Extracted, got {other:?}"),
        }
    }

    fn expect_failed(outcome: ExtractOutcome) -> ExtractFailure {
        match outcome {
            ExtractOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ---------------- xlsx / calamine ----------------

    #[test]
    fn xlsx_extracts_both_sheets_with_headings_and_tab_joined_rows() {
        let bytes = fixtures::xlsx_two_sheets(
            &[&["Account", "ACV"], &["Acme Corp", "48000"]],
            &[&["Quarter", "Forecast"], &["Q3", "125000"]],
        );
        let ex = expect_extracted(extract(&bytes, Some("pipeline.xlsx")));
        assert_eq!(ex.method, "calamine");
        assert!(!ex.truncated);
        assert!(ex.text.contains("Sheet: Pipeline"));
        assert!(ex.text.contains("Sheet: Forecast"));
        assert!(ex.text.contains("Acme Corp\t48000"));
        assert!(ex.text.contains("Q3\t125000"));
        // Sheet order preserved.
        let p = ex.text.find("Sheet: Pipeline").unwrap();
        let f = ex.text.find("Sheet: Forecast").unwrap();
        assert!(p < f);
    }

    #[test]
    fn xlsx_detected_by_magic_even_with_misleading_name() {
        let bytes = fixtures::xlsx_two_sheets(&[&["hello"]], &[]);
        // Magic wins: a zip with xl/workbook.xml is a spreadsheet even if the
        // filename claims .pdf.
        let ex = expect_extracted(extract(&bytes, Some("report.pdf")));
        assert_eq!(ex.method, "calamine");
        assert!(ex.text.contains("hello"));
    }

    #[test]
    fn xlsx_truncation_is_disclosed() {
        let rows: Vec<Vec<&str>> = (0..40).map(|_| vec!["abcdefghij"]).collect();
        let refs: Vec<&[&str]> = rows.iter().map(|r| r.as_slice()).collect();
        let bytes = fixtures::xlsx_two_sheets(&refs, &[]);
        let ExtractOutcome::Extracted(ex) = extract_with_cap(&bytes, Some("big.xlsx"), 64) else {
            panic!("expected Extracted");
        };
        assert!(ex.truncated, "cap overflow must set the truncated flag");
        assert!(ex.text.chars().count() <= 64);
    }

    #[test]
    fn empty_workbook_is_a_typed_no_text_failure_not_silent_empty() {
        let bytes = fixtures::xlsx_two_sheets(&[], &[]);
        let f = expect_failed(extract(&bytes, Some("empty.xlsx")));
        assert_eq!(f, ExtractFailure::NoText);
    }

    // ---------------- pptx ----------------

    #[test]
    fn pptx_extracts_slides_in_order_with_notes() {
        let bytes = fixtures::pptx_two_slides(
            &["Verity roadmap", "Milestone A is the honest engine"],
            &["Ship the extraction tier"],
            "Remind the room about fail-closed defaults",
        );
        let ex = expect_extracted(extract(&bytes, Some("deck.pptx")));
        assert_eq!(ex.method, "pptx-xml");
        assert!(!ex.truncated);
        assert!(ex.text.contains("Slide 1:"));
        assert!(ex.text.contains("Slide 2:"));
        assert!(ex.text.contains("Milestone A is the honest engine"));
        assert!(ex.text.contains("Ship the extraction tier"));
        assert!(ex
            .text
            .contains("Notes:\nRemind the room about fail-closed defaults"));
        let s1 = ex.text.find("Slide 1:").unwrap();
        let s2 = ex.text.find("Slide 2:").unwrap();
        assert!(s1 < s2);
    }

    #[test]
    fn corrupt_zip_claiming_pptx_is_a_typed_parse_failure() {
        let mut bytes = fixtures::pptx_two_slides(&["x"], &["y"], "n");
        bytes.truncate(40); // valid zip magic, mangled central directory
        let f = expect_failed(extract(&bytes, Some("deck.pptx")));
        assert!(matches!(f, ExtractFailure::PptxParse(_)), "got {f:?}");
    }

    // ---------------- pdf ----------------

    #[test]
    fn pdf_extracts_known_sentences() {
        let bytes =
            fixtures::text_pdf(&["The pilot begins in August.", "Budget owner is J. Reyes."]);
        let ex = expect_extracted(extract(&bytes, Some("notes.pdf")));
        assert_eq!(ex.method, "pdf-text");
        assert!(!ex.truncated);
        assert!(ex.text.contains("The pilot begins in August."));
        assert!(ex.text.contains("Budget owner is J. Reyes."));
    }

    #[test]
    fn encrypted_pdf_is_declined_with_the_typed_reason() {
        let f = expect_failed(extract(&fixtures::encrypted_pdf(), Some("secret.pdf")));
        assert_eq!(f, ExtractFailure::EncryptedPdf);
        assert_eq!(f.reason(), "encrypted PDF");
    }

    #[test]
    fn image_only_pdf_is_declined_as_scanned_no_ocr() {
        let f = expect_failed(extract(&fixtures::image_only_pdf(), Some("scan.pdf")));
        assert_eq!(f, ExtractFailure::ScannedPdf);
        assert_eq!(
            f.reason(),
            "scanned/image PDF — no text layer (OCR is a later tier)"
        );
    }

    #[test]
    fn garbage_claiming_pdf_never_panics_and_fails_typed() {
        // Valid PDF magic, hostile body: must be contained, never unwind.
        let mut bytes = b"%PDF-1.7\n".to_vec();
        bytes.extend_from_slice(&[0xff; 512]);
        let f = expect_failed(extract(&bytes, Some("hostile.pdf")));
        assert!(
            matches!(f, ExtractFailure::PdfParse(_) | ExtractFailure::ScannedPdf),
            "got {f:?}"
        );
    }

    // ---------------- detection / not-ours ----------------

    #[test]
    fn extension_claim_with_mismatched_bytes_is_unrecognized_format() {
        let f = expect_failed(extract(b"just some text", Some("fake.pdf")));
        assert_eq!(f, ExtractFailure::UnrecognizedFormat);
        assert_eq!(f.reason(), "unrecognized format");
    }

    #[test]
    fn plain_text_and_unknown_binaries_are_not_handled() {
        assert!(matches!(
            extract(b"hello world", Some("notes.txt")),
            ExtractOutcome::NotHandled
        ));
        assert!(matches!(
            extract(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a], Some("img.png")),
            ExtractOutcome::NotHandled
        ));
    }

    #[test]
    fn non_office_zip_without_claim_is_not_handled_with_claim_is_typed() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            use std::io::Write;
            w.start_file("readme.txt", opts).unwrap();
            w.write_all(b"plain zip").unwrap();
            w.finish().unwrap();
        }
        let bytes = cursor.into_inner();
        assert!(matches!(
            extract(&bytes, Some("archive.zip")),
            ExtractOutcome::NotHandled
        ));
        let f = expect_failed(extract(&bytes, Some("claims.xlsx")));
        assert_eq!(f, ExtractFailure::UnrecognizedFormat);
    }
}
