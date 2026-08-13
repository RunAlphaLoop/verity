//! Tier-1 binary file extraction: PDF, PPTX, XLS(X), DOC(X) → plain text,
//! plus the local OCR tier for scanned PDFs and PNG/JPEG images (ocr.rs).
//!
//! The honesty rules here are load-bearing (founder directive, Tier 1):
//!
//! * **Rust-native, local, no external process.** No LLM, no cloud OCR, no
//!   system dependency. Text-layer extraction is fully deterministic; the OCR
//!   paths ("pdf-ocr" / "image-ocr") are printed-text-grade and BEST-EFFORT —
//!   the receipt always discloses the method so a consumer can weigh
//!   OCR-derived text accordingly (same bytes + same cached models still
//!   yield the same text; a model update may change it).
//! * **Never silently empty.** Every call returns either extracted text with
//!   its method + truncation flag, a *typed* failure reason (encrypted PDF,
//!   scanned PDF where OCR found nothing, OCR engine unavailable, parse
//!   failure, unrecognized format), or an explicit `NotHandled` so the caller
//!   can run its existing text-like/store-only logic. A caller can always
//!   disclose exactly what happened.
//! * **A hostile file never kills the server.** The PDF paths are wrapped in
//!   `catch_unwind` because pdf crates are known to panic on malformed input.
//! * **Honest limits.** Extraction is capped at [`MAX_EXTRACT_CHARS`] with a
//!   disclosed `truncated` flag; scanned-PDF OCR is capped at
//!   `ocr::MAX_OCR_PAGES` pages with the page count disclosed via
//!   `pages_ocred`; encrypted PDFs are still declined outright.
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

use crate::ocr::{self, OcrBackend};

/// Hard cap on extracted text, in chars (~200 KB). Disclosed via
/// `Extraction::truncated` — a capped extraction is never passed off as the
/// whole document.
pub(crate) const MAX_EXTRACT_CHARS: usize = 200_000;

/// A successful extraction: the text, how it was produced, and whether the
/// [`MAX_EXTRACT_CHARS`] cap cut it short.
#[derive(Debug)]
pub(crate) struct Extraction {
    pub(crate) text: String,
    /// "calamine" | "pptx-xml" | "docx-xml" | "doc-piecetable" | "pdf-text" |
    /// "pdf-ocr" | "image-ocr" — recorded into provenance. The two `-ocr`
    /// methods mark best-effort recognized text, not a deterministic text
    /// layer.
    pub(crate) method: &'static str,
    pub(crate) truncated: bool,
    /// For "pdf-ocr" only: the honest page accounting — pages OCRed (engine
    /// consulted; capped at [`ocr::MAX_OCR_PAGES`]), total pages in the
    /// document, and pages skipped because their images use encodings we
    /// don't implement. A partial pass is visible on the receipt.
    pub(crate) ocr_pages: Option<ocr::OcrPages>,
}

/// The disclosed extraction receipt, embedded verbatim in episode payloads
/// and HTTP responses. ONE builder so no call site forgets the OCR page
/// accounting.
pub(crate) fn receipt_json(
    method: &str,
    truncated: bool,
    ocr_pages: Option<ocr::OcrPages>,
) -> serde_json::Value {
    let mut v = serde_json::json!({ "method": method, "truncated": truncated });
    if let Some(pages) = ocr_pages {
        v["pages_ocred"] = pages.ocred.into();
        v["pages_total"] = pages.total.into();
        v["pages_skipped_unsupported"] = pages.skipped_unsupported.into();
    }
    v
}

/// Typed failure reasons. `reason()` strings are part of the disclosed API
/// (they land in episode payloads, HTTP responses, and UI receipts) — change
/// them deliberately.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExtractFailure {
    /// Encrypted PDFs are declined outright — no decryption attempts, no OCR.
    EncryptedPdf,
    /// No text layer AND the OCR pass recognized nothing (or found no
    /// decodable raster images at all).
    ScannedPdf,
    /// No text layer, and every image-bearing page uses an encoding we don't
    /// implement (CCITT/JBIG2/JPX, exotic colorspaces): OCR never got to
    /// ATTEMPT recognition. Distinct from [`Self::ScannedPdf`], which means
    /// OCR ran (or had nothing at all to run on) and found none — conflating
    /// the two would pass off "we can't read this format" as "there was
    /// nothing to read".
    UnsupportedPdfImages,
    PdfParse(String),
    SheetParse(String),
    PptxParse(String),
    DocxParse(String),
    DocParse(String),
    /// A PNG/JPEG whose bytes would not decode.
    ImageParse(String),
    /// An image parsed fine but OCR recognized no text in it.
    ImageNoText,
    /// The local OCR engine could not run (model download/init/inference
    /// failed, or the server was built without the `ocr` feature). Typed and
    /// disclosed — never a panic, never silent empty.
    OcrUnavailable(String),
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
            Self::ScannedPdf => "scanned/image PDF — no text layer and OCR found none".into(),
            Self::UnsupportedPdfImages => {
                "scanned/image PDF — unsupported image encodings; OCR could not attempt".into()
            }
            Self::PdfParse(e) => format!("PDF parse failure: {e}"),
            Self::SheetParse(e) => format!("spreadsheet parse failure: {e}"),
            Self::PptxParse(e) => format!("PPTX parse failure: {e}"),
            Self::DocxParse(e) => format!("DOCX parse failure: {e}"),
            Self::DocParse(e) => format!("legacy .doc parse failure: {e}"),
            Self::ImageParse(e) => format!("image decode failure: {e}"),
            Self::ImageNoText => "image parsed but OCR found no text".into(),
            Self::OcrUnavailable(e) => format!("OCR unavailable: {e}"),
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
    Docx,
    Doc,
    Png,
    Jpeg,
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
    } else if lower.ends_with(".docx") || lower.ends_with(".docm") {
        Some(Claim::Docx)
    } else if lower.ends_with(".doc") {
        Some(Claim::Doc)
    } else if lower.ends_with(".png") {
        Some(Claim::Png)
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some(Claim::Jpeg)
    } else {
        None
    }
}

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
/// JPEG/JFIF/EXIF all open with the SOI marker followed by another marker.
const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];

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
    extract_with_ocr(bytes, filename, cap, ocr::default_backend())
}

/// Backend-parameterized worker: tests inject fake OCR backends here so the
/// OCR plumbing (routing, page walking, caps, failure taxonomy) is provable
/// hermetically — no model downloads in unit tests.
fn extract_with_ocr(
    bytes: &[u8],
    filename: Option<&str>,
    cap: usize,
    ocr: &dyn OcrBackend,
) -> ExtractOutcome {
    let claim = claim_from_name(filename);
    if looks_like_pdf(bytes) {
        return finish(extract_pdf(bytes, cap, ocr));
    }
    if bytes.starts_with(PNG_MAGIC) || bytes.starts_with(JPEG_MAGIC) {
        return finish(extract_image(bytes, cap, ocr));
    }
    if bytes.starts_with(ZIP_MAGIC) {
        // Zip container: xlsx and pptx are both zips — tell them apart by the
        // package structure (magic-level truth), not the extension.
        return match zip_office_kind(bytes) {
            Ok(Some(Claim::Xlsx)) => finish(extract_sheet(bytes, cap)),
            Ok(Some(Claim::Pptx)) => finish(extract_pptx(bytes, cap)),
            Ok(Some(Claim::Docx)) => finish(extract_docx(bytes, cap)),
            // A zip that isn't an office package: ours only if the name
            // claimed so (then the claim is wrong — typed, magic wins).
            Ok(_) => match claim {
                Some(_) => ExtractOutcome::Failed(ExtractFailure::UnrecognizedFormat),
                None => ExtractOutcome::NotHandled,
            },
            Err(e) => match claim {
                Some(Claim::Pptx) => ExtractOutcome::Failed(ExtractFailure::PptxParse(e)),
                Some(Claim::Docx) => ExtractOutcome::Failed(ExtractFailure::DocxParse(e)),
                Some(Claim::Xlsx) | Some(Claim::Xls) => {
                    ExtractOutcome::Failed(ExtractFailure::SheetParse(e))
                }
                Some(Claim::Pdf) | Some(Claim::Doc) | Some(Claim::Png) | Some(Claim::Jpeg) => {
                    ExtractOutcome::Failed(ExtractFailure::UnrecognizedFormat)
                }
                None => ExtractOutcome::NotHandled,
            },
        };
    }
    if bytes.starts_with(OLE2_MAGIC) {
        // Legacy OLE2 compound file: .xls (calamine), .doc (the WordDocument
        // stream), or .ppt (not Tier 1). Try the sheet reader first; a doc
        // isn't a workbook, so on that failure route by the compound file's
        // own streams: a WordDocument stream ⇒ .doc, else fall through.
        if let Ok(ex) = extract_sheet(bytes, cap) {
            return finish(Ok(ex));
        }
        if ole_has_word_stream(bytes) {
            return finish(extract_doc(bytes, cap));
        }
        return match claim {
            // Name claimed .doc but there's no WordDocument stream ⇒ typed.
            Some(Claim::Doc) => ExtractOutcome::Failed(ExtractFailure::DocParse(
                "OLE2 file has no WordDocument stream".into(),
            )),
            Some(Claim::Xls) | Some(Claim::Xlsx) => {
                ExtractOutcome::Failed(ExtractFailure::SheetParse("not a workbook".into()))
            }
            _ => ExtractOutcome::NotHandled,
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
    if names.contains(&"word/document.xml") {
        return Ok(Some(Claim::Docx));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Char-budgeted output assembly (shared truncation semantics)
// ---------------------------------------------------------------------------

/// pub(crate): ocr.rs pushes OCRed page blocks through the same budget so
/// pdf-ocr shares the exact truncation semantics (and stops OCRing early once
/// the cap is hit — recognition is the expensive part).
pub(crate) struct Budget {
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
    pub(crate) fn push(&mut self, s: &str) -> bool {
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
            ocr_pages: None,
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
            ocr_pages: None,
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
            ocr_pages: None,
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

// ---------------------------------------------------------------------------
// DOCX (OOXML Word): word/document.xml is a zip entry of WordprocessingML.
// ---------------------------------------------------------------------------

fn extract_docx(bytes: &[u8], cap: usize) -> Result<Extraction, ExtractFailure> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ExtractFailure::DocxParse(e.to_string()))?;
    let doc_xml =
        read_zip_entry(&mut archive, "word/document.xml").map_err(ExtractFailure::DocxParse)?;
    let text = wordml_text(&doc_xml).map_err(ExtractFailure::DocxParse)?;
    let mut budget = Budget::new(cap);
    budget.push(&text);
    // Word footnotes/endnotes live in sibling parts; pull them too when present.
    for part in ["word/footnotes.xml", "word/endnotes.xml"] {
        if let Ok(xml) = read_zip_entry(&mut archive, part) {
            if let Ok(extra) = wordml_text(&xml) {
                if !extra.trim().is_empty() && !budget.push(&format!("\n{extra}")) {
                    break;
                }
            }
        }
    }
    Ok(Extraction {
        text: budget.out,
        method: "docx-xml",
        truncated: budget.truncated,
        ocr_pages: None,
    })
}

/// Pull visible text from WordprocessingML: `<w:t>` runs are text, `<w:p>` ends
/// a paragraph (newline), `<w:tab/>`/`<w:br/>`/`<w:cr/>` are whitespace.
fn wordml_text(xml: &str) -> Result<String, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut out = String::new();
    let mut in_text_run = false;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) if e.name().as_ref() == b"w:t" => in_text_run = true,
            Event::End(e) if e.name().as_ref() == b"w:t" => in_text_run = false,
            Event::Empty(e) if matches!(e.name().as_ref(), b"w:tab") => out.push('\t'),
            Event::Empty(e) if matches!(e.name().as_ref(), b"w:br" | b"w:cr") => out.push('\n'),
            Event::End(e) if e.name().as_ref() == b"w:p" => {
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

// ---------------------------------------------------------------------------
// DOC (legacy Word 97-2003 binary, OLE2 compound file): the main text is
// reconstructed from the piece table in the table stream (handles fast-saved
// docs where text is fragmented), each piece 8-bit CP1252 or 16-bit UTF-16LE.
// Anything we can't reconstruct cleanly folds to a typed failure (metadata-
// only), never silently-garbled text.
// ---------------------------------------------------------------------------

/// Cheap probe: does the OLE2 file carry a `WordDocument` stream (⇒ a .doc)?
fn ole_has_word_stream(bytes: &[u8]) -> bool {
    cfb::CompoundFile::open(Cursor::new(bytes))
        .map(|cf| cf.exists("/WordDocument"))
        .unwrap_or(false)
}

fn cp1252_char(b: u8) -> char {
    // CP1252 is Latin-1 except 0x80-0x9F. Map the printable specials there;
    // everything else passes through as Latin-1.
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
        '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}',
        'ž', 'Ÿ',
    ];
    match b {
        0x80..=0x9F => HIGH[(b - 0x80) as usize],
        other => other as char,
    }
}

fn extract_doc(bytes: &[u8], cap: usize) -> Result<Extraction, ExtractFailure> {
    use std::io::Read;
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| ExtractFailure::DocParse(e.to_string()))?;

    let mut wds = Vec::new();
    cf.open_stream("/WordDocument")
        .and_then(|mut s| s.read_to_end(&mut wds))
        .map_err(|e| ExtractFailure::DocParse(format!("WordDocument stream: {e}")))?;
    if wds.len() < 0x0200 || u16::from_le_bytes([wds[0], wds[1]]) != 0xA5EC {
        return Err(ExtractFailure::DocParse("not a Word FIB".into()));
    }
    let rd_u32 = |buf: &[u8], off: usize| -> Option<u32> {
        buf.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    // Which table stream holds the piece table (FIB flags bit 9 = fWhichTblStm).
    let flags = u16::from_le_bytes([wds[0x0A], wds[0x0B]]);
    let table_name = if flags & 0x0200 != 0 {
        "/1Table"
    } else {
        "/0Table"
    };
    let mut tbl = Vec::new();
    cf.open_stream(table_name)
        .and_then(|mut s| s.read_to_end(&mut tbl))
        .map_err(|e| ExtractFailure::DocParse(format!("{table_name} stream: {e}")))?;

    // Clx (piece table container): fcClx/lcbClx at FIB offsets 0x01A2/0x01A6.
    let fc_clx = rd_u32(&wds, 0x01A2).ok_or(ExtractFailure::DocParse("no fcClx".into()))? as usize;
    let lcb_clx =
        rd_u32(&wds, 0x01A6).ok_or(ExtractFailure::DocParse("no lcbClx".into()))? as usize;
    let clx = tbl
        .get(fc_clx..fc_clx + lcb_clx)
        .ok_or(ExtractFailure::DocParse("Clx out of range".into()))?;

    // Skip any leading Prc (0x01) blocks to reach the Pcdt (0x02) plcfPcd.
    let mut i = 0usize;
    while i < clx.len() && clx[i] == 0x01 {
        let n = u16::from_le_bytes([clx[i + 1], clx[i + 2]]) as usize;
        i += 3 + n;
    }
    if clx.get(i) != Some(&0x02) {
        return Err(ExtractFailure::DocParse("no Pcdt in Clx".into()));
    }
    let lcb = rd_u32(clx, i + 1).ok_or(ExtractFailure::DocParse("bad Pcdt len".into()))? as usize;
    let plc = clx
        .get(i + 5..i + 5 + lcb)
        .ok_or(ExtractFailure::DocParse("plcfPcd out of range".into()))?;
    // plcfPcd: (n+1) CPs (4 bytes each) then n PCDs (8 bytes each).
    let n = (lcb.saturating_sub(4)) / (4 + 8);
    if n == 0 {
        return Err(ExtractFailure::DocParse("empty piece table".into()));
    }
    let cps: Vec<u32> = (0..=n).filter_map(|k| rd_u32(plc, k * 4)).collect();
    let pcd_base = (n + 1) * 4;

    let mut budget = Budget::new(cap);
    for p in 0..n {
        let cp_start = cps[p];
        let cp_end = cps[p + 1];
        let chars = cp_end.saturating_sub(cp_start) as usize;
        let fc =
            rd_u32(plc, pcd_base + p * 8 + 2).ok_or(ExtractFailure::DocParse("bad PCD".into()))?;
        let compressed = fc & 0x4000_0000 != 0;
        let piece = if compressed {
            let off = (fc & 0x3FFF_FFFF) as usize / 2;
            let end = off + chars;
            let raw = wds.get(off..end).unwrap_or(&[]);
            raw.iter().map(|&b| cp1252_char(b)).collect::<String>()
        } else {
            let off = fc as usize;
            let end = off + chars * 2;
            let raw = wds.get(off..end).unwrap_or(&[]);
            raw.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .map(|u| char::from_u32(u as u32).unwrap_or('\u{FFFD}'))
                .collect::<String>()
        };
        // Word control glyphs → whitespace; drop field/embedded-object markers.
        let cleaned: String = piece
            .chars()
            .filter_map(|c| match c {
                '\r' | '\x07' | '\x0b' | '\x0c' => Some('\n'),
                '\x1e' | '\x1f' => None,
                '\x00'..='\x08' | '\x0e'..='\x1f' => None,
                other => Some(other),
            })
            .collect();
        if !budget.push(&cleaned) {
            break;
        }
    }
    Ok(Extraction {
        text: budget.out.trim().to_string(),
        method: "doc-piecetable",
        truncated: budget.truncated,
        ocr_pages: None,
    })
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
// PDF via pdf-extract (text layer), falling back to local OCR (ocr.rs) when
// the document has none
// ---------------------------------------------------------------------------

fn extract_pdf(
    bytes: &[u8],
    cap: usize,
    ocr: &dyn OcrBackend,
) -> Result<Extraction, ExtractFailure> {
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
        // Parsed fine, ~no text layer: a scanned/image PDF. Run the local OCR
        // pass (ocr.rs) over its embedded page images — best-effort,
        // disclosed as "pdf-ocr" with pages_ocred, and still a typed failure
        // when OCR finds nothing or cannot run. Fenced like the text pass:
        // lopdf must never unwind into the handler either.
        return ocr_scanned_pdf(bytes, cap, ocr);
    }
    let mut budget = Budget::new(cap);
    budget.push(text.trim());
    Ok(budget.into_extraction("pdf-text"))
}

/// The scanned-PDF OCR pass. The engine is only consulted when a page image
/// actually decodes, so a blank or vector-only PDF fails fast as ScannedPdf
/// without touching (or downloading) any model.
fn ocr_scanned_pdf(
    bytes: &[u8],
    cap: usize,
    ocr: &dyn OcrBackend,
) -> Result<Extraction, ExtractFailure> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut budget = Budget::new(cap);
        let pages = ocr::ocr_pdf_pages(bytes, &mut budget, ocr::MAX_OCR_PAGES, ocr)?;
        Ok((budget, pages))
    }));
    let (budget, pages) = match outcome {
        Ok(Ok(ok)) => ok,
        Ok(Err(ocr::PdfOcrError::Parse(e))) => {
            return Err(ExtractFailure::PdfParse(format!("OCR pass: {e}")))
        }
        Ok(Err(ocr::PdfOcrError::Engine(e))) => return Err(ExtractFailure::OcrUnavailable(e)),
        Err(_) => {
            return Err(ExtractFailure::PdfParse(
                "OCR pass: parser panicked on malformed input (contained)".into(),
            ))
        }
    };
    if budget.out.trim().is_empty() {
        // Honesty split: if OCR never got to attempt a single page because
        // every image-bearing page uses an encoding we don't implement, say
        // THAT — "OCR found none" would be a false claim of having looked.
        if pages.ocred == 0 && pages.skipped_unsupported > 0 {
            return Err(ExtractFailure::UnsupportedPdfImages);
        }
        return Err(ExtractFailure::ScannedPdf);
    }
    let mut ex = budget.into_extraction("pdf-ocr");
    ex.ocr_pages = Some(pages);
    Ok(ex)
}

// ---------------------------------------------------------------------------
// Standalone PNG/JPEG via local OCR (ocr.rs)
// ---------------------------------------------------------------------------

fn extract_image(
    bytes: &[u8],
    cap: usize,
    ocr: &dyn OcrBackend,
) -> Result<Extraction, ExtractFailure> {
    // Fenced like the PDF lanes: a decoder or engine panic on a hostile image
    // must surface as a typed failure, never unwind into the handler (where
    // it would become a JoinError 500 off the blocking pool).
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<Extraction, ExtractFailure> {
            let img = ocr::decode_rgb(bytes).map_err(ExtractFailure::ImageParse)?;
            let text = ocr
                .recognize_rgb(img.width(), img.height(), img.as_raw())
                .map_err(ExtractFailure::OcrUnavailable)?;
            let text = text.trim();
            if text.is_empty() {
                return Err(ExtractFailure::ImageNoText);
            }
            let mut budget = Budget::new(cap);
            budget.push(text);
            Ok(budget.into_extraction("image-ocr"))
        },
    ));
    match outcome {
        Ok(res) => res,
        Err(_) => Err(ExtractFailure::ImageParse(
            "image decode/OCR panicked on malformed input (contained)".into(),
        )),
    }
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

    /// A minimal but valid legacy .doc (OLE2 compound file) carrying `text` as
    /// one compressed (CP1252) piece, built with `cfb` — the same round-trip
    /// path real Word docs take through `extract_doc`'s piece-table reader. No
    /// external tool, no PII fixture. ASCII `text` only (1 byte/char).
    pub(crate) fn doc_with_text(text: &str) -> Vec<u8> {
        use std::io::Write as _;
        const TEXT_OFF: usize = 0x200; // where the text lives in WordDocument
        let mut wds = vec![0u8; TEXT_OFF + text.len()];
        wds[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes()); // FIB magic
                                                             // flags at 0x0A: fWhichTblStm=0 ⇒ the "0Table" stream holds the Clx.
        wds[0x1A2..0x1A6].copy_from_slice(&0u32.to_le_bytes()); // fcClx = 0
        wds[0x1A6..0x1AA].copy_from_slice(&21u32.to_le_bytes()); // lcbClx
        wds[TEXT_OFF..].copy_from_slice(text.as_bytes());

        // Clx = 0x02, lcb(u32)=16, then plcfPcd = [CP0,CP1] + one 8-byte PCD.
        let fc: u32 = 0x4000_0000 | ((TEXT_OFF as u32) * 2); // compressed piece
        let mut plc = Vec::new();
        plc.extend_from_slice(&0u32.to_le_bytes()); // CP0
        plc.extend_from_slice(&(text.chars().count() as u32).to_le_bytes()); // CP1
        plc.extend_from_slice(&0u16.to_le_bytes()); // PCD flags
        plc.extend_from_slice(&fc.to_le_bytes()); // PCD.fc
        plc.extend_from_slice(&0u16.to_le_bytes()); // PCD.prm
        let mut tbl = vec![0x02u8];
        tbl.extend_from_slice(&(plc.len() as u32).to_le_bytes());
        tbl.extend_from_slice(&plc);

        let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new()))
            .expect("create compound file");
        cf.create_stream("/WordDocument")
            .and_then(|mut s| s.write_all(&wds))
            .expect("WordDocument stream");
        cf.create_stream("/0Table")
            .and_then(|mut s| s.write_all(&tbl))
            .expect("0Table stream");
        cf.into_inner().into_inner()
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

    /// A valid PDF with one empty page — parses fine, zero text ops, zero
    /// images. The stand-in for a blank/vector-only document: the OCR pass
    /// finds nothing to even attempt.
    pub(crate) fn image_only_pdf() -> Vec<u8> {
        text_pdf(&[])
    }

    /// Flat-color JPEG bytes (a valid, decodable page image; the injected OCR
    /// fakes don't look at the pixels).
    pub(crate) fn jpeg_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(w, h, image::Rgb([180, 180, 180]));
        let mut out = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut out)
            .encode(img.as_raw(), w, h, image::ExtendedColorType::Rgb8)
            .expect("fixture jpeg encodes");
        out
    }

    /// Flat-color PNG bytes.
    pub(crate) fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(w, h, image::Rgb([64, 64, 64]));
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png)
            .expect("fixture png encodes");
        out.into_inner()
    }

    /// A minimal scanned-style PDF: one page per JPEG, each page's content
    /// stream drawing its image XObject (DCTDecode — the stream body IS the
    /// JPEG). Exactly the shape scanner exports take: valid structure, zero
    /// text operators. Authored programmatically with correct xref offsets.
    pub(crate) fn scanned_pdf_with_jpegs(jpegs: &[&[u8]]) -> Vec<u8> {
        let n_pages = jpegs.len();
        let kids: Vec<String> = (0..n_pages).map(|i| format!("{} 0 R", 3 + i * 3)).collect();
        let mut objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            format!(
                "<< /Type /Pages /Kids [{}] /Count {n_pages} >>",
                kids.join(" ")
            )
            .into_bytes(),
        ];
        for (i, jpeg) in jpegs.iter().enumerate() {
            use image::GenericImageView as _;
            // Page object ids run 3, 6, 9, … (matching `kids` above), each
            // followed by its contents and image objects.
            let (contents_obj, image_obj) = (4 + i * 3, 5 + i * 3);
            let img = image::load_from_memory(jpeg).expect("fixture jpeg decodes");
            let (w, h) = img.dimensions();
            let content = format!("q {w} 0 0 {h} 0 0 cm /Im0 Do Q\n");
            objects.push(
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                     /Contents {contents_obj} 0 R \
                     /Resources << /XObject << /Im0 {image_obj} 0 R >> >> >>"
                )
                .into_bytes(),
            );
            objects.push(
                format!(
                    "<< /Length {} >>\nstream\n{content}endstream",
                    content.len()
                )
                .into_bytes(),
            );
            let mut image_object = format!(
                "<< /Type /XObject /Subtype /Image /Width {w} /Height {h} \
                 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode \
                 /Length {} >>\nstream\n",
                jpeg.len()
            )
            .into_bytes();
            image_object.extend_from_slice(jpeg);
            image_object.extend_from_slice(b"\nendstream");
            objects.push(image_object);
        }

        let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            pdf.extend_from_slice(obj);
            pdf.extend_from_slice(b"\nendobj\n");
        }
        let xref_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for off in offsets {
            pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        pdf
    }

    /// The hostile-image harness: a one-page PDF embedding a single image
    /// XObject with EXACTLY the dict entries given (everything but /Length,
    /// which is derived) over an arbitrary stream body. Lets tests declare
    /// lying dimensions, decompression bombs, and unsupported filters that no
    /// honest encoder would produce.
    pub(crate) fn pdf_with_image_xobject(image_dict: &str, stream: &[u8]) -> Vec<u8> {
        let content = "q 100 0 0 100 0 0 cm /Im0 Do Q\n";
        let mut image_object = format!(
            "<< /Type /XObject /Subtype /Image {image_dict} /Length {} >>\nstream\n",
            stream.len()
        )
        .into_bytes();
        image_object.extend_from_slice(stream);
        image_object.extend_from_slice(b"\nendstream");
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Contents 4 0 R /Resources << /XObject << /Im0 5 0 R >> >> >>"
                .to_vec(),
            format!(
                "<< /Length {} >>\nstream\n{content}endstream",
                content.len()
            )
            .into_bytes(),
            image_object,
        ];

        let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            pdf.extend_from_slice(obj);
            pdf.extend_from_slice(b"\nendobj\n");
        }
        let xref_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for off in offsets {
            pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        pdf
    }

    /// zlib-compress bytes (FlateDecode test payloads).
    pub(crate) fn zlib(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    /// The review's probe, as a fixture: a small FlateDecode stream whose
    /// dict declares a tiny image but whose payload inflates to ~100 MB.
    pub(crate) fn flate_bomb_pdf() -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        let zeros = [0u8; 65536];
        for _ in 0..1600 {
            enc.write_all(&zeros).expect("zlib write"); // 1600 * 64 KiB = 100 MiB
        }
        let bomb = enc.finish().expect("zlib finish");
        assert!(bomb.len() < 256 * 1024, "bomb must be small on the wire");
        pdf_with_image_xobject(
            "/Width 10 /Height 10 /ColorSpace /DeviceRGB /BitsPerComponent 8 \
             /Filter /FlateDecode",
            &bomb,
        )
    }

    /// Patch a fixture JPEG's SOF0 header to claim absurd dimensions — the
    /// bytes still decode as a JPEG *header*, but any pixel decode would try
    /// to materialize gigapixels.
    pub(crate) fn jpeg_with_lying_dims(w: u32, h: u32, claim_w: u16, claim_h: u16) -> Vec<u8> {
        let mut jpeg = jpeg_bytes(w, h);
        let sof = jpeg
            .windows(2)
            .position(|m| m == [0xFF, 0xC0])
            .expect("baseline fixture JPEG has an SOF0 marker");
        // SOF0: FF C0 len(2) precision(1) height(2) width(2) …
        jpeg[sof + 5..sof + 7].copy_from_slice(&claim_h.to_be_bytes());
        jpeg[sof + 7..sof + 9].copy_from_slice(&claim_w.to_be_bytes());
        jpeg
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Injected OCR fakes: the plumbing (routing, page walk, caps, failure
    /// taxonomy) is proven hermetically — no model downloads in unit tests.
    /// Real-engine coverage is the VERITY_OCR_E2E=1-gated test below.
    struct FakeOcr(&'static str);
    impl OcrBackend for FakeOcr {
        fn recognize_rgb(&self, _w: u32, _h: u32, _rgb: &[u8]) -> Result<String, String> {
            Ok(self.0.to_string())
        }
    }

    /// The model-unavailable path (download/init failed).
    struct DownOcr;
    impl OcrBackend for DownOcr {
        fn recognize_rgb(&self, _w: u32, _h: u32, _rgb: &[u8]) -> Result<String, String> {
            Err("models unavailable (test)".into())
        }
    }

    /// Proves a code path never consults the engine at all.
    struct PanicOcr;
    impl OcrBackend for PanicOcr {
        fn recognize_rgb(&self, _w: u32, _h: u32, _rgb: &[u8]) -> Result<String, String> {
            panic!("OCR backend must not be consulted on this path")
        }
    }

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

    // ---------------- docx / doc (Word) ----------------

    #[test]
    fn docx_extracts_body_text() {
        // A real .docx (WordprocessingML zip) written by macOS textutil.
        let bytes = include_bytes!("testdata/sample.docx");
        let ex = expect_extracted(extract(bytes, Some("sample.docx")));
        assert_eq!(ex.method, "docx-xml");
        assert!(
            ex.text.contains("Acme Freight renewal risk"),
            "docx text: {:?}",
            ex.text
        );
        assert!(ex.text.contains("61000"), "docx text: {:?}", ex.text);
    }

    #[test]
    fn docx_detected_by_package_structure_even_with_wrong_name() {
        let bytes = include_bytes!("testdata/sample.docx");
        // Magic + word/document.xml win over a misleading .pptx name.
        let ex = expect_extracted(extract(bytes, Some("mislabeled.pptx")));
        assert_eq!(ex.method, "docx-xml");
    }

    #[test]
    fn doc_extracts_body_text_via_piece_table() {
        // A valid legacy .doc built via cfb — the same OLE2 + piece-table path
        // real Word docs take (verified against real .doc files during dev).
        let bytes =
            fixtures::doc_with_text("Acme Freight renewal risk is high. Revised quote 61000.");
        let ex = expect_extracted(extract(&bytes, Some("sample.doc")));
        assert_eq!(ex.method, "doc-piecetable");
        assert!(
            ex.text.contains("Acme Freight renewal risk"),
            "doc text: {:?}",
            ex.text
        );
        assert!(ex.text.contains("61000"), "doc text: {:?}", ex.text);
    }

    #[test]
    fn malformed_ole2_claiming_doc_degrades_to_typed_failure() {
        // OLE2 magic but a garbage body (mirrors real-world .doc files whose
        // compound structure a strict reader refuses, e.g. textutil output).
        // The invariant: fail cleanly (metadata-only), never crash, never fake
        // clean text.
        let mut bytes = OLE2_MAGIC.to_vec();
        bytes.resize(bytes.len() + 4096, 0u8);
        match extract(&bytes, Some("broken.doc")) {
            ExtractOutcome::Failed(_) | ExtractOutcome::NotHandled => {}
            ExtractOutcome::Extracted(ex) => {
                panic!("corrupt .doc must not extract clean text: {:?}", ex.text)
            }
        }
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
    fn imageless_scanned_pdf_fails_typed_without_consulting_the_engine() {
        // No text layer AND no decodable page images: the honest failure, and
        // the engine (PanicOcr) is provably never touched — no model download
        // is ever triggered by a blank/vector-only PDF.
        let f = expect_failed(extract_with_ocr(
            &fixtures::image_only_pdf(),
            Some("scan.pdf"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        assert_eq!(f, ExtractFailure::ScannedPdf);
        assert_eq!(
            f.reason(),
            "scanned/image PDF — no text layer and OCR found none"
        );
    }

    // ---------------- OCR tier (injected backends; see ocr.rs) ----------------

    #[test]
    fn scanned_pdf_ocrs_pages_in_order_with_pdf_ocr_receipt() {
        let j1 = fixtures::jpeg_bytes(24, 16);
        let j2 = fixtures::jpeg_bytes(16, 24);
        let bytes = fixtures::scanned_pdf_with_jpegs(&[&j1, &j2]);
        let ex = expect_extracted(extract_with_ocr(
            &bytes,
            Some("scan.pdf"),
            MAX_EXTRACT_CHARS,
            &FakeOcr("the falcon codeword is zanzibar"),
        ));
        assert_eq!(ex.method, "pdf-ocr");
        assert_eq!(
            ex.ocr_pages,
            Some(crate::ocr::OcrPages {
                ocred: 2,
                total: 2,
                skipped_unsupported: 0
            })
        );
        assert!(!ex.truncated);
        assert!(ex.text.contains("Page 1:"));
        assert!(ex.text.contains("Page 2:"));
        assert!(ex.text.contains("the falcon codeword is zanzibar"));
        let p1 = ex.text.find("Page 1:").unwrap();
        let p2 = ex.text.find("Page 2:").unwrap();
        assert!(p1 < p2, "pages must join in order");
    }

    #[test]
    fn scanned_pdf_ocr_honors_the_page_cap() {
        let jpeg = fixtures::jpeg_bytes(8, 8);
        let pages: Vec<&[u8]> =
            std::iter::repeat_n(jpeg.as_slice(), crate::ocr::MAX_OCR_PAGES + 2).collect();
        let bytes = fixtures::scanned_pdf_with_jpegs(&pages);
        let ex = expect_extracted(extract_with_ocr(
            &bytes,
            Some("big-scan.pdf"),
            MAX_EXTRACT_CHARS,
            &FakeOcr("line"),
        ));
        assert_eq!(ex.method, "pdf-ocr");
        let pages = ex.ocr_pages.expect("pdf-ocr carries page accounting");
        assert_eq!(pages.ocred, crate::ocr::MAX_OCR_PAGES as u32);
        assert_eq!(
            pages.total,
            crate::ocr::MAX_OCR_PAGES as u32 + 2,
            "total must show the WHOLE document so the cap is visible"
        );
        assert!(ex
            .text
            .contains(&format!("Page {}:", crate::ocr::MAX_OCR_PAGES)));
        assert!(!ex
            .text
            .contains(&format!("Page {}:", crate::ocr::MAX_OCR_PAGES + 1)));
    }

    #[test]
    fn scanned_pdf_ocr_honors_the_char_cap_with_truncated_flag() {
        let jpeg = fixtures::jpeg_bytes(8, 8);
        let bytes = fixtures::scanned_pdf_with_jpegs(&[&jpeg, &jpeg, &jpeg]);
        let ExtractOutcome::Extracted(ex) = extract_with_ocr(
            &bytes,
            Some("scan.pdf"),
            24,
            &FakeOcr("0123456789abcdefghij"),
        ) else {
            panic!("expected Extracted");
        };
        assert_eq!(ex.method, "pdf-ocr");
        assert!(
            ex.truncated,
            "char-cap overflow must set the truncated flag"
        );
        assert!(ex.text.chars().count() <= 24);
    }

    #[test]
    fn scanned_pdf_with_ocr_engine_down_is_a_typed_ocr_unavailable_failure() {
        let jpeg = fixtures::jpeg_bytes(8, 8);
        let bytes = fixtures::scanned_pdf_with_jpegs(&[&jpeg]);
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("scan.pdf"),
            MAX_EXTRACT_CHARS,
            &DownOcr,
        ));
        assert_eq!(
            f,
            ExtractFailure::OcrUnavailable("models unavailable (test)".into())
        );
        assert_eq!(f.reason(), "OCR unavailable: models unavailable (test)");
    }

    #[test]
    fn scanned_pdf_whose_ocr_finds_nothing_fails_as_scanned_pdf() {
        let jpeg = fixtures::jpeg_bytes(8, 8);
        let bytes = fixtures::scanned_pdf_with_jpegs(&[&jpeg]);
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("scan.pdf"),
            MAX_EXTRACT_CHARS,
            &FakeOcr("   "),
        ));
        assert_eq!(f, ExtractFailure::ScannedPdf);
    }

    // ------- hostile embedded images: bombs, lying headers, unsupported -------

    /// Records exactly what bitmaps the engine was shown (pixel-level proof
    /// for the decode plumbing) and returns fixed text.
    struct CaptureOcr(std::sync::Mutex<Vec<(u32, u32, Vec<u8>)>>);
    impl CaptureOcr {
        fn new() -> Self {
            Self(std::sync::Mutex::new(Vec::new()))
        }
    }
    impl OcrBackend for CaptureOcr {
        fn recognize_rgb(&self, w: u32, h: u32, rgb: &[u8]) -> Result<String, String> {
            self.0.lock().unwrap().push((w, h, rgb.to_vec()));
            Ok("captured".into())
        }
    }

    #[test]
    fn extract_pdf_flate_bomb_is_skipped_typed_and_never_reaches_the_engine() {
        // The review's probe: ~100 KB on the wire, declares 10x10, inflates
        // to 100 MB. The capped inflate must skip it (typed ScannedPdf, since
        // nothing else is on the page) without materializing the payload and
        // without ever consulting the engine.
        let bytes = fixtures::flate_bomb_pdf();
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("bomb.pdf"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        assert_eq!(f, ExtractFailure::ScannedPdf);
        // And nothing was OCRed / nothing counted as "unsupported encoding":
        // the bomb is bad DATA on a supported path, not an unsupported format.
        let mut budget = Budget::new(MAX_EXTRACT_CHARS);
        let pages =
            crate::ocr::ocr_pdf_pages(&bytes, &mut budget, crate::ocr::MAX_OCR_PAGES, &PanicOcr)
                .expect("walk parses");
        assert_eq!(
            pages,
            crate::ocr::OcrPages {
                ocred: 0,
                total: 1,
                skipped_unsupported: 0
            }
        );
    }

    #[test]
    fn extract_inflate_capped_bounds_output_memory_at_the_cap() {
        // Seam-level proof of the memory bound: a stream inflating to 10 MB
        // against a 1000-byte cap is refused, and the refusal path can never
        // have held more than cap+1 bytes of inflated output.
        let payload = fixtures::zlib(&vec![0u8; 10 * 1024 * 1024]);
        assert_eq!(crate::ocr::inflate_capped(&payload, 1000), None);
        // At exactly the required cap the same stream inflates fine.
        let ok = crate::ocr::inflate_capped(&payload, 10 * 1024 * 1024).expect("fits the cap");
        assert_eq!(ok.len(), 10 * 1024 * 1024);
    }

    #[test]
    fn extract_pdf_image_dict_declaring_oversize_dims_is_skipped_pre_decode() {
        // MAX_OCR_PIXELS in the PDF lane: dict-declared 100k x 100k is
        // refused before any sample is touched; the page contributes nothing.
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 100000 /Height 100000 /ColorSpace /DeviceRGB /BitsPerComponent 8",
            b"tiny",
        );
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("huge.pdf"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        assert_eq!(f, ExtractFailure::ScannedPdf);
    }

    #[test]
    fn extract_image_lane_rejects_lying_jpeg_dims_before_decode() {
        // MAX_OCR_PIXELS in the standalone-image lane: the JPEG header claims
        // 65500 x 65500 (~4.3 gigapixels); the header check must refuse it
        // BEFORE any pixel decode, engine provably untouched.
        let bytes = fixtures::jpeg_with_lying_dims(8, 8, 65500, 65500);
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("liar.jpg"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        match f {
            ExtractFailure::ImageParse(msg) => assert!(
                msg.contains("refuses images over"),
                "must be the pre-decode dimension refusal, got: {msg}"
            ),
            other => panic!("expected ImageParse, got {other:?}"),
        }
    }

    #[test]
    fn extract_pdf_dct_image_with_lying_header_dims_is_rejected_pre_decode() {
        // Same lie inside a PDF: the dict claims 8x8 (passes), but the JPEG's
        // own header claims gigapixels — the header re-check must catch it
        // before load, and the page then contributes nothing (typed).
        let jpeg = fixtures::jpeg_with_lying_dims(8, 8, 65500, 65500);
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode",
            &jpeg,
        );
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("liar.pdf"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        assert_eq!(f, ExtractFailure::ScannedPdf);
    }

    #[test]
    fn extract_pdf_flate_wrapped_dct_image_decodes_and_ocrs() {
        // [/FlateDecode /DCTDecode]: previously dead (lopdf errors
        // Unimplemented on DCT); now the flate layer is stripped manually
        // (capped) and the JPEG rides the normal bomb-checked decode.
        let jpeg = fixtures::jpeg_bytes(24, 16);
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 24 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8 \
             /Filter [/FlateDecode /DCTDecode]",
            &fixtures::zlib(&jpeg),
        );
        let ex = expect_extracted(extract_with_ocr(
            &bytes,
            Some("wrapped.pdf"),
            MAX_EXTRACT_CHARS,
            &FakeOcr("the falcon codeword is zanzibar"),
        ));
        assert_eq!(ex.method, "pdf-ocr");
        assert_eq!(
            ex.ocr_pages,
            Some(crate::ocr::OcrPages {
                ocred: 1,
                total: 1,
                skipped_unsupported: 0
            })
        );
        assert!(ex.text.contains("the falcon codeword is zanzibar"));
    }

    #[test]
    fn extract_pdf_all_pages_unsupported_encoding_fails_with_the_distinct_reason() {
        // A CCITT-only scan: OCR never gets to ATTEMPT anything, and saying
        // "OCR found none" would be a false claim of having looked (C1).
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 1 \
             /Filter /CCITTFaxDecode",
            b"not really ccitt data",
        );
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("fax.pdf"),
            MAX_EXTRACT_CHARS,
            &PanicOcr,
        ));
        assert_eq!(f, ExtractFailure::UnsupportedPdfImages);
        assert_eq!(
            f.reason(),
            "scanned/image PDF — unsupported image encodings; OCR could not attempt"
        );
        // The accounting the receipt would carry on a partial success:
        let mut budget = Budget::new(MAX_EXTRACT_CHARS);
        let pages =
            crate::ocr::ocr_pdf_pages(&bytes, &mut budget, crate::ocr::MAX_OCR_PAGES, &PanicOcr)
                .expect("walk parses");
        assert_eq!(
            pages,
            crate::ocr::OcrPages {
                ocred: 0,
                total: 1,
                skipped_unsupported: 1
            }
        );
    }

    #[test]
    fn extract_pdf_flate_image_with_png_predictor_reconstructs_exact_pixels() {
        // The predictor handling lopdf used to apply inside its (uncapped)
        // inflate, proven preserved on the capped path: Sub- and Up-filtered
        // rows must reconstruct to the exact original samples.
        let raw_rows: [[u8; 4]; 2] = [[10, 20, 30, 40], [50, 60, 70, 80]];
        let filtered = [
            [1u8, 10, 10, 10, 10], // Sub: first byte raw, then deltas of 10
            [2u8, 40, 40, 40, 40], // Up: deltas against the row above
        ]
        .concat();
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 4 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 \
             /Filter /FlateDecode \
             /DecodeParms << /Predictor 15 /Colors 1 /BitsPerComponent 8 /Columns 4 >>",
            &fixtures::zlib(&filtered),
        );
        let capture = CaptureOcr::new();
        let ex = expect_extracted(extract_with_ocr(
            &bytes,
            Some("predicted.pdf"),
            MAX_EXTRACT_CHARS,
            &capture,
        ));
        assert_eq!(ex.method, "pdf-ocr");
        let seen = capture.0.lock().unwrap();
        assert_eq!(seen.len(), 1, "exactly one bitmap must reach the engine");
        let (w, h, rgb) = &seen[0];
        assert_eq!((*w, *h), (4, 2));
        let expected: Vec<u8> = raw_rows.iter().flatten().flat_map(|&g| [g, g, g]).collect();
        assert_eq!(rgb, &expected, "unfiltered gray samples, replicated to RGB");
    }

    #[test]
    fn extract_pdf_plain_flate_rgb_image_still_decodes() {
        // The legit raw-samples lane must survive the bomb-guard rewrite.
        let samples: Vec<u8> = (0..2u8 * 2 * 3).map(|i| i * 10).collect();
        let bytes = fixtures::pdf_with_image_xobject(
            "/Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode",
            &fixtures::zlib(&samples),
        );
        let capture = CaptureOcr::new();
        let ex = expect_extracted(extract_with_ocr(
            &bytes,
            Some("raw.pdf"),
            MAX_EXTRACT_CHARS,
            &capture,
        ));
        assert_eq!(ex.method, "pdf-ocr");
        let seen = capture.0.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].2, samples);
    }

    #[test]
    fn receipt_json_discloses_ocr_page_accounting_only_when_present() {
        let r = receipt_json(
            "pdf-ocr",
            false,
            Some(crate::ocr::OcrPages {
                ocred: 3,
                total: 7,
                skipped_unsupported: 2,
            }),
        );
        assert_eq!(r["method"], "pdf-ocr");
        assert_eq!(r["pages_ocred"], 3);
        assert_eq!(r["pages_total"], 7);
        assert_eq!(r["pages_skipped_unsupported"], 2);
        let r = receipt_json("pdf-text", true, None);
        assert_eq!(r["truncated"], true);
        for key in ["pages_ocred", "pages_total", "pages_skipped_unsupported"] {
            assert!(
                r.get(key).is_none(),
                "non-OCR receipts must not carry {key}"
            );
        }
    }

    #[test]
    fn png_and_jpeg_extract_via_image_ocr() {
        for (bytes, name) in [
            (fixtures::png_bytes(20, 12), "shot.png"),
            (fixtures::jpeg_bytes(20, 12), "photo.jpg"),
        ] {
            let ex = expect_extracted(extract_with_ocr(
                &bytes,
                Some(name),
                MAX_EXTRACT_CHARS,
                &FakeOcr("renewal quote is 61000"),
            ));
            assert_eq!(ex.method, "image-ocr", "for {name}");
            assert_eq!(ex.ocr_pages, None);
            assert!(ex.text.contains("renewal quote is 61000"));
        }
    }

    #[test]
    fn image_detected_by_magic_even_with_misleading_name() {
        // Magic wins: PNG bytes named .pdf still ride the image-ocr path.
        let ex = expect_extracted(extract_with_ocr(
            &fixtures::png_bytes(20, 12),
            Some("report.pdf"),
            MAX_EXTRACT_CHARS,
            &FakeOcr("hello"),
        ));
        assert_eq!(ex.method, "image-ocr");
    }

    #[test]
    fn corrupt_image_is_a_typed_image_parse_failure() {
        // Valid PNG magic, hostile body.
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&[0xAB; 128]);
        let f = expect_failed(extract_with_ocr(
            &bytes,
            Some("bad.png"),
            MAX_EXTRACT_CHARS,
            &PanicOcr, // undecodable ⇒ the engine is never consulted
        ));
        assert!(matches!(f, ExtractFailure::ImageParse(_)), "got {f:?}");
    }

    #[test]
    fn image_where_ocr_finds_nothing_is_a_typed_no_text_failure() {
        let f = expect_failed(extract_with_ocr(
            &fixtures::png_bytes(20, 12),
            Some("blank.png"),
            MAX_EXTRACT_CHARS,
            &FakeOcr(""),
        ));
        assert_eq!(f, ExtractFailure::ImageNoText);
        assert_eq!(f.reason(), "image parsed but OCR found no text");
    }

    #[test]
    fn image_with_ocr_engine_down_is_a_typed_ocr_unavailable_failure() {
        let f = expect_failed(extract_with_ocr(
            &fixtures::png_bytes(20, 12),
            Some("shot.png"),
            MAX_EXTRACT_CHARS,
            &DownOcr,
        ));
        assert!(matches!(f, ExtractFailure::OcrUnavailable(_)), "got {f:?}");
    }

    /// End-to-end with the REAL engine (downloads ~12 MB of models on first
    /// run): gated behind VERITY_OCR_E2E=1. Proves the full lane — rendered
    /// text PNG → image-ocr, and the same image embedded as a scanned PDF →
    /// pdf-ocr — recognizes the known sentence.
    #[test]
    fn e2e_real_engine_reads_rendered_text_from_png_and_scanned_pdf() {
        if std::env::var("VERITY_OCR_E2E").as_deref() != Ok("1") {
            eprintln!("VERITY_OCR_E2E != 1; skipping");
            return;
        }
        let png = include_bytes!("testdata/ocr-sample.png");
        let ex = expect_extracted(extract(png, Some("ocr-sample.png")));
        assert_eq!(ex.method, "image-ocr");
        let lower = ex.text.to_lowercase();
        assert!(
            lower.contains("quick brown fox"),
            "OCR text was: {:?}",
            ex.text
        );

        let jpeg = include_bytes!("testdata/ocr-sample.jpg");
        let pdf = fixtures::scanned_pdf_with_jpegs(&[jpeg.as_slice()]);
        let ex = expect_extracted(extract(&pdf, Some("scan.pdf")));
        assert_eq!(ex.method, "pdf-ocr");
        assert_eq!(
            ex.ocr_pages,
            Some(crate::ocr::OcrPages {
                ocred: 1,
                total: 1,
                skipped_unsupported: 0
            })
        );
        let lower = ex.text.to_lowercase();
        assert!(
            lower.contains("quick brown fox"),
            "OCR text was: {:?}",
            ex.text
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
        // Unknown binary with no format claim: not our job.
        assert!(matches!(
            extract(&[0x00, 0x01, 0x02, 0x03, 0x7f], Some("blob.bin")),
            ExtractOutcome::NotHandled
        ));
        // A TRUNCATED png magic under a .png name: the bytes lie about the
        // claim (magic wins), so this is now a typed refusal, not a silent
        // store-only — PNG became one of our formats with the OCR tier.
        let f = expect_failed(extract(
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a],
            Some("img.png"),
        ));
        assert_eq!(f, ExtractFailure::UnrecognizedFormat);
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
