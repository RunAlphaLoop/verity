//! Local OCR tier: scanned PDFs and standalone PNG/JPEG images → text.
//!
//! Sovereignty-first, same honesty rules as extract.rs (which owns the policy;
//! this module is the mechanism):
//!
//! * **Pure Rust, zero system dependencies.** The engine is the `ocrs` crate
//!   on the `rten` runtime — no tesseract (a system dep would break the
//!   clean-VM stranger gate), no cloud OCR, no Python. OCR quality is
//!   printed-text-grade and best-effort: fine for scans and screenshots of
//!   type, not handwriting, and receipts always disclose the method
//!   ("pdf-ocr" / "image-ocr") so a consumer can weigh the text accordingly.
//! * **Models fetch once, then cache.** The two rten models (~2.5 MB
//!   detection + ~9.7 MB recognition) download on FIRST USE from the ocrs
//!   project's canonical bucket into `~/.cache/ocrs` — the same directory the
//!   `ocrs` CLI uses, and the same fetch-once-then-cache lane as the MiniLM
//!   query encoder (which caches via hf-hub). `VERITY_OCR_MODEL_DIR`
//!   overrides the location for air-gapped deployments (drop the two `.rten`
//!   files there by hand). The engine is only ever initialized when there is
//!   actually an image to recognize — a text PDF never touches this module.
//! * **Failure is typed, never silent, never fatal.** Download/init/inference
//!   failure surfaces as an `Err(String)` that extract.rs turns into the
//!   disclosed `OCR unavailable: …` extraction failure. A failed init is NOT
//!   cached — the next file retries (a transient network blip during the
//!   first-ever scan must not poison the process).
//! * **Bounded work.** Scanned PDFs OCR at most [`MAX_OCR_PAGES`] pages;
//!   individual images over [`MAX_OCR_PIXELS`] are refused (decompression-
//!   bomb guard). Char caps are enforced by the caller's `Budget`.
//!
//! The `ocrs`/`rten` engine itself sits behind the default-ON `ocr` cargo
//! feature; built without it, [`default_backend`] returns a stub whose every
//! call fails typed ("built without the 'ocr' feature") — the decode and
//! PDF-walking plumbing stays compiled and tested either way.

use std::io::Cursor;

use crate::extract::Budget;

/// Hard cap on pages OCRed per scanned PDF. Disclosed via the receipt's
/// `pages_ocred` (a 200-page scan reporting `pages_ocred: 50` is visibly
/// partial; the `truncated` flag additionally covers the char cap).
pub(crate) const MAX_OCR_PAGES: usize = 50;

/// Refuse to decode images beyond this many pixels (~40 MP — comfortably
/// above any sane scan, small enough that a crafted PNG bomb cannot balloon
/// into gigabytes of raster).
pub(crate) const MAX_OCR_PIXELS: u64 = 40_000_000;

/// The OCR seam. Implementations recognize printed text in one RGB8 bitmap
/// (`rgb.len() == 3 * width * height`).
///
/// `Err` means the ENGINE failed (models unavailable, inference error) and is
/// disclosed as such; "ran fine, found no text" is `Ok` with an empty string.
/// Tests inject fakes here; production uses [`default_backend`].
pub(crate) trait OcrBackend: Sync {
    fn recognize_rgb(&self, width: u32, height: u32, rgb: &[u8]) -> Result<String, String>;
}

/// The production backend: lazily initialized global ocrs engine (or the
/// typed always-fails stub when built without the `ocr` feature).
pub(crate) fn default_backend() -> &'static dyn OcrBackend {
    &engine::LazyOcrs
}

// ---------------------------------------------------------------------------
// Standalone image decode (PNG/JPEG bytes → RGB8, bomb-guarded)
// ---------------------------------------------------------------------------

/// Decode PNG/JPEG bytes to RGB8. Dimensions are read from the header FIRST
/// and checked against [`MAX_OCR_PIXELS`] before any pixel is materialized.
pub(crate) fn decode_rgb(bytes: &[u8]) -> Result<image::RgbImage, String> {
    let (w, h) = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| e.to_string())?
        .into_dimensions()
        .map_err(|e| e.to_string())?;
    check_pixels(w, h)?;
    let img = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| e.to_string())?
        .decode()
        .map_err(|e| e.to_string())?;
    Ok(img.into_rgb8())
}

fn check_pixels(w: u32, h: u32) -> Result<(), String> {
    if u64::from(w) * u64::from(h) > MAX_OCR_PIXELS {
        return Err(format!(
            "image is {w}x{h} pixels; OCR refuses images over {MAX_OCR_PIXELS} pixels"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scanned-PDF page walk: embedded image XObjects, in page order
// ---------------------------------------------------------------------------

/// Why a scanned-PDF OCR pass failed. extract.rs maps these to its typed
/// `ExtractFailure` reasons.
#[derive(Debug)]
pub(crate) enum PdfOcrError {
    /// lopdf could not re-parse the document for the image walk.
    Parse(String),
    /// The OCR engine itself failed (model download/init/inference).
    Engine(String),
}

/// Walk a (text-layer-less) PDF's pages in order, decode each page's embedded
/// raster image XObjects, OCR them, and push `Page N:` blocks into `budget`.
///
/// Returns how many pages had at least one image actually OCRed. Undecodable
/// or unsupported-filter images (CCITT/JBIG2/JPX) are skipped — pages built
/// from them simply contribute nothing, and if NOTHING contributes, the
/// caller declares the honest "OCR found none" failure. The engine is never
/// consulted when no image decodes, so a blank-page PDF stays cheap and a
/// broken model cache is only ever reported on files that needed it.
pub(crate) fn ocr_pdf_pages(
    bytes: &[u8],
    budget: &mut Budget,
    max_pages: usize,
    ocr: &dyn OcrBackend,
) -> Result<u32, PdfOcrError> {
    let doc = lopdf::Document::load_mem(bytes).map_err(|e| PdfOcrError::Parse(e.to_string()))?;
    let mut pages_ocred = 0u32;
    for (page_no, page_id) in doc.get_pages().into_iter().take(max_pages) {
        let mut page_text = String::new();
        let mut page_had_image = false;
        for img in page_images(&doc, page_id) {
            page_had_image = true;
            let text = ocr
                .recognize_rgb(img.width(), img.height(), img.as_raw())
                .map_err(PdfOcrError::Engine)?;
            let text = text.trim();
            if !text.is_empty() {
                if !page_text.is_empty() {
                    page_text.push('\n');
                }
                page_text.push_str(text);
            }
        }
        if page_had_image {
            pages_ocred += 1;
        }
        if !page_text.is_empty() && !budget.push(&format!("Page {page_no}:\n{page_text}\n\n")) {
            break; // char cap reached — disclosed via `truncated`
        }
    }
    Ok(pages_ocred)
}

/// Decode the raster image XObjects a page references, in the order the
/// resource dictionary lists them. Only self-describing or raw formats we can
/// reconstruct deterministically are attempted:
///
/// * `DCTDecode` — the stream IS a JPEG; hand it to the image crate.
/// * `FlateDecode` / unfiltered — raw samples; reconstructed for 8-bit
///   DeviceRGB and DeviceGray.
///
/// Anything else (CCITT, JBIG2, JPX, indexed palettes, exotic bit depths) is
/// skipped, never guessed at.
fn page_images(doc: &lopdf::Document, page_id: lopdf::ObjectId) -> Vec<image::RgbImage> {
    let mut out = Vec::new();
    let Ok((inline_dict, resource_ids)) = doc.get_page_resources(page_id) else {
        return out;
    };
    let mut resource_dicts: Vec<&lopdf::Dictionary> = inline_dict.into_iter().collect();
    for id in resource_ids {
        if let Ok(d) = doc.get_dictionary(id) {
            resource_dicts.push(d);
        }
    }
    for resources in resource_dicts {
        let xobjects = match resources.get(b"XObject") {
            Ok(lopdf::Object::Dictionary(d)) => d,
            Ok(lopdf::Object::Reference(id)) => match doc.get_dictionary(*id) {
                Ok(d) => d,
                Err(_) => continue,
            },
            _ => continue,
        };
        for (_name, obj) in xobjects.iter() {
            let stream = match obj {
                lopdf::Object::Reference(id) => {
                    match doc.get_object(*id).and_then(lopdf::Object::as_stream) {
                        Ok(s) => s,
                        Err(_) => continue,
                    }
                }
                lopdf::Object::Stream(s) => s,
                _ => continue,
            };
            let subtype = stream.dict.get(b"Subtype").and_then(lopdf::Object::as_name);
            if !matches!(subtype, Ok(b"Image")) {
                continue;
            }
            if let Some(img) = decode_image_xobject(stream) {
                out.push(img);
            }
        }
    }
    out
}

fn decode_image_xobject(stream: &lopdf::Stream) -> Option<image::RgbImage> {
    let dict = &stream.dict;
    let width = u32::try_from(dict.get(b"Width").and_then(lopdf::Object::as_i64).ok()?).ok()?;
    let height = u32::try_from(dict.get(b"Height").and_then(lopdf::Object::as_i64).ok()?).ok()?;
    check_pixels(width, height).ok()?;

    // Filter may be a single name, an array, or absent (raw samples).
    let filters: Vec<&[u8]> = match dict.get(b"Filter") {
        Ok(lopdf::Object::Name(n)) => vec![n.as_slice()],
        Ok(lopdf::Object::Array(a)) => a.iter().filter_map(|o| o.as_name().ok()).collect(),
        _ => vec![],
    };

    if filters.last() == Some(&b"DCTDecode".as_slice()) {
        // The (possibly flate-wrapped) stream content is a JPEG file.
        let jpeg = if filters.len() > 1 {
            stream.decompressed_content().ok()?
        } else {
            stream.content.clone()
        };
        let img = image::load_from_memory(&jpeg).ok()?;
        let img = img.into_rgb8();
        check_pixels(img.width(), img.height()).ok()?;
        return Some(img);
    }

    // Raw samples (optionally flate-compressed): 8-bit DeviceRGB/DeviceGray.
    let bpc = dict
        .get(b"BitsPerComponent")
        .and_then(lopdf::Object::as_i64);
    if !matches!(bpc, Ok(8)) {
        return None;
    }
    let colorspace = dict
        .get(b"ColorSpace")
        .and_then(lopdf::Object::as_name)
        .ok()?;
    let channels: usize = match colorspace {
        b"DeviceRGB" => 3,
        b"DeviceGray" => 1,
        _ => return None,
    };
    let raw = if filters.is_empty() {
        stream.content.clone()
    } else if filters == [b"FlateDecode".as_slice()] {
        stream.decompressed_content().ok()?
    } else {
        return None;
    };
    let expected = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(channels)?;
    if raw.len() < expected {
        return None;
    }
    match channels {
        3 => image::RgbImage::from_raw(width, height, raw[..expected].to_vec()),
        1 => {
            let rgb: Vec<u8> = raw[..expected].iter().flat_map(|&g| [g, g, g]).collect();
            image::RgbImage::from_raw(width, height, rgb)
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// The engine (feature "ocr"): lazy global ocrs instance + model fetch
// ---------------------------------------------------------------------------

#[cfg(feature = "ocr")]
mod engine {
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use super::OcrBackend;

    /// Canonical distribution point for the ocrs models (the same URLs the
    /// `ocrs` CLI fetches; the author's Hugging Face repo only carries the
    /// pre-2024 model format, which rten ≥0.16 no longer loads).
    const DETECTION_MODEL_URL: &str =
        "https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.rten";
    const RECOGNITION_MODEL_URL: &str =
        "https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.rten";

    /// `VERITY_OCR_MODEL_DIR` override, else `~/.cache/ocrs` (shared with the
    /// ocrs CLI's own cache, so nothing downloads twice on a dev machine).
    fn model_dir() -> Result<PathBuf, String> {
        if let Some(dir) = std::env::var_os("VERITY_OCR_MODEL_DIR") {
            return Ok(PathBuf::from(dir));
        }
        #[cfg(windows)]
        let home = std::env::var_os("USERPROFILE");
        #[cfg(not(windows))]
        let home = std::env::var_os("HOME");
        let home = home.ok_or("no home directory; set VERITY_OCR_MODEL_DIR")?;
        Ok(PathBuf::from(home).join(".cache").join("ocrs"))
    }

    /// Download `url` to `dest` once (no-op if present). Temp-file + rename so
    /// a torn download never lands as a "cached" model.
    fn fetch_once(url: &str, dest: &Path) -> Result<(), String> {
        if dest.exists() {
            return Ok(());
        }
        let dir = dest
            .parent()
            .ok_or_else(|| format!("no parent dir for {}", dest.display()))?;
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let mut resp = ureq::get(url)
            .call()
            .map_err(|e| format!("downloading {url}: {e}"))?;
        let tmp = dest.with_extension(format!("part.{}", std::process::id()));
        let result = (|| -> Result<(), String> {
            let mut file = std::fs::File::create(&tmp)
                .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
            std::io::copy(&mut resp.body_mut().as_reader(), &mut file)
                .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            std::fs::rename(&tmp, dest)
                .map_err(|e| format!("moving model into place at {}: {e}", dest.display()))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    static ENGINE: OnceLock<ocrs::OcrEngine> = OnceLock::new();

    /// Fetch-if-needed, load, and cache the engine. Success is cached for the
    /// process lifetime; failure is NOT (the next file retries, so a network
    /// blip during the first scan doesn't poison every later one). Two racing
    /// first calls may both build an engine; `get_or_init` keeps one.
    fn global() -> Result<&'static ocrs::OcrEngine, String> {
        if let Some(e) = ENGINE.get() {
            return Ok(e);
        }
        let dir = model_dir()?;
        let det_path = dir.join("text-detection.rten");
        let rec_path = dir.join("text-recognition.rten");
        fetch_once(DETECTION_MODEL_URL, &det_path)?;
        fetch_once(RECOGNITION_MODEL_URL, &rec_path)?;
        let detection = rten::Model::load_file(&det_path).map_err(|e| {
            format!(
                "loading {} (delete it to re-download): {e}",
                det_path.display()
            )
        })?;
        let recognition = rten::Model::load_file(&rec_path).map_err(|e| {
            format!(
                "loading {} (delete it to re-download): {e}",
                rec_path.display()
            )
        })?;
        let engine = ocrs::OcrEngine::new(ocrs::OcrEngineParams {
            detection_model: Some(detection),
            recognition_model: Some(recognition),
            ..Default::default()
        })
        .map_err(|e| format!("initializing OCR engine: {e}"))?;
        Ok(ENGINE.get_or_init(|| engine))
    }

    pub(super) struct LazyOcrs;

    impl OcrBackend for LazyOcrs {
        fn recognize_rgb(&self, width: u32, height: u32, rgb: &[u8]) -> Result<String, String> {
            let engine = global()?;
            let source = ocrs::ImageSource::from_bytes(rgb, (width, height))
                .map_err(|e| format!("preparing image: {e}"))?;
            let input = engine
                .prepare_input(source)
                .map_err(|e| format!("preparing OCR input: {e}"))?;
            engine
                .get_text(&input)
                .map_err(|e| format!("recognizing text: {e}"))
        }
    }
}

#[cfg(not(feature = "ocr"))]
mod engine {
    use super::OcrBackend;

    /// Stub for `--no-default-features` builds: every OCR attempt fails typed
    /// and disclosed — never silently empty.
    pub(super) struct LazyOcrs;

    impl OcrBackend for LazyOcrs {
        fn recognize_rgb(&self, _w: u32, _h: u32, _rgb: &[u8]) -> Result<String, String> {
            Err("verity-server was built without the 'ocr' cargo feature".into())
        }
    }
}
