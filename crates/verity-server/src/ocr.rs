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
//!   files there by hand). Downloads run under real connect/global timeouts,
//!   are single-flighted process-wide, and every file — downloaded or cached —
//!   must match a pinned SHA-256 before rten sees it (a corrupt cache
//!   self-heals with one refetch). The engine is only ever initialized when
//!   there is actually an image to recognize — a text PDF never touches this
//!   module.
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

/// The honest page accounting for a scanned-PDF OCR pass, disclosed verbatim
/// on the extraction receipt: `ocred < total` makes a partial pass visible;
/// `skipped_unsupported` makes "we never even attempted this page" visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OcrPages {
    /// Pages where at least one image decoded and the engine was consulted.
    pub(crate) ocred: u32,
    /// Total pages in the document (NOT capped at [`MAX_OCR_PAGES`] — the
    /// receipt must show how much of the document the pass could ever cover).
    pub(crate) total: u32,
    /// Walked pages that carried image XObjects, none of which we could
    /// decode because every one used an encoding we don't implement
    /// (CCITT/JBIG2/JPX, exotic colorspaces/bit depths). OCR never attempted
    /// these pages; the caller reports that distinctly from "OCR found none".
    pub(crate) skipped_unsupported: u32,
}

/// Walk a (text-layer-less) PDF's pages in order, decode each page's embedded
/// raster image XObjects, OCR them, and push `Page N:` blocks into `budget`.
///
/// Returns the per-page accounting. Undecodable images (bombs, lying
/// dimensions, corrupt data) and unsupported-encoding images (CCITT/JBIG2/
/// JPX) are skipped and counted — pages built from them contribute nothing,
/// and if NOTHING contributes, the caller declares the honest typed failure.
/// The engine is never consulted when no image decodes, so a blank-page PDF
/// stays cheap and a broken model cache is only ever reported on files that
/// needed it.
pub(crate) fn ocr_pdf_pages(
    bytes: &[u8],
    budget: &mut Budget,
    max_pages: usize,
    ocr: &dyn OcrBackend,
) -> Result<OcrPages, PdfOcrError> {
    let doc = lopdf::Document::load_mem(bytes).map_err(|e| PdfOcrError::Parse(e.to_string()))?;
    let all_pages = doc.get_pages();
    let mut pages = OcrPages {
        ocred: 0,
        total: u32::try_from(all_pages.len()).unwrap_or(u32::MAX),
        skipped_unsupported: 0,
    };
    for (page_no, page_id) in all_pages.into_iter().take(max_pages) {
        let scan = page_images(&doc, page_id);
        let page_had_image = !scan.images.is_empty();
        let mut page_text = String::new();
        for img in scan.images {
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
            pages.ocred += 1;
        } else if scan.skipped_unsupported > 0 {
            pages.skipped_unsupported += 1;
        }
        if !page_text.is_empty() && !budget.push(&format!("Page {page_no}:\n{page_text}\n\n")) {
            break; // char cap reached — disclosed via `truncated`
        }
    }
    Ok(pages)
}

/// One page's decode results: the images the engine will see, plus the counts
/// of what was skipped (and why) for the honest page accounting above.
struct PageScan {
    images: Vec<image::RgbImage>,
    /// Encodings we don't implement (CCITT/JBIG2/JPX, exotic colorspaces…).
    skipped_unsupported: u32,
    /// Bad data: declared-oversize dims, flate payloads over the size cap
    /// (bomb guard), truncated samples, corrupt JPEG bytes.
    skipped_undecodable: u32,
}

/// What [`decode_image_xobject`] decided about one image stream.
enum XObjectImage {
    Decoded(image::RgbImage),
    Unsupported,
    Undecodable,
}

/// Decode the raster image XObjects a page references, in the order the
/// resource dictionary lists them. Only self-describing or raw formats we can
/// reconstruct deterministically are attempted:
///
/// * `DCTDecode` — the stream IS a JPEG (possibly flate-wrapped); hand it to
///   the image crate after a header-dimensions bomb check.
/// * `FlateDecode` / unfiltered — raw samples; reconstructed for 8-bit
///   DeviceRGB and DeviceGray, inflated under a hard cap.
///
/// Anything else (CCITT, JBIG2, JPX, indexed palettes, exotic bit depths) is
/// skipped and counted, never guessed at.
fn page_images(doc: &lopdf::Document, page_id: lopdf::ObjectId) -> PageScan {
    let mut out = PageScan {
        images: Vec::new(),
        skipped_unsupported: 0,
        skipped_undecodable: 0,
    };
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
            match decode_image_xobject(stream) {
                XObjectImage::Decoded(img) => out.images.push(img),
                XObjectImage::Unsupported => out.skipped_unsupported += 1,
                XObjectImage::Undecodable => out.skipped_undecodable += 1,
            }
        }
    }
    out
}

/// Slack allowed on top of the exact expected sample size when inflating a
/// FlateDecode image stream: PNG predictors prepend 1 filter byte per row
/// (covered by `+ height` at the call sites) and this small fixed margin
/// absorbs encoder padding. Anything beyond the cap is a bomb — skipped.
const INFLATE_MARGIN: usize = 1024;

/// Inflate a FlateDecode payload with a hard output cap. This exists because
/// lopdf's `decompressed_content()` inflates with NO output bound, so a
/// ~100 KB stream declaring a 10x10 image can materialize gigabytes and OOM
/// the server. Memory here is bounded at `cap + 1` bytes: the decoder is read
/// through `Read::take(cap + 1)`, and landing past `cap` means the stream
/// lied about its size → `None` (the caller skips the image, counted).
///
/// Mirrors lopdf's decode quirks so behavior on legit files is unchanged:
/// a zlib failure that produced no output retries as raw deflate (corrupt
/// zlib headers/checksums in the wild), and a mid-stream error keeps the
/// partial output — the caller's expected-length check decides its fate.
pub(crate) fn inflate_capped(input: &[u8], cap: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let limit = cap as u64 + 1; // one probe byte past the cap detects overflow
    let mut out = Vec::new();
    let result = flate2::read::ZlibDecoder::new(input)
        .take(limit)
        .read_to_end(&mut out);
    if result.is_err() && out.is_empty() && input.len() > 2 {
        let _ = flate2::read::DeflateDecoder::new(&input[2..])
            .take(limit)
            .read_to_end(&mut out);
    }
    if out.len() > cap {
        return None;
    }
    Some(out)
}

/// Undo PNG predictors (10-15) per the stream's `/DecodeParms`, row by row —
/// ported from the lopdf path we no longer take (its `filters::png` unfilter
/// ran inside the uncapped `decompressed_content()`). Predictor 1/2 and
/// absent params pass the data through untouched, exactly as lopdf did.
/// `None` means malformed predictor data (bad filter tag, ragged final row).
pub(crate) fn png_unpredict(data: Vec<u8>, params: Option<&lopdf::Dictionary>) -> Option<Vec<u8>> {
    let Some(params) = params else {
        return Some(data);
    };
    let get = |key: &[u8]| params.get(key).and_then(lopdf::Object::as_i64).ok();
    let predictor = get(b"Predictor").unwrap_or(1);
    if !(10..=15).contains(&predictor) {
        return Some(data);
    }
    let columns = get(b"Columns").unwrap_or(1).max(1) as usize;
    let colors = get(b"Colors").unwrap_or(1).max(1) as usize;
    let bits = get(b"BitsPerComponent").unwrap_or(8).max(8) as usize;
    let bpp = colors * bits / 8;
    let row_len = bpp.checked_mul(columns)?;
    let stride = row_len.checked_add(1)?; // +1 leading filter-type byte
    if row_len == 0 || !data.len().is_multiple_of(stride) {
        return None;
    }
    let mut prev = vec![0u8; row_len];
    let mut out = Vec::with_capacity(data.len() / stride * row_len);
    for chunk in data.chunks_exact(stride) {
        let mut cur = chunk[1..].to_vec();
        png_unfilter_row(chunk[0], bpp, &prev, &mut cur)?;
        out.extend_from_slice(&cur);
        prev = cur;
    }
    Some(out)
}

/// One row of PNG unfiltering (RFC 2083 §6): None/Sub/Up/Average/Paeth.
fn png_unfilter_row(filter: u8, bpp: usize, prev: &[u8], cur: &mut [u8]) -> Option<()> {
    let bpp = bpp.min(cur.len());
    match filter {
        0 => {}
        1 => {
            for i in bpp..cur.len() {
                cur[i] = cur[i].wrapping_add(cur[i - bpp]);
            }
        }
        2 => {
            for i in 0..cur.len() {
                cur[i] = cur[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            for i in 0..bpp {
                cur[i] = cur[i].wrapping_add(prev[i] / 2);
            }
            for i in bpp..cur.len() {
                let avg = (u16::from(cur[i - bpp]) + u16::from(prev[i])) / 2;
                cur[i] = cur[i].wrapping_add(avg as u8);
            }
        }
        4 => {
            for i in 0..bpp {
                cur[i] = cur[i].wrapping_add(paeth_predict(0, prev[i], 0));
            }
            for i in bpp..cur.len() {
                cur[i] = cur[i].wrapping_add(paeth_predict(cur[i - bpp], prev[i], prev[i - bpp]));
            }
        }
        _ => return None,
    }
    Some(())
}

fn paeth_predict(left: u8, above: u8, upper_left: u8) -> u8 {
    let (l, a, ul) = (i16::from(left), i16::from(above), i16::from(upper_left));
    let estimate = l + a - ul;
    let (dl, da, dul) = (
        (estimate - l).abs(),
        (estimate - a).abs(),
        (estimate - ul).abs(),
    );
    if dl <= da && dl <= dul {
        left
    } else if da <= dul {
        above
    } else {
        upper_left
    }
}

fn decode_image_xobject(stream: &lopdf::Stream) -> XObjectImage {
    let dict = &stream.dict;
    let dim = |key: &[u8]| {
        dict.get(key)
            .and_then(lopdf::Object::as_i64)
            .ok()
            .and_then(|v| u32::try_from(v).ok())
    };
    let (Some(width), Some(height)) = (dim(b"Width"), dim(b"Height")) else {
        return XObjectImage::Undecodable;
    };
    if check_pixels(width, height).is_err() {
        return XObjectImage::Undecodable;
    }

    // Filter may be a single name, an array, or absent (raw samples).
    let filters: Vec<&[u8]> = match dict.get(b"Filter") {
        Ok(lopdf::Object::Name(n)) => vec![n.as_slice()],
        Ok(lopdf::Object::Array(a)) => a.iter().filter_map(|o| o.as_name().ok()).collect(),
        _ => vec![],
    };
    let params = dict
        .get(b"DecodeParms")
        .and_then(lopdf::Object::as_dict)
        .ok();

    if filters.last() == Some(&b"DCTDecode".as_slice()) {
        // The stream content is a JPEG file, possibly flate-wrapped. lopdf's
        // decompressed_content() errors Unimplemented on DCT streams, so the
        // flate layer is stripped manually — capped: a real JPEG payload for
        // a dict-declared-legal image fits well under raw RGB size.
        let jpeg: std::borrow::Cow<'_, [u8]> = match filters.as_slice() {
            [_] => std::borrow::Cow::Borrowed(&stream.content),
            [f, _] if *f == b"FlateDecode" => {
                let cap = match (width as usize)
                    .checked_mul(height as usize)
                    .and_then(|p| p.checked_mul(3))
                    .and_then(|p| p.checked_add(INFLATE_MARGIN))
                {
                    Some(cap) => cap,
                    None => return XObjectImage::Undecodable,
                };
                match inflate_capped(&stream.content, cap) {
                    Some(jpeg) => std::borrow::Cow::Owned(jpeg),
                    None => return XObjectImage::Undecodable,
                }
            }
            _ => return XObjectImage::Unsupported,
        };
        // decode_rgb reads the JPEG's OWN header dimensions and enforces
        // MAX_OCR_PIXELS BEFORE any pixel decodes — the dict check above only
        // covered the *claimed* size, and headers can lie.
        return match decode_rgb(&jpeg) {
            Ok(img) => XObjectImage::Decoded(img),
            Err(_) => XObjectImage::Undecodable,
        };
    }

    // Raw samples (optionally flate-compressed): 8-bit DeviceRGB/DeviceGray.
    let bpc = dict
        .get(b"BitsPerComponent")
        .and_then(lopdf::Object::as_i64);
    if !matches!(bpc, Ok(8)) {
        return XObjectImage::Unsupported;
    }
    let channels: usize = match dict.get(b"ColorSpace").and_then(lopdf::Object::as_name) {
        Ok(b"DeviceRGB") => 3,
        Ok(b"DeviceGray") => 1,
        _ => return XObjectImage::Unsupported,
    };
    let expected = match (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(channels))
    {
        Some(e) => e,
        None => return XObjectImage::Undecodable,
    };
    let raw = if filters.is_empty() {
        stream.content.clone()
    } else if filters == [b"FlateDecode".as_slice()] {
        // Capped inflation (never lopdf's uncapped decompressed_content):
        // expected samples + 1 predictor filter byte per row + fixed margin.
        // A stream inflating past that declared-size envelope is a bomb.
        let cap = expected
            .saturating_add(height as usize)
            .saturating_add(INFLATE_MARGIN);
        let inflated = match inflate_capped(&stream.content, cap) {
            Some(data) => data,
            None => return XObjectImage::Undecodable,
        };
        match png_unpredict(inflated, params) {
            Some(data) => data,
            None => return XObjectImage::Undecodable,
        }
    } else {
        return XObjectImage::Unsupported;
    };
    if raw.len() < expected {
        return XObjectImage::Undecodable;
    }
    let img = match channels {
        3 => image::RgbImage::from_raw(width, height, raw[..expected].to_vec()),
        1 => {
            let rgb: Vec<u8> = raw[..expected].iter().flat_map(|&g| [g, g, g]).collect();
            image::RgbImage::from_raw(width, height, rgb)
        }
        _ => unreachable!(),
    };
    match img {
        Some(img) => XObjectImage::Decoded(img),
        None => XObjectImage::Undecodable,
    }
}

// ---------------------------------------------------------------------------
// The engine (feature "ocr"): lazy global ocrs instance + model fetch
// ---------------------------------------------------------------------------

#[cfg(feature = "ocr")]
mod engine {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use super::OcrBackend;

    /// Canonical distribution point for the ocrs models (the same URLs the
    /// `ocrs` CLI fetches; the author's Hugging Face repo only carries the
    /// pre-2024 model format, which rten ≥0.16 no longer loads).
    const DETECTION_MODEL_URL: &str =
        "https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.rten";
    const RECOGNITION_MODEL_URL: &str =
        "https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.rten";

    /// Pinned SHA-256 of the canonical model artifacts above (computed from
    /// the upstream files; the bucket serves stable, versioned bytes).
    /// Verified after every download AND on first cache load each process —
    /// a corrupt, truncated, or tampered file never reaches rten, and a bad
    /// cached copy self-heals (delete + one refetch) instead of failing OCR
    /// until someone clears ~/.cache/ocrs by hand.
    const DETECTION_MODEL_SHA256: &str =
        "f15cfb56bd02c4bf478a20343986504a1f01e1665c2b3a0ad66340f054b1b5ca";
    const RECOGNITION_MODEL_SHA256: &str =
        "e484866d4cce403175bd8d00b128feb08ab42e208de30e42cd9889d8f1735a6e";

    /// Real network bounds on the model download: without them a hung
    /// connection parks the blocking extraction thread indefinitely.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const GLOBAL_TIMEOUT: Duration = Duration::from_secs(120);

    /// Process-wide single-flight for the model fetch: N concurrent first
    /// scans must produce ONE download, not N racing ones.
    static FETCH_LOCK: Mutex<()> = Mutex::new(());
    /// Uniquifies temp download names within the process (the name also
    /// carries the pid), so two healing threads can never tear each other's
    /// partial files.
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Injectable fetch seam: production passes [`download`]; tests inject
    /// counting/faulty fetchers to prove single-flight and self-heal without
    /// touching the network.
    type FetchFn<'a> = &'a (dyn Fn(&str, &Path) -> Result<(), String> + Sync);

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

    /// Download `url` to `dest` with real timeouts. Unique temp-file + rename
    /// so a torn download never lands as a "cached" model.
    fn download(url: &str, dest: &Path) -> Result<(), String> {
        let dir = dest
            .parent()
            .ok_or_else(|| format!("no parent dir for {}", dest.display()))?;
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_connect(Some(CONNECT_TIMEOUT))
                .timeout_global(Some(GLOBAL_TIMEOUT))
                .build(),
        );
        let mut resp = agent
            .get(url)
            .call()
            .map_err(|e| format!("downloading {url}: {e}"))?;
        let tmp = dest.with_extension(format!(
            "part.{}.{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
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

    fn sha256_hex(path: &Path) -> Result<String, String> {
        use sha2::Digest as _;
        let mut file =
            std::fs::File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
        let mut hasher = sha2::Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .map_err(|e| format!("hashing {}: {e}", path.display()))?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn verify_sha256(path: &Path, expected: &str) -> Result<(), String> {
        let got = sha256_hex(path)?;
        if got != expected {
            return Err(format!(
                "model checksum mismatch at {}: expected sha256 {expected}, got {got}",
                path.display()
            ));
        }
        Ok(())
    }

    /// Make `dest` present AND checksum-valid, fetching or self-healing as
    /// needed. Fail-closed at every exit: a file that doesn't hash to the
    /// pinned value is deleted, refetched at most ONCE, and if still wrong,
    /// deleted again and reported typed — never handed to rten.
    fn ensure_model_file(
        url: &str,
        dest: &Path,
        expected_sha256: &str,
        fetch: FetchFn<'_>,
    ) -> Result<(), String> {
        if dest.exists() {
            match verify_sha256(dest, expected_sha256) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // Corrupt cache (torn pre-hardening download, disk rot,
                    // tampering): self-heal with one refetch.
                    std::fs::remove_file(dest)
                        .map_err(|e| format!("removing corrupt model {}: {e}", dest.display()))?;
                }
            }
        }
        fetch(url, dest)?;
        verify_sha256(dest, expected_sha256).inspect_err(|_| {
            let _ = std::fs::remove_file(dest);
        })
    }

    /// Fetch/verify both model files under the process-wide single-flight
    /// lock. Split from [`global`] so tests can prove that two racing threads
    /// produce exactly one fetch.
    fn ensure_models_locked(
        specs: &[(&str, &Path, &str)],
        fetch: FetchFn<'_>,
    ) -> Result<(), String> {
        let _guard = FETCH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (url, dest, sha) in specs {
            ensure_model_file(url, dest, sha, fetch)?;
        }
        Ok(())
    }

    /// Load a (present, checksum-valid) model file; if loading fails anyway
    /// (an artifact rten can't parse), delete it, refetch ONCE, and retry —
    /// then fail typed. Generic over the loader so tests can prove the heal
    /// without real rten models.
    fn load_model_healing<T>(
        url: &str,
        dest: &Path,
        expected_sha256: &str,
        fetch: FetchFn<'_>,
        load: &dyn Fn(&Path) -> Result<T, String>,
    ) -> Result<T, String> {
        match load(dest) {
            Ok(model) => Ok(model),
            Err(first) => {
                let _ = std::fs::remove_file(dest);
                ensure_model_file(url, dest, expected_sha256, fetch)?;
                load(dest).map_err(|e| {
                    format!(
                        "loading {} failed even after refetch: {e} (first attempt: {first})",
                        dest.display()
                    )
                })
            }
        }
    }

    static ENGINE: OnceLock<ocrs::OcrEngine> = OnceLock::new();

    /// Fetch-if-needed, verify, load, and cache the engine. Success is cached
    /// for the process lifetime; failure is NOT (the next file retries, so a
    /// transient blip during the first-ever scan must not poison the
    /// process). Fetches are single-flighted via [`ensure_models_locked`];
    /// two racing first calls may still both LOAD an engine from the verified
    /// files (CPU-only) — `get_or_init` keeps one.
    fn global() -> Result<&'static ocrs::OcrEngine, String> {
        if let Some(e) = ENGINE.get() {
            return Ok(e);
        }
        let dir = model_dir()?;
        let det_path = dir.join("text-detection.rten");
        let rec_path = dir.join("text-recognition.rten");
        ensure_models_locked(
            &[
                (DETECTION_MODEL_URL, &det_path, DETECTION_MODEL_SHA256),
                (RECOGNITION_MODEL_URL, &rec_path, RECOGNITION_MODEL_SHA256),
            ],
            &download,
        )?;
        let load = |p: &Path| {
            rten::Model::load_file(p).map_err(|e| format!("loading {}: {e}", p.display()))
        };
        let detection = load_model_healing(
            DETECTION_MODEL_URL,
            &det_path,
            DETECTION_MODEL_SHA256,
            &download,
            &load,
        )?;
        let recognition = load_model_healing(
            RECOGNITION_MODEL_URL,
            &rec_path,
            RECOGNITION_MODEL_SHA256,
            &download,
            &load,
        )?;
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

    /// Hermetic model-plumbing tests: fetch fns are injected, nothing touches
    /// the network or rten. Named ocr_model_* so they ride the `ocr` filter.
    #[cfg(test)]
    mod tests {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use super::*;

        const GOOD: &[u8] = b"pretend this is an rten model";
        /// sha256 of GOOD, computed in-test (no second pinning to drift).
        fn good_sha() -> String {
            use sha2::Digest as _;
            format!("{:x}", sha2::Sha256::digest(GOOD))
        }

        /// Fresh scratch dir per test (std-only; no tempfile dev-dep).
        struct Scratch(PathBuf);
        impl Scratch {
            fn new(tag: &str) -> Self {
                let dir = std::env::temp_dir().join(format!(
                    "verity-ocr-model-tests-{}-{}-{tag}",
                    std::process::id(),
                    TMP_SEQ.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&dir).expect("scratch dir");
                Scratch(dir)
            }
            fn path(&self, name: &str) -> PathBuf {
                self.0.join(name)
            }
        }
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn counting_fetch(
            counter: Arc<AtomicUsize>,
            body: &'static [u8],
        ) -> impl Fn(&str, &Path) -> Result<(), String> + Sync {
            move |_url: &str, dest: &Path| {
                counter.fetch_add(1, Ordering::SeqCst);
                std::fs::write(dest, body).map_err(|e| e.to_string())
            }
        }

        #[test]
        fn ocr_model_fetch_is_single_flight_two_threads_one_download() {
            let scratch = Scratch::new("single-flight");
            let dest = scratch.path("model.rten");
            let sha = good_sha();
            let count = Arc::new(AtomicUsize::new(0));
            std::thread::scope(|s| {
                for _ in 0..2 {
                    let fetch = counting_fetch(count.clone(), GOOD);
                    let (dest, sha) = (dest.clone(), sha.clone());
                    s.spawn(move || {
                        ensure_models_locked(&[("mem://model", &dest, &sha)], &fetch)
                            .expect("fetch succeeds");
                    });
                }
            });
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "two racing first scans must produce exactly one download"
            );
            assert_eq!(std::fs::read(&dest).unwrap(), GOOD);
        }

        #[test]
        fn ocr_model_corrupt_cache_self_heals_with_one_refetch() {
            let scratch = Scratch::new("self-heal");
            let dest = scratch.path("model.rten");
            std::fs::write(&dest, b"bitrot").unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let fetch = counting_fetch(count.clone(), GOOD);
            ensure_model_file("mem://model", &dest, &good_sha(), &fetch)
                .expect("corrupt cache heals");
            assert_eq!(count.load(Ordering::SeqCst), 1, "exactly one refetch");
            assert_eq!(
                std::fs::read(&dest).unwrap(),
                GOOD,
                "healed to canonical bytes"
            );
        }

        #[test]
        fn ocr_model_download_hash_mismatch_is_rejected_and_deleted() {
            let scratch = Scratch::new("bad-download");
            let dest = scratch.path("model.rten");
            let count = Arc::new(AtomicUsize::new(0));
            let fetch = counting_fetch(count.clone(), b"not the pinned artifact");
            let err = ensure_model_file("mem://model", &dest, &good_sha(), &fetch)
                .expect_err("mismatched download must be rejected");
            assert!(err.contains("checksum mismatch"), "typed reason: {err}");
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "refetched ONCE, then failed"
            );
            assert!(
                !dest.exists(),
                "a mismatching file must never linger as cache"
            );
        }

        #[test]
        fn ocr_model_unloadable_file_is_deleted_refetched_once_then_loads() {
            let scratch = Scratch::new("heal-load");
            let dest = scratch.path("model.rten");
            std::fs::write(&dest, GOOD).unwrap(); // checksum-valid but "unloadable"
            let fetches = Arc::new(AtomicUsize::new(0));
            let fetch = counting_fetch(fetches.clone(), GOOD);
            let loads = AtomicUsize::new(0);
            let load = |p: &Path| -> Result<Vec<u8>, String> {
                if loads.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err("rten refused (test)".into())
                } else {
                    std::fs::read(p).map_err(|e| e.to_string())
                }
            };
            let model = load_model_healing("mem://model", &dest, &good_sha(), &fetch, &load)
                .expect("second load succeeds after heal");
            assert_eq!(model, GOOD);
            assert_eq!(fetches.load(Ordering::SeqCst), 1, "healed with ONE refetch");
            assert_eq!(loads.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn ocr_model_unloadable_after_refetch_fails_typed() {
            let scratch = Scratch::new("heal-load-fails");
            let dest = scratch.path("model.rten");
            std::fs::write(&dest, GOOD).unwrap();
            let fetches = Arc::new(AtomicUsize::new(0));
            let fetch = counting_fetch(fetches.clone(), GOOD);
            let load = |_: &Path| -> Result<(), String> { Err("rten refused (test)".into()) };
            let err = load_model_healing("mem://model", &dest, &good_sha(), &fetch, &load)
                .expect_err("still-unloadable model fails typed");
            assert!(err.contains("after refetch"), "typed reason: {err}");
            assert_eq!(
                fetches.load(Ordering::SeqCst),
                1,
                "refetched ONCE, not in a loop"
            );
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
