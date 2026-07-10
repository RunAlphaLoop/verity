//! Terminal polish: manual ANSI (no color dependency), disabled when stdout
//! is not a tty or NO_COLOR is set. Alignment is done on the raw string
//! BEFORE painting, because escape codes break `{:>width}` arithmetic.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

fn paint(code: &str, s: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint("1", s)
}

pub fn dim(s: &str) -> String {
    paint("2", s)
}

pub fn red(s: &str) -> String {
    paint("31", s)
}

pub fn green(s: &str) -> String {
    paint("32", s)
}

pub fn yellow(s: &str) -> String {
    paint("33", s)
}

pub fn cyan(s: &str) -> String {
    paint("36", s)
}

pub fn magenta(s: &str) -> String {
    paint("35", s)
}

/// Section banner: `◆ verity dev`.
pub fn banner(title: &str) {
    println!("\n{} {}", cyan("◆"), bold(title));
}

/// One completed step: `  ✓ label   detail`.
pub fn step_ok(label: &str, detail: &str) {
    println!("  {} {}  {detail}", green("✓"), pad(label, 8));
}

/// Right-pad to `width` before painting (keeps columns straight under ANSI).
pub fn pad(s: &str, width: usize) -> String {
    bold(&format!("{s:<width$}"))
}

/// Truncate to `max` characters on a char boundary, appending `…` when cut.
pub fn truncate(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let cut: String = flat.chars().take(max).collect();
    format!("{cut}…")
}

/// The [acl-provenance] tag, colored by lane (SPEC §5e.6).
pub fn acl_tag(provenance: &str) -> String {
    let tag = format!("[{provenance}]");
    match provenance {
        "mirrored" => green(&tag),
        "approximated" => yellow(&tag),
        "quarantined" => red(&tag),
        _ => cyan(&tag), // admin-assigned: the explicit convenience lane
    }
}

/// The [kind] tag: scoped content vs published knowledge.
pub fn kind_tag(kind: &str) -> String {
    let tag = format!("[{kind}]");
    match kind {
        "knowledge" => magenta(&tag),
        _ => blue(&tag),
    }
}

pub fn blue(s: &str) -> String {
    paint("34", s)
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_is_char_safe_and_flattens_whitespace() {
        assert_eq!(truncate("a  b\nc", 100), "a b c");
        assert_eq!(truncate("héllo wörld", 4), "héll…");
        assert_eq!(truncate("short", 5), "short");
    }
}
