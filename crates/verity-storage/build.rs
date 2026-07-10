fn main() {
    // sqlx::migrate! embeds migrations at compile time; without this, a new
    // migration file does not invalidate the crate and stale binaries miss it.
    println!("cargo:rerun-if-changed=../../migrations");
}
