//! `manifest-test <manifest.yaml> [more.yaml ...]` — the CLI face of the
//! conformance harness (SPEC §5e.3: deterministic `verity manifest test`
//! pass/fail). Exit 0 iff every fixture of every manifest passes; also
//! reports whether each manifest would clear the activation gate.

use std::path::Path;
use std::process::ExitCode;

use verity_manifest::{run_manifest_fixtures, Manifest};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: manifest-test <manifest.yaml> [more.yaml ...]");
        return ExitCode::from(2);
    }

    let mut failed = false;
    for arg in &args {
        let path = Path::new(arg);
        println!("== {arg}");

        let yaml = match std::fs::read_to_string(path) {
            Ok(y) => y,
            Err(e) => {
                println!("   FAIL: unreadable: {e}");
                failed = true;
                continue;
            }
        };
        let manifest = match Manifest::from_yaml(&yaml) {
            Ok(m) => m,
            Err(e) => {
                println!("   FAIL: {e}");
                failed = true;
                continue;
            }
        };
        println!(
            "   parsed: source={} tier={:?} acl_mode={:?} entities={}",
            manifest.source.name,
            manifest.source.tier,
            manifest.acl_mode(),
            manifest.entities.len()
        );
        match manifest.activation_check() {
            Ok(()) => println!("   activation gate: would pass (still requires admin approval)"),
            Err(e) => println!("   activation gate: {e}"),
        }

        match run_manifest_fixtures(path) {
            Ok(outcomes) if outcomes.is_empty() => {
                println!("   no fixtures declared — nothing verified");
            }
            Ok(outcomes) => {
                for o in outcomes {
                    if o.passed {
                        println!("   PASS {}", o.input);
                    } else {
                        failed = true;
                        println!("   FAIL {}", o.input);
                        for f in o.failures {
                            for line in f.lines() {
                                println!("        {line}");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                failed = true;
                println!("   FAIL: {e}");
            }
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
