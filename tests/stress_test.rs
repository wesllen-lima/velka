use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crossbeam_channel::unbounded;
use tempfile::TempDir;

use velka::engine::{investigate, scan_content};
use velka::VelkaConfig;

const TOTAL_FILES: usize = 50_000;
const FILES_WITH_SECRETS: usize = 10_000;

/// Generates a realistic-looking source file with an embedded secret.
fn generate_secret_file(index: usize) -> String {
    let secret_type = index % 5;
    let filler = format!(
        "// File {index} - auto-generated for stress testing\n\
         fn process_data_{index}() {{\n\
         \tlet data = vec![1, 2, 3];\n\
         \tprintln!(\"processing {{}}\", data.len());\n"
    );
    let secret_line = match secret_type {
        0 => format!(
            "\tlet aws_key = \"AKIA{:016X}\";",
            0xDEAD_0000_0000_0000u64 + index as u64
        ),
        1 => format!("\tlet token = \"ghp_{}\";", generate_alphanum(36, index)),
        2 => format!(
            "\tlet stripe = \"sk_live_{}\";",
            generate_alphanum(24, index)
        ),
        3 => format!("\tlet api_key = \"AIza{}\";", generate_alphanum(35, index)),
        _ => format!(
            "\tlet sendgrid = \"SG.{}.{}\";",
            generate_alphanum_dash(22, index),
            generate_alphanum_dash(43, index + 1000)
        ),
    };
    format!("{filler}{secret_line}\n}}\n")
}

/// Generates a clean source file with no secrets.
fn generate_clean_file(index: usize) -> String {
    format!(
        "// Clean file {index}\n\
         fn compute_{index}(x: i32) -> i32 {{\n\
         \tlet result = x * 2 + {index};\n\
         \tprintln!(\"result: {{}}\", result);\n\
         \tresult\n\
         }}\n"
    )
}

fn generate_alphanum(len: usize, seed: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|i| CHARS[(seed * 7 + i * 13) % CHARS.len()] as char)
        .collect()
}

fn generate_alphanum_dash(len: usize, seed: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    (0..len)
        .map(|i| CHARS[(seed * 11 + i * 17) % CHARS.len()] as char)
        .collect()
}

#[test]
#[ignore = "slow: run with cargo test --test stress_test -- --ignored --nocapture"]
fn stress_scan_content_10k_secrets() {
    let config = VelkaConfig::default();
    let start = Instant::now();
    let found = AtomicUsize::new(0);

    // Test scan_content with 10,000 secret-containing strings
    for i in 0..FILES_WITH_SECRETS {
        let content = generate_secret_file(i);
        let result = scan_content(&content, &config).unwrap();
        if !result.is_empty() {
            found.fetch_add(result.len(), Ordering::Relaxed);
        }
    }

    let elapsed = start.elapsed();
    let total_found = found.load(Ordering::Relaxed);
    eprintln!(
        "[STRESS] scan_content: {total_found} secrets found in {FILES_WITH_SECRETS} files, elapsed: {elapsed:.2?}"
    );

    // Must find at least 80% of injected secrets
    assert!(
        total_found >= FILES_WITH_SECRETS * 80 / 100,
        "Detection rate too low: found {total_found} out of {FILES_WITH_SECRETS} expected"
    );
}

#[test]
#[ignore = "slow: run with cargo test --test stress_test -- --ignored --nocapture"]
fn stress_investigate_50k_files() {
    let temp = TempDir::new().unwrap();
    let base = temp.path();

    eprintln!("[STRESS] Generating {TOTAL_FILES} files...");
    let gen_start = Instant::now();

    // Create subdirectories to avoid single-dir bottleneck
    for dir_idx in 0..50 {
        let dir = base.join(format!("module_{dir_idx:03}"));
        fs::create_dir_all(&dir).unwrap();

        let files_per_dir = TOTAL_FILES / 50;
        for file_idx in 0..files_per_dir {
            let global_idx = dir_idx * files_per_dir + file_idx;
            let content = if global_idx < FILES_WITH_SECRETS {
                generate_secret_file(global_idx)
            } else {
                generate_clean_file(global_idx)
            };
            let filename = format!("file_{file_idx:04}.rs");
            fs::write(dir.join(&filename), &content).unwrap();
        }
    }

    eprintln!("[STRESS] File generation: {:.2?}", gen_start.elapsed());

    let mut config = VelkaConfig::default();
    config.cache.enabled = false; // Disable cache for raw perf measurement

    let (sender, receiver) = unbounded();
    let scan_start = Instant::now();

    investigate(base, &config, &sender).unwrap();
    drop(sender);

    let sins: Vec<_> = receiver.iter().collect();
    let scan_elapsed = scan_start.elapsed();

    eprintln!(
        "[STRESS] investigate: {} sins found across {} files in {:.2?}",
        sins.len(),
        TOTAL_FILES,
        scan_elapsed
    );

    // Validate detection rate
    assert!(
        sins.len() >= FILES_WITH_SECRETS * 70 / 100,
        "Detection rate too low: found {} out of {} expected",
        sins.len(),
        FILES_WITH_SECRETS
    );

    // Performance: must complete within 120 seconds even on slow CI
    assert!(
        scan_elapsed.as_secs() < 120,
        "Scan took too long: {scan_elapsed:?}"
    );
}

#[test]
#[ignore = "slow: adversarial input stress test, run with --ignored"]
fn stress_scan_content_no_panic_on_adversarial_input() {
    let config = VelkaConfig::default();

    let long_a = "A".repeat(1_000_000);
    let deep_json = "{".repeat(10_000);
    let many_newlines = "\n".repeat(100_000);
    let unicode_stress = "\u{FEFF}".repeat(1000);
    let binary_like: String = (0..10_000).map(|i| (i % 256) as u8 as char).collect();
    let regex_bomb = format!("Regex::new(\"{}\")", "(a+)+".repeat(100));
    let long_secret = format!("let key = \"AKIA{}\";", "A".repeat(100_000));

    let adversarial_inputs: Vec<&str> = vec![
        "",
        &long_a,
        "hello\0world\0secret",
        &deep_json,
        &many_newlines,
        &unicode_stress,
        &binary_like,
        &regex_bomb,
        &long_secret,
    ];

    for (i, input) in adversarial_inputs.iter().enumerate() {
        let result = scan_content(input, &config);
        assert!(
            result.is_ok(),
            "Adversarial input {} caused error: {:?}",
            i,
            result.err()
        );
    }
}
