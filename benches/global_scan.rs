use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::fs;
use tempfile::TempDir;
use velka::engine::ml_classifier::{classify, classify_default, EnsembleWeights};
use velka::{scan_with_config, VelkaConfig};

fn create_large_bench_dir(file_count: usize) -> TempDir {
    let temp = TempDir::new().unwrap();
    let base = temp.path();

    let dirs = ["src", "lib", "internal", "pkg", "cmd", "api", "web", "core"];
    for d in &dirs {
        fs::create_dir_all(base.join(d)).unwrap();
    }

    let clean_templates: [&str; 4] = [
        // Rust-like
        "fn handler() {\n    let x = 42;\n    println!(\"{}\", x);\n}\n",
        // JS-like
        "const express = require('express');\nconst app = express();\napp.listen(3000);\n",
        // Python-like
        "import os\ndef main():\n    config = os.getenv('HOME')\n    print(config)\n",
        // Go-like
        "package main\nimport \"fmt\"\nfunc main() {\n    fmt.Println(\"ok\")\n}\n",
    ];

    let extensions = ["rs", "js", "py", "go"];

    for i in 0..file_count {
        let dir = dirs[i % dirs.len()];
        let ext = extensions[i % extensions.len()];
        let template = clean_templates[i % clean_templates.len()];
        let path = base.join(dir).join(format!("file_{i}.{ext}"));
        fs::write(path, template).unwrap();
    }

    // Sprinkle some files with secrets for realism
    let secret_files = file_count / 100; // 1% of files have secrets
    for i in 0..secret_files {
        let dir = dirs[i % dirs.len()];
        let content = format!("const API_KEY = \"AKIA{:016X}\";\n", i * 12345 + 999_999);
        fs::write(base.join(dir).join(format!("secret_{i}.js")), content).unwrap();
    }

    temp
}

fn default_config_no_cache() -> VelkaConfig {
    let mut config = VelkaConfig::default();
    config.cache.enabled = false;
    config
}

fn bench_global_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("global_scan");
    group
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(3))
        .measurement_time(std::time::Duration::from_secs(15));

    for &count in &[10_000, 50_000, 100_000] {
        let temp = create_large_bench_dir(count);
        let config = default_config_no_cache();

        group.bench_with_input(BenchmarkId::new("files", count), &count, |b, _| {
            b.iter(|| {
                let _ = scan_with_config(temp.path(), &config);
            });
        });
    }

    group.finish();
}

fn bench_ml_classifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_classifier");
    group.sample_size(100);

    let candidates = vec![
        ("aws_key", "AKIA1234567890ABCDEF", "AWS_ACCESS_KEY"),
        ("github_token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", "GITHUB_TOKEN"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT_TOKEN"),
        ("high_entropy", "aB3$kL9mN2pQ5rS7tU1vW4xY6zA8cD0eFgH2iJ4kL6mN8", "HIGH_ENTROPY"),
        ("false_positive", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "HIGH_ENTROPY"),
    ];

    for (name, candidate, rule_id) in &candidates {
        group.bench_with_input(
            BenchmarkId::new("classify", name),
            &(candidate, rule_id),
            |b, (cand, rule)| {
                b.iter(|| classify_default(cand, rule));
            },
        );
    }

    group.finish();
}

fn bench_ml_classifier_ensemble_weights(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_ensemble_weights");
    group.sample_size(100);

    let candidate = "AKIA1234567890ABCDEF";
    let rule_id = "AWS_ACCESS_KEY";

    let weight_configs = vec![
        ("default", EnsembleWeights::default()),
        (
            "entropy_heavy",
            EnsembleWeights {
                entropy: 0.6,
                char_frequency: 0.15,
                structural: 0.15,
                length: 0.1,
            },
        ),
        (
            "structural_heavy",
            EnsembleWeights {
                entropy: 0.2,
                char_frequency: 0.15,
                structural: 0.5,
                length: 0.15,
            },
        ),
    ];

    for (name, weights) in &weight_configs {
        group.bench_with_input(BenchmarkId::new("weights", name), weights, |b, w| {
            b.iter(|| classify(candidate, rule_id, w));
        });
    }

    group.finish();
}

criterion_group!(
    name = global_benches;
    config = Criterion::default();
    targets = bench_global_scan, bench_ml_classifier, bench_ml_classifier_ensemble_weights
);
criterion_main!(global_benches);
