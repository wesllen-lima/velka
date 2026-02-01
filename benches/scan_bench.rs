use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use tempfile::TempDir;
use velka::{scan_with_config, VelkaConfig};

fn create_bench_dir(file_count: usize) -> TempDir {
    let temp = TempDir::new().unwrap();
    let base = temp.path();
    fs::create_dir_all(base.join("src")).unwrap();
    fs::create_dir_all(base.join("tests")).unwrap();

    let clean_rs = r#"
fn main() {
    let x = 42;
    println!("{}", x);
}
"#;

    for i in 0..file_count {
        let subdir = if i % 3 == 0 { "src" } else { "tests" };
        fs::write(base.join(subdir).join(format!("file_{i}.rs")), clean_rs).unwrap();
    }

    fs::write(
        base.join("Cargo.toml"),
        "[package]\nname = \"bench\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    temp
}

fn default_config_no_cache() -> VelkaConfig {
    let mut config = VelkaConfig::default();
    config.cache.enabled = false;
    config
}

fn default_config_with_cache() -> VelkaConfig {
    let mut config = VelkaConfig::default();
    config.cache.enabled = true;
    config
}

fn bench_scan_100(c: &mut Criterion) {
    let temp = create_bench_dir(100);
    let config = default_config_no_cache();
    c.bench_function("scan_100_files", |b| {
        b.iter(|| {
            let _ = scan_with_config(temp.path(), &config);
        });
    });
}

fn bench_scan_1000(c: &mut Criterion) {
    let temp = create_bench_dir(1000);
    let config = default_config_no_cache();
    c.bench_function("scan_1000_files", |b| {
        b.iter(|| {
            let _ = scan_with_config(temp.path(), &config);
        });
    });
}

fn bench_scan_5000(c: &mut Criterion) {
    let temp = create_bench_dir(5000);
    let config = default_config_no_cache();
    c.bench_function("scan_5000_files", |b| {
        b.iter(|| {
            let _ = scan_with_config(temp.path(), &config);
        });
    });
}

fn bench_scan_10000(c: &mut Criterion) {
    let temp = create_bench_dir(10_000);
    let config = default_config_no_cache();
    c.bench_function("scan_10000_files", |b| {
        b.iter(|| {
            let _ = scan_with_config(temp.path(), &config);
        });
    });
}

fn bench_scan_1000_cache_cold(c: &mut Criterion) {
    let config = default_config_with_cache();
    c.bench_function("scan_1000_files_cache_cold", |b| {
        b.iter_with_setup(
            || create_bench_dir(1000),
            |temp| {
                let _ = scan_with_config(temp.path(), &config);
            },
        );
    });
}

fn bench_scan_1000_cache_hit(c: &mut Criterion) {
    let config = default_config_with_cache();
    c.bench_function("scan_1000_files_cache_hit", |b| {
        b.iter_with_setup(
            || {
                let temp = create_bench_dir(1000);
                let _ = scan_with_config(temp.path(), &config);
                (temp, config.clone())
            },
            |(temp, config)| {
                let _ = scan_with_config(temp.path(), &config);
            },
        );
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(2))
        .measurement_time(std::time::Duration::from_secs(10));
    targets = bench_scan_100, bench_scan_1000, bench_scan_5000, bench_scan_10000,
        bench_scan_1000_cache_cold, bench_scan_1000_cache_hit
);
criterion_main!(benches);
