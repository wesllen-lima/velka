use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn velka() -> Command {
    cargo_bin_cmd!("velka")
}

#[test]
fn test_version() {
    velka()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("velka"));
}

#[test]
fn test_help() {
    velka()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Code Sin Judge"));
}

#[test]
fn test_scan_clean_directory() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("clean.rs"),
        "fn main() { println!(\"Hello\"); }",
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No sins found"));
}

#[test]
fn test_detect_aws_key() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("secrets.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS_ACCESS_KEY"));
}

#[test]
fn test_detect_github_token() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.js"),
        r#"const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("GITHUB_TOKEN"));
}

#[test]
fn test_redaction_enabled_by_default() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("aws.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("****"));
}

#[test]
fn test_no_redact_flag() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("aws.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--no-redact"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AKIA0000000000000000"));
}

#[test]
fn test_mortal_only_flag() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("mixed.py"),
        r#"
ip = "192.168.1.1"
key = "AKIA0000000000000000"
"#,
    )
    .unwrap();

    let output = velka()
        .args([
            "scan",
            temp.path().to_str().unwrap(),
            "--mortal-only",
            "--format",
            "json",
        ])
        .assert()
        .code(1);

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("AWS_ACCESS_KEY"));
    assert!(!stdout.contains("HARDCODED_IP"));
}

#[test]
fn test_json_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"sins\""))
        .stdout(predicate::str::contains("\"summary\""));
}

#[test]
fn test_csv_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "csv"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Path,Line,Severity,Rule"));
}

#[test]
fn test_junit_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "junit"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("<testsuite"))
        .stdout(predicate::str::contains("</testsuite>"));
}

#[test]
fn test_sarif_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "sarif"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"$schema\""))
        .stdout(predicate::str::contains("sarif"));
}

#[test]
fn test_markdown_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args([
            "scan",
            temp.path().to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("# Velka Security Report"));
}

#[test]
fn test_html_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "html"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("<!DOCTYPE html>"))
        .stdout(predicate::str::contains("Velka Security Report"));
}

#[test]
fn test_velka_ignore_comment() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("ignored.rs"),
        r#"let key = "AKIA0000000000000000"; // velka:ignore"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sins\": []"));
}

#[test]
fn test_exit_code_on_mortal_sin() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("fatal.rs"),
        r#"let key = "AKIA0000000000000000";"#,
    )
    .unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn test_exit_code_clean() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("clean.rs"), "fn main() {}").unwrap();

    velka()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_stdin_detects_secret() {
    let input = r#"let key = "AKIA0000000000000000";"#;
    velka()
        .write_stdin(input)
        .args(["stdin", "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS_ACCESS_KEY"));
}

#[test]
fn test_stdin_clean_exit_zero() {
    let input = "fn main() { let x = 42; }";
    velka()
        .write_stdin(input)
        .args(["stdin"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No sins found"));
}

#[test]
fn test_report_format_output_redacted() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.js"),
        r#"const AWS_KEY = "AKIA0000000000000000";"#,
    )
    .unwrap();

    let assert = velka()
        .args(["scan", temp.path().to_str().unwrap(), "--format", "report"])
        .assert()
        .code(1);
    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("BEFORE VELKA"));
    assert!(stdout.contains("AFTER VELKA"));
    assert!(stdout.contains("process.env.AWS_ACCESS_KEY_ID"));
    assert!(
        !stdout.contains("AKIA0000000000000000"),
        "Report must not contain raw secret"
    );
}

#[test]
fn test_migrate_dry_run_no_files_changed() {
    let temp = TempDir::new().unwrap();
    let _ = std::process::Command::new("git")
        .args(["init"])
        .current_dir(temp.path())
        .output();
    fs::write(temp.path().join(".gitignore"), ".env\n").unwrap();
    fs::write(
        temp.path().join("config.js"),
        r#"const AWS_KEY = "AKIA0000000000000000";"#,
    )
    .unwrap();

    let assert = velka()
        .args([
            "scan",
            temp.path().to_str().unwrap(),
            "--migrate-to-env",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("AKIA0000000000000000"),
        "Dry-run output must not contain raw secret"
    );
    assert!(stdout.contains("Migrated") || stdout.contains("Variables added"));
    assert!(
        !temp.path().join(".env").exists(),
        "Dry-run must not create .env"
    );
}

#[test]
fn test_migrate_apply_creates_env_no_secret_in_output() {
    let temp = TempDir::new().unwrap();
    let _ = std::process::Command::new("git")
        .args(["init"])
        .current_dir(temp.path())
        .output();
    fs::write(temp.path().join(".gitignore"), ".env\n").unwrap();
    let src = temp.path().join("app.js");
    fs::write(&src, r#"const AWS_KEY = "AKIA0000000000000000";"#).unwrap();

    let assert = velka()
        .args([
            "scan",
            temp.path().to_str().unwrap(),
            "--migrate-to-env",
            "--yes",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("AKIA0000000000000000"),
        "Migrate output must not contain raw secret"
    );

    let env_path = temp.path().join(".env");
    assert!(env_path.exists(), ".env must be created");
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(env_content.contains("AWS_ACCESS_KEY_ID="));
    let app_content = fs::read_to_string(&src).unwrap();
    assert!(
        app_content.contains("process.env.AWS_ACCESS_KEY_ID"),
        "Source must be updated to use env"
    );
}
