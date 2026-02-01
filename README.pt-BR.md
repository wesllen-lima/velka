# VELKA

[English](README.md) | **Português (BR)**

---

**O Juiz dos Pecados do Código**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/badge/Release-v1.2.0-green)](https://github.com/wesllen-lima/velka/releases)
[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](LICENSE)

> *"Thou who art Undead, art chosen... to expose the guilty."*

---

## Funcionalidades

- **52 regras de detecção**: AWS, GCP, Azure, GitHub, Stripe, SendGrid, Twilio, Datadog, Cloudflare, Supabase, Vercel e mais
- **Privacidade em primeiro lugar**: Zero telemetria, sem chamadas de rede, segredos redactados por padrão
- **Alta performance**: I/O mapeado em memória, varredura paralela, regex compiladas
- **Pronto para CI/CD**: JUnit, SARIF, CSV, Markdown, HTML, report
- **Varredura incremental**: `--diff` e `--staged` para pre-commit rápido
- **Forense Git**: `--deep-scan` encontra segredos no histórico de commits
- **API como biblioteca**: Use como crate Rust nas suas ferramentas

---

## Instalação

### Cargo (crates.io)

```bash
cargo install velka
```

### Cargo (GitHub)

```bash
cargo install --git "https://github.com/wesllen-lima/velka" --locked
```

### A partir do código

```bash
cargo install --path .
```

### Docker

```bash
docker run --rm -v $(pwd):/code velka scan /code
```

### Como biblioteca

```toml
# Cargo.toml
[dependencies]
velka = "1.2"
```

```rust
use velka::{scan, Severity};

fn main() -> velka::VelkaResult<()> {
    let sins = velka::scan(std::path::Path::new("."))?;
    
    let mortal_count = sins.iter()
        .filter(|s| s.severity == Severity::Mortal)
        .count();
    
    if mortal_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}
```

---

## Uso

```bash
# Varredura básica
velka scan .

# Barra de progresso
velka scan . --progress

# Apenas arquivos alterados (pre-commit rápido)
velka scan . --diff

# Apenas arquivos staged
velka scan . --staged

# Forense no histórico Git
velka scan . --deep-scan

# Apenas problemas críticos
velka scan . --mortal-only

# Formatos de saída
velka scan . --format json
velka scan . --format csv
velka scan . --format junit    # dashboards CI
velka scan . --format sarif    # GitHub Code Scanning
velka scan . --format markdown
velka scan . --format html
velka scan . --format report   # Before/After com remediação (redactado)

# Perfil de configuração
velka scan . --profile ci

# Mostrar segredos completos (apenas debug)
velka scan . --no-redact

# Validar tokens via API (opcional; GitHub etc.)
velka scan . --verify

# Migrar segredos para .env (opcional; exige .env no .gitignore)
velka scan . --migrate-to-env --dry-run   # Apenas preview
velka scan . --migrate-to-env --yes       # Aplicar sem confirmação
velka scan . --migrate-to-env             # Confirmação interativa
velka scan . --migrate-to-env --env-file .env.local

# Varredura via stdin (ex.: pipe do git diff)
git diff | velka stdin
cat logs/*.log | velka stdin --format json

# Instalar hook pre-commit
velka install-hook
```

### Códigos de saída

- **0**: nenhum pecado mortal encontrado
- **1**: pelo menos um pecado mortal encontrado

---

## Configuração

Crie `velka.toml` na raiz do projeto:

```toml
[scan]
ignore_paths = ["vendor/**", "tests/fixtures/**"]
entropy_threshold = 4.6
whitelist = ["localhost", "example.com", "test@example.com"]

[output]
redact_secrets = true

[cache]
enabled = true
location = "both"  # "project", "user" ou "both"

[rules]
disable = ["HARDCODED_IP"]

[[rules.custom]]
id = "INTERNAL_API"
pattern = "MYCOMPANY_[A-Z0-9]{32}"
severity = "Mortal"
description = "Internal API key detected"

[profile.ci]
cache.enabled = false
output.redact_secrets = true

[profile.dev]
scan.entropy_threshold = 5.0
output.redact_secrets = false
```

**Ignores inline**: Adicione o comentário `velka:ignore` na linha para ignorá-la.

---

## Regras de detecção

### Pecados mortais (críticos)

| Regra | Descrição |
|-------|-----------|
| `AWS_ACCESS_KEY` | AWS Access Key ID |
| `AWS_SECRET_KEY` | AWS Secret Access Key |
| `GOOGLE_API_KEY` | Google API Key |
| `GITHUB_TOKEN` | GitHub Personal Access Token |
| `STRIPE_SECRET` | Stripe Secret Key |
| `PRIVATE_KEY` | Chaves privadas SSH/PGP |
| `SLACK_WEBHOOK` | URL de webhook Slack |
| `SENDGRID_API` | SendGrid API Key |
| `TWILIO_API` | Twilio API Key |
| `NPM_TOKEN` | NPM Auth Token |
| `PYPI_TOKEN` | PyPI API Token |
| `DISCORD_TOKEN` | Discord Bot Token |
| `TELEGRAM_BOT` | Telegram Bot Token |
| `DB_CONNECTION_STRING` | String de conexão de banco |
| `HARDCODED_PASSWORD` | Senha hardcoded |
| `AZURE_STORAGE_KEY` | Azure Storage Account Key |
| `GCP_SERVICE_ACCOUNT` | GCP Service Account Key |
| `HEROKU_API_KEY` | Heroku API Key |
| `MAILGUN_API_KEY` | Mailgun API Key |
| `SQUARE_ACCESS_TOKEN` | Square Access Token |
| `SQUARE_OAUTH_SECRET` | Square OAuth Secret |
| `CREDIT_CARD` | Cartão de crédito (Luhn) |
| `HIGH_ENTROPY` | Strings de alta entropia |
| `K8S_PRIVILEGED` | Pod Kubernetes privilegiado |

### Pecados veniais (avisos)

| Regra | Descrição |
|-------|-----------|
| `JWT_TOKEN` | JWT Token |
| `HARDCODED_IP` | Endereço IP hardcoded |
| `EVAL_CALL` | Chamada eval() |
| `DOCKER_ROOT` | Dockerfile usuário root |
| `DOCKER_LATEST` | Dockerfile tag :latest |
| `K8S_HOST_NETWORK` | Kubernetes Host Network |
| `K8S_HOST_PID` | Kubernetes Host PID |
| `GENERIC_API_KEY` | Padrão genérico de API Key |
| `GENERIC_SECRET` | Padrão genérico de segredo |

---

## Integração CI/CD

### GitHub Actions

Use a action do Velka (instala via [crates.io](https://crates.io/crates/velka) e executa o scan):

```yaml
- uses: actions/checkout@v4
- uses: wesllen-lima/velka@main
  with:
    path: .
    fail-on-secrets: true
    format: terminal  # ou sarif, json, junit, etc.
```

Ou rode o Velka manualmente e envie SARIF:

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install velka --locked
- run: velka scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
velka-scan:
  script:
    - velka scan . --format junit > velka-report.xml
  artifacts:
    reports:
      junit: velka-report.xml
```

### Hook pre-commit

**Opção 1 – framework pre-commit** (adicione em `.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/wesllen-lima/velka
    rev: v1.2.0
    hooks:
      - id: velka
```

Requer `velka` no PATH (`cargo install velka`). Depois: `pre-commit run velka`.

**Opção 2 – apenas hook Git**:

```bash
velka install-hook
```

---

## Segurança

- **Zero telemetria**: Nenhum dado sai da sua máquina
- **Redação por padrão**: Segredos mascarados na saída (`AKIA****MPLE`)
- **Cache seguro**: Apenas hashes de arquivos, nunca conteúdo de segredos
- **Validação de caminho**: Caminhos de sistema (`/proc`, `/sys`, `/dev`) não são escaneados
- **Erros seguros**: Mensagens de erro não vazam caminhos sensíveis

---

## Performance

- **Varredura paralela**: Walker paralelo da crate `ignore`
- **I/O mapeado em memória**: Arquivos >1MB usam `mmap`
- **Regex compiladas**: Padrões compilados uma vez via `std::sync::LazyLock`
- **Canais lock-free**: `crossbeam-channel` sem contenção
- **Skip inteligente**: Detecção de binário por magic bytes, código minificado ignorado
- **Escrita em lote do cache**: Misses são bufferizados e gravados uma vez por execução

### Benchmarks

Rode `cargo bench` para reproduzir. Benchmarks em `benches/scan_bench.rs`.

**Throughput (cache desabilitado):**

| Arquivos | Nome do benchmark   | Mediana típica |
|----------|---------------------|----------------|
| 100      | `scan_100_files`    | ~2 ms          |
| 1.000    | `scan_1000_files`   | ~4,5 ms        |
| 5.000    | `scan_5000_files`   | ~12 ms         |
| 10.000   | `scan_10000_files`  | ~21 ms         |

**Impacto do cache (1.000 arquivos, cache ligado):**

| Nome do benchmark             | Descrição                          |
|------------------------------|------------------------------------|
| `scan_1000_files_cache_cold` | Primeira execução: scan completo   |
| `scan_1000_files_cache_hit`  | Segunda execução: cache hit        |

Rode só os de cache: `cargo bench scan_1000_files_cache`. Um único: `cargo bench scan_1000_files`.

---

## Extensão VS Code (MVP)

Extensão mínima em `vscode-extension/`. Adiciona o comando **Velka: Scan for secrets**. Requer `velka` no PATH. Veja `vscode-extension/README.md`.

---

## Documentação

- **[Contributing](CONTRIBUTING.md)** – Como contribuir
- **[Changelog](CHANGELOG.md)** – Histórico de versões
- **[Security Policy](SECURITY.md)** – Reportar vulnerabilidades

## Licença

Licenciado sob **MIT OU Apache-2.0**.

Consulte [`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT) e [`LICENSE-APACHE`](LICENSE-APACHE).
