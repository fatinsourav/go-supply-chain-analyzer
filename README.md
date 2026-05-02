# Go Supply Chain Risk Analyzer

A metadata-driven tool for measuring software supply chain risk patterns in the Go ecosystem.
Built as part of a Master's thesis in Information Security at Stockholm University (Spring 2026).

## Research Context

**Thesis:** Measuring Software Supply Chain Risk Patterns in the Go Ecosystem
**Author:** Md Fatin Sirat
**Supervisor:** Nicolas Harrand
**Institution:** Stockholm University, Department of Computer and Systems Sciences

### Research Questions

- **RQ1:** What types of software supply chain risk patterns exist in the Go ecosystem?
- **RQ2:** How prevalent are these risk patterns based on metadata analysis?

## Overview

This tool analyzes Go modules collected from the Go Module Index and detects four categories
of supply chain risk patterns using metadata-based analysis. The approach is designed to be
scalable and reproducible without requiring source code execution.

The dataset spans 7 years (2019-2025) with 285,895 unique modules collected from the
Go Module Index, enabling longitudinal analysis of how risk patterns evolve over time.

## Risk Patterns

| Pattern | Description | Grounded In |
|---------|-------------|-------------|
| Naming Similarity | Detects typosquatting via owner-level permutations using pkgtwist approach | Taylor et al. (2020), Vu et al. (2020) |
| Dependency Source Ambiguity | Flags modules from untrusted or suspicious domains | Cappos et al. (2008) |
| Suspicious Update Behavior | Identifies abnormal release frequency and burst updates | Garrett et al. (2019) |
| Dependency Concentration Risk | Finds modules depended upon by many others via go.mod graph | Zimmermann et al. (2019), Decan et al. (2018) |

## Key Findings

### Year-over-Year Comparison (50,000 modules per year)

| Pattern | 2019 | 2024 | Change |
|---------|------|------|--------|
| Naming Similarity | 415 | 253 | -39% |
| Source Ambiguity | 430 | 555 | +29% |
| Suspicious Update Behavior | 0 | 0 | - |
| Concentration Risk | 21 | 651 | +3,000% |
| **Total** | **866** | **1,459** | **+68%** |

### Notable Concentration Risk Findings (2019)

| Module | Dependents | Severity |
|--------|-----------|----------|
| github.com/stretchr/testify | 236 | HIGH |
| golang.org/x/net | 187 | HIGH |
| golang.org/x/sys | 169 | HIGH |
| github.com/pkg/errors | 154 | HIGH |
| github.com/golang/protobuf | 97 | MEDIUM |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.22 |
| Data Source | Go Module Index + Go Proxy API |
| Storage | SQLite |
| Output | CSV + JSON |
| Container | Docker |

## Project Structure

    go-supply-chain-analyzer/
    cmd/
        main.go                         Entry point and pipeline orchestration
    internal/
        collector/
            collector.go                Go Module Index fetcher
            gomod_fetcher.go            go.mod fetcher for dependency graph
        pipeline/
            preprocessor.go             Deduplication and normalization
        detectors/
            naming_similarity.go        Pattern 1 - Naming Similarity
            source_ambiguity.go         Pattern 2 - Source Ambiguity
            update_behavior.go          Pattern 3 - Suspicious Update Behavior
            concentration_risk.go       Pattern 4 - Concentration Risk
        storage/
            storage.go                  SQLite layer with batch insert support
            models.go                   Data models
        exporter/
            exporter.go                 CSV and JSON export
    scripts/
        collect/main.go                 Basic collector
        collect_full/main.go            Full 2019 collector
        collect_2024/main.go            2024 dataset collector
        collect_2025/main.go            2025 dataset collector
        collect_all_years/main.go       Multi-year collector with auto-combine
    configs/
        config.env.example              Configuration template
    data/
        dataset_full.txt                2019 dataset (gitignored)
        dataset_2020.txt                2020 dataset (gitignored)
        dataset_2021.txt                2021 dataset (gitignored)
        dataset_2022.txt                2022 dataset (gitignored)
        dataset_2023.txt                2023 dataset (gitignored)
        dataset_2024.txt                2024 dataset (gitignored)
        dataset_2025.txt                2025 dataset (gitignored)
        dataset_combined.txt            Combined 2019-2025 (gitignored)
        output/                         Analysis results (gitignored)
    docker/
        Dockerfile                      Multi-stage Docker build
    docker-compose.yml
    go.mod
    go.sum
    README.md

## Prerequisites

- Go 1.22+ (for running without Docker)
- Docker and Docker Compose (for containerized run)
- Git

## Installation

    git clone git@github.com:fatinsourav/go-supply-chain-analyzer.git
    cd go-supply-chain-analyzer
    go mod download

## Configuration

Copy the example config and adjust as needed:

    cp configs/config.env.example configs/config.env

Key configuration options:

    DATASET_PATH=./data/dataset_combined.txt
    PROXY_URL=https://proxy.golang.org
    LEVENSHTEIN_THRESHOLD=2
    UPDATE_FREQUENCY_THRESHOLD=3
    CONCENTRATION_THRESHOLD=3
    GOMOD_FETCH_LIMIT=5000
    DB_PATH=./data/output/analyzer.db
    CSV_OUTPUT_PATH=./data/output

## Dataset Collection

### Collect a single year

    go run scripts/collect_2024/main.go

### Collect all years (2020-2023) and combine

    go run scripts/collect_all_years/main.go

This will collect 50,000 unique modules per year for 2020-2023,
then combine with existing 2019, 2024, and 2025 datasets into
dataset_combined.txt.

### Dataset Summary

| Year | File | Modules | Period |
|------|------|---------|--------|
| 2019 | dataset_full.txt | 50,000 | Apr-Oct 2019 |
| 2020 | dataset_2020.txt | 50,000 | Jan 2020 |
| 2021 | dataset_2021.txt | 50,000 | Jan-Feb 2021 |
| 2022 | dataset_2022.txt | 50,000 | Jan 2022 |
| 2023 | dataset_2023.txt | 50,000 | Jan 2023 |
| 2024 | dataset_2024.txt | 50,000 | Jan 2024 |
| 2025 | dataset_2025.txt | 50,000 | Jan 2025 |
| **Combined** | **dataset_combined.txt** | **285,895** | **2019-2025** |

Note: Combined total is less than 350,000 because popular modules
appear across multiple years and are deduplicated.

## Usage

### Run with Go directly

    go run cmd/main.go

### Run a specific year

    DATASET_PATH=./data/dataset_2024.txt \
    DB_PATH=./data/output/2024/analyzer_2024.db \
    CSV_OUTPUT_PATH=./data/output/2024 \
    go run cmd/main.go

### Run with Docker

    docker compose up

### Run with Docker for a specific year

    docker run -v $(pwd)/data:/app/data \
      -e DATASET_PATH=/app/data/dataset_2024.txt \
      -e DB_PATH=/app/data/output/2024/analyzer_2024.db \
      go-supply-chain-analyzer

## Output

Results are written to data/output/:

| File | Description |
|------|-------------|
| modules.csv | All analyzed modules with metadata |
| risk_patterns.csv | All detected risk patterns with severity |
| summary.json | Aggregated counts by pattern type and severity |

### Example summary.json

    {
      "generated_at": "2026-05-02T23:45:29+02:00",
      "total_modules": 50000,
      "total_risks": 866,
      "by_pattern": {
        "concentration_risk": 21,
        "naming_similarity": 415,
        "source_ambiguity": 430
      },
      "by_severity": {
        "high": 22,
        "medium": 844
      }
    }

## Analysis Pipeline

    Go Module Index
          |
          v
    Year-wise Data Collection (50,000 modules per year)
          |
          v
    Cross-year Deduplication and Combination
          |
          v
    Preprocessing (normalization)
          |
          v
    Pattern Detection
    |           |           |           |
    Pattern 1   Pattern 2   Pattern 3   Pattern 4
    Naming      Source      Update      Concentration
    Similarity  Ambiguity   Behavior    Risk
          |
          v
    Aggregation + Export (SQLite / CSV / JSON)

## References

- Taylor et al. (2020) SpellBound: Defending Against Package Typosquatting
- Vu et al. (2020) Typosquatting and Combosquatting Attacks on the Python Ecosystem
- Cappos et al. (2008) A Look in the Mirror: Attacks on Package Managers
- Zimmermann et al. (2019) Small World with High Risks
- Decan et al. (2018) On the Impact of Security Vulnerabilities in the npm Dependency Network
- Garrett et al. (2019) Detecting Suspicious Package Updates
- Duan et al. (2021) Measuring and Preventing Supply Chain Attacks on Package Managers
- Henriksen (2021) Finding Evil Go Packages

## License

MIT License
