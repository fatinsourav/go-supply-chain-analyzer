# Go Supply Chain Risk Analyzer

A metadata-driven tool for measuring software supply chain risk patterns in the Go ecosystem.
Built as part of a Master's thesis in Information Security at Stockholm University (Spring 2026).

## Overview

This tool analyzes Go modules collected from the Go Module Index and detects four categories
of supply chain risk patterns using metadata-based analysis. The approach is designed to be
scalable and reproducible without requiring source code execution.

## Research Context

**Thesis:** Measuring Software Supply Chain Risk Patterns in the Go Ecosystem
**Author:** Md Fatin Sirat
**Supervisor:** Nicolas Harrand
**Institution:** Stockholm University, Department of Computer and Systems Sciences

### Research Questions

- **RQ1:** What types of software supply chain risk patterns exist in the Go ecosystem?
- **RQ2:** How prevalent are these risk patterns based on metadata analysis?

## Risk Patterns

| Pattern | Description | Grounded In |
|---------|-------------|-------------|
| Naming Similarity | Detects typosquatting via owner-level permutations | Taylor et al. (2020), Vu et al. (2020) |
| Dependency Source Ambiguity | Flags modules from untrusted or suspicious domains | Cappos et al. (2008) |
| Suspicious Update Behavior | Identifies abnormal release frequency and burst updates | Garrett et al. (2019) |
| Dependency Concentration Risk | Finds modules depended upon by many others | Zimmermann et al. (2019), Decan et al. (2018) |

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
        main.go                     Entry point and pipeline orchestration
    internal/
        collector/
            collector.go            Go Module Index fetcher
            gomod_fetcher.go        go.mod fetcher for dependency graph
        pipeline/
            preprocessor.go         Deduplication and normalization
        detectors/
            naming_similarity.go    Pattern 1 - Naming Similarity
            source_ambiguity.go     Pattern 2 - Source Ambiguity
            update_behavior.go      Pattern 3 - Suspicious Update Behavior
            concentration_risk.go   Pattern 4 - Concentration Risk
        storage/
            storage.go              SQLite layer
            models.go               Data models
        exporter/
            exporter.go             CSV and JSON export
    configs/
        config.env.example          Configuration template
    data/
        output/                     Generated results (gitignored)
    docker/
    docker-compose.yml
    go.mod
    go.sum
    README.md

## Prerequisites

- Go 1.22+
- Docker (optional)
- Git

## Installation

    git clone git@github.com:fatinsourav/go-supply-chain-analyzer.git
    cd go-supply-chain-analyzer
    go mod download

## Configuration

Copy the example config and adjust as needed:

    cp configs/config.env.example configs/config.env

Key configuration options:

    DATASET_PATH=./data/dataset.txt
    PROXY_URL=https://proxy.golang.org
    LEVENSHTEIN_THRESHOLD=2
    UPDATE_FREQUENCY_THRESHOLD=3
    CONCENTRATION_THRESHOLD=3
    DB_PATH=./data/output/analyzer.db
    CSV_OUTPUT_PATH=./data/output

## Usage

### Run with Go directly

Place your dataset at data/dataset.txt in Go Module Index JSON lines format:

    {"Path":"github.com/example/repo","Version":"v1.0.0","Timestamp":"2019-04-10T19:08:52Z"}

Then run:

    go run cmd/main.go

### Run with Docker

    docker compose up

## Output

Results are written to data/output/:

| File | Description |
|------|-------------|
| modules.csv | All analyzed modules with metadata |
| risk_patterns.csv | All detected risk patterns with severity |
| summary.json | Aggregated counts by pattern type and severity |

## Analysis Pipeline

    Go Module Index Dataset
            |
            v
    Preprocessing (deduplication + normalization)
            |
            v
    Pattern Detection
    |           |           |           |
    Pattern 1   Pattern 2   Pattern 3   Pattern 4
    Naming      Source      Update      Concentration
    Similarity  Ambiguity   Behavior    Risk
            |
            v
    Aggregation + Export (CSV / JSON)

## Dataset

The dataset used in this study was collected from the Go Module Index and covers
Go modules published between April 10-18, 2019. It contains 2,000 entries
representing 863 unique modules.

The dataset is not included in this repository. To collect your own:

    curl "https://index.golang.org/index?since=2019-04-10T00:00:00Z" > data/dataset.txt

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
