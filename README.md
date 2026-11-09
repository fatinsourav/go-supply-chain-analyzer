# Go Supply Chain Risk Analyzer

Metadata-based detection and evaluation of software supply-chain risk patterns in the Go module ecosystem.

This repository contains the code and data for the Master's thesis
**"Measuring Software Supply Chain Risk Patterns in the Go Ecosystem: A Metadata-Driven Quantitative Analysis of Open-Source Dependencies"**
(MSc Information Security, Department of Computer and Systems Sciences, Stockholm University, Autumn 2026).

- **Author:** Md Fatin Sirat
- **Supervisor:** Nicolas Harrand

## Research questions

- **RQ1.** To what extent can a package-metadata approach identify software supply-chain risk in the Go module ecosystem?
- **RQ2.** Which metadata patterns correspond to independently documented vulnerabilities and attacks, and which reflect only package popularity?
- **RQ3.** What is the security significance of the modules flagged by these metadata patterns?

## Approach

1. **Collection.** Module records are collected from the Go module index (`index.golang.org`) for 2019–2025, querying each year chronologically from 1 January until 50,000 unique modules are recorded. The combined corpus holds 285,895 records (265,479 distinct module paths). No module source code is downloaded or executed.
2. **Detection.** Five metadata patterns are applied to the corpus (table below).
3. **Authoritative verification.** Facts inferred from the crawled corpus are confirmed against the Go module proxy (`proxy.golang.org`): latest release dates for abandonment, and the tagged-version list for pseudo-version dependence.
4. **Evaluation.**
   - *Context:* each pattern's match rate against the Go vulnerability database, compared with the ecosystem base rate (1,136 of 285,895 records, 0.40%).
   - *Risk-signal evaluation:* each pattern is tested against a risk outcome that scrutiny alone does not produce, in a comparison with unflagged modules from the same population. Supply-chain risk is defined as the exposure of a dependent to code it cannot trust or cannot get fixed, with **likelihood** and **impact** as its components.

## Patterns

| Pattern | What it flags | Key parameters | Script / component |
|---|---|---|---|
| Dependency concentration | Modules with many dependents in the corpus dependency graph (impact) | ≥ 3 dependents; > 6 = highest severity | `cmd/main.go` (`internal/detectors/concentration_risk.go`) |
| Abandonment | Widely used modules without a recent release; score = dependents × years since last release | ≥ 5 dependents, ≥ 2 years since release (reference date 30 Sep 2026); release dates from the proxy | `scripts/abandonment_v2` |
| Pseudo-version-only dependence | Widely used modules that have never published a tagged release | ≥ 5 dependents; confirmed against the proxy's `@v/list` | `scripts/pseudoversion_v1` |
| Source ambiguity | Source domains showing impersonation signals (lookalike host, embedded brand, subdomain spoof, IP-literal or punycode host), probed for their `go-import` document | — | `scripts/source_ambiguity_v2` |
| Naming similarity | Modules one structured edit (substitution, omission, insertion, transposition, separator, case, affix) from one of the 1,000 most depended-upon modules, on the package name or the owner | target segment ≥ 5 characters; candidate must not itself be a target | `scripts/naming_v2`, post-processed by `scripts/naming_v2_enrich` |

## Results

### Detection

| Pattern | Flagged |
|---|---|
| Concentration | 3,383 modules |
| Abandonment | 1,745 modules |
| Pseudo-version-only | 518 modules (the proxy found tagged releases for 1,031 of 1,549 corpus candidates) |
| Source ambiguity | 12 domains, 54 modules |
| Naming similarity | 10,092 candidate pairs; 3,977 rows (3,960 distinct pairs) after removing structurally implausible pairs |

### Risk-signal evaluation

| Pattern | Risk outcome | Flagged | Comparison | p (Fisher) | Verdict |
|---|---|---|---|---|---|
| Abandonment | Advisory with no fixed version¹ | 40.2% (33/82) | 12.8% (28/218) | < 10⁻⁶ | Detects risk |
| Pseudo-version | Advisory with no fixed version¹ | 33.3% (4/12) | 19.8% (57/288) | 0.27 | Not shown |
| Source ambiguity | Domain registrable by anyone | 8.3% (1/12) | 5.0% (5/100)² | 0.50 | Not detected |
| Naming (random sample) | Confirmed impersonation | 0/48 | — | — | Not detected |
| Naming (owner-level census) | Confirmed impersonation | 1/6 | — | — | One case³ |
| Concentration | Advisory with no fixed version¹ | 20.5% (60/292) | 40.2% (561/1,396)⁴ | 7 × 10⁻¹¹ | Impact, not likelihood |

¹ Among modules with at least one advisory; advisories published after 30 Sep 2026 or withdrawn are ignored, and those published in the preceding 90 days are excluded.
² Random sample (seed 42) of 100 registrable domains drawn from unflagged vanity domains.
³ `github.com/siruspen/logrus`, an owner-level typosquat of `github.com/sirupsen/logrus` whose cached code adds an `init()` that runs on import. It had already been reported to the Go project in March 2025 ([golang/go#72116](https://github.com/golang/go/issues/72116), golang/vulndb#3502).
⁴ Compared against the rest of the corpus.

## Repository structure

    cmd/main.go                  Core pipeline: collection input, preprocessing, concentration (and legacy) detectors, export
    internal/                    Collector, go.mod fetcher, preprocessing, detectors, SQLite storage, exporters
    scripts/
      collect*/                  Year-wise corpus collectors
      abandonment_v2/            Abandonment pattern with proxy release dates
      abandonment_sample/        Stratified sample of abandonment findings, enriched with repository metadata
      abandonment_classify/      Rule-based classification of the abandonment sample
      pseudoversion_v1/          Pseudo-version-only pattern with proxy tag verification
      source_ambiguity_v2/       Source-ambiguity pattern with go-import probe
      naming_v2/                 Naming-similarity candidate generation
      naming_v2_enrich/          Exclusion of structurally implausible pairs, first-seen timestamps, ranking
      verify_ground_truth/       Matching of flagged modules against the Go vulnerability database
      remediation/               Risk-signal evaluation: fixed vs unfixed advisories per group
    data/output/                 Results used in the thesis (see below)
    data/vulndb_dates/           First-added date of each advisory in golang/vulndb (see below)
    docker/, docker-compose.yml  Container build

`internal/detectors/update_behavior.go` is a legacy detector that is not part of the thesis evaluation.

## Data used in the thesis

| File | Contents |
|---|---|
| `data/output/concentration_ground_truth.csv` | Flagged modules with their advisory matches (all patterns from the core pipeline) |
| `data/output/abandonment_rerun.csv`, `abandonment_gt_rerun.csv` | Abandonment findings (1,745) and their advisory matches |
| `data/output/pseudoversion_rerun.csv`, `pseudoversion_gt_rerun.csv` | Pseudo-version-only findings (518) and their advisory matches |
| `data/output/source_ambiguity_v2_candidates.csv` | Flagged source domains with probe results |
| `data/output/vanity_sample_domains.txt`, `vanity_whois_sample.txt` | Random sample of unflagged vanity domains and their `whois` output |
| `data/output.bak.20260930/` | Naming candidates and enrichment, popular targets, `modules.csv`, abandonment sample and classification |

The raw index dumps (`data/dataset*.txt`) are not committed because of their size; they can be regenerated with the collectors.

## Reproducing the analysis

Requirements: Go 1.22+, Git, network access to `index.golang.org` and `proxy.golang.org`.

    git clone https://github.com/fatinsourav/go-supply-chain-analyzer.git
    cd go-supply-chain-analyzer
    cp configs/config.env.example configs/config.env

**1. Collect the corpus and run the core pipeline.** For the thesis run, set `GOMOD_FETCH_LIMIT=0` (full dependency graph) and `CONCENTRATION_THRESHOLD=3` in `configs/config.env`.

    go run ./scripts/collect_all_years
    go run ./cmd

**2. Run the pattern scripts.** Each script lists its flags with `-h`.

    go run ./scripts/abandonment_v2 -h
    go run ./scripts/pseudoversion_v1 -h
    go run ./scripts/source_ambiguity_v2 -h
    go run ./scripts/naming_v2 -h
    go run ./scripts/naming_v2_enrich -h

**3. Match against the Go vulnerability database.**

    git clone https://github.com/golang/vulndb.git
    go run ./scripts/verify_ground_truth -patterns data/output/risk_patterns.csv -osv-dir vulndb/data/osv

**4. Risk-signal evaluation.** The `published` field in the vulndb repository is a placeholder, so each advisory is dated by the commit that first added it:

    cd vulndb && git log --diff-filter=A --format='C %cs' --name-only -- data/osv | python3 -c "
    import sys
    d={};cur=None
    for l in sys.stdin:
        l=l.strip()
        if l.startswith('C '): cur=l[2:]
        elif l.endswith('.json'):
            i=l.split('/')[-1][:-5]; d[i]=min(d.get(i,cur),cur)
    print('id,added')
    for k in sorted(d): print(f'{k},{d[k]}')
    " > ../data/vulndb_dates/osv_added.csv && cd ..

    go run ./scripts/remediation \
      -parent data/output/concentration_ground_truth.csv \
      -abandoned data/output/abandonment_rerun.csv \
      -pseudo data/output/pseudoversion_rerun.csv \
      -corpus data/output.bak.20260930/modules.csv \
      -osv-dir vulndb/data/osv -dates data/vulndb_dates/osv_added.csv \
      -asof 2026-09-30 -grace 90 -out data/output/remediation

Add `-exact` for exact module-path matching; vary `-grace` (0, 90, 365) for the robustness checks.

## Responsible disclosure

The analysis only reads public metadata; requests to source domains were limited to those the Go toolchain itself would make. The one impersonating module identified (`github.com/siruspen/logrus`) had already been reported to the Go project; further details were added to [golang/go#72116](https://github.com/golang/go/issues/72116).

## Key references

- Cesarano et al. (2024). GoSurf: Identifying Software Supply Chain Attack Vectors in Go. SCORED '24.
- Taylor et al. (2020). Defending Against Package Typosquatting. NSS 2020.
- Zimmermann et al. (2019). Small World with High Risks: A Study of Security Threats in the npm Ecosystem. USENIX Security.
- Decan, Mens & Constantinou (2018). On the Impact of Security Vulnerabilities in the npm Package Dependency Network. MSR.
- Duan et al. (2021). Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages. NDSS.
- Zahan et al. (2022). What Are Weak Links in the npm Supply Chain? ICSE-SEIP.

The full reference list is in the thesis.

## License

MIT License.

## Disclaimer

This tool was developed for academic research. It analyses publicly available metadata from the Go module index and module proxy; it does not exploit vulnerabilities or execute module code. Its findings are intended to support research and raise awareness of supply-chain risk, and must not be used to target or harm any individual, organisation or project.
