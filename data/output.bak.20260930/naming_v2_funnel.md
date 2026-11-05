# naming_v2 candidate enrichment

Input pairs: 10092

Dependent counts were not supplied; the popularity-gap filter and its score term are inactive in this run.

## Exclusion funnel

| Stage | Excluded | Remaining |
|---|---:|---:|
| Input | - | 10092 |
| Same owner controls both paths | 778 | 9314 |
| Match on candidate subdirectory segment | 3277 | 6037 |
| Match on target subdirectory segment | 308 | 5729 |
| Owner-level match, package name differs | 976 | 4753 |
| Timestamp unavailable for one side | 272 | 4481 |
| Candidate predates its target | 521 | 3960 |

Retained for inspection: **3960** (39.24% of input)

## Per-technique retention

| Technique | Input | Retained | Retention |
|---|---:|---:|---:|
| `substitution` | 4657 | 2314 | 49.7% |
| `owner-insertion` | 1330 | 0 | 0.0% |
| `insertion` | 1129 | 887 | 78.6% |
| `case` | 748 | 0 | 0.0% |
| `owner-substitution` | 728 | 3 | 0.4% |
| `separator` | 623 | 456 | 73.2% |
| `omission` | 473 | 282 | 59.6% |
| `owner-omission` | 166 | 0 | 0.0% |
| `owner-separator` | 128 | 1 | 0.8% |
| `owner-affix` | 85 | 1 | 1.2% |
| `transposition` | 22 | 15 | 68.2% |
| `owner-transposition` | 3 | 1 | 33.3% |

A technique that retains nothing after temporal and ownership filtering is generating string collisions rather than impersonation candidates, and its cost is not repaid.

## Most-flagged targets (retained)

| Target | Input | Retained | Share of retained |
|---|---:|---:|---:|
| `github.com/labstack/gommon` | 424 | 263 | 6.6% |
| `github.com/ipfs/go-log` | 167 | 166 | 4.2% |
| `github.com/go-stack/stack` | 176 | 163 | 4.1% |
| `github.com/blang/semver` | 490 | 118 | 3.0% |
| `github.com/masterminds/semver` | 478 | 118 | 3.0% |
| `github.com/masterminds/semver/v3` | 478 | 105 | 2.7% |
| `github.com/kisielk/gotool` | 99 | 95 | 2.4% |
| `github.com/subosito/gotenv` | 85 | 82 | 2.1% |
| `github.com/tidwall/gjson` | 71 | 68 | 1.7% |
| `github.com/go-toolsmith/typep` | 133 | 64 | 1.6% |
| `github.com/hashicorp/go-plugin` | 59 | 59 | 1.5% |
| `github.com/gocql/gocql` | 67 | 58 | 1.5% |
| `github.com/hashicorp/go-uuid` | 58 | 57 | 1.4% |
| `github.com/matoous/godox` | 64 | 56 | 1.4% |
| `github.com/ipfs/go-log/v2` | 167 | 52 | 1.3% |

A single target accounting for a large share of the retained set indicates a generic owner or package string rather than a cluster of genuine impersonation attempts.
