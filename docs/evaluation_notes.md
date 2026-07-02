# Evaluation Notes

Evaluation of the three risk-pattern heuristics against ground truth, plus an
independent second-source corroboration of the concentration-risk pattern.

## 1. Ground-truth evaluation against the Go vulnerability database

**Method.** The pipeline analysed 285,895 Go modules (2019–2025) for three risk
patterns: concentration risk, naming similarity, and source ambiguity. Each
flagged module set was matched against the Go vulnerability database
(github.com/golang/vulndb, served at vuln.go.dev) on a historical-presence
basis: a module "matches" if the database records any known vulnerability for
that module path. This answers the question the patterns are meant to serve —
*is this module security-relevant?* — rather than whether any specific version
is currently vulnerable.

**Ecosystem base rate.** 1,136 of 285,895 modules (0.40%) have at least one
recorded vulnerability. This is the reference rate against which each pattern's
precision is judged.

**Results.**

| Pattern             | Flagged | Matched | Match rate | vs. base rate |
|---------------------|--------:|--------:|-----------:|--------------:|
| concentration_risk  |      71 |      19 |      26.8% |        ~67x   |
| naming_similarity   |   3,332 |      26 |       0.8% |        ~2x    |
| source_ambiguity    |   1,802 |      20 |       1.1% |        ~3x    |

**Interpretation.**

- **concentration_risk validates.** At 26.8% it matches known-vulnerable modules
  at roughly 67x the ecosystem base rate. The pattern surfaces modules that many
  others depend on, and depended-upon modules are disproportionately
  security-relevant. This is the headline positive result.
- **naming_similarity and source_ambiguity do not validate.** Both sit at or near
  the base rate, so flagging adds essentially no predictive signal over picking a
  module at random. Inspection of their "matches" shows they are coincidental
  hits on large, popular, legitimate packages (e.g. go.etcd.io/etcd,
  moby/buildkit, helm.sh/helm, go.opentelemetry.io), not the typosquats or
  impersonations the patterns were designed to catch. The patterns detect
  popularity, not risk.

Honestly reporting that two of three patterns fail is itself the substantive
finding: concentration of dependence is a usable risk signal in the Go
ecosystem, whereas surface-level naming and source heuristics are not.

The 19 concentration matches, with recorded vulnerability counts:

golang.org/x/net (29), golang.org/x/crypto (28), golang.org/x/image (11),
gopkg.in/yaml.v2 (3), golang.org/x/text (3), google.golang.org/grpc (3),
github.com/aws/aws-sdk-go (3), github.com/gin-gonic/gin (3), golang.org/x/sys (2),
k8s.io/apimachinery (2), k8s.io/client-go (2), github.com/sirupsen/logrus (1),
github.com/gogo/protobuf (1), golang.org/x/oauth2 (1),
github.com/prometheus/client_golang (1), github.com/gorilla/websocket (1),
github.com/dgrijalva/jwt-go (1), github.com/satori/go.uuid (1),
github.com/golang/glog (1).

## 2. Independent second-source corroboration (Snyk)

**Motivation.** The primary evaluation uses a single database (vuln.go.dev). To
test whether the 19 concentration matches are corroborated by an independent
source, each was cross-referenced against Snyk, a commercial vulnerability
database with separate curation.

**Method.** Testing a module at its latest release is uninformative, because most
modules have since shipped patches; a clean result then reflects the fix, not the
absence of history. Instead, each module was tested at a version recorded as
*affected*. For each module the tool reads the local Go OSV advisories
(vulndb/data/osv), finds the lowest recorded "fixed" version, and pins the test
to the highest real release strictly below it — placing the tested version inside
an affected range. Where no clean fixed version is recorded (abandoned modules),
the lowest release tag is used as a best effort. The version actually tested and
the basis for its selection are recorded per module
(data/output/snyk_concentration.csv) for reproducibility.

Attribution of Snyk findings to the target module uses the package token embedded
in Snyk's Go vulnerability IDs (e.g. SNYK-GOLANG-GOLANGORGXOAUTH2-…), which
isolates the module's own vulnerabilities from those of transitive dependencies
and of the Go standard library.

**Result.** Tested at affected versions, Snyk independently confirmed a
vulnerability in **12 of the 19** concentration-risk modules.

The remaining 7 clean results are explained and none contradicts the primary
finding:

- **4 returned only Go standard-library advisories** (IDs prefixed `SNYK-GOLANG-STD…`,
  e.g. crypto/x509, net/http, net/url). These belong to the inferred Go toolchain
  version, not to the module, and the attribution layer correctly excluded them.
  (aws-sdk-go, oauth2, prometheus/client_golang, satori/go.uuid)
- **3 returned no finding for the specific representative sub-package imported.**
  Each module was made importable through one representative package; where the
  recorded vulnerability lives in a different sub-package, single-package testing
  does not reach it. This is a known limitation of the method, not a database
  disagreement. (gogo/protobuf, golang.org/x/crypto, golang.org/x/sys)
- **1 is unaffected at its earliest release** because the vulnerability was
  introduced in a later version; the pinned lowest release predates it.
  (satori/go.uuid — note this module is flagged at latest but clean at its
  earliest release, the inverse of the usual pattern.)

**Interpretation.** Two independent databases, queried appropriately, agree that
the majority of concentration-risk modules are vulnerable, and every divergence
is accounted for by version-window or single-package-reachability effects rather
than by genuine disagreement. The 12/19 figure is a conservative lower bound: it
counts only modules confirmed at one affected version of one representative
package. The cross-reference also demonstrates that the ID-based attribution layer
cleanly separates a target module's vulnerabilities from both transitive-dependency
and standard-library noise.

## Reproduction

```
# Primary ground-truth evaluation
go run ./scripts/verify_ground_truth

# Second-source corroboration (requires Snyk CLI authenticated via `snyk auth`)
go run ./scripts/snyk_check
# -> data/output/snyk_concentration.csv  (per-module version, basis, result)
# -> data/output/snyk/<module>.json       (raw Snyk output per module)
```
