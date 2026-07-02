// Command snyk_check corroborates the concentration-risk modules that matched
// the Go vulnerability database (vuln.go.dev) against a SECOND, independent
// vendor database (Snyk).
//
// To make the cross-reference meaningful, each module is tested at a version
// known to be affected: the tool reads the local Go OSV advisories
// (vulndb/data/osv), finds the lowest "fixed" version recorded for the module,
// and pins the test to the highest real release strictly below it (so the
// pinned version sits inside an affected range). If no clean fixed version is
// recorded, it pins the module's lowest release tag as a best effort. The
// version actually tested is reported, for honesty and reproducibility.
//
// Prerequisites:
//   - Go toolchain on PATH
//   - Snyk CLI installed and authenticated (`snyk auth`)
//   - network access (queries proxy.golang.org for the version list)
//   - vulndb checked out at ./vulndb (OSV files under vulndb/data/osv)
//
// Usage (from repo root):
//   go run ./scripts/snyk_check
//
// Output:
//   data/output/snyk/<module>.json       raw Snyk output per module
//   data/output/snyk_concentration.csv    summary table
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type target struct {
	module string
	imp    string
}

var targets = []target{
	{"golang.org/x/net", "golang.org/x/net/html"},
	{"golang.org/x/crypto", "golang.org/x/crypto/bcrypt"},
	{"golang.org/x/image", "golang.org/x/image/bmp"},
	{"gopkg.in/yaml.v2", "gopkg.in/yaml.v2"},
	{"golang.org/x/text", "golang.org/x/text/language"},
	{"google.golang.org/grpc", "google.golang.org/grpc"},
	{"github.com/aws/aws-sdk-go", "github.com/aws/aws-sdk-go/aws"},
	{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
	{"golang.org/x/sys", "golang.org/x/sys/cpu"},
	{"k8s.io/apimachinery", "k8s.io/apimachinery/pkg/runtime"},
	{"k8s.io/client-go", "k8s.io/client-go/rest"},
	{"github.com/sirupsen/logrus", "github.com/sirupsen/logrus"},
	{"github.com/gogo/protobuf", "github.com/gogo/protobuf/proto"},
	{"golang.org/x/oauth2", "golang.org/x/oauth2"},
	{"github.com/prometheus/client_golang", "github.com/prometheus/client_golang/prometheus"},
	{"github.com/gorilla/websocket", "github.com/gorilla/websocket"},
	{"github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go"},
	{"github.com/satori/go.uuid", "github.com/satori/go.uuid"},
	{"github.com/golang/glog", "github.com/golang/glog"},
}

const osvDir = "vulndb/data/osv"

type snykVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type snykResult struct {
	Vulnerabilities []snykVuln `json:"vulnerabilities"`
	Ok              bool       `json:"ok"`
	Error           string     `json:"error"`
}

// OSV (subset) for reading affected ranges.
type osvDoc struct {
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type row struct {
	module    string
	tested    string
	basis     string
	flagged   bool
	vulnCount int
	sevs      string
	note      string
}

var cleanSemver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// parseSemver returns (major, minor, patch, ok) for a clean vX.Y.Z (no
// prerelease, no pseudo, no +incompatible). Non-clean versions are rejected so
// version selection stays on real, comparable release tags.
func parseSemver(s string) (int, int, int, bool) {
	m := cleanSemver.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, 0, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return a, b, c, true
}

func less(a1, a2, a3, b1, b2, b3 int) bool {
	if a1 != b1 {
		return a1 < b1
	}
	if a2 != b2 {
		return a2 < b2
	}
	return a3 < b3
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "_", ".", "_", "@", "_").Replace(s)
}

func snykIDKey(modulePath string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(modulePath) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func idSegment(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func vulnHitsTarget(v snykVuln, module string) bool {
	key := snykIDKey(module)
	if key == "" {
		return false
	}
	seg := idSegment(v.ID)
	if seg == "" {
		return false
	}
	return strings.HasPrefix(seg, key)
}

// lowestFixed scans the OSV directory and returns the lowest clean "fixed"
// version recorded for the module (or a subpackage of it), as (maj,min,patch).
func lowestFixed(module string) (int, int, int, bool) {
	entries, err := os.ReadDir(osvDir)
	if err != nil {
		return 0, 0, 0, false
	}
	have := false
	var fa, fb, fc int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(osvDir, e.Name()))
		if err != nil {
			continue
		}
		var doc osvDoc
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		for _, aff := range doc.Affected {
			name := aff.Package.Name
			if name != module && !strings.HasPrefix(name, module+"/") {
				continue
			}
			for _, rng := range aff.Ranges {
				for _, ev := range rng.Events {
					fx, ok := ev["fixed"]
					if !ok {
						continue
					}
					a, bb, c, ok := parseSemver(fx)
					if !ok {
						continue
					}
					if !have || less(a, bb, c, fa, fb, fc) {
						fa, fb, fc, have = a, bb, c, true
					}
				}
			}
		}
	}
	return fa, fb, fc, have
}

// proxyVersions fetches the clean release tags for a module from the Go proxy.
func proxyVersions(module string) []string {
	url := "https://proxy.golang.org/" + module + "/@v/list"
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, _, _, ok := parseSemver(line); ok {
			out = append(out, line)
		}
	}
	return out
}

// pickVersion chooses a known-affected version to test.
func pickVersion(module string) (version, basis string) {
	vers := proxyVersions(module)
	if len(vers) == 0 {
		return "", "latest (no clean release tags found)"
	}
	// Sort clean tags ascending.
	sort.Slice(vers, func(i, j int) bool {
		a1, a2, a3, _ := parseSemver(vers[i])
		b1, b2, b3, _ := parseSemver(vers[j])
		return less(a1, a2, a3, b1, b2, b3)
	})

	if fa, fb, fc, ok := lowestFixed(module); ok {
		// Highest clean tag strictly below the earliest fixed version.
		best := ""
		for _, v := range vers {
			a, b, c, _ := parseSemver(v)
			if less(a, b, c, fa, fb, fc) {
				best = v
			}
		}
		if best != "" {
			return best, fmt.Sprintf("below earliest fix v%d.%d.%d", fa, fb, fc)
		}
		// All releases are >= earliest fix: nothing provably affected.
		return vers[0], "lowest release (all tags >= earliest fix)"
	}
	// No clean fixed version recorded: best-effort lowest release.
	return vers[0], "lowest release (no clean fixed version in OSV)"
}

func parseSnyk(b []byte) ([]snykVuln, error) {
	var one snykResult
	if err := json.Unmarshal(b, &one); err == nil && (one.Vulnerabilities != nil || one.Ok || one.Error == "") {
		return one.Vulnerabilities, nil
	}
	var many []snykResult
	if err := json.Unmarshal(b, &many); err == nil {
		var all []snykVuln
		for _, r := range many {
			all = append(all, r.Vulnerabilities...)
		}
		return all, nil
	}
	return nil, fmt.Errorf("could not parse snyk JSON")
}

func actualVersion(dir, module string) string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}", module)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(out))
}

func runOne(t target, rawDir string) row {
	version, basis := pickVersion(t.module)

	dir, err := os.MkdirTemp("", "snykcheck-")
	if err != nil {
		return row{module: t.module, note: "mktemp failed: " + err.Error()}
	}
	defer os.RemoveAll(dir)

	gomod := "module snykcheck\n\ngo 1.21\n"
	if version != "" {
		gomod += fmt.Sprintf("\nrequire %s %s\n", t.module, version)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		return row{module: t.module, note: "write go.mod failed: " + err.Error()}
	}
	deps := fmt.Sprintf("package snykcheck\n\nimport _ %q\n", t.imp)
	if err := os.WriteFile(filepath.Join(dir, "deps.go"), []byte(deps), 0o644); err != nil {
		return row{module: t.module, note: "write deps.go failed: " + err.Error()}
	}

	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := tidy.CombinedOutput(); err != nil {
		return row{module: t.module, tested: version, basis: basis,
			note: "go mod tidy failed: " + strings.TrimSpace(string(out))}
	}

	actual := actualVersion(dir, t.module)

	cmd := exec.Command("snyk", "test", "--json")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, _ := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(rawDir, sanitize(t.module)+".json"), out, 0o644)

	vulns, err := parseSnyk(out)
	if err != nil {
		return row{module: t.module, tested: actual, basis: basis,
			note: "parse failed (saved raw json): " + err.Error()}
	}

	seen := map[string]bool{}
	sevSet := map[string]bool{}
	for _, v := range vulns {
		if !vulnHitsTarget(v, t.module) || seen[v.ID] {
			continue
		}
		seen[v.ID] = true
		if v.Severity != "" {
			sevSet[v.Severity] = true
		}
	}
	var sevs []string
	for s := range sevSet {
		sevs = append(sevs, s)
	}
	sort.Strings(sevs)
	return row{
		module:    t.module,
		tested:    actual,
		basis:     basis,
		flagged:   len(seen) > 0,
		vulnCount: len(seen),
		sevs:      strings.Join(sevs, "|"),
	}
}

func main() {
	rawDir := filepath.Join("data", "output", "snyk")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "could not create output dir:", err)
		os.Exit(1)
	}
	if _, err := exec.LookPath("snyk"); err != nil {
		fmt.Fprintln(os.Stderr, "snyk CLI not found on PATH. Install it and run `snyk auth` first.")
		os.Exit(1)
	}
	if _, err := os.Stat(osvDir); err != nil {
		fmt.Fprintf(os.Stderr, "OSV dir %s not found; run from repo root with vulndb checked out.\n", osvDir)
		os.Exit(1)
	}

	fmt.Printf("Corroborating %d concentration modules against Snyk at affected versions...\n\n", len(targets))
	var rows []row
	flagged := 0
	for i, t := range targets {
		fmt.Printf("[%2d/%d] %s\n", i+1, len(targets), t.module)
		r := runOne(t, rawDir)
		if r.flagged {
			flagged++
		}
		rows = append(rows, r)
	}

	var b strings.Builder
	b.WriteString("module_path,tested_version,pin_basis,snyk_flagged,snyk_vuln_count,severities,note\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%t,%d,%s,%s\n",
			r.module, r.tested, strings.ReplaceAll(r.basis, ",", ";"),
			r.flagged, r.vulnCount, r.sevs, strings.ReplaceAll(r.note, ",", ";")))
	}
	csvPath := filepath.Join("data", "output", "snyk_concentration.csv")
	if err := os.WriteFile(csvPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "could not write summary:", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Summary (%s) ===\n", time.Now().Format("2006-01-02"))
	fmt.Printf("Snyk corroborated %d of %d concentration modules at affected versions.\n", flagged, len(targets))
	fmt.Printf("(vuln.go.dev flagged all 19 on a historical-presence basis.)\n")
	fmt.Printf("Per-module summary: %s\n", csvPath)
	fmt.Printf("Raw per-module JSON: %s/\n\n", rawDir)
	for _, r := range rows {
		status := "clean"
		if r.flagged {
			status = fmt.Sprintf("FLAGGED (%d, %s)", r.vulnCount, r.sevs)
		}
		if r.note != "" {
			status = "ERROR: " + r.note
		}
		fmt.Printf("  %-40s @%-28s %s\n", r.module, r.tested, status)
	}
}
