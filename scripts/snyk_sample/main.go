// Command snyk_sample cross-references a sample of naming_similarity and
// source_ambiguity flagged modules against Snyk, using the SAME affected-version
// method as the concentration-risk corroboration (scripts/snyk_check).
//
// Reads data/output/pattern_sample.csv (from scripts/sample_patterns). For each
// module: reads local OSV advisories for the lowest recorded "fixed" version,
// pins the test to the highest real release below it (or the lowest release if
// no fix is recorded), then runs `snyk test --json`.
//
// The importable package is not known in advance, so the tool imports the module
// path itself; if `go mod tidy` cannot resolve a package there, the module is
// recorded as "unresolved" (not counted clean or flagged) so it does not silently
// inflate the clean count.
//
// Usage (from repo root):
//   go run ./scripts/snyk_sample
//
// Output:
//   data/output/snyk_sample/<module>.json     raw Snyk output per module
//   data/output/snyk_sample_summary.csv        summary table
package main

import (
	"bufio"
	"encoding/csv"
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
	pattern   string
	tested    string
	basis     string
	flagged   bool
	vulnCount int
	sevs      string
	note      string
}

var cleanSemver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

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

func pickVersion(module string) (version, basis string) {
	vers := proxyVersions(module)
	if len(vers) == 0 {
		return "", "no clean release tags"
	}
	sort.Slice(vers, func(i, j int) bool {
		a1, a2, a3, _ := parseSemver(vers[i])
		b1, b2, b3, _ := parseSemver(vers[j])
		return less(a1, a2, a3, b1, b2, b3)
	})
	if fa, fb, fc, ok := lowestFixed(module); ok {
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
		return vers[0], "lowest release (all tags >= earliest fix)"
	}
	return vers[0], "lowest release (no OSV record)"
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

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func runOne(module, pattern, rawDir string) row {
	version, basis := pickVersion(module)

	dir, err := os.MkdirTemp("", "snyksample-")
	if err != nil {
		return row{module: module, pattern: pattern, note: "mktemp failed: " + err.Error()}
	}
	defer os.RemoveAll(dir)

	gomod := "module snyksample\n\ngo 1.21\n"
	if version != "" {
		gomod += fmt.Sprintf("\nrequire %s %s\n", module, version)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		return row{module: module, pattern: pattern, note: "write go.mod failed: " + err.Error()}
	}
	deps := fmt.Sprintf("package snyksample\n\nimport _ %q\n", module)
	if err := os.WriteFile(filepath.Join(dir, "deps.go"), []byte(deps), 0o644); err != nil {
		return row{module: module, pattern: pattern, note: "write deps.go failed: " + err.Error()}
	}

	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := tidy.CombinedOutput(); err != nil {
		return row{module: module, pattern: pattern, tested: version, basis: basis,
			note: "unresolved: " + firstLine(string(out))}
	}

	actual := actualVersion(dir, module)

	cmd := exec.Command("snyk", "test", "--json")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, _ := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(rawDir, sanitize(module)+".json"), out, 0o644)

	vulns, err := parseSnyk(out)
	if err != nil {
		return row{module: module, pattern: pattern, tested: actual, basis: basis,
			note: "parse failed (saved raw json): " + err.Error()}
	}

	seen := map[string]bool{}
	sevSet := map[string]bool{}
	for _, v := range vulns {
		if !vulnHitsTarget(v, module) || seen[v.ID] {
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
		module:    module,
		pattern:   pattern,
		tested:    actual,
		basis:     basis,
		flagged:   len(seen) > 0,
		vulnCount: len(seen),
		sevs:      strings.Join(sevs, "|"),
	}
}

func main() {
	rawDir := filepath.Join("data", "output", "snyk_sample")
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

	samplePath := filepath.Join("data", "output", "pattern_sample.csv")
	f, err := os.Open(samplePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n(run `go run ./scripts/sample_patterns` first)\n", samplePath, err)
		os.Exit(1)
	}
	reader := csv.NewReader(bufio.NewReader(f))
	recs, err := reader.ReadAll()
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read sample csv:", err)
		os.Exit(1)
	}
	if len(recs) > 0 {
		recs = recs[1:]
	}

	fmt.Printf("Cross-referencing %d sampled modules against Snyk at affected/lowest versions...\n\n", len(recs))
	var rows []row
	flagged, unresolved := 0, 0
	for i, rec := range recs {
		if len(rec) < 2 {
			continue
		}
		module, pattern := strings.TrimSpace(rec[0]), strings.TrimSpace(rec[1])
		fmt.Printf("[%2d/%d] %-50s (%s)\n", i+1, len(recs), module, pattern)
		r := runOne(module, pattern, rawDir)
		if r.flagged {
			flagged++
		}
		if strings.HasPrefix(r.note, "unresolved") {
			unresolved++
		}
		rows = append(rows, r)
	}

	var b strings.Builder
	b.WriteString("module_path,pattern_type,tested_version,pin_basis,snyk_flagged,snyk_vuln_count,severities,note\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%t,%d,%s,%s\n",
			r.module, r.pattern, r.tested, strings.ReplaceAll(r.basis, ",", ";"),
			r.flagged, r.vulnCount, r.sevs, strings.ReplaceAll(r.note, ",", ";")))
	}
	csvPath := filepath.Join("data", "output", "snyk_sample_summary.csv")
	if err := os.WriteFile(csvPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "could not write summary:", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Summary (%s) ===\n", time.Now().Format("2006-01-02"))
	fmt.Printf("Snyk flagged %d of %d sampled naming/source modules at affected/lowest versions.\n", flagged, len(rows))
	fmt.Printf("(%d unresolved: module root not importable - not counted either way.)\n", unresolved)
	fmt.Printf("Compare: 12/19 concentration modules corroborated by the same method.\n")
	fmt.Printf("Per-module summary: %s\n", csvPath)
	fmt.Printf("Raw per-module JSON: %s/\n\n", rawDir)
	for _, r := range rows {
		status := "clean"
		if r.flagged {
			status = fmt.Sprintf("FLAGGED (%d, %s)", r.vulnCount, r.sevs)
		}
		if r.note != "" {
			status = r.note
		}
		fmt.Printf("  %-46s @%-18s %s\n", r.module, r.tested, status)
	}
}
