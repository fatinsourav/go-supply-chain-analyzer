// abandonment_v1 implements Pattern A: abandonment risk.
//
// Thesis rationale: a module that many other modules depend on, but which
// has not published a release in a long time, is a systemic supply-chain
// hazard. It concentrates risk (many dependents) while accumulating
// unpatched-defect and account/domain-takeover exposure (no maintenance
// signal). This is the intersection of two dimensions the pipeline already
// measures independently:
//
//   dependents        - from the concentration detector (dependent_count)
//   staleness (years) - from the newest release Timestamp in the dataset
//
// Score = dependents * years_since_last_release. Gates keep the two
// degenerate corners out: a freshly-released popular module (staleness ~0)
// and an ancient package nobody depends on (dependents ~0). Both are
// individually benign; only their product is the abandonment signal.
//
// "deps" is read as DEPENDENTS (reverse edges), reusing the exact counts
// Pattern 4 (concentration_risk) emits, so the two patterns never disagree
// on how depended-upon a module is.
//
// Dependents are read from the pipeline's risk_patterns.csv rather than
// re-fetching every go.mod: the concentration rows carry
// details="dependent_count=N ...". Coverage therefore equals whatever the
// pipeline's CONCENTRATION_THRESHOLD admitted -- run the pipeline with a low
// threshold first for a wider abandonment sweep.
//
// Usage:
//   go run scripts/abandonment_v1/main.go \
//     -dataset      data/dataset.txt \
//     -patterns     data/output/risk_patterns.csv \
//     -out          data/output/abandonment_v1_candidates.csv \
//     -patterns-out data/output/abandonment_v1_patterns.csv \
//     [-min-deps 5] [-min-years 2] [-now 2025-01-01T00:00:00Z]
//
// The -patterns-out file is risk_patterns.csv-shaped so it feeds directly
// into verify_ground_truth (vuln.go.dev) and snyk_check for the cross-ref.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type datasetLine struct {
	Path      string    `json:"Path"`
	Version   string    `json:"Version"`
	Timestamp time.Time `json:"Timestamp"`
}

type moduleStat struct {
	path        string
	lastRelease time.Time
	versions    int
}

type finding struct {
	module        string
	dependents    int
	lastRelease   time.Time
	yearsSince    float64
	versions      int
	score         float64
	severity      string
}

const hoursPerYear = 24 * 365.25

var depCountRe = regexp.MustCompile(`dependent_count=(\d+)`)

func main() {
	datasetPath := flag.String("dataset", "data/dataset.txt", "dataset JSON lines {Path,Version,Timestamp}")
	patternsPath := flag.String("patterns", "data/output/risk_patterns.csv", "risk_patterns.csv (source of dependent_count)")
	outPath := flag.String("out", "data/output/abandonment_v1_candidates.csv", "rich candidates CSV")
	patternsOut := flag.String("patterns-out", "data/output/abandonment_v1_patterns.csv", "risk_patterns.csv-shaped output for cross-ref")
	minDeps := flag.Int("min-deps", 5, "minimum dependents to consider (gate)")
	minYears := flag.Float64("min-years", 2.0, "minimum years since last release (gate)")
	nowStr := flag.String("now", "", "reference date RFC3339; default = newest release in dataset")
	flag.Parse()

	// ---- 1. dependents from concentration output ----
	deps, err := loadDependentCounts(*patternsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load patterns:", err)
		os.Exit(1)
	}
	if len(deps) == 0 {
		fmt.Fprintln(os.Stderr, "warning: no dependent_count rows found in", *patternsPath,
			"- run the pipeline (Pattern 4) first, ideally with a low CONCENTRATION_THRESHOLD")
	}

	// ---- 2. last-release date per module from dataset ----
	stats, maxTS, err := loadModuleStats(*datasetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load dataset:", err)
		os.Exit(1)
	}

	ref := maxTS
	if *nowStr != "" {
		ref, err = time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parse -now:", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Reference date: %s (dataset newest release)\n", ref.Format("2006-01-02"))

	// ---- 3. join + score ----
	var findings []finding
	var missingStat, gatedYears, gatedDeps int
	for modLower, count := range deps {
		if count < *minDeps {
			gatedDeps++
			continue
		}
		st, ok := stats[modLower]
		if !ok || st.lastRelease.IsZero() {
			missingStat++
			continue
		}
		years := ref.Sub(st.lastRelease).Hours() / hoursPerYear
		if years < *minYears {
			gatedYears++
			continue
		}
		score := float64(count) * years
		sev := "medium"
		if score >= 100 || (count >= 50 && years >= 3) {
			sev = "high"
		}
		findings = append(findings, finding{
			module:      st.path,
			dependents:  count,
			lastRelease: st.lastRelease,
			yearsSince:  years,
			versions:    st.versions,
			score:       score,
			severity:    sev,
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].score > findings[j].score })

	// ---- 4. write rich CSV ----
	if err := writeRich(*outPath, findings); err != nil {
		fmt.Fprintln(os.Stderr, "write out:", err)
		os.Exit(1)
	}
	// ---- 5. write risk_patterns.csv-shaped file for cross-ref ----
	if err := writePatterns(*patternsOut, findings, ref); err != nil {
		fmt.Fprintln(os.Stderr, "write patterns-out:", err)
		os.Exit(1)
	}

	// ---- summary ----
	var hi, med int
	for _, f := range findings {
		if f.severity == "high" {
			hi++
		} else {
			med++
		}
	}
	fmt.Printf("Dependents table: %d modules | dataset modules: %d\n", len(deps), len(stats))
	fmt.Printf("Gated out: below-min-deps=%d below-min-years=%d no-release-date=%d\n",
		gatedDeps, gatedYears, missingStat)
	fmt.Printf("Flagged: %d (high=%d medium=%d)\n", len(findings), hi, med)
	n := len(findings)
	if n > 10 {
		n = 10
	}
	if n > 0 {
		fmt.Println("Top by abandonment score:")
		for _, f := range findings[:n] {
			fmt.Printf("  %-45s deps=%-5d stale=%.1fy score=%.0f [%s]\n",
				f.module, f.dependents, f.yearsSince, f.score, f.severity)
		}
	}
	fmt.Println("Wrote", *outPath, "and", *patternsOut)
}

func loadDependentCounts(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for i, row := range rows {
		if i == 0 && len(row) > 0 && row[0] == "module_path" {
			continue // header
		}
		if len(row) < 4 {
			continue
		}
		module, pattern, details := row[0], row[1], row[3]
		if pattern != "concentration_risk" {
			continue
		}
		m := depCountRe.FindStringSubmatch(details)
		if m == nil {
			continue
		}
		c, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		key := strings.ToLower(module)
		if c > out[key] {
			out[key] = c
		}
	}
	return out, nil
}

func loadModuleStats(path string) (map[string]*moduleStat, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()

	stats := map[string]*moduleStat{}
	var maxTS time.Time
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var dl datasetLine
		if json.Unmarshal([]byte(line), &dl) != nil || dl.Path == "" {
			continue
		}
		key := strings.ToLower(dl.Path)
		st := stats[key]
		if st == nil {
			st = &moduleStat{path: dl.Path}
			stats[key] = st
		}
		st.versions++
		if dl.Timestamp.After(st.lastRelease) {
			st.lastRelease = dl.Timestamp
		}
		if dl.Timestamp.After(maxTS) {
			maxTS = dl.Timestamp
		}
	}
	return stats, maxTS, sc.Err()
}

func writeRich(path string, findings []finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	fmt.Fprintln(w, "module,dependent_count,last_release,years_since_release,version_count,abandonment_score,severity")
	for _, f := range findings {
		fmt.Fprintf(w, "%s,%d,%s,%.2f,%d,%.1f,%s\n",
			f.module, f.dependents, f.lastRelease.Format("2006-01-02"),
			f.yearsSince, f.versions, f.score, f.severity)
	}
	return nil
}

func writePatterns(path string, findings []finding, ref time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"module_path", "pattern_type", "severity", "details", "detected_at"})
	detected := ref.Format(time.RFC3339)
	for _, f := range findings {
		details := fmt.Sprintf("dependent_count=%d years_since_release=%.2f score=%.1f",
			f.dependents, f.yearsSince, f.score)
		w.Write([]string{f.module, "abandonment_risk", f.severity, details, detected})
	}
	return nil
}
