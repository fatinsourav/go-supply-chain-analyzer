// Command verify_ground_truth cross-references the modules flagged by the
// supply-chain analyzer against the official Go vulnerability database
// (vuln.go.dev / github.com/golang/vulndb).
//
// This implements the "evaluation against known ground truth" step: for each
// flagged module it reports whether that module has any vulnerability recorded
// in the Go vuln DB, and computes the match rate per risk pattern.
//
// USAGE
//
//	# one-time: get the vulnerability data
//	git clone --depth 1 https://github.com/golang/vulndb
//
//	# run against the analyzer output
//	go run scripts/verify_ground_truth/main.go \
//	    -patterns data/output/risk_patterns.csv \
//	    -osv-dir  vulndb/data/osv \
//	    -out      data/output/ground_truth_matches.csv
//
// INTERPRETATION
//
// A match means the flagged module has a *known* vulnerability. A non-match
// does NOT mean the module is safe — it may simply never have been analyzed.
// Absence from the DB is itself a finding: it shows the gap between a metadata
// signal and a validated security signal. Report both rates honestly.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// osvReport is the subset of the OSV schema we need from each vuln report.
type osvReport struct {
	ID       string `json:"id"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"affected"`
}

// flaggedRow is one (module, pattern) entry from risk_patterns.csv.
type flaggedRow struct {
	ModulePath  string
	PatternType string
	Severity    string
}

func main() {
	patternsPath := flag.String("patterns", "", "path to risk_patterns.csv from the analyzer")
	osvDir := flag.String("osv-dir", "vulndb/data/osv", "path to vulndb/data/osv")
	outPath := flag.String("out", "ground_truth_matches.csv", "output CSV path")
	flag.Parse()

	if *patternsPath == "" {
		log.Fatal("missing required -patterns flag (path to risk_patterns.csv)")
	}

	modToVulns, err := loadVulnDB(*osvDir)
	if err != nil {
		log.Fatalf("loading vuln DB: %v", err)
	}

	flagged, err := loadFlagged(*patternsPath)
	if err != nil {
		log.Fatalf("loading flagged modules: %v", err)
	}

	fmt.Printf("Modules with >=1 known vuln in Go DB : %d\n", len(modToVulns))
	fmt.Printf("Flagged (module, pattern) rows       : %d\n\n", len(flagged))

	type counts struct{ total, matched int }
	perPattern := make(map[string]*counts)

	out, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("creating output: %v", err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	w.Write([]string{"module_path", "pattern_type", "severity", "known_vuln_count", "vuln_ids"})

	for _, r := range flagged {
		vulns := lookup(modToVulns, r.ModulePath)
		count := len(vulns)

		c, ok := perPattern[r.PatternType]
		if !ok {
			c = &counts{}
			perPattern[r.PatternType] = c
		}
		c.total++
		if count > 0 {
			c.matched++
		}

		ids := uniqueSorted(vulns)
		w.Write([]string{
			r.ModulePath,
			r.PatternType,
			r.Severity,
			fmt.Sprintf("%d", count),
			strings.Join(ids, ";"),
		})
	}
	w.Flush()

	// Summary: match rate per pattern — this is the core evaluation number.
	fmt.Println("Ground-truth match rate by pattern (this is your evaluation number):")
	fmt.Printf("  %-28s %8s %8s %7s\n", "pattern", "flagged", "matched", "rate")

	pats := make([]string, 0, len(perPattern))
	for p := range perPattern {
		pats = append(pats, p)
	}
	sort.Strings(pats)
	for _, p := range pats {
		c := perPattern[p]
		rate := 0.0
		if c.total > 0 {
			rate = float64(c.matched) / float64(c.total) * 100
		}
		fmt.Printf("  %-28s %8d %8d %6.1f%%\n", p, c.total, c.matched, rate)
	}
	fmt.Printf("\nPer-module results written to: %s\n", *outPath)
}

// loadVulnDB reads every OSV report and maps each affected module path to the
// list of vulnerability IDs that reference it.
func loadVulnDB(osvDir string) (map[string][]string, error) {
	files, err := filepath.Glob(filepath.Join(osvDir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no OSV .json files in %q; did you clone github.com/golang/vulndb?", osvDir)
	}

	modToVulns := make(map[string][]string)
	for _, fp := range files {
		data, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		var rep osvReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		for _, aff := range rep.Affected {
			if name := aff.Package.Name; name != "" {
				modToVulns[name] = append(modToVulns[name], rep.ID)
			}
		}
	}
	return modToVulns, nil
}

// loadFlagged reads risk_patterns.csv, normalizing module paths to lowercase
// and deduplicating by (module, pattern).
func loadFlagged(path string) ([]flaggedRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 1 {
		return nil, fmt.Errorf("empty CSV")
	}

	// Map header names to column indexes.
	header := records[0]
	idx := make(map[string]int)
	for i, h := range header {
		idx[strings.TrimSpace(strings.ToLower(h))] = i
	}
	mp, ok1 := idx["module_path"]
	pt, ok2 := idx["pattern_type"]
	sv, ok3 := idx["severity"]
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("CSV must have module_path and pattern_type columns")
	}

	seen := make(map[string]bool)
	var rows []flaggedRow
	for _, rec := range records[1:] {
		if mp >= len(rec) || pt >= len(rec) {
			continue
		}
		mod := strings.ToLower(strings.TrimSpace(rec[mp]))
		pat := strings.TrimSpace(rec[pt])
		sev := ""
		if ok3 && sv < len(rec) {
			sev = strings.TrimSpace(rec[sv])
		}
		if mod == "" {
			continue
		}
		key := mod + "|" + pat
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, flaggedRow{ModulePath: mod, PatternType: pat, Severity: sev})
	}
	return rows, nil
}

// lookup returns the vuln IDs for a module, with a prefix fallback so a flagged
// module that is a parent (or child) of an affected package still counts.
func lookup(modToVulns map[string][]string, mod string) []string {
	if v, ok := modToVulns[mod]; ok {
		return v
	}
	var hits []string
	for affected, ids := range modToVulns {
		if affected == mod ||
			strings.HasPrefix(affected, mod+"/") ||
			strings.HasPrefix(mod, affected+"/") {
			hits = append(hits, ids...)
		}
	}
	return hits
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]bool)
	for _, s := range in {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
