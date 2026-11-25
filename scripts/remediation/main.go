// Command remediation tests whether a metadata pattern detects risk, rather
// than scrutiny, by measuring remediation instead of disclosure.
//
// Rationale. Whether a module carries an advisory depends on how much
// attention it receives, so a raw advisory match rate cannot separate risk
// from popularity. Whether a fix was ever published for an advisory that
// exists is a different quantity: it is not produced by scrutiny, and it is
// exactly what abandonment (and absence of releases) should affect.
//
// For every module in the parent population (the concentration set, i.e. the
// modules with enough dependents to enter the abandonment and pseudo-version
// patterns), the command:
//  1. finds the Go vulnerability database advisories that affect it, using the
//     same exact-or-prefix matching as scripts/verify_ground_truth;
//  2. classifies each advisory as FIXED (some affected range records a
//     "fixed" event for the matching package) or UNFIXED (no range does);
//  3. compares, for a flagged group G and its complement in the parent,
//     P(module has >=1 unfixed advisory | module has >=1 advisory)
//     with Wilson 95% intervals, a chi-square test and Fisher's exact test.
//
// Advisories withdrawn, or published after -asof, are excluded. Advisories
// published within -grace days before -asof are excluded from the fixed/unfixed
// classification, since a fix may simply not have been released yet.
//
// Usage:
//
//	go run ./scripts/remediation \
//	  -parent data/output/concentration_ground_truth.csv \
//	  -abandoned data/output/abandonment_v2_candidates.csv \
//	  -pseudo data/output/pseudoversion_v1_candidates.csv \
//	  -osv-dir vulndb/data/osv -asof 2026-09-30 -grace 90 \
//	  -out data/output/remediation
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvReport struct {
	ID        string `json:"id"`
	Published string `json:"published"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// advisory status for one (package, advisory) pair.
type advStatus struct {
	ID        string
	Published time.Time
	Fixed     bool
}

func main() {
	parentPath := flag.String("parent", "", "concentration_ground_truth.csv (rows with pattern_type=concentration_risk define the parent population)")
	abandonedPath := flag.String("abandoned", "", "abandonment_v2_candidates.csv (column: module)")
	pseudoPath := flag.String("pseudo", "", "pseudoversion_v1_candidates.csv (column: module)")
	osvDir := flag.String("osv-dir", "vulndb/data/osv", "path to vulndb/data/osv")
	asofStr := flag.String("asof", "2026-09-30", "analysis date; advisories published after it are ignored")
	grace := flag.Int("grace", 90, "advisories published within this many days before -asof are not classified")
	datesPath := flag.String("dates", "", "optional CSV id,added giving each advisory's first-added date in golang/vulndb git history; used when the OSV 'published' field is the zero placeholder the repository stores")
	corpusPath := flag.String("corpus", "", "optional modules.csv (column: path); if set, also compares the concentration set against the rest of the corpus")
	exactOnly := flag.Bool("exact", false, "match advisories by exact module path only (no prefix fallback)")
	outPrefix := flag.String("out", "remediation", "output prefix (writes <prefix>_by_module.csv and <prefix>_summary.md)")
	flag.Parse()
	if *parentPath == "" || *abandonedPath == "" || *pseudoPath == "" {
		log.Fatal("-parent, -abandoned and -pseudo are required")
	}
	asof, err := time.Parse("2006-01-02", *asofStr)
	if err != nil {
		log.Fatalf("bad -asof: %v", err)
	}
	cutoff := asof.AddDate(0, 0, -*grace)

	dates := map[string]time.Time{}
	if *datesPath != "" {
		dates = loadDates(*datesPath)
	}
	db, err := loadOSV(*osvDir, asof, dates)
	if err != nil {
		log.Fatal(err)
	}
	parent, err := readColumn(*parentPath, "module_path", "pattern_type", "concentration_risk")
	if err != nil {
		log.Fatal(err)
	}
	abandoned, err := readColumn(*abandonedPath, "module", "", "")
	if err != nil {
		log.Fatal(err)
	}
	pseudo, err := readColumn(*pseudoPath, "module", "", "")
	if err != nil {
		log.Fatal(err)
	}

	type modRow struct {
		mod                          string
		inA, inP                     bool
		all, classified, unfixed     int
		fixedIDs, unfixedIDs, recent []string
	}
	var rows []modRow
	notInParent := map[string]int{}
	for m := range abandoned {
		if !parent[m] {
			notInParent["abandoned"]++
		}
	}
	for m := range pseudo {
		if !parent[m] {
			notInParent["pseudo"]++
		}
	}

	for _, m := range sortedKeys(parent) {
		r := modRow{mod: m, inA: abandoned[m], inP: pseudo[m]}
		seen := map[string]bool{}
		for _, a := range lookup(db, m, *exactOnly) {
			if seen[a.ID] {
				continue
			}
			seen[a.ID] = true
			r.all++
			if a.Published.After(cutoff) {
				r.recent = append(r.recent, a.ID)
				continue
			}
			r.classified++
			if a.Fixed {
				r.fixedIDs = append(r.fixedIDs, a.ID)
			} else {
				r.unfixed++
				r.unfixedIDs = append(r.unfixedIDs, a.ID)
			}
		}
		rows = append(rows, r)
	}

	// Per-module CSV.
	f, err := os.Create(*outPrefix + "_by_module.csv")
	if err != nil {
		log.Fatal(err)
	}
	w := csv.NewWriter(f)
	w.Write([]string{"module", "abandoned", "pseudoversion_only", "advisories", "classified", "unfixed", "fixed_ids", "unfixed_ids", "excluded_recent_ids"})
	for _, r := range rows {
		w.Write([]string{r.mod, fmt.Sprint(r.inA), fmt.Sprint(r.inP), fmt.Sprint(r.all), fmt.Sprint(r.classified), fmt.Sprint(r.unfixed),
			strings.Join(r.fixedIDs, ";"), strings.Join(r.unfixedIDs, ";"), strings.Join(r.recent, ";")})
	}
	w.Flush()
	f.Close()

	// Group tallies.
	type tally struct{ n, withAdv, withClassified, withUnfixed, advTotal, advUnfixed int }
	add := func(t *tally, r modRow) {
		t.n++
		if r.all > 0 {
			t.withAdv++
		}
		if r.classified > 0 {
			t.withClassified++
		}
		if r.unfixed > 0 {
			t.withUnfixed++
		}
		t.advTotal += r.classified
		t.advUnfixed += r.unfixed
	}
	var all, a, notA, p, notP tally
	for _, r := range rows {
		add(&all, r)
		if r.inA {
			add(&a, r)
		} else {
			add(&notA, r)
		}
		if r.inP {
			add(&p, r)
		} else {
			add(&notP, r)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Remediation analysis\n\n")
	match := "exact module path, else prefix in either direction (as scripts/verify_ground_truth)"
	if *exactOnly {
		match = "exact module path only"
	}
	fmt.Fprintf(&sb, "Advisory matching: %s.\n", match)
	fmt.Fprintf(&sb, "As-of date: %s. Advisories published after it, or withdrawn, are ignored. Advisories published after %s (grace %d days) are counted but not classified.\n\n",
		asof.Format("2006-01-02"), cutoff.Format("2006-01-02"), *grace)
	fmt.Fprintf(&sb, "Parent population (concentration set): %d modules, %d with >=1 advisory.\n", all.n, all.withAdv)
	fmt.Fprintf(&sb, "Flagged modules not found in the parent: abandoned %d, pseudo-version %d.\n\n", notInParent["abandoned"], notInParent["pseudo"])

	group := func(name string, g, c tally, gName, cName string) {
		fmt.Fprintf(&sb, "## %s\n\n", name)
		fmt.Fprintf(&sb, "| Group | Modules | With advisory | With classified advisory | With >=1 unfixed | Unfixed rate among advisory-carrying (95%% CI) | Advisories unfixed |\n|---|---|---|---|---|---|---|\n")
		for _, x := range []struct {
			n string
			t tally
		}{{gName, g}, {cName, c}} {
			lo, hi := wilson(x.t.withUnfixed, x.t.withClassified)
			fmt.Fprintf(&sb, "| %s | %d | %d | %d | %d | %s (%.1f–%.1f%%) | %d / %d |\n", x.n, x.t.n, x.t.withAdv, x.t.withClassified, x.t.withUnfixed,
				pct(x.t.withUnfixed, x.t.withClassified), lo*100, hi*100, x.t.advUnfixed, x.t.advTotal)
		}
		// 2x2 on advisory-carrying modules: unfixed vs all-fixed.
		A, B := g.withUnfixed, g.withClassified-g.withUnfixed
		C, D := c.withUnfixed, c.withClassified-c.withUnfixed
		chi, chiP := chiSquare(A, B, C, D)
		fp := fisherTwoSided(A, B, C, D)
		or := oddsRatio(A, B, C, D)
		fmt.Fprintf(&sb, "\n2×2 (modules with >=1 classified advisory; unfixed vs all fixed): [[%d, %d], [%d, %d]]  \n", A, B, C, D)
		fmt.Fprintf(&sb, "Chi-square (1 df, no continuity correction) = %.2f, p = %.3g; Fisher exact two-sided p = %.3g; odds ratio = %.2f\n\n", chi, chiP, fp, or)
		// Disclosure comparison for context (the confounded quantity).
		chi2, p2 := chiSquare(g.withAdv, g.n-g.withAdv, c.withAdv, c.n-c.withAdv)
		fmt.Fprintf(&sb, "For context only (confounded by scrutiny): advisory rate %s vs %s, chi-square = %.2f, p = %.3g\n\n",
			pct(g.withAdv, g.n), pct(c.withAdv, c.n), chi2, p2)
	}
	group("Abandonment vs non-abandoned (same parent)", a, notA, "Abandoned", "Not abandoned")
	group("Pseudo-version-only vs tagged (same parent)", p, notP, "Pseudo-version-only", "Has tagged release")

	if *corpusPath != "" {
		corpus, err := readColumn(*corpusPath, "path", "", "")
		if err != nil {
			log.Fatal(err)
		}
		var cIn, cOut tally
		for m := range corpus {
			r := modRow{mod: m}
			seen := map[string]bool{}
			for _, adv := range lookup(db, m, *exactOnly) {
				if seen[adv.ID] {
					continue
				}
				seen[adv.ID] = true
				r.all++
				if adv.Published.After(cutoff) {
					continue
				}
				r.classified++
				if !adv.Fixed {
					r.unfixed++
				}
			}
			if parent[m] {
				add(&cIn, r)
			} else {
				add(&cOut, r)
			}
		}
		missing := 0
		for m := range parent {
			if !corpus[m] {
				missing++
			}
		}
		fmt.Fprintf(&sb, "Corpus: %d distinct modules; concentration modules absent from it: %d.\n\n", len(corpus), missing)
		group("Concentration vs rest of corpus", cIn, cOut, "Concentration (>=3 dependents)", "Rest of corpus")
	}

	if err := os.WriteFile(*outPrefix+"_summary.md", []byte(sb.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Print(sb.String())
}

// loadOSV maps each affected package path to its advisories, with fix status.
func loadOSV(dir string, asof time.Time, dates map[string]time.Time) (map[string][]advStatus, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no OSV files in %q", dir)
	}
	db := map[string][]advStatus{}
	for _, fp := range files {
		data, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		var rep osvReport
		if json.Unmarshal(data, &rep) != nil {
			continue
		}
		if rep.Withdrawn != "" {
			continue
		}
		pub, err := time.Parse(time.RFC3339, rep.Published)
		if err != nil || pub.Year() < 2000 {
			d, ok := dates[rep.ID]
			if !ok {
				continue // no usable date: cannot place it relative to -asof
			}
			pub = d
		}
		if pub.After(asof) {
			continue
		}
		for _, aff := range rep.Affected {
			name := aff.Package.Name
			if name == "" {
				continue
			}
			fixed := false
			for _, rg := range aff.Ranges {
				for _, ev := range rg.Events {
					if ev.Fixed != "" {
						fixed = true
					}
				}
			}
			db[name] = append(db[name], advStatus{ID: rep.ID, Published: pub, Fixed: fixed})
		}
	}
	return db, nil
}

// lookup mirrors scripts/verify_ground_truth: exact match, else prefix match in
// either direction. If several affected packages of one advisory match, the
// advisory counts as fixed only if every matching package records a fix.
func lookup(db map[string][]advStatus, mod string, exactOnly bool) []advStatus {
	var hits []advStatus
	if v, ok := db[mod]; ok {
		hits = v
	} else if !exactOnly {
		for affected, v := range db {
			if strings.HasPrefix(affected, mod+"/") || strings.HasPrefix(mod, affected+"/") {
				hits = append(hits, v...)
			}
		}
	}
	merged := map[string]advStatus{}
	for _, h := range hits {
		if prev, ok := merged[h.ID]; ok {
			prev.Fixed = prev.Fixed && h.Fixed
			merged[h.ID] = prev
		} else {
			merged[h.ID] = h
		}
	}
	var out []advStatus
	for _, id := range sortedKeys2(merged) {
		out = append(out, merged[id])
	}
	return out
}

// readColumn returns the set of (lowercased, as in verify_ground_truth) values
// of column col, optionally filtered to rows where filterCol == filterVal.
func readColumn(path, col, filterCol, filterVal string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	c, ok := idx[col]
	if !ok {
		return nil, fmt.Errorf("%s: no column %q", path, col)
	}
	fc, hasF := idx[filterCol]
	out := map[string]bool{}
	for _, rec := range recs[1:] {
		if c >= len(rec) {
			continue
		}
		if filterCol != "" && (!hasF || fc >= len(rec) || strings.TrimSpace(rec[fc]) != filterVal) {
			continue
		}
		if v := strings.ToLower(strings.TrimSpace(rec[c])); v != "" {
			out[v] = true
		}
	}
	return out, nil
}

func wilson(k, n int) (float64, float64) {
	if n == 0 {
		return 0, 0
	}
	z := 1.959964
	p := float64(k) / float64(n)
	nn := float64(n)
	d := 1 + z*z/nn
	c := (p + z*z/(2*nn)) / d
	h := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / d
	return math.Max(0, c-h), math.Min(1, c+h)
}

func pct(k, n int) string {
	if n == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d = %.1f%%", k, n, 100*float64(k)/float64(n))
}

func chiSquare(a, b, c, d int) (float64, float64) {
	n := float64(a + b + c + d)
	r1, r2 := float64(a+b), float64(c+d)
	c1, c2 := float64(a+c), float64(b+d)
	if r1 == 0 || r2 == 0 || c1 == 0 || c2 == 0 {
		return 0, 1
	}
	diff := float64(a)*float64(d) - float64(b)*float64(c)
	chi := n * diff * diff / (r1 * r2 * c1 * c2)
	return chi, math.Erfc(math.Sqrt(chi / 2)) // survival of chi-square with 1 df
}

func lnFact(n int) float64 { v, _ := math.Lgamma(float64(n) + 1); return v }

func hyper(a, b, c, d int) float64 {
	return math.Exp(lnFact(a+b) + lnFact(c+d) + lnFact(a+c) + lnFact(b+d) - lnFact(a) - lnFact(b) - lnFact(c) - lnFact(d) - lnFact(a+b+c+d))
}

// fisherTwoSided sums the probabilities of all tables with the same margins
// that are no more likely than the observed one.
func fisherTwoSided(a, b, c, d int) float64 {
	r1, c1 := a+b, a+c
	n := a + b + c + d
	obs := hyper(a, b, c, d)
	lo := max(0, r1+c1-n)
	hi := min(r1, c1)
	p := 0.0
	for x := lo; x <= hi; x++ {
		pr := hyper(x, r1-x, c1-x, n-r1-c1+x)
		if pr <= obs*(1+1e-7) {
			p += pr
		}
	}
	return math.Min(1, p)
}

func oddsRatio(a, b, c, d int) float64 {
	if b*c == 0 {
		return math.Inf(1)
	}
	return float64(a*d) / float64(b*c)
}

func sortedKeys(m map[string]bool) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func sortedKeys2(m map[string]advStatus) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// loadDates reads id,added (YYYY-MM-DD).
func loadDates(path string) map[string]time.Time {
	out := map[string]time.Time{}
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range recs[1:] {
		if t, err := time.Parse("2006-01-02", r[1]); err == nil {
			out[r[0]] = t
		}
	}
	return out
}
