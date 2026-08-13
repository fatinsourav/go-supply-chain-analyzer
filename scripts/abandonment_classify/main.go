// abandonment_classify applies a documented, reproducible decision rule to the
// abandonment sample worksheet and computes precision with a Wilson interval.
//
// Why a rule instead of 50 free-hand judgements: a stated rule with an audited
// threshold is reproducible, cannot drift between row 5 and row 40, and lets a
// reviewer disagree with the THRESHOLD rather than with 50 separate opinions.
// Any row the rule cannot decide is left for manual review, and any
// classification already present in the worksheet is preserved -- the human
// overrides the rule, never the other way round.
//
// The rule operationalises the two-axis reframe: release staleness alone does
// not mean abandonment, because a module can be actively committed and simply
// not tagged. Commit activity is the discriminator.
//
//   archived=true                       -> abandoned      (owner's own signal)
//   last push within -active-years       -> maintained     (release stagnation,
//                                                          NOT abandonment)
//   last push older than -dormant-years  -> abandoned      (no release, no commits)
//   in between / no data                 -> needs_review   (human decides)
//
// "finished" (complete rather than neglected) is deliberately NOT inferred
// mechanically: nothing in the API distinguishes a finished library from a
// neglected one. Rows the rule calls abandoned should be skimmed for this.
//
// Precision is reported as an interval because needs_review rows are genuinely
// unknown: the lower bound counts them as false positives, the upper bound as
// true positives. The truth lies between, and the gap shrinks as you classify.
//
// Usage:
//   go run scripts/abandonment_classify/main.go \
//     -worksheet data/output/abandonment_sample_worksheet.csv \
//     -out       data/output/abandonment_sample_classified.csv \
//     [-active-years 1.5] [-dormant-years 3.0] [-ref 2026-07-24]
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

const hoursPerYear = 24 * 365.25

type row struct {
	cells  []string
	module string
	class  string
	rule   string
	pushY  float64 // years since last push; NaN if unknown
}

// wilson returns the Wilson score interval for k successes in n trials.
func wilson(k, n int, z float64) (float64, float64) {
	if n == 0 {
		return 0, 0
	}
	p := float64(k) / float64(n)
	den := 1 + z*z/float64(n)
	centre := p + z*z/(2*float64(n))
	spread := z * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n)))
	return (centre - spread) / den, (centre + spread) / den
}

func colIndex(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}

func main() {
	wsPath := flag.String("worksheet", "data/output/abandonment_sample_worksheet.csv", "sample worksheet")
	outPath := flag.String("out", "data/output/abandonment_sample_classified.csv", "classified output")
	activeYears := flag.Float64("active-years", 1.5, "pushed within this many years => maintained")
	dormantYears := flag.Float64("dormant-years", 3.0, "no push for this many years => abandoned")
	refStr := flag.String("ref", "", "reference date YYYY-MM-DD (default: today)")
	flag.Parse()

	ref := time.Now().UTC()
	if *refStr != "" {
		t, err := time.Parse("2006-01-02", *refStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parse -ref:", err)
			os.Exit(1)
		}
		ref = t
	}

	f, err := os.Open(*wsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open worksheet:", err)
		os.Exit(1)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	f.Close()
	if err != nil || len(recs) < 2 {
		fmt.Fprintln(os.Stderr, "read worksheet:", err)
		os.Exit(1)
	}
	header := recs[0]
	iMod := colIndex(header, "module")
	iArch := colIndex(header, "gh_archived")
	iPush := colIndex(header, "gh_last_push")
	iClass := colIndex(header, "classification")
	iNotes := colIndex(header, "notes")
	if iMod < 0 || iArch < 0 || iPush < 0 || iClass < 0 {
		fmt.Fprintln(os.Stderr, "worksheet missing expected columns")
		os.Exit(1)
	}

	var rows []*row
	for _, rec := range recs[1:] {
		if len(rec) <= iClass {
			continue
		}
		x := &row{cells: rec, module: rec[iMod], pushY: math.NaN()}

		if p := strings.TrimSpace(rec[iPush]); p != "" {
			if t, err := time.Parse(time.RFC3339, p); err == nil {
				x.pushY = ref.Sub(t).Hours() / hoursPerYear
			}
		}

		// human classification always wins
		if existing := strings.TrimSpace(rec[iClass]); existing != "" {
			x.class, x.rule = existing, "manual"
			rows = append(rows, x)
			continue
		}

		switch {
		case strings.EqualFold(strings.TrimSpace(rec[iArch]), "true"):
			x.class, x.rule = "abandoned", "archived"
		case math.IsNaN(x.pushY):
			x.class, x.rule = "needs_review", "no_push_data"
		case x.pushY <= *activeYears:
			x.class, x.rule = "maintained", "recent_push"
		case x.pushY >= *dormantYears:
			x.class, x.rule = "abandoned", "dormant"
		default:
			x.class, x.rule = "needs_review", "middle_band"
		}
		rows = append(rows, x)
	}

	// ---- write ----
	of, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	w := csv.NewWriter(of)
	outHeader := append([]string{}, header...)
	outHeader = append(outHeader, "rule", "years_since_push")
	w.Write(outHeader)
	for _, x := range rows {
		c := append([]string{}, x.cells...)
		for len(c) <= iNotes && iNotes >= 0 {
			c = append(c, "")
		}
		if iClass < len(c) {
			c[iClass] = x.class
		}
		py := ""
		if !math.IsNaN(x.pushY) {
			py = fmt.Sprintf("%.2f", x.pushY)
		}
		c = append(c, x.rule, py)
		w.Write(c)
	}
	w.Flush()
	of.Close()

	// ---- tallies ----
	byClass := map[string]int{}
	byRule := map[string]int{}
	for _, x := range rows {
		byClass[x.class]++
		byRule[x.rule]++
	}
	n := len(rows)
	ab := byClass["abandoned"]
	mt := byClass["maintained"]
	fin := byClass["finished"]
	nr := byClass["needs_review"] + byClass["unclear"]

	fmt.Printf("Reference date: %s | thresholds: active<=%.1fy, dormant>=%.1fy\n",
		ref.Format("2006-01-02"), *activeYears, *dormantYears)
	fmt.Printf("Sample size: %d\n\n", n)
	fmt.Println("Classification:")
	var ck []string
	for k := range byClass {
		ck = append(ck, k)
	}
	sort.Strings(ck)
	for _, k := range ck {
		fmt.Printf("  %-14s %3d  (%.1f%%)\n", k, byClass[k], 100*float64(byClass[k])/float64(n))
	}
	fmt.Println("\nRule fired:")
	var rk []string
	for k := range byRule {
		rk = append(rk, k)
	}
	sort.Strings(rk)
	for _, k := range rk {
		fmt.Printf("  %-14s %3d\n", k, byRule[k])
	}

	// precision: abandoned = true positive for "abandonment risk"
	lo1, hi1 := wilson(ab, n, 1.96)
	lo2, hi2 := wilson(ab+nr, n, 1.96)
	fmt.Printf("\nPrecision for abandonment (TP = abandoned):\n")
	fmt.Printf("  lower bound (needs_review counted as FP): %d/%d = %.1f%%  95%% CI [%.1f%%, %.1f%%]\n",
		ab, n, 100*float64(ab)/float64(n), 100*lo1, 100*hi1)
	fmt.Printf("  upper bound (needs_review counted as TP): %d/%d = %.1f%%  95%% CI [%.1f%%, %.1f%%]\n",
		ab+nr, n, 100*float64(ab+nr)/float64(n), 100*lo2, 100*hi2)
	fmt.Printf("\nRelease stagnation (flagged stale but actively committed): %d/%d = %.1f%%\n",
		mt, n, 100*float64(mt)/float64(n))
	if fin > 0 {
		fmt.Printf("Marked 'finished' by hand: %d\n", fin)
	}
	fmt.Println("\nWrote", *outPath)
	fmt.Println("Review the needs_review rows and any 'abandoned' row that may be 'finished',")
	fmt.Println("edit the classification column, and re-run: manual values are preserved.")
}
