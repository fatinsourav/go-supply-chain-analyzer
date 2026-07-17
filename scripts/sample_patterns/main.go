// Command sample_patterns draws a reproducible random sample of unique modules
// flagged by the naming_similarity and source_ambiguity patterns, for
// second-source (Snyk) cross-referencing.
//
// risk_patterns.csv has one row per detection signal, so a module flagged by
// several signals appears several times. This tool deduplicates on module path
// first, then samples, so the sample reflects unique flagged modules (matching
// the 3,332 / 1,802 figures in the evaluation).
//
// The sample is seeded (default 42) so the exact selection is reproducible.
//
// Usage (from repo root):
//   go run ./scripts/sample_patterns
//   go run ./scripts/sample_patterns -n 15 -seed 7
//
// Output: data/output/pattern_sample.csv  (module_path,pattern_type)
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func uniqueModules(rows [][]string, pattern string) []string {
	seen := map[string]bool{}
	var out []string
	for _, rec := range rows {
		if len(rec) < 2 || rec[1] != pattern {
			continue
		}
		m := strings.TrimSpace(rec[0])
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func sample(mods []string, n int, r *rand.Rand) []string {
	if n >= len(mods) {
		return mods
	}
	idx := r.Perm(len(mods))[:n]
	sort.Ints(idx)
	var out []string
	for _, i := range idx {
		out = append(out, mods[i])
	}
	return out
}

func main() {
	n := flag.Int("n", 12, "number of modules to sample per pattern")
	seed := flag.Int64("seed", 42, "random seed for reproducibility")
	inPath := flag.String("in", filepath.Join("data", "output", "risk_patterns.csv"), "risk_patterns.csv path")
	flag.Parse()

	f, err := os.Open(*inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open input:", err)
		os.Exit(1)
	}
	defer f.Close()

	reader := csv.NewReader(bufio.NewReader(f))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read csv:", err)
		os.Exit(1)
	}
	if len(rows) > 0 {
		rows = rows[1:]
	}

	naming := uniqueModules(rows, "naming_similarity")
	source := uniqueModules(rows, "source_ambiguity")
	fmt.Printf("unique naming_similarity modules: %d\n", len(naming))
	fmt.Printf("unique source_ambiguity modules:  %d\n", len(source))

	r := rand.New(rand.NewSource(*seed))
	namingSample := sample(naming, *n, r)
	sourceSample := sample(source, *n, r)

	var b strings.Builder
	b.WriteString("module_path,pattern_type\n")
	for _, m := range namingSample {
		b.WriteString(m + ",naming_similarity\n")
	}
	for _, m := range sourceSample {
		b.WriteString(m + ",source_ambiguity\n")
	}
	outPath := filepath.Join("data", "output", "pattern_sample.csv")
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write sample:", err)
		os.Exit(1)
	}

	fmt.Printf("\nSampled %d naming + %d source modules (seed %d) -> %s\n",
		len(namingSample), len(sourceSample), *seed, outPath)
	fmt.Println("\nnaming_similarity sample:")
	for _, m := range namingSample {
		fmt.Println("  " + m)
	}
	fmt.Println("\nsource_ambiguity sample:")
	for _, m := range sourceSample {
		fmt.Println("  " + m)
	}
}
