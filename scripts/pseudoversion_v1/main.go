// pseudoversion_v1 implements Pattern B: pseudo-version-only dependence.
//
// Risk rationale: a Go pseudo-version (v0.0.0-20190306220234-b354f8bf4d9e)
// pins a dependent to an arbitrary commit rather than to a released, tagged
// artifact. When a widely-depended-upon module has NEVER tagged a release, its
// whole dependent population is pinned to untagged commits, which means:
//   - no release gate, changelog, or review boundary between commits
//   - no semantic-versioning contract, so consumers cannot express a
//     compatible-upgrade constraint
//   - the maintainer can rewrite history or move the default branch without
//     any versioned artifact remaining as a reference point
// Combined with dependent count this is a blast-radius signal, in the same
// family as concentration_risk rather than an accusation of wrongdoing.
//
// CRITICAL METHODOLOGICAL POINT (learned the hard way from Pattern A):
// "pseudo-version-only IN THE DATASET" is NOT the same as "pseudo-version-only
// in reality". The crawl frequently captured only the single pseudo-version a
// dependent happened to pin, even for modules with many tags -- golang.org/x/sys
// appears in the dataset solely as v0.0.0-20190306220234-b354f8bf4d9e despite
// having a full tag history. Measuring tag absence from the dataset therefore
// measures CRAWL COVERAGE, not release practice, and fails hardest on exactly
// the popular modules the pattern cares about.
//
// So tag absence is confirmed against the module proxy. <proxy>/<module>/@v/list
// returns TAGGED versions only (pseudo-versions are never listed), so an empty
// 200 response is authoritative evidence that the module has never tagged a
// release. Every finding records how tag absence was established.
//
// Usage:
//   go run scripts/pseudoversion_v1/main.go \
//     -dataset      data/dataset_combined.txt \
//     -patterns     data/output/risk_patterns.csv \
//     -out          data/output/pseudoversion_v1_candidates.csv \
//     -patterns-out data/output/pseudoversion_v1_patterns.csv \
//     -net [-workers 25] [-timeout 15] [-min-deps 5]
//
// Without -net the tool reports dataset-only evidence and warns that the
// figures are not suitable for evaluation.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type datasetLine struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

// pseudoRe matches all three Go pseudo-version forms: the timestamp and the
// 12-hex commit prefix are the invariant part.
var pseudoRe = regexp.MustCompile(`[-.]\d{14}-[0-9a-f]{12}$`)

var depCountRe = regexp.MustCompile(`dependent_count=(\d+)`)

type modStat struct {
	path      string
	total     int
	pseudo    int
	anExample string
}

type finding struct {
	module      string
	dependents  int
	dsTotal     int
	dsPseudo    int
	example     string
	tagCount    int
	evidence    string // proxy_no_tags | proxy_has_tags | dataset_only | proxy_error
	severity    string
}

func isPseudo(v string) bool { return pseudoRe.MatchString(v) }

func escapeModulePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// listTags asks the proxy for the module's tagged versions. An empty body with
// HTTP 200 means no tags have ever been published.
func listTags(client *http.Client, base, module string) (int, string) {
	url := strings.TrimSuffix(base, "/") + "/" + escapeModulePath(module) + "/@v/list"
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return -1, "proxy_error"
	}
	req.Header.Set("User-Agent", "go-supply-chain-analyzer/1.0 (MSc research)")
	resp, err := client.Do(req)
	if err != nil {
		return -1, "proxy_error"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		// module unknown to the proxy at all
		return 0, "proxy_no_tags"
	}
	if resp.StatusCode != http.StatusOK {
		return -1, "proxy_error"
	}
	n := 0
	for _, ln := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	if n == 0 {
		return 0, "proxy_no_tags"
	}
	return n, "proxy_has_tags"
}

func main() {
	datasetPath := flag.String("dataset", "data/dataset_combined.txt", "dataset JSON lines")
	patternsPath := flag.String("patterns", "data/output/risk_patterns.csv", "risk_patterns.csv (dependent_count source)")
	outPath := flag.String("out", "data/output/pseudoversion_v1_candidates.csv", "rich candidates CSV")
	patternsOut := flag.String("patterns-out", "data/output/pseudoversion_v1_patterns.csv", "risk_patterns.csv-shaped output")
	minDeps := flag.Int("min-deps", 5, "minimum dependents (gate)")
	doNet := flag.Bool("net", false, "confirm tag absence against the module proxy")
	proxyBase := flag.String("proxy", "https://proxy.golang.org", "module proxy base URL")
	workers := flag.Int("workers", 25, "proxy worker pool size")
	timeoutS := flag.Int("timeout", 15, "per-request timeout seconds")
	flag.Parse()

	deps, err := loadDependentCounts(*patternsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load patterns:", err)
		os.Exit(1)
	}
	stats, err := loadModStats(*datasetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load dataset:", err)
		os.Exit(1)
	}

	// candidates: enough dependents, and every dataset version is a pseudo-version
	var cands []*finding
	var gatedDeps, gatedTagged int
	for modLower, count := range deps {
		if count < *minDeps {
			gatedDeps++
			continue
		}
		st, ok := stats[modLower]
		if !ok || st.total == 0 {
			continue
		}
		if st.pseudo != st.total {
			gatedTagged++ // dataset already proves a tagged release exists
			continue
		}
		cands = append(cands, &finding{
			module: st.path, dependents: count,
			dsTotal: st.total, dsPseudo: st.pseudo, example: st.anExample,
			tagCount: -1, evidence: "dataset_only",
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].module < cands[j].module })
	fmt.Printf("Dependents table: %d | dataset modules: %d\n", len(deps), len(stats))
	fmt.Printf("Gated: below-min-deps=%d has-tagged-version-in-dataset=%d\n", gatedDeps, gatedTagged)
	fmt.Printf("Dataset-only pseudo-version candidates: %d\n", len(cands))

	tally := map[string]int{}
	if *doNet {
		fmt.Printf("Confirming tag absence via %s (%d workers)...\n", *proxyBase, *workers)
		client := &http.Client{
			Timeout: time.Duration(*timeoutS) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConns:        *workers * 2,
				MaxIdleConnsPerHost: *workers,
			},
		}
		jobs := make(chan *finding)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var done int
		for i := 0; i < *workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for f := range jobs {
					n, ev := listTags(client, *proxyBase, f.module)
					mu.Lock()
					f.tagCount, f.evidence = n, ev
					tally[ev]++
					done++
					if done%250 == 0 {
						fmt.Printf("  %d/%d\n", done, len(cands))
					}
					mu.Unlock()
				}
			}()
		}
		for _, f := range cands {
			jobs <- f
		}
		close(jobs)
		wg.Wait()
	} else {
		fmt.Println("WARNING: no -net. Tag absence is inferred from the dataset only,")
		fmt.Println("which measures crawl coverage rather than release practice.")
		fmt.Println("These numbers are NOT suitable for evaluation. Re-run with -net.")
	}

	// findings: with -net keep only proxy-confirmed; without, keep all (warned)
	var findings []*finding
	for _, f := range cands {
		if *doNet && f.evidence != "proxy_no_tags" {
			continue
		}
		switch {
		case f.dependents >= 100:
			f.severity = "high"
		case f.dependents >= 20:
			f.severity = "medium"
		default:
			f.severity = "low"
		}
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].dependents > findings[j].dependents })

	if err := writeRich(*outPath, findings); err != nil {
		fmt.Fprintln(os.Stderr, "write out:", err)
		os.Exit(1)
	}
	if err := writePatterns(*patternsOut, findings); err != nil {
		fmt.Fprintln(os.Stderr, "write patterns-out:", err)
		os.Exit(1)
	}

	var hi, med, low, blast int
	for _, f := range findings {
		switch f.severity {
		case "high":
			hi++
		case "medium":
			med++
		default:
			low++
		}
		blast += f.dependents
	}
	fmt.Printf("\nFlagged: %d (high=%d medium=%d low=%d)\n", len(findings), hi, med, low)
	fmt.Printf("Total dependent edges pinned to untagged commits: %d\n", blast)
	if len(tally) > 0 {
		fmt.Println("Proxy evidence tally:")
		var ks []string
		for k := range tally {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Printf("  %-16s %d\n", k, tally[k])
		}
		fmt.Printf("  (proxy_has_tags = dataset-only false positives eliminated)\n")
	}
	n := len(findings)
	if n > 15 {
		n = 15
	}
	if n > 0 {
		fmt.Println("Top by dependents:")
		for _, f := range findings[:n] {
			fmt.Printf("  %-45s deps=%-6d versions=%d [%s/%s]\n",
				f.module, f.dependents, f.dsTotal, f.severity, f.evidence)
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
			continue
		}
		if len(row) < 4 || row[1] != "concentration_risk" {
			continue
		}
		m := depCountRe.FindStringSubmatch(row[3])
		if m == nil {
			continue
		}
		c, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		k := strings.ToLower(row[0])
		if c > out[k] {
			out[k] = c
		}
	}
	return out, nil
}

func loadModStats(path string) (map[string]*modStat, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stats := map[string]*modStat{}
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
		k := strings.ToLower(dl.Path)
		st := stats[k]
		if st == nil {
			st = &modStat{path: dl.Path}
			stats[k] = st
		}
		st.total++
		if isPseudo(dl.Version) {
			st.pseudo++
			if st.anExample == "" {
				st.anExample = dl.Version
			}
		}
	}
	return stats, sc.Err()
}

func writeRich(path string, findings []*finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	fmt.Fprintln(w, "module,dependent_count,dataset_versions,dataset_pseudo,example_version,proxy_tag_count,evidence,severity")
	for _, x := range findings {
		fmt.Fprintf(w, "%s,%d,%d,%d,%s,%d,%s,%s\n",
			x.module, x.dependents, x.dsTotal, x.dsPseudo, x.example,
			x.tagCount, x.evidence, x.severity)
	}
	return nil
}

func writePatterns(path string, findings []*finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"module_path", "pattern_type", "severity", "details", "detected_at"})
	detected := time.Now().UTC().Format(time.RFC3339)
	for _, x := range findings {
		details := fmt.Sprintf("dependent_count=%d dataset_versions=%d evidence=%s example=%s",
			x.dependents, x.dsTotal, x.evidence, x.example)
		w.Write([]string{x.module, "pseudoversion_only", x.severity, details, detected})
	}
	return nil
}
