// abandonment_v2 implements Pattern A with an authoritative release oracle.
//
// v1 defect: staleness was computed as "years since the newest release present
// in the dataset". For heavily-depended-upon modules the crawl often captured
// only an old v0.0.0-<date>-<hash> pseudo-version (what dependents pinned
// before those repos adopted semantic tags), so golang.org/x/sys, x/net,
// x/crypto and stretchr/testify were all reported ~5.8 years stale and
// dominated the results. That measured DATASET COVERAGE, not abandonment, and
// it failed hardest on exactly the high-dependent modules the pattern most
// needs to judge correctly. The tight cluster of identical staleness values
// was the tell.
//
// v2 therefore takes the last-release date from the Go module proxy
// (<proxy>/<module>/@latest), which returns the true latest version and its
// commit time, and falls back to the dataset timestamp only when the proxy has
// no answer. Every finding records which source its date came from, so the
// evaluation can be reported over proxy-verified modules alone.
//
// Score = dependents * years_since_last_release, with gates excluding the two
// degenerate corners (freshly-released popular modules, ancient unused ones).
//
// Usage:
//   go run scripts/abandonment_v2/main.go \
//     -dataset      data/dataset_combined.txt \
//     -patterns     data/output/risk_patterns.csv \
//     -out          data/output/abandonment_v2_candidates.csv \
//     -patterns-out data/output/abandonment_v2_patterns.csv \
//     -net [-workers 25] [-timeout 15] [-min-deps 5] [-min-years 2]
//
// Without -net it behaves like v1 (dataset dates) and prints a warning that
// the staleness figures are not authoritative.
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
	Path      string    `json:"Path"`
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
	releaseSource string // proxy | dataset
	latestVersion string
}

const hoursPerYear = 24 * 365.25

var depCountRe = regexp.MustCompile(`dependent_count=(\d+)`)

// escapeModulePath applies the Go module proxy's case encoding: an uppercase
// letter is written as '!' followed by its lowercase form. Without this,
// modules such as github.com/Masterminds/semver 404 on the proxy.
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

type latestInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// fetchLatest asks the module proxy for the authoritative newest release.
func fetchLatest(client *http.Client, base, module string) (latestInfo, string) {
	url := strings.TrimSuffix(base, "/") + "/" + escapeModulePath(module) + "/@latest"
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return latestInfo{}, "req_error"
	}
	req.Header.Set("User-Agent", "go-supply-chain-analyzer/1.0 (MSc research)")
	resp, err := client.Do(req)
	if err != nil {
		return latestInfo{}, "net_error"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return latestInfo{}, "not_found"
	}
	if resp.StatusCode != http.StatusOK {
		return latestInfo{}, "http_" + strconv.Itoa(resp.StatusCode)
	}
	var li latestInfo
	if json.Unmarshal(body, &li) != nil || li.Time.IsZero() {
		return latestInfo{}, "bad_json"
	}
	return li, "ok"
}

func main() {
	datasetPath := flag.String("dataset", "data/dataset_combined.txt", "dataset JSON lines")
	patternsPath := flag.String("patterns", "data/output/risk_patterns.csv", "risk_patterns.csv (source of dependent_count)")
	outPath := flag.String("out", "data/output/abandonment_v2_candidates.csv", "rich candidates CSV")
	patternsOut := flag.String("patterns-out", "data/output/abandonment_v2_patterns.csv", "risk_patterns.csv-shaped output")
	minDeps := flag.Int("min-deps", 5, "minimum dependents (gate)")
	minYears := flag.Float64("min-years", 2.0, "minimum years since last release (gate)")
	doNet := flag.Bool("net", false, "resolve authoritative release dates via the module proxy")
	proxyBase := flag.String("proxy", "https://proxy.golang.org", "module proxy base URL")
	workers := flag.Int("workers", 25, "proxy worker pool size")
	timeoutS := flag.Int("timeout", 15, "per-request timeout seconds")
	nowStr := flag.String("now", "", "reference date RFC3339; default = now when -net, else newest dataset release")
	flag.Parse()

	deps, err := loadDependentCounts(*patternsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load patterns:", err)
		os.Exit(1)
	}
	stats, maxTS, err := loadModuleStats(*datasetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load dataset:", err)
		os.Exit(1)
	}

	// candidate set: dependents gate only, dates resolved afterwards
	var cands []*finding
	var gatedDeps int
	for modLower, count := range deps {
		if count < *minDeps {
			gatedDeps++
			continue
		}
		path := modLower
		var ds time.Time
		var vers int
		if st, ok := stats[modLower]; ok {
			path, ds, vers = st.path, st.lastRelease, st.versions
		}
		cands = append(cands, &finding{
			module: path, dependents: count,
			lastRelease: ds, versions: vers, releaseSource: "dataset",
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].module < cands[j].module })
	fmt.Printf("Dependents table: %d modules | dataset modules: %d | candidates after min-deps: %d\n",
		len(deps), len(stats), len(cands))

	ref := maxTS
	if *doNet {
		ref = time.Now().UTC()
	}
	if *nowStr != "" {
		ref, err = time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parse -now:", err)
			os.Exit(1)
		}
	}

	statusTally := map[string]int{}
	if *doNet {
		fmt.Printf("Resolving release dates via %s (%d workers)...\n", *proxyBase, *workers)
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
					li, status := fetchLatest(client, *proxyBase, f.module)
					mu.Lock()
					statusTally[status]++
					done++
					if done%250 == 0 {
						fmt.Printf("  %d/%d\n", done, len(cands))
					}
					mu.Unlock()
					if status == "ok" {
						f.lastRelease = li.Time
						f.latestVersion = li.Version
						f.releaseSource = "proxy"
					}
				}
			}()
		}
		for _, f := range cands {
			jobs <- f
		}
		close(jobs)
		wg.Wait()
	} else {
		fmt.Println("WARNING: running without -net. Staleness comes from dataset timestamps,")
		fmt.Println("which systematically overstate staleness for popularity-skewed modules.")
		fmt.Println("These numbers are NOT suitable for evaluation. Re-run with -net.")
	}
	fmt.Printf("Reference date: %s\n", ref.Format("2006-01-02"))

	// score
	var findings []*finding
	var gatedYears, missingDate int
	for _, f := range cands {
		if f.lastRelease.IsZero() {
			missingDate++
			continue
		}
		f.yearsSince = ref.Sub(f.lastRelease).Hours() / hoursPerYear
		if f.yearsSince < *minYears {
			gatedYears++
			continue
		}
		f.score = float64(f.dependents) * f.yearsSince
		f.severity = "medium"
		if f.score >= 100 || (f.dependents >= 50 && f.yearsSince >= 3) {
			f.severity = "high"
		}
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].score > findings[j].score })

	if err := writeRich(*outPath, findings); err != nil {
		fmt.Fprintln(os.Stderr, "write out:", err)
		os.Exit(1)
	}
	if err := writePatterns(*patternsOut, findings, ref); err != nil {
		fmt.Fprintln(os.Stderr, "write patterns-out:", err)
		os.Exit(1)
	}

	var hi, med, proxyN int
	for _, f := range findings {
		if f.severity == "high" {
			hi++
		} else {
			med++
		}
		if f.releaseSource == "proxy" {
			proxyN++
		}
	}
	fmt.Printf("Gated out: below-min-deps=%d below-min-years=%d no-release-date=%d\n",
		gatedDeps, gatedYears, missingDate)
	fmt.Printf("Flagged: %d (high=%d medium=%d) | proxy-verified dates: %d of %d\n",
		len(findings), hi, med, proxyN, len(findings))
	if len(statusTally) > 0 {
		fmt.Println("Proxy status tally:")
		var ks []string
		for k := range statusTally {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Printf("  %-12s %d\n", k, statusTally[k])
		}
	}
	n := len(findings)
	if n > 15 {
		n = 15
	}
	if n > 0 {
		fmt.Println("Top by abandonment score:")
		for _, f := range findings[:n] {
			fmt.Printf("  %-45s deps=%-6d stale=%.1fy score=%.0f [%s/%s]\n",
				f.module, f.dependents, f.yearsSince, f.score, f.severity, f.releaseSource)
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
		k := strings.ToLower(dl.Path)
		st := stats[k]
		if st == nil {
			st = &moduleStat{path: dl.Path}
			stats[k] = st
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

func writeRich(path string, findings []*finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	fmt.Fprintln(w, "module,dependent_count,last_release,years_since_release,latest_version,release_source,version_count,abandonment_score,severity")
	for _, x := range findings {
		fmt.Fprintf(w, "%s,%d,%s,%.2f,%s,%s,%d,%.1f,%s\n",
			x.module, x.dependents, x.lastRelease.Format("2006-01-02"), x.yearsSince,
			x.latestVersion, x.releaseSource, x.versions, x.score, x.severity)
	}
	return nil
}

func writePatterns(path string, findings []*finding, ref time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"module_path", "pattern_type", "severity", "details", "detected_at"})
	detected := ref.Format(time.RFC3339)
	for _, x := range findings {
		details := fmt.Sprintf("dependent_count=%d years_since_release=%.2f score=%.1f release_source=%s latest=%s",
			x.dependents, x.yearsSince, x.score, x.releaseSource, x.latestVersion)
		w.Write([]string{x.module, "abandonment_risk", x.severity, details, detected})
	}
	return nil
}
