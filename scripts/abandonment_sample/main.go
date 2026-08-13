// abandonment_sample draws a reproducible stratified random sample from the
// abandonment_v2 findings and enriches each row with the ground truth that is
// actually appropriate for abandonment.
//
// Why not the vulnerability database: measuring abandonment against
// vuln.go.dev is invalid. Within the same popularity-controlled population,
// abandoned modules match known vulnerabilities at ~4.6% while actively
// maintained ones match at ~13.6% — advisories are an artifact of maintenance
// attention (someone auditing, triaging and disclosing), so a vuln DB measures
// SCRUTINY rather than INSECURITY and penalises a correct abandonment
// detector. The appropriate ground truth is maintenance status itself:
//
//   archived        - repository explicitly archived by its owner
//   pushed_at       - last push to the default branch (activity, not releases)
//   open_issues     - unattended issue backlog
//
// Sampling is stratified by abandonment score so the estimate is not dominated
// by the long tail, and seeded so the draw is reproducible for the write-up.
//
// Usage:
//   export GITHUB_TOKEN=...   # 60 req/h unauthenticated, 5000 with a token
//   go run scripts/abandonment_sample/main.go \
//     -candidates data/output/abandonment_v2_candidates.csv \
//     -n 50 -seed 42 \
//     -out        data/output/abandonment_sample_worksheet.csv \
//     -snyk-out   data/output/abandonment_sample_snyk_targets.txt
//
// The worksheet has blank `classification` and `notes` columns: fill them in
// by hand (abandoned / maintained / finished / unclear). "finished" is the key
// distinction — go-spew and beorn7/perks are low-churn because they are
// complete, not neglected, and conflating the two is the central construct
// validity threat for this pattern.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type finding struct {
	module     string
	dependents int
	lastRel    string
	years      float64
	latest     string
	relSource  string
	score      float64
	severity   string
	// enrichment
	ghOwner    string
	ghRepo     string
	ghArchived string
	ghPushedAt string
	ghIssues   string
	ghStatus   string
}

type repoInfo struct {
	Archived   bool   `json:"archived"`
	PushedAt   string `json:"pushed_at"`
	OpenIssues int    `json:"open_issues_count"`
	Message    string `json:"message"`
}

// githubCoords returns owner/repo for a github.com module path, else false.
func githubCoords(module string) (string, string, bool) {
	if !strings.HasPrefix(module, "github.com/") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(module, "/"), "/")
	if len(parts) < 3 {
		return "", "", false
	}
	repo := strings.TrimSuffix(parts[2], ".git")
	return parts[1], repo, true
}

func fetchRepo(client *http.Client, token, owner, repo string) (repoInfo, string) {
	url := "https://api.github.com/repos/" + owner + "/" + repo
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return repoInfo{}, "req_error"
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "go-supply-chain-analyzer/1.0 (MSc research)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return repoInfo{}, "net_error"
	}
	defer resp.Body.Close()
	var ri repoInfo
	dec := json.NewDecoder(resp.Body)
	_ = dec.Decode(&ri)
	switch resp.StatusCode {
	case 200:
		return ri, "ok"
	case 404:
		return repoInfo{}, "not_found"
	case 403, 429:
		return repoInfo{}, "rate_limited"
	}
	return repoInfo{}, "http_" + strconv.Itoa(resp.StatusCode)
}

func main() {
	candPath := flag.String("candidates", "data/output/abandonment_v2_candidates.csv", "abandonment_v2 candidates CSV")
	n := flag.Int("n", 50, "sample size")
	seed := flag.Int64("seed", 42, "RNG seed (record this in the write-up)")
	strata := flag.Int("strata", 5, "number of score strata")
	outPath := flag.String("out", "data/output/abandonment_sample_worksheet.csv", "classification worksheet")
	snykOut := flag.String("snyk-out", "data/output/abandonment_sample_snyk_targets.txt", "module list for Snyk corroboration")
	workers := flag.Int("workers", 8, "GitHub API workers")
	flag.Parse()

	f, err := os.Open(*candPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open candidates:", err)
		os.Exit(1)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read candidates:", err)
		os.Exit(1)
	}

	var all []*finding
	for i, row := range rows {
		if i == 0 || len(row) < 9 {
			continue
		}
		deps, _ := strconv.Atoi(row[1])
		yrs, _ := strconv.ParseFloat(row[3], 64)
		sc, _ := strconv.ParseFloat(row[7], 64)
		all = append(all, &finding{
			module: row[0], dependents: deps, lastRel: row[2], years: yrs,
			latest: row[4], relSource: row[5], score: sc, severity: row[8],
		})
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "no findings parsed from", *candPath)
		os.Exit(1)
	}
	fmt.Printf("Population: %d findings\n", len(all))

	// ---- stratified sample by score ----
	sort.Slice(all, func(i, j int) bool { return all[i].score > all[j].score })
	rng := rand.New(rand.NewSource(*seed))
	perStratum := *n / *strata
	extra := *n % *strata
	size := len(all) / *strata
	var sample []*finding
	for s := 0; s < *strata; s++ {
		lo := s * size
		hi := lo + size
		if s == *strata-1 {
			hi = len(all)
		}
		bucket := make([]*finding, hi-lo)
		copy(bucket, all[lo:hi])
		rng.Shuffle(len(bucket), func(i, j int) { bucket[i], bucket[j] = bucket[j], bucket[i] })
		take := perStratum
		if s < extra {
			take++
		}
		if take > len(bucket) {
			take = len(bucket)
		}
		sample = append(sample, bucket[:take]...)
		fmt.Printf("  stratum %d: population %d, sampled %d (score %.0f..%.0f)\n",
			s+1, hi-lo, take, all[hi-1].score, all[lo].score)
	}
	fmt.Printf("Sample size: %d (seed %d)\n", len(sample), *seed)

	// ---- enrich from GitHub ----
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("NOTE: GITHUB_TOKEN unset — unauthenticated limit is 60 requests/hour.")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	jobs := make(chan *finding)
	var wg sync.WaitGroup
	var mu sync.Mutex
	tally := map[string]int{}
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := range jobs {
				owner, repo, ok := githubCoords(x.module)
				if !ok {
					mu.Lock()
					x.ghStatus = "not_github"
					tally["not_github"]++
					mu.Unlock()
					continue
				}
				x.ghOwner, x.ghRepo = owner, repo
				ri, status := fetchRepo(client, token, owner, repo)
				mu.Lock()
				x.ghStatus = status
				tally[status]++
				mu.Unlock()
				if status == "ok" {
					x.ghArchived = strconv.FormatBool(ri.Archived)
					x.ghPushedAt = ri.PushedAt
					x.ghIssues = strconv.Itoa(ri.OpenIssues)
				}
				time.Sleep(120 * time.Millisecond) // be polite
			}
		}()
	}
	for _, x := range sample {
		jobs <- x
	}
	close(jobs)
	wg.Wait()

	// ---- worksheet ----
	of, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	w := csv.NewWriter(of)
	w.Write([]string{"module", "dependent_count", "years_since_release", "latest_version",
		"abandonment_score", "severity", "release_source",
		"gh_archived", "gh_last_push", "gh_open_issues", "gh_status",
		"classification", "notes"})
	sort.Slice(sample, func(i, j int) bool { return sample[i].score > sample[j].score })
	archived := 0
	for _, x := range sample {
		if x.ghArchived == "true" {
			archived++
		}
		w.Write([]string{x.module, strconv.Itoa(x.dependents),
			fmt.Sprintf("%.2f", x.years), x.latest,
			fmt.Sprintf("%.1f", x.score), x.severity, x.relSource,
			x.ghArchived, x.ghPushedAt, x.ghIssues, x.ghStatus, "", ""})
	}
	w.Flush()
	of.Close()

	// ---- snyk target list ----
	sf, err := os.Create(*snykOut)
	if err == nil {
		bw := bufio.NewWriter(sf)
		for _, x := range sample {
			fmt.Fprintln(bw, x.module)
		}
		bw.Flush()
		sf.Close()
	}

	fmt.Println("GitHub lookup tally:")
	var ks []string
	for k := range tally {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Printf("  %-14s %d\n", k, tally[k])
	}
	fmt.Printf("Explicitly archived in sample: %d of %d (%.1f%%)\n",
		archived, len(sample), 100*float64(archived)/float64(len(sample)))
	fmt.Println("Wrote", *outPath, "and", *snykOut)
	fmt.Println("Now fill the classification column by hand: abandoned | maintained | finished | unclear")
}
