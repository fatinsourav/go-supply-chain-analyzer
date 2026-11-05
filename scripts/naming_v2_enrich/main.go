// naming_v2_enrich enriches naming_v2 candidate pairs with temporal and
// popularity evidence, applies documented exclusions, and ranks the survivors
// for manual inspection.
//
// Rationale: a typosquat must be published AFTER its target became worth
// impersonating, and must be substantially less depended upon than the target.
// naming_v2 emits candidates on string similarity alone, which cannot separate
// coincidental collisions between independent projects from impersonation.
// This tool adds the two signals that can, using data already present in the
// module index dump (first-seen timestamps) and, optionally, dependent counts.
//
// Nothing is silently discarded: every input pair appears in the enriched
// output with an explicit exclusion reason (empty = retained), so the funnel
// is auditable and each stage is reportable.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- module path helpers ----------

func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// pathParts splits a module path, dropping a trailing /vN major-version suffix.
func pathParts(modulePath string) []string {
	p := strings.TrimSpace(strings.ToLower(modulePath))
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	if n := len(parts); n > 1 && isMajorVersion(parts[n-1]) {
		parts = parts[:n-1]
	}
	return parts
}

func host(modulePath string) string {
	parts := pathParts(modulePath)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// depth is the number of meaningful path components (host counts as one).
// github.com/spf13/cobra -> 3.  A depth > 3 on a forge host means the match
// was made on a subdirectory segment rather than a repository name.
func depth(modulePath string) int {
	return len(pathParts(modulePath))
}

var forgeHosts = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true,
	"codeberg.org": true, "sr.ht": true, "git.sr.ht": true,
}

// repoOwner returns the account that controls the namespace.  For forge hosts
// this is unambiguously the component after the host.  naming_v2 instead used
// the second-to-last segment, which on deep paths yields a directory name
// ("services", "provider") rather than an owner -- the deep-path artifact.
func repoOwner(modulePath string) string {
	parts := pathParts(modulePath)
	if len(parts) < 2 {
		return ""
	}
	if forgeHosts[parts[0]] {
		return parts[1]
	}
	// Vanity/self-hosted: fall back to the second-to-last component, matching
	// naming_v2 behaviour, but only when the path is shallow enough that the
	// component is plausibly an owner rather than a directory.
	if len(parts) >= 3 {
		return parts[len(parts)-2]
	}
	return parts[0]
}

// lastSegment returns the final meaningful path component -- the package
// name a developer actually types.  Major-version suffixes are stripped by
// pathParts, so .../httpware/v2 yields "httpware".
func lastSegment(modulePath string) string {
	parts := pathParts(modulePath)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ---------- dataset first-seen index ----------

type datasetLine struct {
	Path      string    `json:"Path"`
	Version   string    `json:"Version"`
	Timestamp time.Time `json:"Timestamp"`
}

type moduleTime struct {
	firstSeen time.Time
	versions  int
}

// buildFirstSeen folds the module index dump into one record per module path,
// keeping the earliest timestamp.  This mirrors the last-release fold in
// abandonment_v2 with the comparison inverted.
func buildFirstSeen(path string) (map[string]moduleTime, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	idx := make(map[string]moduleTime, 300000)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lines, parsed := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		var dl datasetLine
		if json.Unmarshal([]byte(line), &dl) != nil || dl.Path == "" {
			continue
		}
		parsed++
		key := strings.ToLower(dl.Path)
		st, ok := idx[key]
		if !ok {
			idx[key] = moduleTime{firstSeen: dl.Timestamp, versions: 1}
			continue
		}
		st.versions++
		if !dl.Timestamp.IsZero() && (st.firstSeen.IsZero() || dl.Timestamp.Before(st.firstSeen)) {
			st.firstSeen = dl.Timestamp
		}
		idx[key] = st
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "dataset: %d lines, %d parsed, %d distinct modules\n", lines, parsed, len(idx))
	return idx, nil
}

// ---------- target popularity ranks ----------

// loadTargetRanks reads the popular-target list, which is emitted in
// descending dependent-count order.  Line position is therefore a usable
// ordinal proxy for target popularity: rank 1 is the most depended-upon
// module in the ecosystem.  This is an ordinal, not a count -- the gap
// between rank 1 and rank 2 is not the gap between rank 500 and 501 -- so it
// is used only to order candidates, never as a magnitude.
func loadTargetRanks(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ranks := map[string]int{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		p := strings.ToLower(strings.TrimSpace(sc.Text()))
		if p == "" {
			continue
		}
		n++
		if _, seen := ranks[p]; !seen {
			ranks[p] = n
		}
	}
	return ranks, sc.Err()
}

// ---------- optional dependent counts ----------

// loadDeps reads "module,count" pairs.  Accepts an optional header line and
// ignores any extra columns, so it tolerates whatever the concentration
// exporter produced.
func loadDeps(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	deps := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		mod := strings.ToLower(strings.TrimSpace(fields[0]))
		n, err := strconv.Atoi(strings.TrimSpace(fields[1]))
		if err != nil {
			continue // header or malformed row
		}
		deps[mod] = n
	}
	return deps, sc.Err()
}

// ---------- enrichment ----------

type record struct {
	candidate    string
	candSeg      string
	target       string
	targetSeg    string
	technique    string
	crossHost    bool
	candFirst    time.Time
	targFirst    time.Time
	lagDays      int
	postdates    bool
	candVersions int
	targetRank   int
	candDeps     int
	targDeps     int
	depsKnown    bool
	excluded     string
	score        float64
}

func main() {
	candPath := flag.String("candidates", "data/output/naming_v2_candidates.csv", "naming_v2 candidate CSV")
	dsPath := flag.String("dataset", "data/dataset_combined.txt", "module index dump (JSON lines)")
	targetsPath := flag.String("targets", "data/output/popular_targets.txt", "popular targets, in descending dependent-count order")
	depsPath := flag.String("deps", "", "optional CSV of module,dependent_count")
	outPath := flag.String("out", "data/output/naming_v2_enriched.csv", "enriched output CSV")
	topPath := flag.String("top", "data/output/naming_v2_top.csv", "ranked shortlist for manual inspection")
	reportPath := flag.String("report", "data/output/naming_v2_funnel.md", "funnel + breakdown report")
	topN := flag.Int("topn", 50, "size of the ranked shortlist")
	maxDepth := flag.Int("maxdepth", 3, "max path depth on forge hosts; deeper matches are subdirectory artifacts")
	flag.Parse()

	firstSeen, err := buildFirstSeen(*dsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dataset:", err)
		os.Exit(1)
	}

	ranks, err := loadTargetRanks(*targetsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "targets:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "targets: %d ranked popular modules\n", len(ranks))

	var deps map[string]int
	if *depsPath != "" {
		deps, err = loadDeps(*depsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deps:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "deps: %d modules with dependent counts\n", len(deps))
	}

	cf, err := os.Open(*candPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidates:", err)
		os.Exit(1)
	}
	defer cf.Close()
	r := csv.NewReader(cf)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse candidates:", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "candidates file is empty")
		os.Exit(1)
	}
	start := 0
	if strings.EqualFold(strings.TrimSpace(rows[0][0]), "candidate_module") {
		start = 1
	}

	var recs []record
	for _, row := range rows[start:] {
		if len(row) < 5 {
			continue
		}
		rec := record{
			candidate: strings.TrimSpace(row[0]),
			candSeg:   strings.TrimSpace(row[1]),
			target:    strings.TrimSpace(row[2]),
			targetSeg: strings.TrimSpace(row[3]),
			technique: strings.TrimSpace(row[4]),
		}
		if len(row) >= 6 {
			rec.crossHost = strings.EqualFold(strings.TrimSpace(row[5]), "true")
		}

		ck := strings.ToLower(rec.candidate)
		tk := strings.ToLower(rec.target)

		if mt, ok := firstSeen[ck]; ok {
			rec.candFirst = mt.firstSeen
			rec.candVersions = mt.versions
		}
		if mt, ok := firstSeen[tk]; ok {
			rec.targFirst = mt.firstSeen
		}
		if !rec.candFirst.IsZero() && !rec.targFirst.IsZero() {
			rec.lagDays = int(rec.candFirst.Sub(rec.targFirst).Hours() / 24)
			rec.postdates = rec.candFirst.After(rec.targFirst)
		}
		rec.targetRank = ranks[tk] // 0 = not in the ranked list
		if deps != nil {
			rec.candDeps = deps[ck]
			rec.targDeps = deps[tk]
			_, okT := deps[tk]
			rec.depsKnown = okT
		}

		// --- exclusions, in a fixed order so the funnel is well defined ---
		switch {
		case repoOwner(rec.candidate) != "" && repoOwner(rec.candidate) == repoOwner(rec.target):
			// Same account controls both: a project's own naming variants,
			// e.g. testcontainers/testcontainer-go. Cannot be impersonation.
			rec.excluded = "same_owner"

		case forgeHosts[host(rec.candidate)] && depth(rec.candidate) > *maxDepth:
			// Match landed on a subdirectory segment, not a repository name.
			rec.excluded = "deep_path_candidate"

		case forgeHosts[host(rec.target)] && depth(rec.target) > *maxDepth:
			rec.excluded = "deep_path_target"

		case strings.HasPrefix(rec.technique, "owner-") &&
			lastSegment(rec.candidate) != lastSegment(rec.target):
			// An owner-level edit is only an impersonation attempt if the
			// package name is preserved: the developer types the package
			// name, so a squat must keep it and vary only the account.  The
			// one documented Go owner-squat, boltdb-go/bolt against
			// boltdb/bolt, has exactly this shape.  Without the constraint,
			// owner matching pairs every repository a similarly-named account
			// happens to own against every target that account published.
			rec.excluded = "owner_segment_mismatch"

		case rec.candFirst.IsZero() || rec.targFirst.IsZero():
			rec.excluded = "no_timestamp"

		case !rec.postdates:
			// Candidate existed before the target. Whatever the string
			// similarity, it was not created to impersonate it.
			rec.excluded = "predates_target"

		case rec.depsKnown && rec.candDeps >= rec.targDeps:
			// No popularity asymmetry: impersonation requires the target to be
			// the more depended-upon of the pair.
			rec.excluded = "no_popularity_gap"
		}

		// --- ranking score for retained rows ---
		if rec.excluded == "" {
			// Primary term: how attractive the target is to impersonate.
			// Rank 1 is the most depended-upon module in the ecosystem, so a
			// candidate shadowing it is a categorically more serious object
			// than one shadowing rank 900.  Ordinal, so used only to order.
			rank := rec.targetRank
			if rank <= 0 {
				rank = len(ranks) + 1 // unranked target: sort last
			}
			popularity := float64(len(ranks)) / float64(rank)

			// Secondary term: candidate obscurity.  A module with a single
			// captured version is the classic squat shape; an established
			// project with many releases is more likely an independent one.
			obscurity := 1.0
			if rec.candVersions > 0 {
				obscurity = 1.0 + 1.0/float64(rec.candVersions)
			}

			// Publication lag is deliberately NOT scored.  The dataset holds
			// index timestamps for whichever version the crawl captured, not
			// true first-publication dates, so lag is reported for context
			// and verified against the module proxy before it is relied on.
			rec.score = popularity * obscurity

			if rec.depsKnown && rec.targDeps > 0 {
				rec.score *= 1.0 + float64(rec.targDeps-rec.candDeps)/float64(rec.targDeps)
			}
		}
		recs = append(recs, rec)
	}

	// ---------- write enriched CSV ----------
	of, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	w := csv.NewWriter(of)
	w.Write([]string{
		"candidate_module", "candidate_segment", "target_module", "target_segment",
		"technique", "cross_host", "candidate_first_seen", "target_first_seen",
		"lag_days", "postdates_target", "candidate_versions", "target_rank",
		"candidate_deps", "target_deps", "score", "excluded_reason",
	})
	fmtTime := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02")
	}
	for _, rec := range recs {
		w.Write([]string{
			rec.candidate, rec.candSeg, rec.target, rec.targetSeg,
			rec.technique, strconv.FormatBool(rec.crossHost),
			fmtTime(rec.candFirst), fmtTime(rec.targFirst),
			strconv.Itoa(rec.lagDays), strconv.FormatBool(rec.postdates),
			strconv.Itoa(rec.candVersions), strconv.Itoa(rec.targetRank),
			strconv.Itoa(rec.candDeps), strconv.Itoa(rec.targDeps),
			strconv.FormatFloat(rec.score, 'f', 2, 64), rec.excluded,
		})
	}
	w.Flush()
	of.Close()

	// ---------- ranked shortlist ----------
	var kept []record
	for _, rec := range recs {
		if rec.excluded == "" {
			kept = append(kept, rec)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].score != kept[j].score {
			return kept[i].score > kept[j].score
		}
		if kept[i].candVersions != kept[j].candVersions {
			return kept[i].candVersions < kept[j].candVersions
		}
		return kept[i].candidate < kept[j].candidate
	})
	n := *topN
	if n > len(kept) {
		n = len(kept)
	}
	tf, err := os.Create(*topPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create top:", err)
		os.Exit(1)
	}
	tw := csv.NewWriter(tf)
	tw.Write([]string{
		"rank", "candidate_module", "target_module", "target_rank", "technique",
		"lag_days", "candidate_versions", "candidate_deps", "target_deps",
		"score", "manual_verdict", "justification",
	})
	for i := 0; i < n; i++ {
		rec := kept[i]
		tw.Write([]string{
			strconv.Itoa(i + 1), rec.candidate, rec.target,
			strconv.Itoa(rec.targetRank), rec.technique,
			strconv.Itoa(rec.lagDays), strconv.Itoa(rec.candVersions),
			strconv.Itoa(rec.candDeps), strconv.Itoa(rec.targDeps),
			strconv.FormatFloat(rec.score, 'f', 2, 64), "", "",
		})
	}
	tw.Flush()
	tf.Close()

	// ---------- funnel + breakdown report ----------
	order := []string{
		"same_owner", "deep_path_candidate", "deep_path_target",
		"owner_segment_mismatch", "no_timestamp", "predates_target",
		"no_popularity_gap",
	}
	label := map[string]string{
		"same_owner":             "Same owner controls both paths",
		"deep_path_candidate":    "Match on candidate subdirectory segment",
		"deep_path_target":       "Match on target subdirectory segment",
		"owner_segment_mismatch": "Owner-level match, package name differs",
		"no_timestamp":           "Timestamp unavailable for one side",
		"predates_target":        "Candidate predates its target",
		"no_popularity_gap":      "Candidate at least as depended-upon as target",
	}
	byReason := map[string]int{}
	techTotal := map[string]int{}
	techKept := map[string]int{}
	for _, rec := range recs {
		techTotal[rec.technique]++
		if rec.excluded == "" {
			techKept[rec.technique]++
		} else {
			byReason[rec.excluded]++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# naming_v2 candidate enrichment\n\n")
	fmt.Fprintf(&b, "Input pairs: %d\n\n", len(recs))
	if deps == nil {
		fmt.Fprintf(&b, "Dependent counts were not supplied; the popularity-gap "+
			"filter and its score term are inactive in this run.\n\n")
	}
	fmt.Fprintf(&b, "## Exclusion funnel\n\n")
	fmt.Fprintf(&b, "| Stage | Excluded | Remaining |\n|---|---:|---:|\n")
	remaining := len(recs)
	fmt.Fprintf(&b, "| Input | - | %d |\n", remaining)
	for _, k := range order {
		if byReason[k] == 0 {
			continue
		}
		remaining -= byReason[k]
		fmt.Fprintf(&b, "| %s | %d | %d |\n", label[k], byReason[k], remaining)
	}
	fmt.Fprintf(&b, "\nRetained for inspection: **%d** (%.2f%% of input)\n\n",
		len(kept), 100*float64(len(kept))/float64(max(1, len(recs))))

	fmt.Fprintf(&b, "## Per-technique retention\n\n")
	fmt.Fprintf(&b, "| Technique | Input | Retained | Retention |\n|---|---:|---:|---:|\n")
	var techs []string
	for t := range techTotal {
		techs = append(techs, t)
	}
	sort.Slice(techs, func(i, j int) bool { return techTotal[techs[i]] > techTotal[techs[j]] })
	for _, t := range techs {
		pct := 100 * float64(techKept[t]) / float64(max(1, techTotal[t]))
		fmt.Fprintf(&b, "| `%s` | %d | %d | %.1f%% |\n", t, techTotal[t], techKept[t], pct)
	}
	fmt.Fprintf(&b, "\nA technique that retains nothing after temporal and ownership "+
		"filtering is generating string collisions rather than impersonation "+
		"candidates, and its cost is not repaid.\n")

	// Per-target concentration: one target monopolising the retained set is a
	// generic-owner-string artifact, not a cluster of real impersonations.
	tgtTotal := map[string]int{}
	tgtKept := map[string]int{}
	for _, rec := range recs {
		tgtTotal[rec.target]++
		if rec.excluded == "" {
			tgtKept[rec.target]++
		}
	}
	var tgts []string
	for t := range tgtKept {
		if tgtKept[t] > 0 {
			tgts = append(tgts, t)
		}
	}
	sort.Slice(tgts, func(i, j int) bool {
		if tgtKept[tgts[i]] != tgtKept[tgts[j]] {
			return tgtKept[tgts[i]] > tgtKept[tgts[j]]
		}
		return tgts[i] < tgts[j]
	})
	fmt.Fprintf(&b, "\n## Most-flagged targets (retained)\n\n")
	fmt.Fprintf(&b, "| Target | Input | Retained | Share of retained |\n|---|---:|---:|---:|\n")
	lim := 15
	if lim > len(tgts) {
		lim = len(tgts)
	}
	for i := 0; i < lim; i++ {
		t := tgts[i]
		fmt.Fprintf(&b, "| `%s` | %d | %d | %.1f%% |\n",
			t, tgtTotal[t], tgtKept[t], 100*float64(tgtKept[t])/float64(max(1, len(kept))))
	}
	fmt.Fprintf(&b, "\nA single target accounting for a large share of the retained "+
		"set indicates a generic owner or package string rather than a cluster "+
		"of genuine impersonation attempts.\n")

	if err := os.WriteFile(*reportPath, []byte(b.String()), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		os.Exit(1)
	}

	fmt.Printf("input=%d retained=%d shortlist=%d\n", len(recs), len(kept), n)
	fmt.Printf("wrote %s, %s, %s\n", *outPath, *topPath, *reportPath)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
