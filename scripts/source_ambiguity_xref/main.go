// source_ambiguity_xref converts the source_ambiguity_v2 candidate CSV into a
// risk_patterns.csv-shaped file so it can be fed to verify_ground_truth and
// snyk_check without any glue code.
//
// The candidate CSV carries one row per flagged DOMAIN (with an exemplar
// module). Cross-referencing only the 12 exemplars would under-count: the
// unit of risk is the domain, but the unit the vuln databases key on is the
// MODULE. This expands each flagged domain back to every module in the
// dataset that declares it, so the cross-ref covers all affected modules.
//
// Usage:
//   go run scripts/source_ambiguity_xref/main.go \
//     -candidates data/output/source_ambiguity_v2_candidates.csv \
//     -dataset    data/dataset_combined.txt \
//     -out        data/output/source_ambiguity_v2_patterns.csv
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type datasetLine struct {
	Path      string    `json:"Path"`
	Timestamp time.Time `json:"Timestamp"`
}

type domainInfo struct {
	signals   string
	severity  string
	netStatus string
}

func extractDomain(modulePath string) string {
	p := strings.ToLower(strings.TrimSpace(modulePath))
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, ':'); i >= 0 {
		p = p[:i]
	}
	return p
}

func main() {
	candPath := flag.String("candidates", "data/output/source_ambiguity_v2_candidates.csv", "source_ambiguity_v2 candidates CSV")
	datasetPath := flag.String("dataset", "data/dataset_combined.txt", "dataset JSON lines")
	outPath := flag.String("out", "data/output/source_ambiguity_v2_patterns.csv", "risk_patterns.csv-shaped output")
	flag.Parse()

	// ---- flagged domains ----
	cf, err := os.Open(*candPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open candidates:", err)
		os.Exit(1)
	}
	r := csv.NewReader(cf)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	cf.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read candidates:", err)
		os.Exit(1)
	}

	flagged := map[string]domainInfo{}
	for i, row := range rows {
		if i == 0 || len(row) < 6 {
			continue
		}
		net := ""
		if len(row) >= 6 {
			net = row[5]
		}
		flagged[strings.ToLower(row[1])] = domainInfo{
			signals: row[3], severity: row[4], netStatus: net,
		}
	}
	if len(flagged) == 0 {
		fmt.Fprintln(os.Stderr, "no flagged domains found in", *candPath)
		os.Exit(1)
	}
	fmt.Printf("Flagged domains: %d\n", len(flagged))

	// ---- expand to every module on those domains ----
	df, err := os.Open(*datasetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open dataset:", err)
		os.Exit(1)
	}
	defer df.Close()

	type modRow struct {
		module string
		domain string
	}
	seen := map[string]bool{}
	var mods []modRow
	var maxTS time.Time
	scanned := 0

	sc := bufio.NewScanner(df)
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
		scanned++
		if dl.Timestamp.After(maxTS) {
			maxTS = dl.Timestamp
		}
		d := extractDomain(dl.Path)
		if _, ok := flagged[d]; !ok {
			continue
		}
		key := strings.ToLower(dl.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		mods = append(mods, modRow{module: dl.Path, domain: d})
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan dataset:", err)
		os.Exit(1)
	}

	sort.Slice(mods, func(i, j int) bool { return mods[i].module < mods[j].module })

	// ---- write ----
	of, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	defer of.Close()
	w := csv.NewWriter(of)
	defer w.Flush()
	w.Write([]string{"module_path", "pattern_type", "severity", "details", "detected_at"})
	detected := maxTS.Format(time.RFC3339)

	perDomain := map[string]int{}
	for _, m := range mods {
		info := flagged[m.domain]
		details := fmt.Sprintf("domain=%s signals=%s net_status=%s",
			m.domain, strings.ReplaceAll(info.signals, ",", ";"), info.netStatus)
		w.Write([]string{m.module, "source_ambiguity", info.severity, details, detected})
		perDomain[m.domain]++
	}

	fmt.Printf("Scanned %d dataset lines; expanded to %d unique modules\n", scanned, len(mods))
	fmt.Println("Modules per flagged domain:")
	var keys []string
	for k := range flagged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-50s %d  [%s]\n", k, perDomain[k], flagged[k].netStatus)
	}
	fmt.Println("Wrote", *outPath)
}
