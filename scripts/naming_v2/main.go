package main

import (
"bufio"
"encoding/json"
"flag"
"fmt"
"os"
"strings"
)

type moduleLine struct {
Path string `json:"Path"`
}

var genericNames = map[string]bool{"errors":true,"error":true,"crypt":true,"crypto":true,"metrics":true,"metric":true,"config":true,"configs":true,"oauth":true,"oauth2":true,"logger":true,"logging":true,"common":true,"commons":true,"utils":true,"util":true,"client":true,"clients":true,"server":true,"cache":true,"queue":true,"worker":true,"session":true,"sessions":true,"locale":true,"locales":true,"tracer":true,"trace":true,"tracing":true,"goutils":true,"gotils":true,"jsonpath":true,"jsonpatch":true,"structtag":true,"structtags":true,"state":true,"stats":true,"clock":true,"flock":true,"pkcs7":true,"pkcs8":true,"goversion":true,"version":true,"versions":true,"sconfig":true,"goflags":true,"flags":true,"xerrors":true}

func baseName(seg string) string {
s := strings.ToLower(seg)
s = strings.TrimPrefix(s, "go-")
s = strings.TrimSuffix(s, "-go")
s = strings.TrimPrefix(s, "go")
return s
}

func isGeneric(seg string) bool {
if genericNames[seg] {
return true
}
return genericNames[baseName(seg)]
}

func lastSegment(modulePath string) string {
p := strings.ToLower(strings.TrimSpace(modulePath))
if p == "" {
return ""
}
parts := strings.Split(p, "/")
i := len(parts) - 1
if i > 0 && isMajorVersion(parts[i]) {
i--
}
return parts[i]
}

func isMajorVersion(s string) bool {
if len(s) < 2 || s[0] != 'v' {
return false
}
for _, r := range s[1:] {
if r < '0' || r > '9' {
return false
}
}
return true
}

func stripVersionSuffix(seg string) string {
 if i := strings.LastIndex(seg, "."); i > 0 {
  suf := seg[i+1:]
  if len(suf) >= 2 && suf[0] == 'v' {
   allDigit := true
   for _, r := range suf[1:] {
    if r < '0' || r > '9' {
     allDigit = false
     break
    }
   }
   if allDigit {
    return seg[:i]
   }
  }
 }
 return seg
}

func sameProjectDifferentVersion(a, b string) bool {
 ba, bb := stripVersionSuffix(a), stripVersionSuffix(b)
 return ba == bb && (ba != a || bb != b)
}

func host(modulePath string) string {
p := strings.ToLower(strings.TrimSpace(modulePath))
if i := strings.IndexByte(p, '/'); i >= 0 {
return p[:i]
}
return p
}

func normalizeSeparators(s string) string {
return strings.NewReplacer("-", "", "_", "", ".", "").Replace(s)
}

func levenshtein(a, b string) int {
la, lb := len(a), len(b)
if la == 0 {
return lb
}
if lb == 0 {
return la
}
prev := make([]int, lb+1)
cur := make([]int, lb+1)
for j := 0; j <= lb; j++ {
prev[j] = j
}
for i := 1; i <= la; i++ {
cur[0] = i
for j := 1; j <= lb; j++ {
cost := 1
if a[i-1] == b[j-1] {
cost = 0
}
cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
}
prev, cur = cur, prev
}
return prev[lb]
}

func min3(a, b, c int) int {
m := a
if b < m {
m = b
}
if c < m {
m = c
}
return m
}

func technique(c, t string) string {
if c == t {
return ""
}
if normalizeSeparators(c) == normalizeSeparators(t) {
return "separator"
}
d := levenshtein(c, t)
if d == 0 {
return ""
}
if d == 1 {
switch {
case len(c) == len(t):
if isTransposition(c, t) {
return "transposition"
}
return "substitution"
case len(c) == len(t)+1:
return "insertion"
case len(c) == len(t)-1:
return "omission"
}
return "edit1"
}
if d == 2 && len(c) == len(t) && isTransposition(c, t) {
return "transposition"
}
return ""
}

func isTransposition(c, t string) bool {
if len(c) != len(t) {
return false
}
diff := []int{}
for i := 0; i < len(c); i++ {
if c[i] != t[i] {
diff = append(diff, i)
if len(diff) > 2 {
return false
}
}
}
if len(diff) != 2 {
return false
}
i, j := diff[0], diff[1]
return j == i+1 && c[i] == t[j] && c[j] == t[i]
}

func main() {
targetsPath := flag.String("targets", "data/output/popular_targets.txt", "popular-target module paths")
datasetPath := flag.String("dataset", "data/dataset_combined.txt", "dataset JSON lines")
outPath := flag.String("out", "data/output/naming_v2_candidates.csv", "output CSV")
minLen := flag.Int("minlen", 5, "minimum segment length to consider")
flag.Parse()

tf, err := os.Open(*targetsPath)
if err != nil {
fmt.Fprintln(os.Stderr, "open targets:", err)
os.Exit(1)
}
type target struct{ path, seg string }
var targets []target
popularPath := map[string]bool{}
ts := bufio.NewScanner(tf)
for ts.Scan() {
p := strings.TrimSpace(ts.Text())
if p == "" {
continue
}
seg := lastSegment(p)
if len(seg) < *minLen {
continue
}
targets = append(targets, target{path: strings.ToLower(p), seg: seg})
popularPath[strings.ToLower(p)] = true
}
tf.Close()

byLen := map[int][]target{}
for _, t := range targets {
byLen[len(t.seg)] = append(byLen[len(t.seg)], t)
}
fmt.Printf("Loaded %d popular targets (>= %d chars)\n", len(targets), *minLen)

df, err := os.Open(*datasetPath)
if err != nil {
fmt.Fprintln(os.Stderr, "open dataset:", err)
os.Exit(1)
}
defer df.Close()

of, err := os.Create(*outPath)
if err != nil {
fmt.Fprintln(os.Stderr, "create out:", err)
os.Exit(1)
}
defer of.Close()
w := bufio.NewWriter(of)
defer w.Flush()
fmt.Fprintln(w, "candidate_module,candidate_segment,target_module,target_segment,technique,cross_host")

seenCandidate := map[string]bool{}
scanned, flagged := 0, 0
sc := bufio.NewScanner(df)
sc.Buffer(make([]byte, 1024*1024), 1024*1024)
for sc.Scan() {
line := strings.TrimSpace(sc.Text())
if line == "" {
continue
}
var ml moduleLine
if json.Unmarshal([]byte(line), &ml) != nil || ml.Path == "" {
continue
}
scanned++
candPath := strings.ToLower(ml.Path)
if popularPath[candPath] {
continue
}
seg := lastSegment(candPath)
if len(seg) < *minLen {
continue
}
for dl := -1; dl <= 1; dl++ {
for _, t := range byLen[len(seg)+dl] {
if t.seg == seg {
continue
}
if sameProjectDifferentVersion(seg, t.seg) {
continue
}
if isGeneric(t.seg) {
continue
}
tech := technique(seg, t.seg)
if tech == "" {
continue
}
crossHost := host(candPath) != host(t.path)
key := candPath + "|" + t.path
if seenCandidate[key] {
continue
}
seenCandidate[key] = true
flagged++
fmt.Fprintf(w, "%s,%s,%s,%s,%s,%t\n", ml.Path, seg, t.path, t.seg, tech, crossHost)
}
}
}

fmt.Printf("Scanned %d modules; flagged %d typosquat candidates -> %s\n", scanned, flagged, *outPath)
}
