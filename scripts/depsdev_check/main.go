// Command depsdev_check validates the popularity baseline against deps.dev.
// For each top-N target, it queries the deps.dev API and records whether the
// package is recognized and how many published versions it has (a proxy for an
// established, real ecosystem package). This validates that the in-dataset
// popularity baseline corresponds to genuine, established ecosystem packages.
package main

import (
"bufio"
"encoding/json"
"fmt"
"net/http"
"net/url"
"os"
"strings"
"time"
)

type depsResp struct {
PackageKey struct {
Name string `json:"name"`
} `json:"packageKey"`
Versions []struct {
PublishedAt string `json:"publishedAt"`
} `json:"versions"`
}

func main() {
targetsPath := "data/output/popular_targets.txt"
topN := 25
if len(os.Args) > 1 {
fmt.Sscanf(os.Args[1], "%d", &topN)
}

f, err := os.Open(targetsPath)
if err != nil {
fmt.Fprintln(os.Stderr, "open targets:", err)
os.Exit(1)
}
defer f.Close()

client := &http.Client{Timeout: 20 * time.Second}
sc := bufio.NewScanner(f)

recognized, total := 0, 0
fmt.Printf("%-45s %-12s %s\n", "TARGET", "RECOGNIZED", "VERSIONS")
fmt.Println(strings.Repeat("-", 72))

for sc.Scan() && total < topN {
p := strings.TrimSpace(sc.Text())
if p == "" {
continue
}
total++
api := "https://api.deps.dev/v3/systems/go/packages/" + url.PathEscape(p)
resp, err := client.Get(api)
if err != nil {
fmt.Printf("%-45s %-12s %s\n", p, "ERROR", err.Error())
continue
}
if resp.StatusCode != 200 {
fmt.Printf("%-45s %-12s (HTTP %d)\n", p, "NO", resp.StatusCode)
resp.Body.Close()
continue
}
var dr depsResp
json.NewDecoder(resp.Body).Decode(&dr)
resp.Body.Close()
nver := len(dr.Versions)
if nver > 0 {
recognized++
fmt.Printf("%-45s %-12s %d\n", p, "YES", nver)
} else {
fmt.Printf("%-45s %-12s %d\n", p, "NO", nver)
}
time.Sleep(100 * time.Millisecond)
}

fmt.Println(strings.Repeat("-", 72))
fmt.Printf("Recognized by deps.dev: %d / %d top targets\n", recognized, total)
}
