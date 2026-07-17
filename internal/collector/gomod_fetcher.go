package collector

import (
"fmt"
"io"
"log/slog"
"net/http"
"strings"
"sync"
"time"
)

type GoModFetcher struct {
proxyURL     string
httpClient   *http.Client
fetchLimit   int
fetchWorkers int
}

type Dependency struct {
ModulePath string
Version    string
}

type GoModInfo struct {
ModulePath   string
Version      string
Dependencies []Dependency
}

func NewGoModFetcher(proxyURL string, fetchLimit int) *GoModFetcher {
return &GoModFetcher{
proxyURL:   proxyURL,
fetchLimit: fetchLimit,
httpClient: &http.Client{
Timeout: 15 * time.Second,
},
}
}

// NewGoModFetcherWithWorkers is like NewGoModFetcher but lets the caller set the
// concurrency level for batch fetching.
func NewGoModFetcherWithWorkers(proxyURL string, fetchLimit, workers int) *GoModFetcher {
f := NewGoModFetcher(proxyURL, fetchLimit)
f.fetchWorkers = workers
return f
}

func (f *GoModFetcher) FetchGoMod(modulePath, version string) (*GoModInfo, error) {
cleanVer := cleanVersion(version)
url := fmt.Sprintf("%s/%s/@v/%s.mod",
f.proxyURL,
strings.ToLower(modulePath),
cleanVer,
)

resp, err := f.httpClient.Get(url)
if err != nil {
return nil, fmt.Errorf("fetching go.mod: %w", err)
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
return nil, fmt.Errorf("proxy returned %d for %s", resp.StatusCode, modulePath)
}

body, err := io.ReadAll(resp.Body)
if err != nil {
return nil, fmt.Errorf("reading go.mod body: %w", err)
}

deps := parseGoMod(string(body))

return &GoModInfo{
ModulePath:   modulePath,
Version:      cleanVer,
Dependencies: deps,
}, nil
}

func (f *GoModFetcher) FetchGoModBatch(modules []ModuleInfo) []GoModInfo {
seen := make(map[string]bool)
var targets []ModuleInfo

limit := f.fetchLimit
if limit <= 0 || limit > len(modules) {
limit = len(modules)
}

for _, m := range modules {
if len(targets) >= limit {
break
}
if seen[m.Path] {
continue
}
seen[m.Path] = true
targets = append(targets, m)
}

workers := f.workers()
slog.Info("Starting go.mod fetch", "targets", len(targets), "total_modules", len(modules), "workers", workers)

jobs := make(chan ModuleInfo)
resultsCh := make(chan *GoModInfo)

var wg sync.WaitGroup
for w := 0; w < workers; w++ {
wg.Add(1)
go func() {
defer wg.Done()
for m := range jobs {
info, err := f.FetchGoMod(m.Path, m.Version)
if err != nil {
slog.Warn("Failed to fetch go.mod", "module", m.Path, "err", err)
resultsCh <- nil
continue
}
resultsCh <- info
}
}()
}

go func() {
for _, m := range targets {
jobs <- m
}
close(jobs)
}()

go func() {
wg.Wait()
close(resultsCh)
}()

var results []GoModInfo
processed := 0
for info := range resultsCh {
processed++
if info != nil {
results = append(results, *info)
}
if processed%500 == 0 {
slog.Info("go.mod fetch progress", "processed", processed, "targets", len(targets), "ok", len(results))
}
}

slog.Info("go.mod fetch complete", "total_fetched", len(results), "attempted", len(targets))
return results
}

func (f *GoModFetcher) workers() int {
if f.fetchWorkers > 0 {
return f.fetchWorkers
}
return 25
}

func parseGoMod(content string) []Dependency {
var deps []Dependency
lines := strings.Split(content, "\n")
inRequireBlock := false

for _, line := range lines {
line = strings.TrimSpace(line)

if line == "require (" {
inRequireBlock = true
continue
}
if inRequireBlock && line == ")" {
inRequireBlock = false
continue
}

if strings.HasPrefix(line, "require ") {
parts := strings.Fields(line)
if len(parts) >= 3 {
deps = append(deps, Dependency{
ModulePath: parts[1],
Version:    parts[2],
})
}
continue
}

if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
parts := strings.Fields(line)
if len(parts) >= 2 {
deps = append(deps, Dependency{
ModulePath: parts[0],
Version:    parts[1],
})
}
}
}

return deps
}

func cleanVersion(version string) string {
if version == "" {
return "latest"
}
return strings.TrimSuffix(version, "+incompatible")
}
