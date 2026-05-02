package collector

import (
"fmt"
"io"
"log/slog"
"net/http"
"strings"
"time"
)

type GoModFetcher struct {
proxyURL   string
httpClient *http.Client
fetchLimit int
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
var results []GoModInfo
seen := make(map[string]bool)

limit := f.fetchLimit
if limit <= 0 || limit > len(modules) {
limit = len(modules)
}

slog.Info("Starting go.mod fetch", "limit", limit, "total_modules", len(modules))

fetched := 0
for i, m := range modules {
if fetched >= limit {
break
}

if seen[m.Path] {
continue
}
seen[m.Path] = true

info, err := f.FetchGoMod(m.Path, m.Version)
if err != nil {
slog.Warn("Failed to fetch go.mod",
"module", m.Path,
"err", err,
)
fetched++
continue
}

results = append(results, *info)
fetched++

if (i+1)%500 == 0 {
slog.Info("go.mod fetch progress",
"fetched", fetched,
"limit", limit,
)
}

time.Sleep(200 * time.Millisecond)
}

slog.Info("go.mod fetch complete", "total_fetched", len(results))
return results
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
