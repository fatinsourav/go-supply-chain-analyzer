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

func NewGoModFetcher(proxyURL string) *GoModFetcher {
return &GoModFetcher{
proxyURL: proxyURL,
httpClient: &http.Client{
Timeout: 15 * time.Second,
},
}
}

func (f *GoModFetcher) FetchGoMod(modulePath, version string) (*GoModInfo, error) {
// Clean version for proxy request
cleanVersion := cleanVersion(version)

url := fmt.Sprintf("%s/%s/@v/%s.mod",
f.proxyURL,
strings.ToLower(modulePath),
cleanVersion,
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

slog.Debug("Fetched go.mod",
"module", modulePath,
"version", cleanVersion,
"dependencies", len(deps),
)

return &GoModInfo{
ModulePath:   modulePath,
Version:      cleanVersion,
Dependencies: deps,
}, nil
}

// FetchGoModBatch fetches go.mod for multiple modules
// with rate limiting to avoid proxy throttling
func (f *GoModFetcher) FetchGoModBatch(modules []ModuleInfo) []GoModInfo {
var results []GoModInfo
seen := make(map[string]bool)

for i, m := range modules {
// Skip duplicates — only fetch each unique module once
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
continue
}

results = append(results, *info)

// Progress logging every 50 modules
if (i+1)%50 == 0 {
slog.Info("go.mod fetch progress",
"fetched", len(results),
"total", len(modules),
)
}

// Rate limiting — be respectful to the proxy
time.Sleep(200 * time.Millisecond)
}

slog.Info("go.mod fetch complete",
"total_fetched", len(results),
)

return results
}

// parseGoMod parses require directives from a go.mod file
func parseGoMod(content string) []Dependency {
var deps []Dependency
lines := strings.Split(content, "\n")

inRequireBlock := false

for _, line := range lines {
line = strings.TrimSpace(line)

// Handle require block
if line == "require (" {
inRequireBlock = true
continue
}
if inRequireBlock && line == ")" {
inRequireBlock = false
continue
}

// Handle single line require
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

// Handle lines inside require block
if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
parts := strings.Fields(line)
if len(parts) >= 2 {
// Skip indirect dependencies marker
modulePath := parts[0]
version := parts[1]
if modulePath != "" && version != "" {
deps = append(deps, Dependency{
ModulePath: modulePath,
Version:    version,
})
}
}
}
}

return deps
}

// cleanVersion ensures version is usable for proxy API
func cleanVersion(version string) string {
// Handle pseudo-versions and incompatible versions
if version == "" {
return "latest"
}
// Remove +incompatible suffix for proxy requests
version = strings.TrimSuffix(version, "+incompatible")
return version
}
