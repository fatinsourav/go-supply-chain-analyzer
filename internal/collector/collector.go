package collector

import (
"encoding/json"
"fmt"
"io"
"log/slog"
"net/http"
"net/url"
"strings"
"time"
)

type ModuleEntry struct {
Path      string    `json:"Path"`
Version   string    `json:"Version"`
Timestamp time.Time `json:"Timestamp"`
}

type ModuleInfo struct {
Path      string
Version   string
Timestamp string
Domain    string
Owner     string
Repo      string
}

type Collector struct {
indexURL   string
proxyURL   string
httpClient *http.Client
maxModules int
}

func NewCollector(indexURL, proxyURL string, maxModules int) *Collector {
return &Collector{
indexURL:   indexURL,
proxyURL:   proxyURL,
maxModules: maxModules,
httpClient: &http.Client{Timeout: 30 * time.Second},
}
}

func (c *Collector) FetchModules() ([]ModuleInfo, error) {
slog.Info("Starting module collection", "max", c.maxModules)
var modules []ModuleInfo
since := "2019-01-01T00:00:00.000000Z"

for len(modules) < c.maxModules {
batch, nextSince, err := c.fetchBatch(since)
if err != nil {
return nil, fmt.Errorf("fetching batch: %w", err)
}
if len(batch) == 0 {
break
}
for _, entry := range batch {
if len(modules) >= c.maxModules {
break
}
info := c.parseModuleEntry(entry)
modules = append(modules, info)
}
slog.Info("Collected modules", "count", len(modules))
since = nextSince
time.Sleep(500 * time.Millisecond)
}

slog.Info("Collection complete", "total", len(modules))
return modules, nil
}

func (c *Collector) fetchBatch(since string) ([]ModuleEntry, string, error) {
reqURL := fmt.Sprintf("%s?since=%s", c.indexURL, url.QueryEscape(since))
resp, err := c.httpClient.Get(reqURL)
if err != nil {
return nil, since, err
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
return nil, since, err
}

var entries []ModuleEntry
lines := strings.Split(strings.TrimSpace(string(body)), "\n")
for _, line := range lines {
if line == "" {
continue
}
var entry ModuleEntry
if err := json.Unmarshal([]byte(line), &entry); err != nil {
continue
}
entries = append(entries, entry)
}

nextSince := since
if len(entries) > 0 {
nextSince = entries[len(entries)-1].Timestamp.Format(time.RFC3339Nano)
}

return entries, nextSince, nil
}

func (c *Collector) parseModuleEntry(entry ModuleEntry) ModuleInfo {
domain, owner, repo := parseModulePath(entry.Path)
return ModuleInfo{
Path:      entry.Path,
Version:   entry.Version,
Timestamp: entry.Timestamp.Format(time.RFC3339),
Domain:    domain,
Owner:     owner,
Repo:      repo,
}
}

func parseModulePath(modulePath string) (domain, owner, repo string) {
parts := strings.Split(modulePath, "/")
if len(parts) >= 1 {
domain = parts[0]
}
if len(parts) >= 2 {
owner = parts[1]
}
if len(parts) >= 3 {
repo = parts[2]
}
return domain, owner, repo
}

func (c *Collector) FetchVersions(modulePath string) ([]string, error) {
reqURL := fmt.Sprintf("%s/%s/@v/list", c.proxyURL, modulePath)
resp, err := c.httpClient.Get(reqURL)
if err != nil {
return nil, err
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
return nil, err
}

versions := strings.Split(strings.TrimSpace(string(body)), "\n")
var result []string
for _, v := range versions {
if v != "" {
result = append(result, v)
}
}
return result, nil
}
