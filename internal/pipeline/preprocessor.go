package pipeline

import (
"log/slog"
"strings"

"github.com/fatinsourav/go-supply-chain-analyzer/internal/collector"
)

type Preprocessor struct{}

func NewPreprocessor() *Preprocessor {
return &Preprocessor{}
}

// Process cleans and deduplicates collected modules
func (p *Preprocessor) Process(modules []collector.ModuleInfo) []collector.ModuleInfo {
slog.Info("Starting preprocessing", "input_count", len(modules))

// Step 1: Deduplicate by path
seen := make(map[string]bool)
var deduped []collector.ModuleInfo
for _, m := range modules {
if !seen[m.Path] {
seen[m.Path] = true
deduped = append(deduped, m)
}
}

// Step 2: Normalize module paths
var normalized []collector.ModuleInfo
for _, m := range deduped {
m.Path = strings.ToLower(strings.TrimSpace(m.Path))
m.Domain = strings.ToLower(strings.TrimSpace(m.Domain))
m.Owner = strings.ToLower(strings.TrimSpace(m.Owner))
m.Repo = strings.ToLower(strings.TrimSpace(m.Repo))
if m.Path != "" {
normalized = append(normalized, m)
}
}

slog.Info("Preprocessing complete",
"input", len(modules),
"deduplicated", len(deduped),
"normalized", len(normalized),
)

return normalized
}

// ExtractPaths returns just the module paths as a string slice
func (p *Preprocessor) ExtractPaths(modules []collector.ModuleInfo) []string {
paths := make([]string, len(modules))
for i, m := range modules {
paths[i] = m.Path
}
return paths
}
