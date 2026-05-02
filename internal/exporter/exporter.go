package exporter

import (
"encoding/csv"
"encoding/json"
"fmt"
"log/slog"
"os"
"path/filepath"
"time"

"github.com/fatinsourav/go-supply-chain-analyzer/internal/storage"
)

type Exporter struct {
outputPath string
}

func NewExporter(outputPath string) *Exporter {
return &Exporter{outputPath: outputPath}
}

// ExportModulesCSV exports all modules to CSV
func (e *Exporter) ExportModulesCSV(modules []storage.Module) error {
filename := filepath.Join(e.outputPath, "modules.csv")
f, err := os.Create(filename)
if err != nil {
return fmt.Errorf("creating modules CSV: %w", err)
}
defer f.Close()

w := csv.NewWriter(f)
defer w.Flush()

// Header
w.Write([]string{"path", "version", "timestamp", "domain", "owner", "repo"})

for _, m := range modules {
w.Write([]string{
m.Path, m.Version, m.Timestamp,
m.Domain, m.Owner, m.Repo,
})
}

slog.Info("Exported modules CSV", "file", filename, "count", len(modules))
return nil
}

// ExportRiskPatternsCSV exports all detected risk patterns to CSV
func (e *Exporter) ExportRiskPatternsCSV(patterns []storage.RiskPattern) error {
filename := filepath.Join(e.outputPath, "risk_patterns.csv")
f, err := os.Create(filename)
if err != nil {
return fmt.Errorf("creating risk patterns CSV: %w", err)
}
defer f.Close()

w := csv.NewWriter(f)
defer w.Flush()

// Header
w.Write([]string{"module_path", "pattern_type", "severity", "details", "detected_at"})

for _, p := range patterns {
w.Write([]string{
p.ModulePath, p.PatternType,
p.Severity, p.Details, p.DetectedAt,
})
}

slog.Info("Exported risk patterns CSV", "file", filename, "count", len(patterns))
return nil
}

// ExportSummaryJSON exports a summary of results to JSON
func (e *Exporter) ExportSummaryJSON(patterns []storage.RiskPattern, moduleCount int) error {
filename := filepath.Join(e.outputPath, "summary.json")

// Count by pattern type
patternCounts := make(map[string]int)
severityCounts := make(map[string]int)
for _, p := range patterns {
patternCounts[p.PatternType]++
severityCounts[p.Severity]++
}

summary := map[string]interface{}{
"generated_at":   time.Now().Format(time.RFC3339),
"total_modules":  moduleCount,
"total_risks":    len(patterns),
"by_pattern":     patternCounts,
"by_severity":    severityCounts,
}

data, err := json.MarshalIndent(summary, "", "  ")
if err != nil {
return fmt.Errorf("marshalling summary: %w", err)
}

if err := os.WriteFile(filename, data, 0644); err != nil {
return fmt.Errorf("writing summary JSON: %w", err)
}

slog.Info("Exported summary JSON", "file", filename)
return nil
}
