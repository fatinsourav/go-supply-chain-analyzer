package detectors

import (
"fmt"
"log/slog"
"sort"
"strings"
)

type ConcentrationRiskDetector struct {
threshold int
}

type ConcentrationResult struct {
ModulePath     string
DependentCount int
Severity       string
Issue          string
}

// DependencyGraph holds the relationship between modules
type DependencyGraph struct {
// dependents[module] = list of modules that depend on it
dependents map[string][]string
// dependencies[module] = list of modules it depends on
dependencies map[string][]string
}

func NewDependencyGraph() *DependencyGraph {
return &DependencyGraph{
dependents:   make(map[string][]string),
dependencies: make(map[string][]string),
}
}

// AddDependency records that `from` depends on `to`
func (g *DependencyGraph) AddDependency(from, to string) {
from = strings.ToLower(from)
to = strings.ToLower(to)
g.dependencies[from] = append(g.dependencies[from], to)
g.dependents[to] = append(g.dependents[to], from)
}

// GetDependentCount returns how many modules depend on a given module
func (g *DependencyGraph) GetDependentCount(modulePath string) int {
return len(g.dependents[strings.ToLower(modulePath)])
}

// GetAllModules returns all modules in the graph
func (g *DependencyGraph) GetAllModules() []string {
seen := make(map[string]bool)
var modules []string
for m := range g.dependents {
if !seen[m] {
seen[m] = true
modules = append(modules, m)
}
}
for m := range g.dependencies {
if !seen[m] {
seen[m] = true
modules = append(modules, m)
}
}
return modules
}

func NewConcentrationRiskDetector(threshold int) *ConcentrationRiskDetector {
return &ConcentrationRiskDetector{threshold: threshold}
}

// Detect identifies modules with high dependent counts
// representing systemic risk as per Zimmermann et al. (2019)
// and Decan et al. (2018) — modules depended upon by many
// projects are single points of failure in the ecosystem
func (d *ConcentrationRiskDetector) Detect(graph *DependencyGraph) []ConcentrationResult {
var results []ConcentrationResult
seen := make(map[string]bool)

for modulePath, deps := range graph.dependents {
if seen[modulePath] {
continue
}
seen[modulePath] = true

count := len(deps)
if count >= d.threshold {
severity := "medium"
if count >= d.threshold*2 {
severity = "high"
}

issue := fmt.Sprintf("depended_upon_by_%d_modules", count)

slog.Info("Concentration risk detected",
"module", modulePath,
"dependent_count", count,
"severity", severity,
)

results = append(results, ConcentrationResult{
ModulePath:     modulePath,
DependentCount: count,
Severity:       severity,
Issue:          issue,
})
}
}

// Sort by dependent count descending
// Most concentrated modules appear first
sort.Slice(results, func(i, j int) bool {
return results[i].DependentCount > results[j].DependentCount
})

return results
}

func FormatConcentrationDetails(r ConcentrationResult) string {
return fmt.Sprintf("dependent_count=%d issue=%s",
r.DependentCount, r.Issue)
}
