package detectors

import (
"fmt"
"log/slog"
"strings"

"zntr.io/typogenerator"
"zntr.io/typogenerator/strategy"
)

type NamingSimilarityDetector struct {
threshold int
}

type SimilarityResult struct {
ModulePath string
SimilarTo  string
OwnerA     string
OwnerB     string
Signal     string
Severity   string
}

func NewNamingSimilarityDetector(threshold int) *NamingSimilarityDetector {
return &NamingSimilarityDetector{threshold: threshold}
}

// Detect uses pkgtwist's generative approach:
// generate typo variants of each owner and check
// if those variants exist in the dataset
func (d *NamingSimilarityDetector) Detect(modules []string) []SimilarityResult {
var results []SimilarityResult

// Build owner -> module path map for quick lookup
ownerToModule := make(map[string]string)
for _, m := range modules {
owner := extractOwner(m)
if owner != "" {
ownerToModule[strings.ToLower(owner)] = m
}
}

// Track reported pairs to avoid duplicates
reported := make(map[string]bool)

// Use same 4 strategies as pkgtwist
strategies := []strategy.Strategy{
strategy.Omission,
strategy.Repetition,
strategy.Transposition,
strategy.BitSquatting,
}

for _, m := range modules {
owner := extractOwner(m)
if owner == "" {
continue
}

ownerLower := strings.ToLower(owner)

permutations, err := typogenerator.Fuzz(ownerLower, strategies...)
if err != nil {
slog.Warn("Failed to generate permutations",
"owner", owner,
"err", err,
)
continue
}

for _, result := range permutations {
for _, perm := range result.Permutations {
variant := strings.ToLower(perm)

// Skip if variant is same as original
if variant == ownerLower {
continue
}

// Check if this variant exists in our dataset
existingModule, exists := ownerToModule[variant]
if !exists {
continue
}

// Avoid duplicate pairs
pairKey := fmt.Sprintf("%s|%s", ownerLower, variant)
reversePairKey := fmt.Sprintf("%s|%s", variant, ownerLower)
if reported[pairKey] || reported[reversePairKey] {
continue
}
reported[pairKey] = true

// Severity based on strategy
severity := "medium"
if result.StrategyName == "Transposition" {
severity = "high"
}

slog.Info("Naming similarity detected",
"owner_a", owner,
"owner_b", variant,
"signal", result.StrategyName,
)

results = append(results, SimilarityResult{
ModulePath: m,
SimilarTo:  existingModule,
OwnerA:     owner,
OwnerB:     variant,
Signal:     result.StrategyName,
Severity:   severity,
})
}
}
}

return results
}

func FormatSimilarityDetails(r SimilarityResult) string {
return fmt.Sprintf("owner_a=%s owner_b=%s signal=%s",
r.OwnerA, r.OwnerB, r.Signal)
}

func extractOwner(modulePath string) string {
parts := strings.Split(modulePath, "/")
if len(parts) >= 2 {
return parts[1]
}
return ""
}
