package detectors

import (
"fmt"
"log/slog"
"time"
)

type UpdateBehaviorDetector struct {
frequencyThreshold float64
}

type UpdateResult struct {
ModulePath     string
VersionCount   int
ReleasesPerDay float64
Issue          string
Severity       string
}

type VersionEntry struct {
Version   string
Timestamp time.Time
}

func NewUpdateBehaviorDetector(frequencyThreshold float64) *UpdateBehaviorDetector {
return &UpdateBehaviorDetector{frequencyThreshold: frequencyThreshold}
}

func (d *UpdateBehaviorDetector) Detect(modulePath string, versions []VersionEntry) *UpdateResult {
if len(versions) < 2 {
return nil
}

first := versions[0].Timestamp
last := versions[len(versions)-1].Timestamp
duration := last.Sub(first)

days := duration.Hours() / 24
if days < 1 {
days = 1
}

releasesPerDay := float64(len(versions)) / days

// Signal 1: Abnormally high release frequency
// e.g. golang.org/x/tools has 65 versions in ~8 days = ~8/day
if releasesPerDay >= d.frequencyThreshold {
slog.Info("High release frequency detected",
"module", modulePath,
"versions", len(versions),
"releases_per_day", releasesPerDay,
)
return &UpdateResult{
ModulePath:     modulePath,
VersionCount:   len(versions),
ReleasesPerDay: releasesPerDay,
Issue:          "abnormally_high_release_frequency",
Severity:       "high",
}
}

// Signal 2: Burst releases — many versions within 24 hours
if d.hasBurstReleases(versions) {
slog.Info("Burst releases detected", "module", modulePath)
return &UpdateResult{
ModulePath:     modulePath,
VersionCount:   len(versions),
ReleasesPerDay: releasesPerDay,
Issue:          "burst_releases_detected",
Severity:       "medium",
}
}

// Signal 3: Irregular versioning gaps
if d.hasIrregularVersioning(versions) {
return &UpdateResult{
ModulePath:     modulePath,
VersionCount:   len(versions),
ReleasesPerDay: releasesPerDay,
Issue:          "irregular_version_sequence",
Severity:       "low",
}
}

return nil
}

func (d *UpdateBehaviorDetector) hasBurstReleases(versions []VersionEntry) bool {
windowSize := 5
if len(versions) < windowSize {
return false
}
for i := 0; i <= len(versions)-windowSize; i++ {
window := versions[i : i+windowSize]
duration := window[windowSize-1].Timestamp.Sub(window[0].Timestamp)
if duration.Hours() < 24 {
return true
}
}
return false
}

func (d *UpdateBehaviorDetector) hasIrregularVersioning(versions []VersionEntry) bool {
if len(versions) < 3 {
return false
}
var gaps []float64
for i := 1; i < len(versions); i++ {
gap := versions[i].Timestamp.Sub(versions[i-1].Timestamp).Hours()
gaps = append(gaps, gap)
}
avg := averageFloat(gaps)
if avg == 0 {
return false
}
for _, gap := range gaps {
if gap > avg*10 || (gap < avg*0.1 && gap > 0) {
return true
}
}
return false
}

func averageFloat(vals []float64) float64 {
if len(vals) == 0 {
return 0
}
sum := 0.0
for _, v := range vals {
sum += v
}
return sum / float64(len(vals))
}

func FormatUpdateDetails(r *UpdateResult) string {
return fmt.Sprintf("versions=%d releases_per_day=%.2f issue=%s",
r.VersionCount, r.ReleasesPerDay, r.Issue)
}
