package detectors

import (
"fmt"
"log/slog"
"strings"

"github.com/agnivade/levenshtein"
)

type SourceAmbiguityDetector struct{}

type AmbiguityResult struct {
ModulePath string
Domain     string
Issue      string
Severity   string
}

// Trusted domains in the Go ecosystem based on literature
// and observed patterns in the dataset
var trustedDomains = map[string]bool{
"github.com":            true,
"gitlab.com":            true,
"bitbucket.org":         true,
"golang.org":            true,
"google.golang.org":     true,
"gopkg.in":              true,
"k8s.io":                true,
"sigs.k8s.io":           true,
"go.uber.org":           true,
"go.opencensus.io":      true,
"cloud.google.com":      true,
"contrib.go.opencensus.io": true,
"rsc.io":                true,
}

// Suspicious TLDs that are commonly abused
var suspiciousTLDs = []string{
".xyz", ".top", ".club", ".online",
".site", ".info", ".biz", ".tk",
".ml", ".ga", ".cf",
}

func NewSourceAmbiguityDetector() *SourceAmbiguityDetector {
return &SourceAmbiguityDetector{}
}

func (d *SourceAmbiguityDetector) Detect(modules []string) []AmbiguityResult {
var results []AmbiguityResult
seen := make(map[string]bool)

for _, modulePath := range modules {
domain := extractDomain(modulePath)
if domain == "" || seen[domain] {
continue
}
seen[domain] = true

// Check 1: Domain similar to trusted ones (typosquatting at domain level)
// e.g. "githab.com" vs "github.com"
if similarDomain, found := isSimilarToTrusted(domain); found {
results = append(results, AmbiguityResult{
ModulePath: modulePath,
Domain:     domain,
Issue:      fmt.Sprintf("domain_similar_to_%s", similarDomain),
Severity:   "high",
})
slog.Info("Domain similarity detected", "domain", domain, "similar_to", similarDomain)
continue
}

// Check 2: IP address as domain
if isIPAddress(domain) {
results = append(results, AmbiguityResult{
ModulePath: modulePath,
Domain:     domain,
Issue:      "ip_address_used_as_domain",
Severity:   "high",
})
continue
}

// Check 3: Suspicious TLD
for _, tld := range suspiciousTLDs {
if strings.HasSuffix(domain, tld) {
results = append(results, AmbiguityResult{
ModulePath: modulePath,
Domain:     domain,
Issue:      fmt.Sprintf("suspicious_tld_%s", tld),
Severity:   "high",
})
break
}
}

// Check 4: Unknown/untrusted domain
if !trustedDomains[domain] {
results = append(results, AmbiguityResult{
ModulePath: modulePath,
Domain:     domain,
Issue:      "untrusted_domain",
Severity:   "medium",
})
slog.Info("Untrusted domain detected", "domain", domain)
}
}

return results
}

func extractDomain(modulePath string) string {
parts := strings.Split(modulePath, "/")
if len(parts) >= 1 {
return strings.ToLower(parts[0])
}
return ""
}

func isIPAddress(domain string) bool {
parts := strings.Split(domain, ".")
if len(parts) != 4 {
return false
}
for _, part := range parts {
for _, c := range part {
if c < '0' || c > '9' {
return false
}
}
if len(part) == 0 {
return false
}
}
return true
}

func isSimilarToTrusted(domain string) (string, bool) {
trusted := []string{
"github.com",
"gitlab.com",
"golang.org",
"bitbucket.org",
"google.golang.org",
}
for _, t := range trusted {
if domain == t {
return "", false
}
dist := levenshtein.ComputeDistance(domain, t)
if dist > 0 && dist <= 2 {
return t, true
}
}
return "", false
}

func FormatAmbiguityDetails(r AmbiguityResult) string {
return fmt.Sprintf("domain=%s issue=%s", r.Domain, r.Issue)
}
