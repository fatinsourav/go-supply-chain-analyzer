package main

import (
"bufio"
"encoding/json"
"log/slog"
"os"
"strconv"
"strings"
"time"

"github.com/fatinsourav/go-supply-chain-analyzer/internal/collector"
"github.com/fatinsourav/go-supply-chain-analyzer/internal/detectors"
"github.com/fatinsourav/go-supply-chain-analyzer/internal/exporter"
"github.com/fatinsourav/go-supply-chain-analyzer/internal/pipeline"
"github.com/fatinsourav/go-supply-chain-analyzer/internal/storage"
"github.com/joho/godotenv"
)

func main() {
// Setup structured logging
slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
Level: slog.LevelInfo,
})))

// Load config
if err := godotenv.Load("configs/config.env"); err != nil {
slog.Warn("Could not load config.env, using defaults")
}

dbPath := getEnv("DB_PATH", "./data/output/analyzer.db")
outputPath := getEnv("CSV_OUTPUT_PATH", "./data/output")
datasetPath := getEnv("DATASET_PATH", "./data/dataset.txt")
levenshteinThreshold := getEnvInt("LEVENSHTEIN_THRESHOLD", 2)
updateThreshold := getEnvFloat("UPDATE_FREQUENCY_THRESHOLD", 5.0)
concentrationThreshold := getEnvInt("CONCENTRATION_THRESHOLD", 3)

slog.Info("Starting Go Supply Chain Analyzer")

// Initialize storage
db, err := storage.NewDB(dbPath)
if err != nil {
slog.Error("Failed to initialize database", "err", err)
os.Exit(1)
}
defer db.Close()

// Step 1: Load dataset
slog.Info("Loading dataset", "path", datasetPath)
modules, err := loadDataset(datasetPath)
if err != nil {
slog.Error("Failed to load dataset", "err", err)
os.Exit(1)
}
slog.Info("Dataset loaded", "count", len(modules))

// Step 2: Preprocess
prep := pipeline.NewPreprocessor()
processed := prep.Process(modules)
modulePaths := prep.ExtractPaths(processed)

// Step 3: Store modules
for _, m := range processed {
if err := db.InsertModule(m.Path, m.Version, m.Timestamp, m.Domain, m.Owner, m.Repo); err != nil {
slog.Warn("Failed to insert module", "path", m.Path, "err", err)
}
}
slog.Info("Modules stored", "count", len(processed))

// Step 4: Pattern Detection

// Pattern 1: Naming Similarity
slog.Info("Running Pattern 1: Naming Similarity")
similarityDetector := detectors.NewNamingSimilarityDetector(levenshteinThreshold)
similarityResults := similarityDetector.Detect(modulePaths)
for _, r := range similarityResults {
db.InsertRiskPattern(r.ModulePath, "naming_similarity", r.Severity,
detectors.FormatSimilarityDetails(r))
}
slog.Info("Pattern 1 complete", "findings", len(similarityResults))

// Pattern 2: Dependency Source Ambiguity
slog.Info("Running Pattern 2: Dependency Source Ambiguity")
ambiguityDetector := detectors.NewSourceAmbiguityDetector()
ambiguityResults := ambiguityDetector.Detect(modulePaths)
for _, r := range ambiguityResults {
db.InsertRiskPattern(r.ModulePath, "source_ambiguity", r.Severity,
detectors.FormatAmbiguityDetails(r))
}
slog.Info("Pattern 2 complete", "findings", len(ambiguityResults))

// Pattern 3: Suspicious Update Behavior
slog.Info("Running Pattern 3: Suspicious Update Behavior")
updateDetector := detectors.NewUpdateBehaviorDetector(updateThreshold)
versionMap := buildVersionMap(processed)
updateCount := 0
for modulePath, versions := range versionMap {
if len(versions) < 2 {
continue
}
result := updateDetector.Detect(modulePath, versions)
if result != nil {
db.InsertRiskPattern(result.ModulePath, "suspicious_update", result.Severity,
detectors.FormatUpdateDetails(result))
updateCount++
}
}
slog.Info("Pattern 3 complete", "findings", updateCount)

// Pattern 4: Dependency Concentration Risk
slog.Info("Running Pattern 4: Dependency Concentration Risk")
proxyURL := getEnv("PROXY_URL", "https://proxy.golang.org")
gomodFetcher := collector.NewGoModFetcher(proxyURL)
gomodInfos := gomodFetcher.FetchGoModBatch(processed)

graph := detectors.NewDependencyGraph()
for _, info := range gomodInfos {
for _, dep := range info.Dependencies {
graph.AddDependency(info.ModulePath, dep.ModulePath)
}
}

concentrationDetector := detectors.NewConcentrationRiskDetector(concentrationThreshold)
concentrationResults := concentrationDetector.Detect(graph)
for _, r := range concentrationResults {
db.InsertRiskPattern(r.ModulePath, "concentration_risk", r.Severity,
detectors.FormatConcentrationDetails(r))
}
slog.Info("Pattern 4 complete", "findings", len(concentrationResults))

// Step 5: Export results
slog.Info("Exporting results")
exp := exporter.NewExporter(outputPath)

allModules, _ := db.GetAllModules()
exp.ExportModulesCSV(allModules)

allPatterns, _ := db.GetAllRiskPatterns()
exp.ExportRiskPatternsCSV(allPatterns)
exp.ExportSummaryJSON(allPatterns, len(processed))

slog.Info("Analysis complete",
"modules_analyzed", len(processed),
"total_risks_found", len(allPatterns),
)
}

// loadDataset reads the Go Module Index JSON lines format
func loadDataset(path string) ([]collector.ModuleInfo, error) {
f, err := os.Open(path)
if err != nil {
return nil, err
}
defer f.Close()

var modules []collector.ModuleInfo
scanner := bufio.NewScanner(f)
for scanner.Scan() {
line := strings.TrimSpace(scanner.Text())
if line == "" {
continue
}
var entry struct {
Path      string    `json:"Path"`
Version   string    `json:"Version"`
Timestamp time.Time `json:"Timestamp"`
}
if err := json.Unmarshal([]byte(line), &entry); err != nil {
continue
}
parts := strings.Split(entry.Path, "/")
domain, owner, repo := "", "", ""
if len(parts) >= 1 {
domain = parts[0]
}
if len(parts) >= 2 {
owner = parts[1]
}
if len(parts) >= 3 {
repo = parts[2]
}
modules = append(modules, collector.ModuleInfo{
Path:      entry.Path,
Version:   entry.Version,
Timestamp: entry.Timestamp.Format(time.RFC3339),
Domain:    domain,
Owner:     owner,
Repo:      repo,
})
}
return modules, scanner.Err()
}

// buildVersionMap groups versions by module path for update behavior detection
func buildVersionMap(modules []collector.ModuleInfo) map[string][]detectors.VersionEntry {
versionMap := make(map[string][]detectors.VersionEntry)
for _, m := range modules {
t, err := time.Parse(time.RFC3339, m.Timestamp)
if err != nil {
continue
}
versionMap[m.Path] = append(versionMap[m.Path], detectors.VersionEntry{
Version:   m.Version,
Timestamp: t,
})
}
return versionMap
}

func getEnv(key, defaultVal string) string {
if val := os.Getenv(key); val != "" {
return val
}
return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
if val := os.Getenv(key); val != "" {
if i, err := strconv.Atoi(val); err == nil {
return i
}
}
return defaultVal
}

func getEnvFloat(key string, defaultVal float64) float64 {
if val := os.Getenv(key); val != "" {
if f, err := strconv.ParseFloat(val, 64); err == nil {
return f
}
}
return defaultVal
}
