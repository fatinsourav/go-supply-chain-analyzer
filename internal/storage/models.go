package storage

type Module struct {
Path      string
Version   string
Timestamp string
Domain    string
Owner     string
Repo      string
}

type RiskPattern struct {
ModulePath  string
PatternType string
Severity    string
Details     string
DetectedAt  string
}

type Version struct {
Version   string
Timestamp string
}
