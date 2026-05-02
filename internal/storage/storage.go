package storage

import (
"database/sql"
"log/slog"
_ "github.com/mattn/go-sqlite3"
)

type DB struct {
conn *sql.DB
}

func NewDB(dbPath string) (*DB, error) {
conn, err := sql.Open("sqlite3", dbPath)
if err != nil {
return nil, err
}
db := &DB{conn: conn}
if err := db.initialize(); err != nil {
return nil, err
}
slog.Info("Database initialized", "path", dbPath)
return db, nil
}

func (db *DB) initialize() error {
queries := []string{
`CREATE TABLE IF NOT EXISTS modules (
id INTEGER PRIMARY KEY AUTOINCREMENT,
path TEXT UNIQUE NOT NULL,
version TEXT,
timestamp TEXT,
domain TEXT,
owner TEXT,
repo TEXT,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
`CREATE TABLE IF NOT EXISTS risk_patterns (
id INTEGER PRIMARY KEY AUTOINCREMENT,
module_path TEXT NOT NULL,
pattern_type TEXT NOT NULL,
severity TEXT NOT NULL,
details TEXT,
detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
`CREATE TABLE IF NOT EXISTS versions (
id INTEGER PRIMARY KEY AUTOINCREMENT,
module_path TEXT NOT NULL,
version TEXT NOT NULL,
timestamp TEXT NOT NULL
)`,
}
for _, q := range queries {
if _, err := db.conn.Exec(q); err != nil {
return err
}
}
return nil
}

func (db *DB) InsertModule(path, version, timestamp, domain, owner, repo string) error {
_, err := db.conn.Exec(
`INSERT OR IGNORE INTO modules (path, version, timestamp, domain, owner, repo) VALUES (?, ?, ?, ?, ?, ?)`,
path, version, timestamp, domain, owner, repo,
)
return err
}

func (db *DB) InsertRiskPattern(modulePath, patternType, severity, details string) error {
_, err := db.conn.Exec(
`INSERT INTO risk_patterns (module_path, pattern_type, severity, details) VALUES (?, ?, ?, ?)`,
modulePath, patternType, severity, details,
)
return err
}

func (db *DB) InsertVersion(modulePath, version, timestamp string) error {
_, err := db.conn.Exec(
`INSERT INTO versions (module_path, version, timestamp) VALUES (?, ?, ?)`,
modulePath, version, timestamp,
)
return err
}

func (db *DB) GetAllModules() ([]Module, error) {
rows, err := db.conn.Query(`SELECT path, version, timestamp, domain, owner, repo FROM modules`)
if err != nil {
return nil, err
}
defer rows.Close()
var modules []Module
for rows.Next() {
var m Module
if err := rows.Scan(&m.Path, &m.Version, &m.Timestamp, &m.Domain, &m.Owner, &m.Repo); err != nil {
return nil, err
}
modules = append(modules, m)
}
return modules, nil
}

func (db *DB) GetAllRiskPatterns() ([]RiskPattern, error) {
rows, err := db.conn.Query(`SELECT module_path, pattern_type, severity, details, detected_at FROM risk_patterns`)
if err != nil {
return nil, err
}
defer rows.Close()
var patterns []RiskPattern
for rows.Next() {
var p RiskPattern
if err := rows.Scan(&p.ModulePath, &p.PatternType, &p.Severity, &p.Details, &p.DetectedAt); err != nil {
return nil, err
}
patterns = append(patterns, p)
}
return patterns, nil
}

func (db *DB) GetVersionsByModule(modulePath string) ([]Version, error) {
rows, err := db.conn.Query(
`SELECT version, timestamp FROM versions WHERE module_path = ? ORDER BY timestamp ASC`,
modulePath,
)
if err != nil {
return nil, err
}
defer rows.Close()
var versions []Version
for rows.Next() {
var v Version
if err := rows.Scan(&v.Version, &v.Timestamp); err != nil {
return nil, err
}
versions = append(versions, v)
}
return versions, nil
}

func (db *DB) Close() error {
return db.conn.Close()
}

func (db *DB) InsertModulesBatch(modules []Module) error {
tx, err := db.conn.Begin()
if err != nil {
return err
}
defer tx.Rollback()

stmt, err := tx.Prepare(
"INSERT OR IGNORE INTO modules (path, version, timestamp, domain, owner, repo) VALUES (?, ?, ?, ?, ?, ?)",
)
if err != nil {
return err
}
defer stmt.Close()
return tx.Commit()
}
