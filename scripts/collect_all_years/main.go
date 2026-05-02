package main

import (
"bufio"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"strings"
"time"
)

type ModuleEntry struct {
Path      string    `json:"Path"`
Version   string    `json:"Version"`
Timestamp time.Time `json:"Timestamp"`
}

func collectYear(year int, client *http.Client) error {
outputFile := fmt.Sprintf("./data/dataset_%d.txt", year)
maxUnique := 50000
since := fmt.Sprintf("%d-01-01T00:00:00.000000Z", year)
endTime := time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)
indexURL := "https://index.golang.org/index"

f, err := os.Create(outputFile)
if err != nil {
return fmt.Errorf("creating file: %w", err)
}
defer f.Close()

writer := bufio.NewWriter(f)
seen := make(map[string]bool)
uniqueCount := 0
batchCount := 0

fmt.Printf("\n=== Collecting year %d ===\n", year)

for uniqueCount < maxUnique {
url := fmt.Sprintf("%s?since=%s", indexURL, since)
resp, err := client.Get(url)
if err != nil {
return fmt.Errorf("fetching: %w", err)
}
body, err := io.ReadAll(resp.Body)
resp.Body.Close()
if err != nil {
return err
}

lines := strings.Split(strings.TrimSpace(string(body)), "\n")
if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
break
}

batchCount++
added := 0
var lastTimestamp string
var lastTime time.Time

for _, line := range lines {
if line == "" {
continue
}
var entry ModuleEntry
if err := json.Unmarshal([]byte(line), &entry); err != nil {
continue
}
lastTimestamp = entry.Timestamp.Format(time.RFC3339Nano)
lastTime = entry.Timestamp
if !seen[entry.Path] {
seen[entry.Path] = true
writer.WriteString(line + "\n")
uniqueCount++
added++
if uniqueCount >= maxUnique {
break
}
}
}
writer.Flush()

if !lastTime.IsZero() && lastTime.After(endTime) {
fmt.Printf("Reached end of %d\n", year)
break
}
if lastTimestamp == "" || lastTimestamp == since {
break
}
since = lastTimestamp
if batchCount%10 == 0 {
fmt.Printf("  Batch %d: total=%d since=%s\n", batchCount, uniqueCount, since[:10])
}
time.Sleep(300 * time.Millisecond)
}

info, _ := os.Stat(outputFile)
fmt.Printf("Year %d done: %d modules | %.2f MB\n", year, uniqueCount, float64(info.Size())/1024/1024)
return nil
}

func combineDatasets() {
years := []int{2019, 2020, 2021, 2022, 2023, 2024, 2025}
outputFile := "./data/dataset_combined.txt"

out, err := os.Create(outputFile)
if err != nil {
fmt.Println("Error creating combined file:", err)
return
}
defer out.Close()

writer := bufio.NewWriter(out)
seen := make(map[string]bool)
totalUnique := 0

for _, year := range years {
var inputFile string
if year == 2019 {
inputFile = "./data/dataset_full.txt"
} else {
inputFile = fmt.Sprintf("./data/dataset_%d.txt", year)
}

f, err := os.Open(inputFile)
if err != nil {
fmt.Printf("Skipping %d: %v\n", year, err)
continue
}

yearCount := 0
scanner := bufio.NewScanner(f)
buf := make([]byte, 1024*1024)
scanner.Buffer(buf, len(buf))

for scanner.Scan() {
line := strings.TrimSpace(scanner.Text())
if line == "" {
continue
}
var entry ModuleEntry
if err := json.Unmarshal([]byte(line), &entry); err != nil {
continue
}
if !seen[entry.Path] {
seen[entry.Path] = true
writer.WriteString(line + "\n")
totalUnique++
yearCount++
}
}
f.Close()
fmt.Printf("Added %d unique modules from %d\n", yearCount, year)
}

writer.Flush()
info, _ := os.Stat(outputFile)
fmt.Printf("\nCombined: %d unique modules | %.2f MB\n", totalUnique, float64(info.Size())/1024/1024)
}

func main() {
os.MkdirAll("./data", 0755)
client := &http.Client{Timeout: 30 * time.Second}

years := []int{2020, 2021, 2022, 2023}
fmt.Printf("Collecting years: %v\n", years)

for _, year := range years {
if err := collectYear(year, client); err != nil {
fmt.Printf("Error collecting %d: %v\n", year, err)
}
}

fmt.Println("\n=== Combining all datasets ===")
combineDatasets()
}
