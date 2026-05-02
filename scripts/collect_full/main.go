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

func main() {
outputFile := "./data/dataset_full.txt"
maxUnique := 50000
since := "2019-04-10T00:00:00.000000Z"
endTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
indexURL := "https://index.golang.org/index"

os.MkdirAll("./data", 0755)

f, err := os.Create(outputFile)
if err != nil {
fmt.Println("Error creating output file:", err)
os.Exit(1)
}
defer f.Close()

writer := bufio.NewWriter(f)
client := &http.Client{Timeout: 30 * time.Second}
seen := make(map[string]bool)
uniqueCount := 0
batchCount := 0

fmt.Printf("Starting full collection: target=%d\n", maxUnique)
fmt.Printf("From: %s\n", since)
fmt.Printf("To:   %s\n", endTime.Format(time.RFC3339))

for uniqueCount < maxUnique {
url := fmt.Sprintf("%s?since=%s", indexURL, since)
resp, err := client.Get(url)
if err != nil {
fmt.Println("Error fetching:", err)
break
}

body, err := io.ReadAll(resp.Body)
resp.Body.Close()
if err != nil {
fmt.Println("Error reading response:", err)
break
}

lines := strings.Split(strings.TrimSpace(string(body)), "\n")
if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
fmt.Println("No more data available.")
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

// Stop if we've reached end time
if !lastTime.IsZero() && lastTime.After(endTime) {
fmt.Printf("Reached end time %s, stopping.\n", endTime.Format(time.RFC3339))
break
}

if lastTimestamp == "" || lastTimestamp == since {
fmt.Println("No progress, stopping.")
break
}

since = lastTimestamp
fmt.Printf("Batch %d: +%d new | total: %d | since: %s\n",
batchCount, added, uniqueCount, since)

time.Sleep(300 * time.Millisecond)
}

fmt.Printf("\nCollection complete!\n")
fmt.Printf("Total unique modules: %d\n", uniqueCount)
fmt.Printf("Output: %s\n", outputFile)

info, _ := os.Stat(outputFile)
fmt.Printf("File size: %.2f MB\n", float64(info.Size())/1024/1024)
}
