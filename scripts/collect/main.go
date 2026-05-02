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
maxUnique := 10000
since := "2019-04-10T00:00:00.000000Z"
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

fmt.Printf("Starting collection: target=%d since=%s\n", maxUnique, since)

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
if len(lines) == 0 {
fmt.Println("No more data.")
break
}

batchCount++
added := 0
var lastTimestamp string

for _, line := range lines {
if line == "" {
continue
}
var entry ModuleEntry
if err := json.Unmarshal([]byte(line), &entry); err != nil {
continue
}

lastTimestamp = entry.Timestamp.Format(time.RFC3339Nano)

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

if lastTimestamp == "" || lastTimestamp == since {
fmt.Println("No progress, stopping.")
break
}

since = lastTimestamp
fmt.Printf("Batch %d: +%d new | total unique: %d | since: %s\n",
batchCount, added, uniqueCount, since)

time.Sleep(500 * time.Millisecond)
}

fmt.Printf("\nCollection complete!\n")
fmt.Printf("Total unique modules: %d\n", uniqueCount)
fmt.Printf("Output: %s\n", outputFile)
}
