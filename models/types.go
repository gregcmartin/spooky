package models

import (
	"encoding/json"
	"os"
	"sync"
)

// Statistics tracks scanning metrics
type Statistics struct {
	ScannedURLs    int
	FoundSecrets   int
	ProcessedBytes int64
	Categories     map[string]int
	Mu             *sync.Mutex // Exported for scanner package
}

// Secret represents a single secret finding
type Secret struct {
	Category    string `json:"category"`
	PatternType string `json:"pattern_type"`
	Value       string `json:"value"`
	URI         string `json:"uri"`
}

// URLFindings represents all findings for a specific URL
type URLFindings struct {
	URL     string   `json:"url"`
	Secrets []Secret `json:"secrets"`
}

// Findings stores all secret findings grouped by URL
type Findings struct {
	Sites      map[string]*URLFindings `json:"-"` // Internal map for grouping
	Mu         *sync.Mutex             // Exported for scanner package
	jsonFile   *os.File                // File handle for realtime JSON writing
	firstEntry bool                    // Track if this is the first entry
}

// NewFindings creates a new Findings instance
func NewFindings() *Findings {
	return &Findings{
		Sites:      make(map[string]*URLFindings),
		Mu:         &sync.Mutex{},
		firstEntry: true,
	}
}

// InitJSONFile initializes the JSON file for realtime writing
func (f *Findings) InitJSONFile(filename string) error {
	var err error
	f.jsonFile, err = os.Create(filename)
	if err != nil {
		return err
	}

	// Write the opening bracket for the JSON array
	_, err = f.jsonFile.WriteString("[\n")
	return err
}

// CloseJSONFile closes the JSON file and writes the final bracket
func (f *Findings) CloseJSONFile() error {
	if f.jsonFile == nil {
		return nil
	}

	// Write the closing bracket
	_, err := f.jsonFile.WriteString("\n]")
	if err != nil {
		return err
	}

	return f.jsonFile.Close()
}

// NewStatistics creates a new Statistics instance
func NewStatistics() *Statistics {
	return &Statistics{
		Categories: make(map[string]int),
		Mu:         &sync.Mutex{},
	}
}

// MarshalJSON implements custom JSON marshaling for Findings
func (f *Findings) MarshalJSON() ([]byte, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	// Convert map to slice for JSON output
	sites := make([]URLFindings, 0, len(f.Sites))
	for _, findings := range f.Sites {
		sites = append(sites, *findings)
	}
	return json.Marshal(sites)
}

// Add adds a new secret finding and writes it to JSON file immediately
func (f *Findings) Add(urlStr, category, patternType, secret, uri string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	if f.Sites == nil {
		f.Sites = make(map[string]*URLFindings)
	}

	if _, exists := f.Sites[urlStr]; !exists {
		f.Sites[urlStr] = &URLFindings{
			URL:     urlStr,
			Secrets: make([]Secret, 0),
		}
	}

	newSecret := Secret{
		Category:    category,
		PatternType: patternType,
		Value:       secret,
		URI:         uri,
	}

	f.Sites[urlStr].Secrets = append(f.Sites[urlStr].Secrets, newSecret)

	// Write to JSON file in realtime if file handle exists
	if f.jsonFile != nil {
		finding := URLFindings{
			URL:     urlStr,
			Secrets: []Secret{newSecret},
		}

		data, err := json.MarshalIndent(finding, "", "  ")
		if err == nil {
			if !f.firstEntry {
				f.jsonFile.WriteString(",\n")
			}
			f.jsonFile.Write(data)
			f.firstEntry = false
		}
	}
}

// Increment increments the statistics counters
func (s *Statistics) Increment(category string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.FoundSecrets++
	if s.Categories == nil {
		s.Categories = make(map[string]int)
	}
	s.Categories[category]++
}

// IncrementScanned increments the scanned URLs counter and processed bytes
func (s *Statistics) IncrementScanned(bytes int64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.ScannedURLs++
	s.ProcessedBytes += bytes
}
