package models

import (
	"encoding/json"
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
}

// URLFindings represents all findings for a specific URL
type URLFindings struct {
	URL     string   `json:"url"`
	Secrets []Secret `json:"secrets"`
}

// Findings stores all secret findings grouped by URL
type Findings struct {
	Sites map[string]*URLFindings `json:"-"` // Internal map for grouping
	Mu    *sync.Mutex             // Exported for scanner package
}

// NewFindings creates a new Findings instance
func NewFindings() *Findings {
	return &Findings{
		Sites: make(map[string]*URLFindings),
		Mu:    &sync.Mutex{},
	}
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

// Add adds a new secret finding
func (f *Findings) Add(urlStr, category, patternType, secret string) {
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

	f.Sites[urlStr].Secrets = append(f.Sites[urlStr].Secrets, Secret{
		Category:    category,
		PatternType: patternType,
		Value:       secret,
	})
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
