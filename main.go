package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gregcmartin/spooky/patterns"
)

var (
	thread   *int
	silent   *bool
	ua       *string
	detailed *bool
	majestic *bool
	percent  *int
	category string
	jsonFile *string
	stats    = &Statistics{mu: &sync.Mutex{}}
	findings = &Findings{mu: &sync.Mutex{}}
)

// Statistics tracks scanning metrics
type Statistics struct {
	ScannedURLs    int
	FoundSecrets   int
	ProcessedBytes int64
	Categories     map[string]int
	mu             *sync.Mutex
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
	mu    *sync.Mutex
}

func NewFindings() *Findings {
	return &Findings{
		Sites: make(map[string]*URLFindings),
		mu:    &sync.Mutex{},
	}
}

// MarshalJSON implements custom JSON marshaling for Findings
func (f *Findings) MarshalJSON() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Convert map to slice for JSON output
	sites := make([]URLFindings, 0, len(f.Sites))
	for _, findings := range f.Sites {
		sites = append(sites, *findings)
	}
	return json.Marshal(sites)
}

func (f *Findings) add(urlStr, category, patternType, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()

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

// CompiledPatterns holds pre-compiled regex patterns
type CompiledPatterns struct {
	Category    string
	PatternType string
	Patterns    []*regexp.Regexp
}

func (s *Statistics) increment(category string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FoundSecrets++
	if s.Categories == nil {
		s.Categories = make(map[string]int)
	}
	s.Categories[category]++
}

const majesticURL = "https://downloads.majestic.com/majestic_million.csv"

// drawProgressBar creates an ASCII progress bar
func drawProgressBar(current, total int) string {
	width := 40
	progress := float64(current) / float64(total)
	filled := int(progress * float64(width))
	percentage := int(progress * 100)

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("\r\033[34m[*]\033[37m Progress: [%s] %d%% (%d/%d domains)", bar, percentage, current, total)
}

// getPatternType returns a descriptive name for each pattern type
func getPatternType(category string, pattern string) string {
	switch {
	// AWS Patterns
	case strings.Contains(pattern, "AKIA"):
		return "AWS Access Key ID"
	case strings.Contains(pattern, "aws_access_key_id"):
		return "AWS Access Key ID"
	case strings.Contains(pattern, "aws_secret_access_key"):
		return "AWS Secret Access Key"

	// API Patterns
	case strings.Contains(pattern, "bearer"):
		return "Bearer Token"
	case strings.Contains(pattern, "authorization"):
		return "Authorization Token"
	case strings.Contains(pattern, "api[_-]?key"):
		return "Generic API Key"
	case strings.Contains(pattern, "client[_-]?secret"):
		return "Client Secret"

	// Payment Patterns
	case strings.Contains(pattern, "sk_live"):
		return "Stripe Secret Key"
	case strings.Contains(pattern, "pk_live"):
		return "Stripe Public Key"
	case strings.Contains(pattern, "rk_live"):
		return "Stripe Restricted Key"
	case strings.Contains(pattern, "sq0csp"):
		return "Square Access Token"
	case strings.Contains(pattern, "sqOatp"):
		return "Square OAuth Token"

	// Database Patterns
	case strings.Contains(pattern, "mongodb"):
		return "MongoDB Connection String"
	case strings.Contains(pattern, "mysql"):
		return "MySQL Connection String"
	case strings.Contains(pattern, "postgres"):
		return "PostgreSQL Connection String"
	case strings.Contains(pattern, "redis"):
		return "Redis Connection String"

	// Private Key Patterns
	case strings.Contains(pattern, "RSA"):
		return "RSA Private Key"
	case strings.Contains(pattern, "OPENSSH"):
		return "OpenSSH Private Key"
	case strings.Contains(pattern, "PGP"):
		return "PGP Private Key"
	case strings.Contains(pattern, "PRIVATE KEY"):
		return "Generic Private Key"

	// Social Patterns
	case strings.Contains(pattern, "ghp_"):
		return "GitHub Personal Access Token"
	case strings.Contains(pattern, "github_pat"):
		return "GitHub Fine-grained Token"
	case strings.Contains(pattern, "xox"):
		return "Slack Token"
	case strings.Contains(pattern, "EAACEdEose0cBA"):
		return "Facebook Access Token"
	case strings.Contains(pattern, "AIza"):
		return "Google API Key"

	// Communication Patterns
	case strings.Contains(pattern, "twilio") && strings.Contains(pattern, "SK"):
		return "Twilio API Key"
	case strings.Contains(pattern, "twilio") && strings.Contains(pattern, "AC"):
		return "Twilio Account SID"
	case strings.Contains(pattern, "SG."):
		return "SendGrid API Key"
	case strings.Contains(pattern, "mailgun"):
		return "Mailgun API Key"
	case strings.Contains(pattern, "mailchimp"):
		return "Mailchimp API Key"
	case strings.Contains(pattern, "postmark"):
		return "Postmark Server Token"

	// Service Patterns
	case strings.Contains(pattern, "npm_"):
		return "NPM Token"
	case strings.Contains(pattern, "docker_auth"):
		return "Docker Auth Configuration"
	case strings.Contains(pattern, "TRAVIS"):
		return "Travis CI Token"
	case strings.Contains(pattern, "circleci"):
		return "Circle CI Token"
	case strings.Contains(pattern, "sonar"):
		return "SonarQube Token"
	case strings.Contains(pattern, "VAULT_TOKEN"):
		return "Vault Token"

	default:
		return "Unknown Pattern"
	}
}

// compilePatterns pre-compiles all regex patterns for better performance
func compilePatterns() []CompiledPatterns {
	allPatterns := patterns.GetAllPatterns()
	compiled := make([]CompiledPatterns, 0, len(allPatterns))

	for cat, patternList := range allPatterns {
		if category != "" && category != "all" && !strings.EqualFold(category, cat) {
			continue
		}

		patterns := make([]*regexp.Regexp, 0, len(patternList))
		for _, p := range patternList {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			patterns = append(patterns, re)
		}
		compiled = append(compiled, CompiledPatterns{
			Category:    cat,
			Patterns:    patterns,
			PatternType: getPatternType(cat, patternList[0]),
		})
	}
	return compiled
}

func processMajesticStream(urls chan<- string) error {
	resp, err := http.Get(majesticURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	_, err = reader.Read() // Skip header
	if err != nil {
		return err
	}

	total := 0
	maxDomains := 1000000 // Majestic Million size
	if *percent > 0 && *percent < 100 {
		maxDomains = (maxDomains * *percent) / 100
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if !*silent {
				fmt.Print(drawProgressBar(total, maxDomains))
			}
		}
	}()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if total >= maxDomains {
			break
		}

		if len(record) > 2 {
			urls <- "https://" + record[2]
			total++
		}
	}

	if !*silent {
		fmt.Print(drawProgressBar(total, maxDomains))
		fmt.Println()
	}
	return nil
}

func scanForSecrets(urlStr string, content string, compiledPatterns []CompiledPatterns) {
	stats.mu.Lock()
	stats.ProcessedBytes += int64(len(content))
	stats.ScannedURLs++
	stats.mu.Unlock()

	for _, cp := range compiledPatterns {
		for _, pattern := range cp.Patterns {
			matches := pattern.FindAllString(content, -1)
			for _, match := range matches {
				patternType := getPatternType(cp.Category, pattern.String())
				if !*silent && !*majestic {
					if *detailed {
						fmt.Printf("\033[32m[+]\033[37m Found %s (%s): %s\n", cp.Category, patternType, match)
					} else {
						fmt.Printf("\033[32m[+]\033[37m Found %s (%s)\n", cp.Category, patternType)
					}
				}
				stats.increment(cp.Category)
				findings.add(urlStr, cp.Category, patternType, match)
			}
		}
	}
}

func readLocalFile(filepath string) (string, error) {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func req(urlStr string, compiledPatterns []CompiledPatterns) {
	if !strings.Contains(urlStr, "http") && !strings.Contains(urlStr, "file://") {
		fmt.Println("\033[31m[-]\033[37m Send URLs via stdin (ex: cat js.txt | spooky). Each url must contain 'http' or 'file://'")
		os.Exit(0)
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return
	}

	var content string
	if parsedURL.Scheme == "file" {
		// Remove 'file://' prefix and decode the path
		filepath := strings.TrimPrefix(urlStr, "file://")
		filepath, err = url.QueryUnescape(filepath)
		if err != nil {
			return
		}
		content, err = readLocalFile(filepath)
		if err != nil {
			if !*silent && !*majestic {
				fmt.Printf("\033[31m[-]\033[37m Error reading file %s: %v\n", filepath, err)
			}
			return
		}
	} else {
		transp := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: transp,
			Timeout:   10 * time.Second,
		}

		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return
		}

		req.Header.Set("User-Agent", *ua)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		content = string(body)
	}

	scanForSecrets(urlStr, content, compiledPatterns)
}

func init() {
	silent = flag.Bool("s", false, "silent mode")
	thread = flag.Int("t", 50, "number of threads")
	ua = flag.String("ua", "Spooky", "User-Agent")
	detailed = flag.Bool("d", false, "detailed mode")
	majestic = flag.Bool("m", false, "use Majestic Million list")
	percent = flag.Int("p", 100, "percentage of Majestic Million to scan (1-100)")
	jsonFile = flag.String("o", "", "output results to JSON file")
	flag.StringVar(&category, "c", "all", "category to scan (AWS, API, Cloud, Payment, Database, PrivateKey, Social, Communication, Service, or 'all')")
}

func banner() {
	fmt.Printf("\033[31m" + `
	 ███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
	 ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██║ ██╔╝╚██╗ ██╔╝
	 ███████╗██████╔╝██║   ██║██║   ██║█████╔╝  ╚████╔╝ 
	 ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔═██╗   ╚██╔╝  
	 ███████║██║     ╚██████╔╝╚██████╔╝██║  ██╗   ██║   
	 ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
			   ` + "\033[31m[\033[37mAPI Key Scanner\033[31m]\n" +
		`                             ` + "\033[31m[\033[37mVersion 1.1\033[31m]\n")
}

func printStats() {
	if !*majestic {
		fmt.Printf("\n\033[34m[*]\033[37m Scan Statistics:\n")
		fmt.Printf("    URLs Scanned: %d\n", stats.ScannedURLs)
		fmt.Printf("    Secrets Found: %d\n", stats.FoundSecrets)
		fmt.Printf("    Data Processed: %.2f MB\n", float64(stats.ProcessedBytes)/1024/1024)

		if len(stats.Categories) > 0 {
			fmt.Printf("\n    Secrets by Category:\n")
			for category, count := range stats.Categories {
				fmt.Printf("    - %s: %d\n", category, count)
			}
		}
	}
}

func writeJSONOutput() error {
	outputFile := *jsonFile
	if *majestic {
		if outputFile == "" {
			outputFile = "spooky_results.json"
		}
	} else if outputFile == "" {
		return nil
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	err = ioutil.WriteFile(outputFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing JSON file: %v", err)
	}

	if !*silent && !*majestic {
		fmt.Printf("\n\033[34m[*]\033[37m Results written to: %s\n", outputFile)
	}
	return nil
}

func main() {
	flag.Parse()

	if !*silent && !*majestic {
		banner()
	}

	findings = NewFindings() // Initialize findings with new structure
	compiledPatterns := compilePatterns()
	urls := make(chan string)
	var wg sync.WaitGroup

	startTime := time.Now()

	// Start worker goroutines
	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				req(url, compiledPatterns)
			}
		}()
	}

	// Handle Majestic Million mode
	if *majestic {
		err := processMajesticStream(urls)
		if err != nil {
			fmt.Println("\033[31m[-]\033[37m Error processing Majestic Million list:", err)
			os.Exit(1)
		}
	} else {
		// Handle stdin mode
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls <- scanner.Text()
		}
	}

	close(urls)
	wg.Wait()

	if !*silent && !*majestic {
		duration := time.Since(startTime)
		fmt.Printf("\n\033[34m[*]\033[37m Scan completed in %.2f seconds\n", duration.Seconds())
		printStats()
	}

	if err := writeJSONOutput(); err != nil {
		fmt.Printf("\033[31m[-]\033[37m %v\n", err)
		os.Exit(1)
	}
}
