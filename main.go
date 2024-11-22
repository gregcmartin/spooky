package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
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
	stats    = &Statistics{mu: &sync.Mutex{}}
)

// Statistics tracks scanning metrics
type Statistics struct {
	ScannedURLs    int
	FoundSecrets   int
	ProcessedBytes int64
	Categories     map[string]int
	mu             *sync.Mutex
}

// CompiledPatterns holds pre-compiled regex patterns
type CompiledPatterns struct {
	Category string
	Patterns []*regexp.Regexp
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
			Category: cat,
			Patterns: patterns,
		})
	}
	return compiled
}

func processMajesticStream(urls chan<- string) error {
	fmt.Println("\033[34m[*]\033[37m Downloading Majestic Million list...")

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

	fmt.Printf("\033[34m[*]\033[37m Processed %d domains\n", total)
	return nil
}

func scanForSecrets(content string, compiledPatterns []CompiledPatterns) {
	stats.mu.Lock()
	stats.ProcessedBytes += int64(len(content))
	stats.ScannedURLs++
	stats.mu.Unlock()

	for _, cp := range compiledPatterns {
		for _, pattern := range cp.Patterns {
			matches := pattern.FindAllString(content, -1)
			for _, match := range matches {
				if !*silent {
					if *detailed {
						fmt.Printf("\033[32m[+]\033[37m Found %s secret: %s\n", cp.Category, match)
					} else {
						fmt.Printf("\033[32m[+]\033[37m Found %s secret\n", cp.Category)
					}
				}
				stats.increment(cp.Category)
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
			if !*silent {
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

	scanForSecrets(content, compiledPatterns)
}

func init() {
	silent = flag.Bool("s", false, "silent mode")
	thread = flag.Int("t", 50, "number of threads")
	ua = flag.String("ua", "Spooky", "User-Agent")
	detailed = flag.Bool("d", false, "detailed mode")
	majestic = flag.Bool("m", false, "use Majestic Million list")
	percent = flag.Int("p", 100, "percentage of Majestic Million to scan (1-100)")
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
		`                             ` + "\033[31m[\033[37mVersion 1.0\033[31m]\n")
}

func printStats() {
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

func main() {
	flag.Parse()

	if !*silent {
		banner()
	}

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

	if !*silent {
		duration := time.Since(startTime)
		fmt.Printf("\n\033[34m[*]\033[37m Scan completed in %.2f seconds\n", duration.Seconds())
		printStats()
	}
}
