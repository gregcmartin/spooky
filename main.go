package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/gregcmartin/spooky/models"
	"github.com/gregcmartin/spooky/scanner"
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
)

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
		`                             ` + "\033[31m[\033[37mVersion 1.15\033[31m]\n")
}

func printStats(stats *models.Statistics) {
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

func writeJSONOutput(findings *models.Findings) error {
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

	stats := models.NewStatistics()
	findings := models.NewFindings()
	scanner := scanner.NewScanner(stats, findings, *silent, *detailed, *majestic, *ua, category)
	urls := make(chan string)

	startTime := time.Now()

	// Start worker goroutines
	done := make(chan bool)
	for i := 0; i < *thread; i++ {
		go func() {
			for url := range urls {
				scanner.ProcessURL(url)
			}
			done <- true
		}()
	}

	// Handle Majestic Million mode
	if *majestic {
		err := scanner.ProcessMajesticStream(urls, *percent)
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

	// Wait for all workers to finish
	for i := 0; i < *thread; i++ {
		<-done
	}

	if !*silent && !*majestic {
		duration := time.Since(startTime)
		fmt.Printf("\n\033[34m[*]\033[37m Scan completed in %.2f seconds\n", duration.Seconds())
		printStats(stats)
	}

	if err := writeJSONOutput(findings); err != nil {
		fmt.Printf("\033[31m[-]\033[37m %v\n", err)
		os.Exit(1)
	}
}
