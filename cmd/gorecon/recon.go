package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorecon/internal/common"
)

// runRecon runs the full recon pipeline with correct ordering:
//
//  1. subdomain  (passive enumeration)
//  2. dns        (resolution, A/AAAA records)
//  3. scan       (port scanning, optional)
//  4. PARALLEL: http, tls, cdn, takeover  (all consume DNS output)
//  5. crawl      (consumes HTTP live URLs)
//  6. vuln       (consumes HTTP live URLs + crawl endpoints)
func runRecon(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-d", Aliases: []string{"--domain"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-w", Aliases: []string{"--wordlist"}, HasValue: true},
		{Name: "-p", Aliases: []string{"--ports"}, HasValue: true},
		{Name: "-s", Aliases: []string{"--severity"}, HasValue: true},
		{Name: "-t", Aliases: []string{"--templates"}, HasValue: true},
		{Name: "--no-scan", HasValue: false},
		{Name: "--no-http", HasValue: false},
		{Name: "--no-tls", HasValue: false},
		{Name: "--no-cdn", HasValue: false},
		{Name: "--no-crawl", HasValue: false},
		{Name: "--no-vuln", HasValue: false},
		{Name: "--no-takeover", HasValue: false},
	})

	// Handle --help
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printReconHelp()
			return nil
		}
	}

	// Collect domains
	singleDomain := pf.Strings["-d"]
	if singleDomain == "" && len(pf.Args) > 0 {
		singleDomain = pf.Args[0]
	}

	domains, err := common.CollectTargets(pf.Strings["-l"], singleDomain)
	if err != nil {
		return err
	}

	// Setup output directory
	outputDir := pf.Strings["-o"]
	if outputDir == "" {
		outputDir = fmt.Sprintf("gorecon-output-%s", time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("could not create output directory: %s", err)
	}

	fmt.Println()
	fmt.Printf("╔══════════════════════════════════════════╗\n")
	fmt.Printf("║   GoRecon Pipeline — %-19s ║\n", outputDir)
	fmt.Printf("║   Targets: %-28s ║\n", strings.Join(domains, ", "))
	fmt.Printf("╚══════════════════════════════════════════╝\n\n")

	// Stage 1: Subdomain Enumeration
	fmt.Println("─── Stage 1/7: Subdomain Enumeration ───")
	subFile := filepath.Join(outputDir, "1-subdomains.txt")
	for _, domain := range domains {
		fmt.Printf("  [*] Enumerating: %s\n", domain)
		runSubdomain([]string{"-d", domain, "-silent", "-o", subFile})
	}
	subCount := countLines(subFile)
	fmt.Printf("  [+] %d subdomains discovered\n\n", subCount)

	// Stage 2: DNS Resolution
	fmt.Println("─── Stage 2/7: DNS Resolution ───")
	dnsFile := filepath.Join(outputDir, "2-dns-resolved.txt")
	var allTargets []string
	allTargets = append(allTargets, domains...)
	if f, err := os.Open(subFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if t := strings.TrimSpace(scanner.Text()); t != "" {
				allTargets = append(allTargets, t)
			}
		}
		f.Close()
	}
	targetsFile := filepath.Join(outputDir, ".all-targets.txt")
	os.WriteFile(targetsFile, []byte(strings.Join(uniqueStr(allTargets), "\n")), 0644)

	runDNS([]string{"-l", targetsFile, "-a", "-re", "-o", dnsFile})
	dnsCount := countLines(dnsFile)
	fmt.Printf("  [+] %d hosts resolved\n\n", dnsCount)

	// Stage 3: Port Scanning (optional)
	scanFile := filepath.Join(outputDir, "3-open-ports.txt")
	if !pf.Bools["--no-scan"] {
		fmt.Println("─── Stage 3/7: Port Scanning ───")
		ports := pf.Strings["-p"]
		if ports == "" {
			ports = "80,443,8080,8443,3000,5000,8000,8081,9090,9443"
		}
		runPortScan([]string{"-l", targetsFile, "-p", ports, "-silent", "-o", scanFile})
		fmt.Printf("  [+] %d hosts with open ports\n\n", countLines(scanFile))
	} else {
		fmt.Println("─── Stage 3/7: Port Scanning (skipped) ───")
	}

	// Stage 4: HTTP, TLS, CDN (PARALLEL)
	fmt.Println("─── Stage 4/7: HTTP Probing | TLS Analysis | CDN Detection | Takeover Check ───")
	hostsFile := filepath.Join(outputDir, ".hosts.txt")
	extractHostnamesFromDNS(dnsFile, hostsFile)

	httpFile := filepath.Join(outputDir, "4-http-live.txt")
	tlsFile := filepath.Join(outputDir, "4-tls-results.txt")
	cdnFile := filepath.Join(outputDir, "4-cdn-results.txt")
	takeoverFile := filepath.Join(outputDir, "4-takeover-results.txt")

	type stageResult struct {
		name  string
		file  string
		count int
	}
	results := make(chan stageResult, 4)

	// Stage 4: HTTP, TLS, CDN run in parallel.
	// Only runHTTP touches os.Args (briefly, for option parsing before I/O begins).
	// runTLS and runCDN use their own client libraries without modifying globals.
	if !pf.Bools["--no-http"] {
		go func() {
			runHTTP([]string{"-l", hostsFile, "-silent", "-sc", "-title", "-td", "-server",
				"-cdn", "-cname", "-o", httpFile})
			results <- stageResult{"HTTP Probing", httpFile, countLines(httpFile)}
		}()
	} else {
		results <- stageResult{"HTTP Probing", httpFile, 0}
	}

	if !pf.Bools["--no-tls"] {
		go func() {
			runTLS([]string{"-l", hostsFile, "-san", "-cn", "-tv", "-o", tlsFile})
			results <- stageResult{"TLS Analysis", tlsFile, countLines(tlsFile)}
		}()
	} else {
		results <- stageResult{"TLS Analysis", tlsFile, 0}
	}

	if !pf.Bools["--no-cdn"] {
		go func() {
			runCDN([]string{"-l", hostsFile, "-resp", "-o", cdnFile})
			results <- stageResult{"CDN Detection", cdnFile, countLines(cdnFile)}
		}()
	} else {
		results <- stageResult{"CDN Detection", cdnFile, 0}
	}

	// Takeover check — also consumes DNS hostnames
	if !pf.Bools["--no-takeover"] {
		go func() {
			runTakeover([]string{"-l", hostsFile, "-silent", "-o", takeoverFile})
			results <- stageResult{"Takeover Check", takeoverFile, countTakeoverFindings(takeoverFile)}
		}()
	} else {
		results <- stageResult{"Takeover Check", takeoverFile, 0}
	}

	for i := 0; i < 4; i++ {
		r := <-results
		fmt.Printf("  [+] %s: %d results  → %s\n", r.name, r.count, filepath.Base(r.file))
	}
	fmt.Println()

	// Stage 5: Crawling (consumes HTTP live URLs)
	crawlFile := filepath.Join(outputDir, "5-crawl-endpoints.txt")
	if !pf.Bools["--no-crawl"] {
		fmt.Println("─── Stage 5/7: Web Crawling ───")
		liveCount := countLines(httpFile)
		if liveCount > 0 {
			var crawlTargets []string
			if f, err := os.Open(httpFile); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "[200]") || strings.Contains(line, "[30") {
						if url := extractURL(line); url != "" {
							crawlTargets = append(crawlTargets, url)
						}
					}
				}
				f.Close()
			}
			if len(crawlTargets) > 5 {
				crawlTargets = crawlTargets[:5]
			}
			if len(crawlTargets) == 0 && liveCount > 0 {
				crawlTargets = firstURLs(httpFile, 3)
			}

			if len(crawlTargets) > 0 {
				crawlTargetsFile := filepath.Join(outputDir, ".crawl-targets.txt")
				os.WriteFile(crawlTargetsFile, []byte(strings.Join(crawlTargets, "\n")), 0644)
				defer os.Remove(crawlTargetsFile)

				fmt.Printf("  [*] Crawling %d targets...\n", len(crawlTargets))
				runCrawl([]string{"-u", crawlTargetsFile, "-d", "3", "-s", "depth-first",
					"-o", crawlFile})
			}
		}
		fmt.Printf("  [+] Crawling complete  → %s\n\n", filepath.Base(crawlFile))
	} else {
		fmt.Println("─── Stage 5/7: Web Crawling (skipped) ───")
	}

	// Stage 6: Vulnerability Scanning (consumes HTTP live URLs)
	vulnFile := filepath.Join(outputDir, "6-vulnerabilities.jsonl")
	if !pf.Bools["--no-vuln"] {
		fmt.Println("─── Stage 6/7: Vulnerability Scanning ───")
		severity := pf.Strings["-s"]
		if severity == "" {
			severity = "critical,high,medium"
		}
		if countLines(httpFile) > 0 {
			vulnArgs := []string{"-l", httpFile, "-j", "-s", severity, "-o", vulnFile}
			if t := pf.Strings["-t"]; t != "" {
				vulnArgs = append(vulnArgs, "-t", t)
			}
			fmt.Printf("  [*] Scanning with severity: %s\n", severity)
			runVuln(vulnArgs)
		} else {
			fmt.Println("  [!] No live URLs to scan")
		}
		fmt.Printf("  [+] Vulnerability scan complete  → %s\n\n", filepath.Base(vulnFile))
	} else {
		fmt.Println("─── Stage 6/7: Vulnerability Scanning (skipped) ───")
	}

	// Cleanup temp files
	os.Remove(targetsFile)
	os.Remove(hostsFile)

	fmt.Printf("╔══════════════════════════════════════════╗\n")
	fmt.Printf("║        RECON PIPELINE COMPLETE           ║\n")
	fmt.Printf("╚══════════════════════════════════════════╝\n\n")
	fmt.Printf("  Results saved to: %s/\n\n", outputDir)
	fmt.Printf("  1-subdomains.txt       %4d subdomains\n", subCount)
	fmt.Printf("  2-dns-resolved.txt     %4d resolved hosts\n", dnsCount)
	if !pf.Bools["--no-scan"] {
		fmt.Printf("  3-open-ports.txt       %4d open ports\n", countLines(scanFile))
	}
	if !pf.Bools["--no-http"] {
		fmt.Printf("  4-http-live.txt        %4d live HTTP endpoints\n", countLines(httpFile))
	}
	if !pf.Bools["--no-tls"] {
		fmt.Printf("  4-tls-results.txt      %4d TLS analyzed\n", countLines(tlsFile))
	}
	if !pf.Bools["--no-cdn"] {
		fmt.Printf("  4-cdn-results.txt      %4d CDN/WAF checked\n", countLines(cdnFile))
	}
	if !pf.Bools["--no-takeover"] {
		fmt.Printf("  4-takeover-results.txt %4d takeover findings\n", countTakeoverFindings(takeoverFile))
	}
	if !pf.Bools["--no-vuln"] {
		fmt.Printf("  6-vulnerabilities.jsonl  vulnerability findings\n")
	}
	fmt.Println()
	return nil
}

// helpers

// countTakeoverFindings counts verified takeover findings (lines starting with "⚠").
func countTakeoverFindings(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(strings.TrimSpace(scanner.Text()), "⚠") {
			count++
		}
	}
	return count
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func uniqueStr(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// extractHostnamesFromDNS extracts hostnames from DNS output.
// Handles both "-re" format ("hostname [A] [ip]") and plain format (one per line).
func extractHostnamesFromDNS(dnsFile, outputFile string) {
	f, err := os.Open(dnsFile)
	if err != nil {
		return
	}
	defer f.Close()

	var hostnames []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, " ["); idx > 0 {
			hostnames = append(hostnames, line[:idx])
		} else if cleanLine := strings.TrimSpace(line); cleanLine != "" {
			hostnames = append(hostnames, cleanLine)
		}
	}
	hostnames = uniqueStr(hostnames)
	if len(hostnames) > 0 {
		os.WriteFile(outputFile, []byte(strings.Join(hostnames, "\n")), 0644)
	}
}

func extractURL(line string) string {
	if idx := strings.Index(line, " ["); idx > 0 {
		return line[:idx]
	}
	if parts := strings.Fields(line); len(parts) > 0 {
		if strings.HasPrefix(parts[0], "http") {
			return parts[0]
		}
	}
	return ""
}

func firstURLs(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && len(urls) < n {
		if u := extractURL(scanner.Text()); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

func printReconHelp() {
	fmt.Println(`
	Recon Pipeline

	Full pipeline with correct dependency ordering:
	  1. subdomain → passive enumeration
	  2. dns       → DNS resolution
	  3. scan      → port scanning
	  4. http | tls | cdn  (parallel — all consume DNS output)
	  5. crawl     → endpoint discovery (consumes HTTP output)
	  6. vuln      → vulnerability scan (consumes HTTP + crawl output)

	Usage:
	  gorecon recon [flags] <domain>
	  gorecon recon -l domains.txt

	Flags:
	  -d, --domain string     target domain
	  -l, --list string       list of domains
	  -o, --output string     output directory (default: gorecon-output-<timestamp>/)
	  -w, --wordlist string   wordlist for DNS bruteforce (optional)
	  -p, --ports string      custom ports for scanning (default: common web ports)
	  -s, --severity string   nuclei severity filter (default: critical,high,medium)
	  -t, --templates string  nuclei templates directory
	  --no-scan               skip port scanning
	  --no-http               skip HTTP probing
	  --no-tls                skip TLS analysis
	  --no-cdn                skip CDN detection
	  --no-crawl              skip web crawling
	  --no-vuln               skip vulnerability scanning
	  --no-takeover           skip takeover detection

	Examples:
	  gorecon recon example.com
	  gorecon recon example.com -s critical,high
	  gorecon recon -l domains.txt -o results/
	  gorecon recon example.com -p 80,443,8443,9090
	  gorecon recon example.com --no-scan --no-cdn
	`)
}
