package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gorecon/internal/common"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	katanaTypes "github.com/projectdiscovery/katana/pkg/types"
)

// runCrawl implements web crawling using katana's public packages
func runCrawl(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-u", Aliases: []string{"--list", "--target"}, HasValue: true},
		{Name: "-d", Aliases: []string{"--depth"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-j", Aliases: []string{"--json"}, HasValue: false},
		{Name: "-td", Aliases: []string{"--tech-detect"}, HasValue: false},
		{Name: "-proxy", Aliases: []string{"--proxy"}, HasValue: true},
		{Name: "-nc", Aliases: []string{"--no-color"}, HasValue: false},
		{Name: "-s", Aliases: []string{"--strategy"}, HasValue: true},
	})

	depth := parseIntArg(pf, "-d", 3)
	jsonOutput := pf.Bools["-j"]
	techDetect := pf.Bools["-td"]
	noColor := pf.Bools["-nc"]
	strategy := pf.Strings["-s"]
	if strategy == "" {
		strategy = "depth-first" // default matching katana CLI
	}

	// Determine target from -u flag or positional arg
	list := pf.Strings["-u"]
	if list == "" && len(pf.Args) > 0 {
		list = pf.Args[0]
	}

	// Handle --help
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printCrawlHelp()
			return nil
		}
	}

	// Parse targets
	var urls []string
	if strings.HasPrefix(list, "http") || strings.HasPrefix(list, "https") {
		urls = append(urls, list)
	} else if list != "" {
		f, err := os.Open(list)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					urls = append(urls, line)
				}
			}
		} else {
			urls = append(urls, list)
		}
	}

	// Fallback to stdin
	if len(urls) == 0 {
		stdinTargets, _ := common.CollectTargets("", "")
		if len(stdinTargets) > 0 {
			urls = stdinTargets
		}
	}

	if len(urls) == 0 {
		return fmt.Errorf("no target URLs specified. Use -u <url> or pipe input")
	}

	// Start from katana DefaultOptions to get sane defaults (BodyReadSize, FieldScope, etc.)
	katanaOptions := &katanaTypes.Options{}
	*katanaOptions = katanaTypes.DefaultOptions // copy defaults

	// Override with user-specified flags
	katanaOptions.MaxDepth = depth
	katanaOptions.Strategy = strategy
	katanaOptions.TechDetect = techDetect
	katanaOptions.NoColors = noColor
	katanaOptions.JSON = jsonOutput
	if v := pf.Strings["-proxy"]; v != "" {
		katanaOptions.Proxy = v
	}
	if v := pf.Strings["-o"]; v != "" {
		katanaOptions.OutputFile = v
	}

	// Use NewCrawlerOptions for proper initialization (parser, scope, filters, etc.)
	crawlerOptions, err := katanaTypes.NewCrawlerOptions(katanaOptions)
	if err != nil {
		return fmt.Errorf("could not create crawler options: %s", err)
	}

	// Create crawler
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return fmt.Errorf("could not create crawler: %s", err)
	}
	defer crawler.Close()

	// Crawl each URL
	for _, url := range urls {
		fmt.Fprintf(os.Stderr, "[*] Crawling: %s (depth: %d)\n", url, depth)
		if err := crawler.Crawl(url); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error crawling %s: %s\n", url, err)
		}
	}

	return nil
}

// parseIntArg parses an integer from ParsedFlags with a default.
func parseIntArg(pf *common.ParsedFlags, name string, defaultVal int) int {
	if s, ok := pf.Strings[name]; ok {
		var v int
		if _, err := fmt.Sscanf(s, "%d", &v); err == nil {
			return v
		}
	}
	return defaultVal
}
