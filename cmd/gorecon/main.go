package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	logutil "github.com/projectdiscovery/utils/log"
)

func main() {
	logutil.DisableDefaultLogger()

	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		os.Exit(0)
	}

	subcommand := os.Args[1]

	// Handle global commands
	switch subcommand {
	case "help", "--help", "-h":
		if len(os.Args) > 2 {
			showHelp(os.Args[2])
		} else {
			printUsage()
		}
		os.Exit(0)
	case "version", "--version", "-v":
		printVersion()
		os.Exit(0)
	}

	// Parse global flags from remaining args
	args := os.Args[2:]

	// Setup logging
	setupLogging(append([]string{subcommand}, args...))

	// Dispatch to subcommand
	var err error
	switch subcommand {
	case "subdomain", "sub":
		err = runSubdomain(args)
	case "dns", "dnsx":
		err = runDNS(args)
	case "scan", "portscan", "naabu":
		err = runPortScan(args)
	case "http", "httpx":
		err = runHTTP(args)
	case "crawl", "katana":
		err = runCrawl(args)
	case "vuln", "nuclei":
		err = runVuln(args)
	case "tls", "tlsx", "ssl":
		err = runTLS(args)
	case "cdn", "cdncheck":
		err = runCDN(args)
	case "recon", "pipeline":
		err = runRecon(args)
	case "takeover", "take":
		err = runTakeover(args)
	case "tools", "list":
		listTools()
		os.Exit(0)
	case "update", "upgrade":
		err = updateTools(args)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown command: %s\n", subcommand)
		fmt.Fprintf(os.Stderr, "Run 'gorecon help' for usage.\n")
		os.Exit(1)
	}

	if err != nil {
		gologger.Fatal().Msgf("Error: %s\n", err)
	}
}

func setupLogging(args []string) {
	for _, arg := range args {
		switch arg {
		case "--silent", "-silent":
			gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
		case "--verbose", "-v":
			gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
		case "--no-color", "-nc":
			gologger.DefaultLogger.SetFormatter(formatter.NewCLI(false))
		}
	}
}

func showHelp(cmd string) {
	lower := strings.ToLower(cmd)
	switch lower {
	case "subdomain", "sub":
		printSubdomainHelp()
	case "dns", "dnsx":
		printDNSHelp()
	case "scan", "portscan", "naabu":
		printScanHelp()
	case "http", "httpx":
		printHTTPHelp()
	case "crawl", "katana":
		printCrawlHelp()
	case "vuln", "nuclei":
		printVulnHelp()
	case "tls", "tlsx", "ssl":
		printTLSHelp()
	case "cdn", "cdncheck":
		printCDNHelp()
	case "recon", "pipeline":
		printReconHelp()
	case "takeover", "take":
		printTakeoverHelp()
	default:
		printUsage()
	}
}

func listTools() {
	printBanner()
	fmt.Println()
	fmt.Println("  GoRecon includes the following tools:")
	fmt.Println()
	fmt.Printf("  %-20s %s\n", "subdomain", "Subdomain enumeration")
	fmt.Printf("  %-20s %s\n", "dns", "DNS resolution & bruteforce")
	fmt.Printf("  %-20s %s\n", "scan", "Port scanning")
	fmt.Printf("  %-20s %s\n", "http", "HTTP probing")
	fmt.Printf("  %-20s %s\n", "crawl", "Web crawling")
	fmt.Printf("  %-20s %s\n", "vuln", "Vulnerability scanning")
	fmt.Printf("  %-20s %s\n", "tls", "TLS/SSL analysis")
	fmt.Printf("  %-20s %s\n", "cdn", "CDN/Cloud/WAF detection")
	fmt.Printf("  %-20s %s\n", "recon", "Full pipeline: subdomain->dns->http->vuln")
	fmt.Printf("  %-20s %s\n", "takeover", "Subdomain takeover detection")
	fmt.Println()
	fmt.Println("  Use 'gorecon <command> --help' for detailed usage.")
}

func updateTools(args []string) error {
	if len(args) > 0 && args[0] != "all" {
		return fmt.Errorf("update: unknown option %s (use 'all' to update all tools)", args[0])
	}
	fmt.Println("[*] GoRecon is built from ProjectDiscovery source code.")
	fmt.Println("[*] To update individual components, rebuild gorecon:")
	fmt.Println("    cd /home/0x/Documents/project/gorecon && go build -o ~/.local/bin/gorecon ./cmd/gorecon/")
	return nil
}
