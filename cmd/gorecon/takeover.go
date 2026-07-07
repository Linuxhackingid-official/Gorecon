package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gorecon/internal/common"

	"github.com/miekg/dns"
	dnsxlibs "github.com/projectdiscovery/dnsx/libs/dnsx"
)

// takeoverService defines a SaaS service vulnerable to subdomain takeover.
type takeoverService struct {
	Name       string
	Domains    []string
	Signature  string
	HTTPCodes  []int
	CheckHTTPS bool
}

var takeoverServices = []takeoverService{
	{Name: "AWS S3", Domains: []string{"s3.amazonaws.com", "s3-website-", "s3-website."}, Signature: "The specified bucket does not exist", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "GitHub Pages", Domains: []string{"github.io"}, Signature: "There isn't a GitHub Pages site here", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Heroku", Domains: []string{"herokuapp.com", "herokudns.com"}, Signature: "No such app", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Surge.sh", Domains: []string{"surge.sh"}, Signature: "project not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Bitbucket", Domains: []string{"bitbucket.io"}, Signature: "Repository not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Netlify", Domains: []string{"netlify.app", "netlify.com"}, Signature: "Not Found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Firebase", Domains: []string{"firebaseapp.com", "web.app"}, Signature: "Site not found", HTTPCodes: []int{404, 403}, CheckHTTPS: true},
	{Name: "Cloudflare Pages", Domains: []string{"pages.dev"}, Signature: "Site not found", HTTPCodes: []int{404, 403}, CheckHTTPS: true},
	{Name: "Azure WebApps", Domains: []string{"azurewebsites.net", "trafficmanager.net"}, Signature: "This web app is stopped", HTTPCodes: []int{403}, CheckHTTPS: true},
	{Name: "Shopify", Domains: []string{"myshopify.com"}, Signature: "Sorry, this shop is currently unavailable", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Readme.io", Domains: []string{"readmessl.com", "readme.io"}, Signature: "Project not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Freshdesk", Domains: []string{"freshdesk.com", "myfreshworks.com"}, Signature: "Account not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "HelpScout", Domains: []string{"helpscoutdocs.com", "helpscout.com"}, Signature: "Site not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Cargo", Domains: []string{"cargocollective.com"}, Signature: "404 Not Found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Tilda", Domains: []string{"tilda.ws"}, Signature: "Page not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Statuspage", Domains: []string{"statuspage.io", "stspg-customer.com"}, Signature: "Status page not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "AWS CloudFront", Domains: []string{"cloudfront.net"}, Signature: "The request could not be satisfied", HTTPCodes: []int{403}, CheckHTTPS: true},
	{Name: "Intercom", Domains: []string{"intercom.io", "intercomhelp.com"}, Signature: "This page is not available", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Zendesk", Domains: []string{"zendesk.com", "zendesk-help.com"}, Signature: "Help Center is not available", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Ghost", Domains: []string{"ghost.io"}, Signature: "Site not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Pantheon", Domains: []string{"pantheonsite.io"}, Signature: "Site not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Unbounce", Domains: []string{"unbouncepages.com"}, Signature: "Page not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "LaunchRock", Domains: []string{"launchrock.com"}, Signature: "It looks like you may have taken a wrong turn", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Acquia", Domains: []string{"acsitefactory.com"}, Signature: "Site not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "GetResponse", Domains: []string{"gr8.com"}, Signature: "Domain not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "Campaign Monitor", Domains: []string{"createsend.com"}, Signature: "Site not found", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "WordPress", Domains: []string{"wordpress.com"}, Signature: "Do you want to register", HTTPCodes: []int{404}, CheckHTTPS: true},
	{Name: "MailChimp", Domains: []string{"list-manage.com", "mailchi.mp"}, Signature: "Landing page not found", HTTPCodes: []int{404}, CheckHTTPS: true},
}

type takeoverResult struct {
	Subdomain string
	CNAME     string
	Service   string
	HTTPCode  int
	Signature string
	Verified  bool
}

func runTakeover(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-d", Aliases: []string{"--domain"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-w", Aliases: []string{"--wordlist"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-t", Aliases: []string{"--threads"}, HasValue: true},
		{Name: "-silent", Aliases: []string{"--silent"}, HasValue: false},
		{Name: "-j", Aliases: []string{"--json"}, HasValue: false},
		{Name: "-v", Aliases: []string{"--verbose"}, HasValue: false},
		{Name: "-all", Aliases: []string{"--all"}, HasValue: false},
		{Name: "--only", HasValue: true},
		{Name: "--exclude", HasValue: true},
		{Name: "--no-discover", HasValue: false},
		{Name: "--no-http", HasValue: false},
	})

	for _, a := range args {
		if a == "-h" || a == "--help" {
			printTakeoverHelp()
			return nil
		}
	}

	threads := parseIntArg(pf, "-t", 50)
	jsonOutput := pf.Bools["-j"]
	verbose := pf.Bools["-v"]
	noDiscover := pf.Bools["--no-discover"]
	noHTTP := pf.Bools["--no-http"]
	allSources := pf.Bools["-all"]
	onlyService := strings.ToLower(pf.Strings["--only"])
	excludeService := strings.ToLower(pf.Strings["--exclude"])

	// ─── Phase 0: Collect targets ───
	var targets []string

	if domain := pf.Strings["-d"]; domain != "" {
		if !noDiscover {
			if !pf.Bools["-silent"] {
				fmt.Printf("[*] Discovering subdomains for %s...\n", domain)
			}
			tmpFile, err := os.CreateTemp("", "gorecon-takeover-*.txt")
			if err != nil {
				return err
			}
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			subFlags := []string{"-d", domain, "-silent", "-o", tmpFile.Name()}
			if allSources {
				subFlags = append(subFlags, "-all")
			}
			runSubdomain(subFlags)

			f, _ := os.Open(tmpFile.Name())
			if f != nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if t := strings.TrimSpace(scanner.Text()); t != "" {
						targets = append(targets, t)
					}
				}
				f.Close()
			}
			if !pf.Bools["-silent"] {
				fmt.Printf("[+] %d subdomains discovered\n", len(targets))
			}
		}
		// Always include apex
		targets = append(targets, domain)

		// Brute-force with wordlist if provided
		if wordlist := pf.Strings["-w"]; wordlist != "" {
			fmt.Printf("[*] Bruteforcing subdomains from wordlist...\n")
			bruteTargets := generateBruteTargets(domain, wordlist)
			targets = append(targets, bruteTargets...)
			fmt.Printf("[+] %d bruteforce targets added\n", len(bruteTargets))
		}
	} else if listFile := pf.Strings["-l"]; listFile != "" {
		var err error
		targets, err = common.CollectTargets(listFile, "")
		if err != nil {
			return err
		}
	} else if len(pf.Args) > 0 {
		// Positional arg: could be a domain or subdomain
		targets = pf.Args
	} else {
		// Stdin
		var err error
		targets, err = common.CollectTargets("", "")
		if err != nil {
			return err
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets. Use -d <domain>, -l <file>, pipe input, or positional arg")
	}

	// Deduplicate
	targets = uniqueStr(targets)

	// ─── Phase 1: DNS CNAME resolution ───
	if !pf.Bools["-silent"] {
		fmt.Printf("[*] Resolving CNAMEs for %d targets (%d threads)...\n", len(targets), threads)
	}

	type cnameEntry struct{ subdomain, cname string }

	dnsClient, err := dnsxlibs.New(dnsxlibs.Options{
		BaseResolvers: dnsxlibs.DefaultResolvers,
		MaxRetries:    2,
		QuestionTypes: []uint16{dns.TypeCNAME, dns.TypeA},
		Timeout:       5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("dns client: %s", err)
	}

	var (
		cnameResults []cnameEntry
		cnameMu      sync.Mutex
		wg           sync.WaitGroup
		sem          = make(chan struct{}, threads)
	)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := dnsClient.QueryMultiple(target)
			if err != nil || data == nil {
				return
			}
			for _, cname := range data.CNAME {
				cnameMu.Lock()
				cnameResults = append(cnameResults, cnameEntry{
					subdomain: target, cname: strings.TrimSuffix(cname, "."),
				})
				cnameMu.Unlock()
			}
		}(t)
	}
	wg.Wait()

	if !pf.Bools["-silent"] {
		fmt.Printf("[+] %d CNAME records found\n", len(cnameResults))
	}
	if len(cnameResults) == 0 {
		fmt.Println("[*] No CNAME records found.")
		return nil
	}

	// ─── Phase 2: Match + HTTP verify ───
	if !pf.Bools["-silent"] {
		fmt.Printf("[*] Checking against %d takeover services...\n", len(takeoverServices))
	}

	// Filter services
	var activeServices []takeoverService
	for _, svc := range takeoverServices {
		if onlyService != "" && !strings.Contains(strings.ToLower(svc.Name), onlyService) {
			continue
		}
		if excludeService != "" && strings.Contains(strings.ToLower(svc.Name), excludeService) {
			continue
		}
		activeServices = append(activeServices, svc)
	}

	var (
		findings   []takeoverResult
		findingsMu sync.Mutex
		wg2        sync.WaitGroup
		sem2       = make(chan struct{}, threads)
	)

	if !noHTTP {
		for _, entry := range cnameResults {
			var matched *takeoverService
			for i := range activeServices {
				for _, domain := range activeServices[i].Domains {
					if strings.Contains(entry.cname, domain) {
						matched = &activeServices[i]
						break
					}
				}
				if matched != nil {
					break
				}
			}
			if matched == nil {
				continue
			}

			wg2.Add(1)
			sem2 <- struct{}{}
			go func(entry cnameEntry, svc *takeoverService) {
				defer wg2.Done()
				defer func() { <-sem2 }()

				scheme := "http"
				if svc.CheckHTTPS {
					scheme = "https"
				}
				client := &http.Client{
					Timeout: 8 * time.Second,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, entry.cname))
				if err != nil {
					return
				}
				defer resp.Body.Close()

				codeMatch := len(svc.HTTPCodes) == 0
				for _, c := range svc.HTTPCodes {
					if resp.StatusCode == c {
						codeMatch = true
						break
					}
				}
				if !codeMatch {
					return
				}

				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				if strings.Contains(string(body), svc.Signature) {
					findingsMu.Lock()
					findings = append(findings, takeoverResult{
						Subdomain: entry.subdomain, CNAME: entry.cname,
						Service: svc.Name, HTTPCode: resp.StatusCode,
						Signature: svc.Signature, Verified: true,
					})
					findingsMu.Unlock()
				}
			}(entry, matched)
		}
		wg2.Wait()
	} else {
		// No HTTP verification — just show CNAME matches
		for _, entry := range cnameResults {
			for i := range activeServices {
				for _, domain := range activeServices[i].Domains {
					if strings.Contains(entry.cname, domain) {
						findings = append(findings, takeoverResult{
							Subdomain: entry.subdomain, CNAME: entry.cname,
							Service: activeServices[i].Name,
						})
						break
					}
				}
			}
		}
	}

	// ─── Phase 3: Output ───
	w, cleanup, err := common.OutputWriter(pf.Strings["-o"])
	if err != nil {
		return err
	}
	defer cleanup()

	if verbose && !noHTTP {
		fmt.Fprintf(os.Stderr, "\n[*] All CNAME records found:\n")
		for _, e := range cnameResults {
			fmt.Fprintf(os.Stderr, "    %s → %s\n", e.subdomain, e.cname)
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(findings) == 0 {
		if !pf.Bools["-silent"] {
			fmt.Println("[+] No takeover vulnerabilities found.")
		}
		return nil
	}

	verified := 0
	for _, f := range findings {
		if f.Verified {
			verified++
		}
	}

	if !pf.Bools["-silent"] {
		if noHTTP {
			fmt.Printf("\n[+] %d potential CNAME matches (use without --no-http to verify):\n\n", len(findings))
		} else {
			fmt.Printf("\n╔══════════════════════════════════════════════╗\n")
			fmt.Printf("║  %d TAKEOVER VULNERABILITIES FOUND        ║\n", verified)
			fmt.Printf("╚══════════════════════════════════════════════╝\n\n")
		}
	}

	for _, f := range findings {
		if jsonOutput {
			fmt.Fprintf(w, `{"subdomain":"%s","cname":"%s","service":"%s","http_code":%d,"verified":%v}`+"\n",
				f.Subdomain, f.CNAME, f.Service, f.HTTPCode, f.Verified)
		} else {
			marker := "⚠ "
			if !f.Verified {
				marker = "? "
			}
			fmt.Fprintf(w, "%s%s\n", marker, f.Subdomain)
			fmt.Fprintf(w, "   CNAME:    %s\n", f.CNAME)
			fmt.Fprintf(w, "   Service:  %s\n", f.Service)
			if f.Verified {
				fmt.Fprintf(w, "   HTTP:     %d\n", f.HTTPCode)
				fmt.Fprintf(w, "   Message:  \"%s\"\n", f.Signature)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	return nil
}

// generateBruteTargets generates subdomains from wordlist for a domain.
func generateBruteTargets(domain, wordlist string) []string {
	f, err := os.Open(wordlist)
	if err != nil {
		return nil
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" {
			targets = append(targets, w+"."+domain)
		}
	}
	return targets
}

func printTakeoverHelp() {
	fmt.Print(`
Subdomain Takeover Detection

Discover subdomains and check for dangling CNAME records
pointing to unclaimed SaaS/cloud services (30+ services).

Pipeline: enumerate → DNS CNAME → service match → HTTP verify

Usage:
  gorecon takeover -d <domain>               auto-discover + check
  gorecon takeover -l <subdomains.txt>        check existing list
  gorecon takeover -d <domain> -w <wordlist>  discover + bruteforce
  gorecon takeover <subdomain>                check single target
  gorecon takeover -d <domain> -all           all subdomain sources
  cat subs.txt | gorecon takeover             pipe targets via stdin

Flags:
  -d, --domain string    target domain (auto-discovers subdomains)
  -l, --list string      file with list of subdomains to check
  -w, --wordlist string  wordlist for DNS bruteforce
  -o, --output string    output file (default: stdout)
  -t, --threads int      concurrency (default: 50)
  -j, --json             JSON output
  -v, --verbose          show all CNAME records found
  -all                   use all subfinder sources (thorough but slow)
  --only <name>          only check specific service (e.g. "github","heroku")
  --exclude <name>       exclude service (e.g. "cloudfront")
  --no-discover          skip subdomain discovery (check given targets only)
  --no-http              skip HTTP verification (just show CNAME matches)
  -silent                results only

Supported Services (30+):
  AWS S3, CloudFront, GitHub Pages, Heroku, Surge.sh, Netlify,
  Firebase, Cloudflare Pages, Azure WebApps, Shopify, Bitbucket,
  Readme.io, Freshdesk, HelpScout, Cargo, Tilda, Statuspage,
  Intercom, Zendesk, Ghost, Pantheon, Unbounce, LaunchRock,
  Acquia, GetResponse, Campaign Monitor, WordPress, MailChimp

Examples:
  gorecon takeover -d example.com
  gorecon takeover -d example.com -all -w subs.txt
  gorecon takeover -l subs.txt -o results.txt
  gorecon takeover -d example.com --only heroku
  gorecon takeover -d example.com -v --no-http    (dry-run)
  gorecon takeover -d example.com -j | tee findings.jsonl
  gorecon takeover api.example.com               (single check)
  cat subs.txt | gorecon takeover -silent        (pipe)
`)
}
