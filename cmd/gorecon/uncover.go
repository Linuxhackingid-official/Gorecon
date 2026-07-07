package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gorecon/internal/common"

	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	dnsxlibs "github.com/projectdiscovery/dnsx/libs/dnsx"
)

// runUncover discovers exposed assets via search engines (Shodan, Censys, Fofa, etc.).
//
// Two modes:
//   - Domain/IP mode (-d, -i): resolves DNS → queries shodan-idb (free, no API key needed)
//   - Query mode (-q): raw search queries against configured agents (requires API keys)
func runUncover(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-d", Aliases: []string{"--domain"}, HasValue: true},
		{Name: "-i", Aliases: []string{"--ip"}, HasValue: true},
		{Name: "-q", Aliases: []string{"--query"}, HasValue: true},
		{Name: "-a", Aliases: []string{"--agent"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--limit"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-t", Aliases: []string{"--threads"}, HasValue: true},
		{Name: "-timeout", Aliases: []string{"--timeout"}, HasValue: true},
		{Name: "-j", Aliases: []string{"--json"}, HasValue: false},
		{Name: "-v", Aliases: []string{"--verbose"}, HasValue: false},
		{Name: "-silent", Aliases: []string{"--silent"}, HasValue: false},
	})

	for _, a := range args {
		if a == "-h" || a == "--help" {
			printUncoverHelp()
			return nil
		}
	}

	domain := pf.Strings["-d"]
	ip := pf.Strings["-i"]
	query := pf.Strings["-q"]
	agent := pf.Strings["-a"]
	limit := parseIntArg(pf, "-l", 100)
	timeout := parseIntArg(pf, "-timeout", 10)
	jsonOutput := pf.Bools["-j"]
	silent := pf.Bools["-silent"]

	// Default agent
	if agent == "" {
		// shodan-idb is free and works for IP/domain input
		if domain != "" || ip != "" {
			agent = "shodan-idb"
		} else {
			agent = "shodan"
		}
	}

	if !silent {
		fmt.Fprintf(os.Stderr, "[*] uncover :: agent=%s limit=%d\n", agent, limit)
	}

	// ─── Collect queries ───
	var queries []string

	if domain != "" {
		needsIPs := strings.Contains(agent, "shodan-idb")
		needsSearch := agent != "shodan-idb" // any non-idb agent uses search syntax

		if needsIPs {
			// shodan-idb only accepts IPs — resolve DNS first
			if !silent {
				fmt.Fprintf(os.Stderr, "[*] Resolving DNS for %s...\n", domain)
			}
			ips, err := resolveDomainToIPs(domain, timeout)
			if err != nil {
				return fmt.Errorf("dns resolution: %s", err)
			}
			if len(ips) == 0 {
				return fmt.Errorf("no IPs resolved for %s", domain)
			}
			if !silent {
				fmt.Fprintf(os.Stderr, "[+] %d IPs resolved\n", len(ips))
			}
			queries = append(queries, ips...)
		}
		if needsSearch {
			// Other agents use search syntax — pass domain as query
			queries = append(queries, fmt.Sprintf("hostname:%s", domain))
		}
		if !needsIPs && !needsSearch {
			// Fallback: just resolve DNS
			queries = append(queries, domain)
		}
	} else if ip != "" {
		queries = append(queries, ip)
	} else if query != "" {
		queries = append(queries, query)
	} else if len(pf.Args) > 0 {
		// Positional arg: could be domain, IP, or query
		queries = append(queries, pf.Args...)
	} else {
		// Stdin
		targets, err := common.CollectTargets("", "")
		if err != nil {
			return err
		}
		queries = targets
	}

	if len(queries) == 0 {
		return fmt.Errorf("no queries. Use -d <domain>, -i <ip>, -q <query>, or pipe input")
	}

	// ─── Setup output ───
	w, cleanup, err := common.OutputWriter(pf.Strings["-o"])
	if err != nil {
		return err
	}
	defer cleanup()

	// ─── Run uncover ───
	agents := strings.Split(agent, ",")
	for i := range agents {
		agents[i] = strings.TrimSpace(agents[i])
	}

	opts := uncover.Options{
		Agents:  agents,
		Queries: queries,
		Limit:   limit,
		Timeout: timeout,
	}
	service, err := uncover.New(&opts)
	if err != nil {
		return fmt.Errorf("uncover init: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second*2)
	defer cancel()

	found := 0
	seen := make(map[string]bool)

	callback := func(result sources.Result) {
		if result.Error != nil {
			if pf.Bools["-v"] {
				fmt.Fprintf(os.Stderr, "[!] %s: %s\n", result.Source, result.Error)
			}
			return
		}

		var line string
		key := fmt.Sprintf("%s:%d", result.IP, result.Port)

		if jsonOutput {
			line = result.JSON()
		} else {
			if result.Host != "" {
				line = fmt.Sprintf("%s:%d (%s) [%s]", result.IP, result.Port, result.Host, result.Source)
				key = fmt.Sprintf("%s:%d:%s", result.IP, result.Port, result.Host)
			} else {
				line = fmt.Sprintf("%s:%d [%s]", result.IP, result.Port, result.Source)
			}
		}

		if !seen[key] {
			seen[key] = true
			fmt.Fprintln(w, line)
			found++
		}
	}

	if err := service.ExecuteWithCallback(ctx, callback); err != nil {
		return err
	}

	if !silent {
		fmt.Fprintf(os.Stderr, "[+] %d results found\n", found)
	}

	return nil
}

// resolveDomainToIPs resolves a domain to unique IPv4 addresses using dnsx.
func resolveDomainToIPs(domain string, timeout int) ([]string, error) {
	dnsClient, err := dnsxlibs.New(dnsxlibs.Options{
		BaseResolvers: dnsxlibs.DefaultResolvers,
		MaxRetries:    2,
		QuestionTypes: []uint16{1}, // A records only
		Timeout:       time.Duration(timeout) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	data, err := dnsClient.QueryMultiple(domain)
	if err != nil {
		return nil, err
	}

	var ips []string
	seen := make(map[string]bool)
	for _, ip := range data.A {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func printUncoverHelp() {
	fmt.Print(`
  External Asset Discovery

  Query public search engines (Shodan, Censys, Fofa, etc.) to discover
  exposed hosts, IPs, and services beyond passive DNS enumeration.

  Free mode: use shodan-idb (Shodan InternetDB) with domain or IP input.
  Advanced mode: use -q with raw queries against any supported agent.

  Usage:
    gorecon uncover -d <domain>                 free: resolve DNS + query shodan-idb
    gorecon uncover -i <ip>                     query shodan-idb for single IP
    gorecon uncover -q <query> -a <agent>       raw query with specific agent
    gorecon uncover -d example.com -a shodan    domain query with API key agent
    gorecon uncover -d example.com -j -o out.jsonl
    echo 1.2.3.4 | gorecon uncover             pipe IPs via stdin

  Flags:
    -d, --domain string    target domain (auto-resolves DNS → queries shodan-idb)
    -i, --ip string        target IP or CIDR
    -q, --query string     raw search query (requires API key agent)
    -a, --agent string     search engines: shodan,shodan-idb,censys,fofa,quake,
                           hunter,zoomeye,netlas,criminalip,hunterhow,publicwww,
                           google,odin,binaryedge,onyphe,greynoise (default: shodan-idb)
    -l, --limit int        max results per agent (default: 100)
    -o, --output string    output file (default: stdout)
    -t, --threads int      concurrency (default: 10)
    -timeout int           timeout in seconds (default: 10)
    -j, --json             JSONL output
    -v, --verbose          show errors and warnings
    -silent                results only

  Supported Agents (19):
    shodan-idb (free)  shodan      censys      fofa        quake
    hunter             zoomeye     netlas      criminalip  publicwww
    hunterhow          google      odin        binaryedge  onyphe
    driftnet           greynoise   daydaymap   nerdydata

  Provider config: ~/.config/uncover/provider-config.yaml

  Examples:
    gorecon uncover -d example.com
    gorecon uncover -d example.com -o ips.txt
    gorecon uncover -i 1.2.3.4 -j
    gorecon uncover -q "ssl:example.com" -a shodan,censys
    gorecon uncover -q "org:Google" -a shodan -l 500
    cat ips.txt | gorecon uncover -silent
`)
}
