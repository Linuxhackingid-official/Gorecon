package main

import "fmt"

func printBanner() {
	fmt.Printf(`
  ╔══════════════════════════════════╗
  ║     GoRecon - Unified Recon Tool  ║
  ║   ProjectDiscovery All-in-One    ║
  ╚══════════════════════════════════╝

`)
}

func printVersion() {
	fmt.Println("GoRecon v1.0.0")
	fmt.Println("Unified ProjectDiscovery Reconnaissance Tool")
}

func printUsage() {
	fmt.Print(`
Usage:
  gorecon <command> [flags]

Recon Commands:
  subdomain   Subdomain enumeration
  dns         DNS resolution & bruteforce
  scan        Port scanning
  http        HTTP probing
  crawl       Web crawling
  vuln        Vulnerability scanning
  tls         TLS/SSL analysis
  cdn         CDN/Cloud/WAF detection
  recon       Full pipeline: subdomain->dns->http->vuln
  takeover    Subdomain takeover detection

Utility Commands:
  tools       List all integrated tools
  update      Update instructions (rebuild from source)
  version     Show version information
  help        Show this help

Use 'gorecon help <command>' for detailed help.
`)
}

func printSubdomainHelp() {
	fmt.Print(`
Subdomain Enumeration

Discover subdomains using passive online sources.

Usage:
  gorecon subdomain [flags] <domain>

Flags:
  -d, -domain string[]    domains to find subdomains for
  -dL, -list string       file containing list of domains
  -s, -sources string[]   specific sources to use
  -es, -exclude-sources   sources to exclude
  -all                    use all sources (slow)
  -recursive              use only recursive sources
  -o, -output string      output file
  -oJ, -json              JSON output
  -nW, -active            verify active subdomains only
  -oI, -ip                include host IP in output
  -r string[]             custom resolvers
  -rl, -rate-limit int    max requests/sec
  -t int                  concurrency (default 10)
  -timeout int            timeout in seconds (default 30)
  -max-time int           max runtime in minutes (default 10)
  -proxy string           HTTP proxy
  -silent                 show only results
  -v                      verbose output
  -nc, -no-color          disable colors

Examples:
  gorecon subdomain example.com
  gorecon subdomain example.com -all -o subdomains.txt
  gorecon subdomain -dL domains.txt -json -o output.json
`)
}

func printDNSHelp() {
	fmt.Print(`
DNS Resolution & Bruteforce

Multi-purpose DNS toolkit for resolution and bruteforce.

Usage:
  gorecon dns [flags]

Input:
  -l, -list string        list of hosts to resolve
  -d, -domain string      domain to bruteforce
  -w, -wordlist string    wordlist for bruteforce

Query Types:
  -a                      A record (default)
  -aaaa                   AAAA record
  -cname                  CNAME record
  -ns                     NS record
  -txt                    TXT record
  -srv                    SRV record
  -ptr                    PTR record
  -mx                     MX record
  -soa                    SOA record
  -axfr                   AXFR (zone transfer)
  -caa                    CAA record
  -all, -recon            query all record types

Output:
  -o, -output string      output file
  -j, -json               JSON output
  -re, -resp              display DNS response
  -ro, -resp-only         display response only
  -cdn                    show CDN name
  -asn                    show ASN information

Rate Limit:
  -t, -threads int        concurrency (default 100)
  -rl, -rate-limit int    requests/sec (default unlimited)
  -retry int              retries (default 2)
  -timeout duration       timeout (default 3s)

Examples:
  gorecon dns -l hosts.txt
  gorecon dns -d example.com -w wordlist.txt -all
  gorecon dns -l hosts.txt -a -cdn -asn -json
`)
}

func printScanHelp() {
	fmt.Print(`
Port Scanning

Fast port scanner with SYN and CONNECT methods.

Usage:
  gorecon scan [flags] <host>

Flags:
  -host string[]          hosts to scan (comma-separated)
  -l, -list string        list of hosts
  -p, -port string        ports to scan (80,443 or 1-1000)
  -tp, -top-ports string  top ports (full, 100, 1000)
  -s, -scan-type string   scan type: c (connect) or s (syn)
  -c int                  worker threads (default 25)
  -rate int               packets/sec (default 1000)
  -o, -output string      output file
  -j, -json               JSON output
  -csv                    CSV output
  -passive                use Shodan InternetDB
  -ec, -exclude-cdn       skip CDN full scan
  -nmap-cli string        nmap command to run on results
  -proxy string           SOCKS5 proxy
  -retries int            retry count (default 3)

Examples:
  gorecon scan example.com -p 80,443
  gorecon scan -l hosts.txt -tp 1000 -rate 5000
  gorecon scan example.com --passive
`)
}

func printHTTPHelp() {
	fmt.Print(`
HTTP Probing

Fast and multi-purpose HTTP toolkit.

Usage:
  gorecon http [flags] <target>

Flags:
  -u, -target string[]    target URL(s)
  -l, -list string        input file
  -sc, -status-code       show status code
  -cl, -content-length    show content length
  -ct, -content-type      show content type
  -title                  show page title
  -td, -tech-detect       technology detection
  -server                 show server header
  -ip                     show host IP
  -cname                  show host CNAME
  -asn                    show ASN
  -cdn                    show CDN/WAF
  -location               show redirect location
  -rt, -response-time     show response time
  -method                 show request method
  -hash string            body hash (md5,mmh3,sha1,sha256)
  -jarm                   show JARM fingerprint
  -favicon                show favicon hash
  -bp, -body-preview int  body preview (default 100)
  -ss, -screenshot        screenshot (headless)
  -fr, -follow-redirects  follow redirects
  -o, -output string      output file
  -j, -json               JSON output
  -x string               HTTP methods to probe
  -H, -header string[]    custom headers
  -body string            POST body
  -mr, -match-regex       regex match
  -mc, -match-code        status code match
  -fe, -filter-regex      regex filter
  -fc, -filter-code       status code filter
  -timeout int            timeout (default 10)
  -retries int            retries
  -e string               exclude filter (cdn,private-ips)

Examples:
  gorecon http -l hosts.txt -sc -title -td
  gorecon http -u https://example.com -ss -fr
  gorecon http -l hosts.txt -mc 200,302 -title
`)
}

func printCrawlHelp() {
	fmt.Print(`
Web Crawling

Fast crawler focused on automation pipelines.

Usage:
  gorecon crawl [flags] <url>

Flags:
  -u, -list string[]      target URL(s)
  -d, -depth int          max crawl depth (default 3)
  -jc, -js-crawl          parse JavaScript files
  -hl, -headless          headless crawling (experimental)
  -ct, -crawl-duration    max crawl duration
  -kf, -known-files       crawl known files (robotstxt)
  -td, -tech-detect       technology detection
  -o, -output string      output file
  -j, -json               JSON output
  -mr, -match-regex       regex URL match
  -fr, -filter-regex      regex URL filter
  -cs, -crawl-scope       in-scope URL regex
  -ef, -extension-filter  filter extensions
  -proxy string           HTTP/SOCKS5 proxy
  -H, -header string[]    custom headers
  -timeout int            request timeout (default 10)
  -s, -strategy string    crawl strategy (depth-first/breadth-first)
  -ns, -no-scope          disable host scoping

Examples:
  gorecon crawl https://example.com
  gorecon crawl -u https://example.com -d 5 -jc -td
  gorecon crawl -u https://example.com -hl -d 10
`)
}

func printVulnHelp() {
	fmt.Print(`
Vulnerability Scanning

Fast template-based vulnerability scanner.

Usage:
  gorecon vuln [flags] <target>

Flags:
  -u, -target string[]    target URLs/hosts
  -l, -list string        input file
  -t, -templates string   template(s) or directory
  -w, -workflows string   workflow(s) to run
  -tags string            template tags to run
  -etags, -exclude-tags   tags to exclude
  -s, -severity string    severity filter (info,low,medium,high,critical)
  -es, -exclude-severity  exclude severity
  -id, -template-id       template IDs to run
  -et, -exclude-templates templates to exclude
  -as, -automatic-scan    auto-scan from tech detection
  -nt, -new-templates     only new templates
  -rl, -rate-limit        max requests/sec
  -c, -concurrency        concurrency
  -o, -output string      output file
  -j, -jsonl              JSONL output
  -me, -markdown-export   markdown export directory
  -se, -sarif-export      SARIF export file
  -je, -json-export       JSON export file
  -jle, -jsonl-export     JSONL export file
  -rdb, -report-db        reporting database
  -H, -header string[]    custom headers
  -proxy string           proxy
  -timeout int            timeout
  -retries int            retries
  -tl                     list templates
  -validate               validate templates
  -silent                 findings only
  -nc, -no-color          disable colors

Examples:
  gorecon vuln -u https://example.com
  gorecon vuln -l live_hosts.txt -s critical,high
  gorecon vuln -u https://example.com -t cves/ -tags rce
  gorecon vuln -l targets.txt -as -je results.json
`)
}

func printTLSHelp() {
	fmt.Print(`
TLS/SSL Analysis

TLS data gathering and analysis toolkit.

Usage:
  gorecon tls [flags] <target>

Flags:
  -u, -host string[]      target host(s)
  -l, -list string        input file
  -p, -port string        target port(s) (default 443)
  -san                    show SAN
  -cn                     show CN
  -so                     show organization
  -tv, -tls-version       show TLS version
  -cipher                 show cipher
  -hash string            cert hash (md5,sha1,sha256)
  -jarm                   show JARM hash
  -ja3                    show JA3 hash
  -ja3s                   show JA3S hash
  -ex, -expired           show expired certs
  -ss, -self-signed       show self-signed
  -mm, -mismatched        show mismatched
  -sm, -scan-mode string  scan mode (auto,ctls,ztls,openssl)
  -ve, -version-enum      enumerate TLS versions
  -ce, -cipher-enum       enumerate ciphers
  -c, -concurrency        concurrency (default 300)
  -timeout int            timeout (default 5s)
  -o, -output string      output file
  -j, -json               JSON output
  -proxy string           SOCKS5 proxy

Examples:
  gorecon tls example.com
  gorecon tls -l hosts.txt -san -cn -tv -jarm
  gorecon tls example.com -ex -ss -mm
`)
}

func printCDNHelp() {
	fmt.Print(`
CDN/Cloud/WAF Detection

Identify technology behind IP/DNS addresses.

Usage:
  gorecon cdn [flags] <input>

Flags:
  -i, -input string[]     IPs or DNS to check
  -l, -list string        input file
  -cdn                    show CDN only
  -cloud                  show cloud only
  -waf                    show WAF only
  -resp                   show technology name
  -j, -jsonl              JSON output
  -o, -output string      output file
  -v, -verbose            verbose output
  -silent                 results only
  -nc, -no-color          disable colors

Examples:
  gorecon cdn -i 1.1.1.1
  gorecon cdn -l hosts.txt -resp
  gorecon cdn -i cloudflare.com -cdn -waf
`)
}
