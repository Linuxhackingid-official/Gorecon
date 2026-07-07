# GoRecon

> Ten ProjectDiscovery engines. One binary. Zero friction.

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
║  ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
║  ██║  ███╗██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
║  ██║   ██║██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
║  ╚██████╔╝╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
║                                                              ║
║              Unified Reconnaissance Toolkit                  ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Engines

| Command | Purpose |
|----------|---------|
| `subdomain` | Passive subdomain enumeration |
| `dns` | DNS resolution & bruteforce |
| `scan` | Port scanning (SYN/CONNECT) |
| `http` | HTTP probing & technology detection |
| `crawl` | Web crawling & endpoint discovery |
| `vuln` | Template-based vulnerability scanning |
| `tls` | TLS/SSL certificate analysis |
| `cdn` | CDN / Cloud / WAF detection |
| `takeover` | Subdomain takeover detection (30+ services) |
| `uncover` | External asset discovery (19 search engines) |

> **Aliases:** `sub`, `dnsx`, `portscan`/`naabu`, `httpx`, `katana`, `nuclei`, `tlsx`/`ssl`, `cdncheck`, `take`, `pipeline`, `search`, `list`

---

## Architecture

### Reconnaissance Phases

```mermaid
flowchart TD
    subgraph DISCOVERY["🔍 DISCOVERY — What exists?"]
        direction LR
        A["subdomain"] --> B["dns"] --> C["scan"]
    end

    subgraph ENUMERATION["📋 ENUMERATION — What runs there?"]
        direction LR
        D["http"] ~~~ E["tls"] ~~~ F["cdn"] ~~~ G["takeover"]
    end

    subgraph CRAWL["🕸️ DEEP DISCOVERY — What's hidden?"]
        direction LR
        H["crawl"]
    end

    subgraph EXPLOITATION["💥 EXPLOITATION — What is weak?"]
        direction LR
        I["vuln"]
    end

    DISCOVERY --> ENUMERATION --> CRAWL --> EXPLOITATION
    ENUMERATION --> EXPLOITATION

    style DISCOVERY fill:#1a1a2e,stroke:#16213e,color:#e94560
    style ENUMERATION fill:#1a1a2e,stroke:#16213e,color:#f5a623
    style CRAWL fill:#1a1a2e,stroke:#16213e,color:#4ecdc4
    style EXPLOITATION fill:#1a1a2e,stroke:#16213e,color:#e94560
```

### Engine Input/Output Map

```mermaid
flowchart TD
    DOMAIN["example.com"] --> SUB

    SUB["subdomain"] --> SUBS["subdomains.txt"]
    SUBS --> DNS
    DOMAIN --> DNS

    DNS["dns"] --> HOSTS["resolved hosts"]
    HOSTS --> |"hostnames"| SCAN
    HOSTS --> |"hostnames"| HTTP
    HOSTS --> |"hostnames"| TLS
    HOSTS --> |"IPs"| CDN

    SCAN["scan"] --> PORTS["open ports"]
    HTTP["http"] --> LIVE["live URLs<br/>+ status + title + tech"]
    TLS["tls"] --> CERTS["certificates<br/>+ ciphers + SANs"]
    CDN["cdn"] --> INFRA["cloud/CDN/WAF<br/>providers"]

    LIVE --> CRAWL
    LIVE --> VULN

    CRAWL["crawl"] --> ENDPOINTS["endpoints<br/>+ APIs + paths"]
    VULN["vuln"] --> FINDINGS["vulnerabilities<br/>CVEs, misconfigs"]

    style DOMAIN fill:#0e5160,color:#fff
    style SUB fill:#1a1a2e,stroke:#e94560,color:#e94560
    style DNS fill:#1a1a2e,stroke:#e94560,color:#e94560
    style SCAN fill:#1a1a2e,stroke:#f5a623,color:#f5a623
    style HTTP fill:#1a1a2e,stroke:#f5a623,color:#f5a623
    style TLS fill:#1a1a2e,stroke:#f5a623,color:#f5a623
    style CDN fill:#1a1a2e,stroke:#f5a623,color:#f5a623
    style CRAWL fill:#1a1a2e,stroke:#4ecdc4,color:#4ecdc4
    style VULN fill:#1a1a2e,stroke:#e94560,color:#e94560
```

---

## Pipeline: `gorecon recon`

### Execution Order (Mermaid Flowchart)

```mermaid
flowchart TD
    START(["gorecon recon example.com"]) --> S1

    S1["1. SUBDOMAIN"] --> S2
    S1 -.-> |"output"| F1["1-subdomains.txt"]

    S2["2. DNS"] --> S3
    S2 -.-> |"output"| F2["2-dns-resolved.txt"]

    S3["3. SCAN"] --> S4

    S3 -.-> |"output"| F3["3-open-ports.txt"]

    S4{"4. PARALLEL STAGE"} --> S4A
    S4 --> S4B
    S4 --> S4C
    S4 --> S4D

    S4A["4a. HTTP"] --> S5
    S4A -.-> |"output"| F4A["4-http-live.txt"]

    S4B["4b. TLS"] -.-> |"output"| F4B["4-tls-results.txt"]
    S4C["4c. CDN"] -.-> |"output"| F4C["4-cdn-results.txt"]
    S4D["4d. TAKEOVER"] -.-> |"output"| F4D["4-takeover-results.txt"]

    S5["5. CRAWL"] --> S6
    S5 -.-> |"output"| F5["5-crawl-endpoints.txt"]

    S6["6. VULN"] --> DONE
    S6 -.-> |"output"| F6["6-vulnerabilities.jsonl"]

    DONE(["✅ Pipeline Complete"])

    style S4 fill:#f5a623,stroke:#f5a623,color:#000
    style S4A fill:#2d6a4f,stroke:#2d6a4f,color:#fff
    style S4B fill:#2d6a4f,stroke:#2d6a4f,color:#fff
    style S4C fill:#2d6a4f,stroke:#2d6a4f,color:#fff
    style S4D fill:#2d6a4f,stroke:#2d6a4f,color:#fff
```

### Why This Order (Sequence Diagram)

```mermaid
sequenceDiagram
    actor U as User
    participant SD as subdomain
    participant DN as dns
    participant SC as scan
    participant HP as http
    participant TL as tls
    participant CD as cdn
    participant TK as takeover
    participant CR as crawl
    participant VN as vuln

    U->>SD: 1. enumerate subdomains
    SD-->>DN: subdomains.txt

    U->>DN: 2. resolve DNS
    DN-->>SC: resolved hosts
    DN-->>HP: resolved hosts
    DN-->>TL: resolved hosts
    DN-->>CD: resolved hosts
    DN-->>TK: resolved hosts

    U->>SC: 3. scan ports

    par Parallel Stage
        U->>HP: 4a. probe HTTP
    and
        U->>TL: 4b. analyze TLS
    and
        U->>CD: 4c. detect CDN/WAF
    and
        U->>TK: 4d. check takeovers
    end

    HP-->>CR: live URLs (200/30x)
    HP-->>VN: live URLs (all)

    U->>CR: 5. crawl endpoints
    U->>VN: 6. scan vulnerabilities
```

### Usage

```bash
# Full pipeline — every stage runs
gorecon recon example.com

# Custom ports and severity
gorecon recon example.com -p 80,443,8080,8443 -s critical,high

# Output to named directory
gorecon recon example.com -o results/

# Lightweight — skip heavy stages
gorecon recon example.com --no-scan --no-crawl --no-vuln

# Discovery only — just find what exists
gorecon recon example.com --no-tls --no-cdn --no-crawl --no-vuln
```

### Pipeline Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d`, `--domain` | *(required)* | Target domain |
| `-l`, `--list` | — | File with list of domains |
| `-o`, `--output` | `gorecon-output-<ts>/` | Output directory |
| `-w`, `--wordlist` | — | Wordlist for DNS bruteforce |
| `-p`, `--ports` | `80,443,8080,8443,...` | Ports to scan |
| `-s`, `--severity` | `critical,high,medium` | Nuclei severity filter |
| `-t`, `--templates` | — | Nuclei templates path |
| `--no-scan` | false | Skip port scanning |
| `--no-http` | false | Skip HTTP probing |
| `--no-tls` | false | Skip TLS analysis |
| `--no-cdn` | false | Skip CDN detection |
| `--no-takeover` | false | Skip takeover detection |
| `--no-crawl` | false | Skip web crawling |
| `--no-vuln` | false | Skip vulnerability scanning |

### Output Structure

```
gorecon-output-20260706-120000/
├── 1-subdomains.txt          ← list of subdomains (one per line)
├── 2-dns-resolved.txt        ← host [TYPE] [value]
├── 3-open-ports.txt          ← host:port pairs
├── 4-http-live.txt           ← https://host [status] [title] [tech1,tech2]
├── 4-tls-results.txt         ← host:port tls_version CN:name SAN:name1,name2
├── 4-cdn-results.txt         ← host [type] [provider]
├── 4-takeover-results.txt    ← subdomain CNAME service http_code verified
├── 5-crawl-endpoints.txt     ← discovered URLs and endpoints
└── 6-vulnerabilities.jsonl   ← vulnerability findings in JSONL format
```

---

## Command Reference

### Data Flow: Which Command Needs What

```mermaid
flowchart TD
    subgraph INPUTS["Required Input Types"]
        I1["domain name"]
        I2["hostname"]
        I3["IP address"]
        I4["live URL<br/>(200/30x)"]
        I5["any URL"]
    end

    subgraph COMMANDS["Commands"]
        SD["subdomain"] --> I1
        DN["dns"] --> I2
        SC["scan"] --> I2
        HP["http"] --> I2
        TL["tls"] --> I2
        CD["cdn"] --> I3
        UN["uncover"] --> I3
        CR["crawl"] --> I4
        VN["vuln"] --> I5
    end

    style I1 fill:#0e5160,color:#fff
    style I2 fill:#0e5160,color:#fff
    style I3 fill:#0e5160,color:#fff
    style I4 fill:#f5a623,color:#000
    style I5 fill:#e94560,color:#fff
```

---

### 1. `subdomain` — Passive Enumeration

```mermaid
flowchart LR
    IN["example.com"] --> ENG["50+ passive sources"]
    ENG --> OUT["api.example.com<br/>app.example.com<br/>dev.example.com<br/>..."]
```

Discover subdomains via passive sources: crt.sh, AlienVault, Censys, Chaos, Shodan, etc.

```bash
gorecon subdomain example.com                        # basic
gorecon subdomain example.com -all                   # all sources (thorough)
gorecon subdomain example.com -all -silent -o out.txt # output to file
gorecon subdomain -dL domains.txt -o all.txt         # multiple domains
```

| Flag | Description |
|------|-------------|
| `-d`, `-domain` | Target domain(s) |
| `-dL`, `-list` | File containing list of domains |
| `-all` | Use all sources (slow but complete) |
| `-s`, `-sources` | Specific sources (comma-separated) |
| `-o`, `-output` | Output file |
| `-oJ`, `-json` | JSON output |
| `-silent` | Results only, no banner |

---

### 2. `dns` — Resolution & Bruteforce

```mermaid
flowchart LR
    IN["hosts.txt"] --> ENG["A, AAAA, CNAME, NS, MX, TXT, SOA..."]
    ENG --> OUT["host [A] [10.0.0.1]<br/>host [CNAME] [elb.amazonaws.com]"]
```

```bash
gorecon dns -l hosts.txt                        # resolve a list
gorecon dns -l hosts.txt -a -re                 # all records + full response
gorecon dns -d example.com -w words.txt -a      # bruteforce mode
gorecon dns -l hosts.txt -a -ro > ips.txt       # IPs only (for piping)
```

| Flag | Description |
|------|-------------|
| `-l`, `--list` | File with hosts/domains |
| `-d`, `--domain` | Domain to bruteforce |
| `-w`, `--wordlist` | Wordlist for bruteforce |
| `-a`, `--all` | All record types |
| `-re`, `--resp` | Show full DNS response |
| `-ro`, `--resp-only` | IP addresses only |
| `-j`, `--json` | JSON output |
| `-o`, `--output` | Output file |
| `-t`, `--threads` | Concurrency (default: 100) |
| `-rl`, `--rate-limit` | Requests/second |

---

### 3. `scan` — Port Scanning

```mermaid
flowchart LR
    IN["10.0.0.1<br/>10.0.0.2"] --> ENG["SYN / CONNECT scan"]
    ENG --> OUT["10.0.0.1:80<br/>10.0.0.1:443<br/>10.0.0.2:443<br/>10.0.0.2:8080"]
```

```bash
gorecon scan example.com -p 80,443              # specific ports
gorecon scan example.com -tp 1000               # top 1000 ports
gorecon scan example.com -tp 1000 -rate 5000    # high-speed scan
gorecon scan example.com -passive               # Shodan only (stealth)
gorecon scan -l hosts.txt -tp 100 -o ports.txt
```

| Flag | Description |
|------|-------------|
| `-host` | Target host(s) |
| `-l`, `-list` | File with hosts |
| `-p`, `-port` | Ports (`80,443` or `1-1000`) |
| `-tp`, `-top-ports` | `full`, `100`, `1000` |
| `-rate` | Packets/second (default: 1000) |
| `-passive` | Shodan InternetDB (no active scan) |
| `-o`, `-output` | Output file |

---

### 4. Parallel Stage — HTTP, TLS, CDN, Takeover

```mermaid
flowchart TD
    DNS["DNS output<br/>(hostnames)"] --> HTTP
    DNS --> TLS
    DNS --> CDN
    DNS --> TAKEOVER

    HTTP["4a. HTTP"] --> HO["https://host [200] [Title] [nginx,react]"]
    TLS["4b. TLS"] --> TO["host:443 tls13 CN:*.example.com SAN:..."]
    CDN["4c. CDN"] --> CO["host [cloud] [aws]<br/>host [cdn] [cloudflare]"]
    TAKEOVER["4d. TAKEOVER"] --> TKO["⚠ api.example.com<br/>   CNAME: api.herokuapp.com<br/>   Service: Heroku"]

    style DNS fill:#0e5160,color:#fff
    style HTTP fill:#2d6a4f,color:#fff
    style TLS fill:#2d6a4f,color:#fff
    style CDN fill:#2d6a4f,color:#fff
    style TAKEOVER fill:#e94560,color:#fff
```

**HTTP:**
```bash
gorecon http -l hosts.txt                                    # basic
gorecon http -l hosts.txt -sc -title -td                     # status + title + tech
gorecon http -l hosts.txt -sc -title -td -server -ip -cdn    # full detail
gorecon http -l hosts.txt -sc -mc 200,302 -o live.txt        # filter 200/302
```

**TLS:**
```bash
gorecon tls example.com                                      # basic
gorecon tls example.com -san -cn -tv -cipher -jarm           # full cert
gorecon tls -l hosts.txt -ex -ss -mm -o weak-certs.txt       # filter weak
```

**CDN:**
```bash
gorecon cdn -i 1.1.1.1                                       # single IP
gorecon cdn -l ips.txt -resp                                  # show provider names
gorecon cdn -l hosts.txt -cdn -o cdn-only.txt                 # CDN only
```

**Takeover:**
```bash
gorecon takeover -d example.com                                # auto-discover + check
gorecon takeover -d example.com -all -w subs.txt               # all sources + bruteforce
gorecon takeover -l subs.txt -o results.txt                    # check existing list
gorecon takeover -d example.com --only heroku                  # filter by service
gorecon takeover -d example.com -v --no-http                   # dry-run (CNAME only)
gorecon takeover api.example.com                               # single subdomain
cat subs.txt | gorecon takeover -silent                        # pipe via stdin
```

---

### 4d. `takeover` — Subdomain Takeover Detection

```mermaid
flowchart LR
    IN["subdomains.txt"] --> DNS["DNS CNAME<br/>Resolution"]
    DNS --> MATCH["Service<br/>Matching"]
    MATCH --> HTTP["HTTP<br/>Verification"]
    HTTP --> OUT["⚠ api.target.com<br/>→ Heroku (verified)"]
```

Detect dangling CNAME records pointing to unclaimed SaaS/cloud services. Pipeline: enumerate subdomains (optional) → resolve CNAMEs → match against 30+ service fingerprints → HTTP verify with signature matching.

```bash
gorecon takeover -d example.com                                # auto-discover + check
gorecon takeover -d example.com -all                           # all subdomain sources
gorecon takeover -d example.com -w wordlist.txt                # discover + bruteforce
gorecon takeover -l subs.txt                                   # check existing list
gorecon takeover -d example.com --only heroku                  # single service
gorecon takeover -d example.com --exclude cloudfront           # exclude false positives
gorecon takeover -d example.com -v --no-http                   # dry-run (CNAME only)
gorecon takeover -d example.com -j -o findings.jsonl           # JSON output
gorecon takeover api.example.com                               # single subdomain
cat subs.txt | gorecon takeover -silent                        # pipe via stdin
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (auto-discovers subdomains) |
| `-l`, `--list` | File with list of subdomains |
| `-w`, `--wordlist` | Wordlist for DNS bruteforce |
| `-o`, `--output` | Output file |
| `-t`, `--threads` | Concurrency (default: 50) |
| `-j`, `--json` | JSON output |
| `-v`, `--verbose` | Show all CNAME records found |
| `-all` | Use all passive sources |
| `--only` | Only check specific service (e.g. `github`, `heroku`) |
| `--exclude` | Exclude service (e.g. `cloudfront`) |
| `--no-discover` | Skip subdomain discovery |
| `--no-http` | Skip HTTP verification (CNAME matches only) |
| `-silent` | Results only |

**Supported Services (30+):**
AWS S3, CloudFront, GitHub Pages, Heroku, Surge.sh, Netlify, Firebase,
Cloudflare Pages, Azure WebApps, Shopify, Bitbucket, Readme.io, Freshdesk,
HelpScout, Cargo, Tilda, Statuspage, Intercom, Zendesk, Ghost, Pantheon,
Unbounce, LaunchRock, Acquia, GetResponse, Campaign Monitor, WordPress, MailChimp

---

### 5. `uncover` — External Asset Discovery

```mermaid
flowchart LR
    IN["domain / IP / query"] --> ENG["19 search engines<br/>Shodan, Censys, Fofa, Hunter..."]
    ENG --> OUT["IP:port (hostname) [source]<br/>JSONL output"]
```

Query public search engines to discover exposed hosts, IPs, and services beyond passive DNS enumeration. Free tier via `shodan-idb` (no API key). Advanced use with raw search queries across Shodan, Censys, Fofa, Hunter, ZoomEye, and more.

```bash
gorecon uncover -d example.com                                # free: DNS + shodan-idb
gorecon uncover -d example.com -a shodan,censys               # multi-agent
gorecon uncover -d example.com -j -o results.jsonl            # JSON output
gorecon uncover -i 1.2.3.4                                    # single IP
gorecon uncover -q "ssl:example.com" -a shodan -l 500         # raw query
gorecon uncover -q "org:Google" -a shodan,censys,fofa         # multi-agent query
cat ips.txt | gorecon uncover -silent                         # pipe via stdin
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (auto-resolves DNS → queries shodan-idb) |
| `-i`, `--ip` | Target IP or CIDR |
| `-q`, `--query` | Raw search query (requires API key agent) |
| `-a`, `--agent` | Search engines (default: shodan-idb) |
| `-l`, `--limit` | Max results per agent (default: 100) |
| `-o`, `--output` | Output file |
| `-j`, `--json` | JSONL output |
| `-silent` | Results only |
| `-v`, `--verbose` | Show errors and warnings |

**Supported Agents (19):**
`shodan-idb` (free), `shodan`, `censys`, `fofa`, `quake`, `hunter`, `zoomeye`,
`netlas`, `criminalip`, `publicwww`, `hunterhow`, `google`, `odin`, `binaryedge`,
`onyphe`, `driftnet`, `greynoise`, `daydaymap`, `nerdydata`

> API keys stored in `~/.config/uncover/provider-config.yaml`. See `gorecon uncover -h` for provider config format.

---

### 6. `crawl` — Endpoint Discovery

```mermaid
flowchart LR
    IN["https://example.com<br/>(live, 200 OK)"] --> ENG["link extraction<br/>+ JS parsing"]
    ENG --> OUT["/<br/>/blog/<br/>/api/v1/users<br/>/wp-json/wp/v2/pages<br/>/admin/panel<br/>/backup.zip"]
```

```bash
gorecon crawl https://example.com                            # basic
gorecon crawl https://example.com -d 5                       # deep crawl
gorecon crawl https://example.com -d 5 -s breadth-first      # wider coverage
gorecon crawl https://example.com -d 3 -td --json            # + tech detection
```

| Flag | Description |
|------|-------------|
| `-u`, `-list`, `--target` | Target URL(s) |
| `-d`, `--depth` | Max depth (default: 3) |
| `-s`, `--strategy` | `depth-first` or `breadth-first` |
| `-td`, `--tech-detect` | Technology detection |
| `-j`, `--json` | JSON output with full HTTP details |
| `-o`, `--output` | Output file |

---

### 7. `vuln` — Vulnerability Scanning

```mermaid
flowchart LR
    IN["https://example.com<br/>(live URLs)"] --> ENG["13,000+ templates<br/>CVE, misconfig, exposure"]
    ENG --> OUT["[CVE-2024-xxxx] [critical]<br/>[exposed-panel] [medium]<br/>[missing-headers] [info]"]
```

```bash
gorecon vuln -u https://example.com                          # basic
gorecon vuln -u https://example.com -s critical,high         # severity filter
gorecon vuln -u https://example.com -tags rce,xss            # tag filter
gorecon vuln -l live.txt -s critical,high -j -o findings.jsonl
```

| Flag | Description |
|------|-------------|
| `-u`, `--target` | Target URL(s) |
| `-l`, `--list` | Input file |
| `-t`, `--templates` | Templates directory (use dir, not file) |
| `-tags` | Template tags (`rce,xss,oob`) |
| `-s`, `--severity` | `info,low,medium,high,critical` |
| `-j`, `--jsonl` | JSONL output |
| `-silent` | Findings only |

---

## Workflows

### Quick Recon (~5 min)

```mermaid
flowchart LR
    S1["subdomain<br/>-all"] --> S2["dns<br/>-a -re"]
    S2 --> S3["http<br/>-sc -title -td"]
```

```bash
domain="example.com"
gorecon subdomain "$domain" -all -silent          > 1-subs.txt
gorecon dns -l 1-subs.txt -a -re                   > 2-dns.txt
gorecon http -l 2-dns.txt -sc -title -td -server   > 3-http.txt
```

### Standard Recon (~15 min)

```mermaid
flowchart TD
    S1["1. subdomain"] --> S2["2. dns"] --> S3["3. scan"]
    S2 --> S4A["4a. http"]
    S2 --> S4B["4b. tls"]
    S2 --> S4C["4c. cdn"]
    S2 --> S4D["4d. takeover"]

    style S4A fill:#2d6a4f,color:#fff
    style S4B fill:#2d6a4f,color:#fff
    style S4C fill:#2d6a4f,color:#fff
    style S4D fill:#e94560,color:#fff
```

```bash
domain="example.com"
gorecon subdomain "$domain" -all -silent             > 1-subs.txt
gorecon dns -l 1-subs.txt -a -re                     > 2-dns.txt
gorecon scan -l 2-dns.txt -tp 1000 -silent           > 3-ports.txt

# Stage 4 runs in parallel
gorecon http -l 2-dns.txt -sc -title -td -server -cdn > 4-http.txt &
gorecon tls  -l 2-dns.txt -san -cn -tv                > 4-tls.txt  &
gorecon cdn  -l 2-dns.txt -resp                       > 4-cdn.txt  &
gorecon takeover -l 2-dns.txt                          > 4-takeover.txt &
wait
```

### Deep Recon (~30+ min)

```mermaid
flowchart TD
    S1["subdomain"] --> S2["dns + bruteforce"] --> S3["scan"]
    S3 --> S4["http ∥ tls ∥ cdn ∥ takeover<br/>(parallel)"]
    S4 --> S5["crawl<br/>(live URLs only)"]
    S4 --> S6["vuln<br/>(critical+high)"]

    style S4 fill:#f5a623,color:#000
    style S6 fill:#e94560,color:#fff
```

```bash
domain="example.com"

# Discovery
gorecon subdomain "$domain" -all -silent                          > 1-subs.txt
echo "$domain" >> 1-subs.txt    # always add apex
gorecon dns -d "$domain" -w /path/to/subdomains.txt -a -re        > 2-dns.txt
gorecon scan -l 2-dns.txt -tp 1000 -rate 5000 -silent            > 3-ports.txt

# Clean hostnames for HTTP/TLS/CDN
awk -F' \\[' '{print $1}' 2-dns.txt | sort -u > hosts-clean.txt

# Parallel enumeration
gorecon http -l hosts-clean.txt -sc -title -td -server -ip -cdn   > 4-http.txt &
gorecon tls  -l hosts-clean.txt -san -cn -tv -cipher -jarm        > 4-tls.txt  &
gorecon cdn  -l hosts-clean.txt -resp                              > 4-cdn.txt  &
gorecon takeover -l hosts-clean.txt                                 > 4-takeover.txt &
wait

# Crawl live endpoints
grep -E '\[20[0-9]\]|\[30[0-9]\]' 4-http.txt | awk '{print $1}' | head -10 | while read url; do
    gorecon crawl "$url" -d 3 -s breadth-first | tee -a 5-crawl.txt
done

# Vulnerability scan
gorecon vuln -l 4-http.txt -s critical,high -j -o 6-vulns.jsonl
```

### Single Command (equivalent to Deep Recon)

```bash
gorecon recon example.com

# With custom options
gorecon recon example.com \
    -o "recon-$(date +%Y%m%d)" \
    -p 80,443,8080,8443,9090 \
    -s critical,high \
    -t ~/nuclei-templates/
```

---

## Quick Reference Card

```
╔══════════════════════════════════════════════════════════════╗
║                    GORECON CHEAT SHEET                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  DISCOVER WHAT EXISTS:                                       ║
║    gorecon subdomain <domain> -all -silent -o subs.txt       ║
║    gorecon dns -l subs.txt -a -re          -o dns.txt        ║
║    gorecon scan -l dns.txt -tp 1000        -o ports.txt      ║
║                                                              ║
║  FIND WHAT'S ALIVE:                                          ║
║    gorecon http -l dns.txt -sc -title -td  -o live.txt       ║
║    gorecon tls  -l dns.txt -san -cn -tv    -o tls.txt        ║
║    gorecon cdn  -l dns.txt -resp           -o cdn.txt        ║
║    gorecon takeover -l dns.txt             -o takeover.txt   ║
║                                                              ║
║  SEARCH ENGINES (external discovery):                         ║
║    gorecon uncover -d <domain>                                ║
║    gorecon uncover -q "ssl:target" -a shodan -l 100           ║
║                                                              ║
║  DIG DEEPER:                                                 ║
║    gorecon crawl <live-url> -d 3 -s breadth-first            ║
║    gorecon vuln  -l live.txt -s critical,high -j             ║
║                                                              ║
║  ONE COMMAND DOES IT ALL:                                    ║
║    gorecon recon <domain>                                    ║
║                                                              ║
║  PIPING:                                                     ║
║    gorecon subdomain ... | gorecon dns -a -ro | gorecon http ║
║                                                              ║
║  CORRECT ORDER:                                              ║
║    subdomain → dns → scan → (http∥tls∥cdn∥takeover) → crawl→vuln ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Tips & Tricks from Real Bug Hunting

### 1. TLS is your best friend for infrastructure mapping

TLS certificates often reveal more than any other stage. A single cert can expose related domains, brands, and internal hostnames via SAN fields.

```bash
# Always include these TLS flags
gorecon tls -l hosts.txt -san -cn -so -tv -cipher -jarm

# Real example: a *.sheingsp.com cert exposed 30+ SHEIN brand domains
# in the SAN field — shein.com, romwe.com, sheglam.com, shopemeryrose.com...
```

### 2. CDN ≠ single tenant

Akamai `edgekey.net` and CloudFront `cloudfront.net` CNAMEs mean the IP is shared across many customers. Don't assume one IP = one target.

```mermaid
flowchart LR
    YOU["Your target<br/>th.example.com"] --> EDGE["Akamai Edge IP<br/>114.10.245.41"]
    OTHER["Other customer<br/>some-site.com"] --> EDGE
    EDGE --> ORIGIN["Origin Server<br/>(not directly reachable)"]

    style EDGE fill:#f5a623,color:#000
```

```bash
# Always check who owns the IP
gorecon cdn -l ips.txt -resp
# If behind CDN, you're probing shared infrastructure
```

### 3. Takeover: CNAMEs pointing to SaaS = check them

Subdomain takeover is one of the highest-signal findings in bug bounty. A dangling CNAME to an unclaimed Heroku/AWS/GitHub Pages app means anyone can register it and serve content on your target's subdomain.

```bash
# Auto-discovery + check in one command
gorecon takeover -d example.com -all

# Dry-run first to see what CNAMEs exist
gorecon takeover -d example.com -v --no-http

# Then verify with HTTP
gorecon takeover -d example.com -o findings.txt

# Common false positive: CloudFront. Exclude it.
gorecon takeover -d example.com --exclude cloudfront
```

### 4. Clean hostnames between DNS and HTTP/TLS/CDN

DNS `-re` output includes IPs and record types. HTTP/TLS need clean hostnames.

```bash
# ❌ WRONG — HTTP gets confused by [A] [IP] format
gorecon dns -l subs.txt -a -re -o dns.txt
gorecon http -l dns.txt

# ✅ RIGHT — extract hostnames first
gorecon dns -l subs.txt -a -re -o dns.txt
awk -F' \\[' '{print $1}' dns.txt | sort -u > hosts-clean.txt
gorecon http -l hosts-clean.txt
```

### 5. SPA pages need headless crawl

Single Page Applications render content via JavaScript. Standard crawl only parses static HTML.

**SPA Detection Checklist:**
- Page title is generic (`GSP`, `App`, `Loading...`)
- Body is short or contains `<div id="root">` / `<div id="app">`
- Standard crawl returns only the root URL (no links discovered)

> **Workaround:** Use the `-hl` (headless) flag for JS-rendered pages: `gorecon crawl https://target.com -hl -d 3`

### 6. Nuclei needs patience and template scoping

With 13,000+ templates, nuclei SDK init takes 30-90 seconds.

```bash
# ✅ Start narrow, expand if needed
gorecon vuln -u https://target.com -s critical -silent
gorecon vuln -u https://target.com -t ~/nuclei-templates/http/misconfiguration/
gorecon vuln -u https://target.com -tags cve -s critical,high

# ✅ Use directories (not single files) for -t
gorecon vuln -u https://target.com -t ~/nuclei-templates/http/   # ✅
gorecon vuln -u https://target.com -t ~/nuclei-templates/http/specific.yaml  # ❌

# ❌ Avoid: no severity filter + no template scope = very slow
gorecon vuln -l live.txt    # scans ALL 13k templates
```

### 7. Country TLD subdomains = global CDN

If you find `cn.`, `us.`, `br.`, `th.` subdomains all serving the same app:

```mermaid
flowchart TD
    US["🇺🇸 us.target.com"] --> ORIGIN["Same Origin Server"]
    CN["🇨🇳 cn.target.com"] --> ORIGIN
    BR["🇧🇷 br.target.com"] --> ORIGIN
    TH["🇹🇭 th.target.com"] --> ORIGIN

    style ORIGIN fill:#e94560,color:#fff
```

- Test one country endpoint = test all (same origin)
- Check if content differs by region (pricing, availability, language)

### 8. Always add the apex domain

Subdomain enumeration often misses `example.com` itself.

```bash
gorecon subdomain -d example.com -silent > subs.txt
echo "example.com" >> subs.txt   # ← always add this
gorecon dns -l subs.txt -a -re
```

### 9. Flag styles

All flags support both single-dash and double-dash forms:

```bash
gorecon tls example.com -san -cn -tv       # ✓ short
gorecon tls example.com --san --cn --tv    # ✓ explicit
```

### 10. Common Gotchas

```mermaid
flowchart TD
    Q1["FTL: no input list provided?"] --> A1["Missing required flag.<br/>Use -d (subdomain), -host (scan),<br/>-i (cdn), -u (crawl)"]
    Q2["Subdomain shows 0 results?"] --> A2["Target has no passive DNS.<br/>Try -all flag or add apex manually."]
    Q3["HTTP returns 0 results?"] --> A3["DNS output format mismatch.<br/>Extract clean hostnames from DNS -re output."]
    Q4["Crawl returns only 1 URL?"] --> A4["Page is SPA or redirect.<br/>Standard crawler can't execute JS."]
    Q5["Vuln times out?"] --> A5["Too many templates loaded.<br/>Add -s critical or -t <specific-dir>."]
    Q6["No templates available?"] --> A6["Wrong template path.<br/>Use a directory, not a single file."]
    Q7["Takeover shows nothing?"] --> A7["CNAME may point to claimed service.<br/>Use -v to see all CNAME records."]

    style Q1 fill:#3d0000,color:#e94560
    style Q2 fill:#3d0000,color:#e94560
    style Q3 fill:#3d0000,color:#e94560
    style Q4 fill:#3d0000,color:#e94560
    style Q5 fill:#3d0000,color:#e94560
    style Q6 fill:#3d0000,color:#e94560
    style Q7 fill:#3d0000,color:#e94560
    style A1 fill:#002d00,color:#4ecdc4
    style A2 fill:#002d00,color:#4ecdc4
    style A3 fill:#002d00,color:#4ecdc4
    style A4 fill:#002d00,color:#4ecdc4
    style A5 fill:#002d00,color:#4ecdc4
    style A6 fill:#002d00,color:#4ecdc4
    style A7 fill:#002d00,color:#4ecdc4
```

---

## Utility Commands

```bash
gorecon tools            # list all integrated engines
gorecon list             # alias for 'tools'
gorecon version          # show version (v1.0.0)
gorecon help             # show usage overview
gorecon help <command>   # show detailed help for a command
gorecon update           # show rebuild instructions
```

---

## Build

```bash
make build        # go build with stripped symbols
make install      # install to ~/.local/bin
make all          # fmt + vet + build
make clean        # remove binary + cache
```

## Requirements

- **Go 1.26+**
- Local ProjectDiscovery repos (see `go.mod` replace directives)
- Nuclei templates in `~/nuclei-templates/` (for `vuln`)

## License

MIT
