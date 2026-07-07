package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"gorecon/internal/common"

	"github.com/miekg/dns"
	dnsxlibs "github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/ratelimit"
	retryabledns "github.com/projectdiscovery/retryabledns"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

type dnsResult struct {
	target string
	data   *retryabledns.DNSData
}

func runDNS(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-d", Aliases: []string{"--domain"}, HasValue: true},
		{Name: "-w", Aliases: []string{"--wordlist"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-t", Aliases: []string{"--threads"}, HasValue: true},
		{Name: "-rl", Aliases: []string{"--rate-limit"}, HasValue: true},
		{Name: "-retry", Aliases: []string{"--retries"}, HasValue: true},
		{Name: "-timeout", Aliases: []string{"--timeout"}, HasValue: true},
		{Name: "-a", Aliases: []string{"--all", "-recon"}, HasValue: false},
		{Name: "-j", Aliases: []string{"--json"}, HasValue: false},
		{Name: "-re", Aliases: []string{"--resp"}, HasValue: false},
		{Name: "-ro", Aliases: []string{"--resp-only"}, HasValue: false},
		{Name: "-version", Aliases: []string{"--version"}, HasValue: false},
	})

	threads := parseIntArg(pf, "-t", 100)
	rateLimit := parseIntArg(pf, "-rl", -1)
	retries := parseIntArg(pf, "-retry", 2)
	timeout := parseIntArg(pf, "-timeout", 3)
	queryAll := pf.Bools["-a"]

	// Handle --help / --version
	for _, a := range args {
		switch a {
		case "-h", "--help":
			printDNSHelp()
			return nil
		case "-version", "--version":
			fmt.Println("dnsx engine v1.2.3 (integrated in gorecon)")
			return nil
		}
	}

	// --- Collect targets ---
	var targets []string
	domain := pf.Strings["-d"]
	wordlist := pf.Strings["-w"]
	useStreaming := wordlist != "" && domain != ""

	if wordlist != "" && domain != "" {
		// Wordlist bruteforce: targets will be streamed directly via producer
		// goroutine to avoid loading large wordlists entirely into memory.
	} else if listFile := pf.Strings["-l"]; listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return fmt.Errorf("error opening list: %s", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				targets = append(targets, line)
			}
		}
	} else if domain != "" {
		targets = append(targets, domain)
	} else {
		stdinTargets, _ := common.CollectTargets("", "")
		if len(stdinTargets) > 0 {
			targets = stdinTargets
		}
	}

	if !useStreaming && len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	// Expand CIDR (non-streaming targets only — wordlist targets are plain subdomains)
	var expanded []string
	for _, t := range targets {
		if iputil.IsCIDR(t) {
			ips, err := mapcidr.IPAddresses(t)
			if err == nil {
				expanded = append(expanded, ips...)
			}
		} else {
			expanded = append(expanded, t)
		}
	}
	targets = expanded

	// --- Setup DNS client ---
	var questionTypes []uint16
	if queryAll {
		questionTypes = []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS,
			dns.TypeTXT, dns.TypeSRV, dns.TypePTR, dns.TypeMX,
			dns.TypeSOA, dns.TypeCAA,
		}
	} else {
		questionTypes = []uint16{dns.TypeA}
	}

	dnsClient, err := dnsxlibs.New(dnsxlibs.Options{
		BaseResolvers: dnsxlibs.DefaultResolvers,
		MaxRetries:    retries,
		QuestionTypes: questionTypes,
		Timeout:       time.Duration(timeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("could not create dns client: %s", err)
	}

	// --- Rate limiter ---
	ctx := context.Background()
	var limiter *ratelimit.Limiter
	if rateLimit > 0 {
		limiter = ratelimit.New(ctx, uint(rateLimit), time.Second)
	} else {
		limiter = ratelimit.NewUnlimited(ctx)
	}

	// --- Output ---
	w, cleanup, err := common.OutputWriter(pf.Strings["-o"])
	if err != nil {
		return err
	}
	defer cleanup()

	// --- Parallel DNS resolution ---
	targetChan := make(chan string, threads*2)
	resultChan := make(chan dnsResult, threads*2)

	jsonOutput := pf.Bools["-j"]
	resp := pf.Bools["-re"]
	respOnly := pf.Bools["-ro"]

	// Collector goroutine
	var wgCollect sync.WaitGroup
	wgCollect.Add(1)
	go func() {
		defer wgCollect.Done()
		for res := range resultChan {
			if res.data == nil {
				continue
			}
			outputDNSResult(w, res.target, res.data, jsonOutput, resp, respOnly)
		}
	}()

	// Worker pool
	var wgWorkers sync.WaitGroup
	for i := 0; i < threads; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			for target := range targetChan {
				limiter.Take()

				var data *retryabledns.DNSData
				var err error
				if queryAll {
					data, err = dnsClient.QueryMultiple(target)
				} else {
					data, err = dnsClient.QueryOne(target)
				}
				if err == nil && data != nil {
					resultChan <- dnsResult{target: target, data: data}
				}
			}
		}()
	}

	// Feed targets — streaming for wordlist, batch for others
	if useStreaming {
		// Producer goroutine: reads wordlist and feeds targetChan directly.
		// This avoids loading the entire wordlist into memory.
		go func() {
			wordsChan, err := fileutil.ReadFile(wordlist)
			if err != nil {
				close(targetChan)
				return
			}
			for word := range wordsChan {
				word = strings.TrimSpace(word)
				if word != "" {
					targetChan <- word + "." + domain
				}
			}
			close(targetChan)
		}()
	} else {
		for _, t := range targets {
			targetChan <- t
		}
		close(targetChan)
	}

	wgWorkers.Wait()
	close(resultChan)
	wgCollect.Wait()

	return nil
}

func outputDNSResult(w io.Writer, target string, data *retryabledns.DNSData, jsonOutput, resp, respOnly bool) {
	if data == nil {
		return
	}
	switch {
	case jsonOutput:
		respData := dnsxlibs.ResponseData{DNSData: data}
		if jsonBytes, err := respData.JSON(); err == nil {
			fmt.Fprintln(w, jsonBytes)
		}
	case respOnly:
		for _, a := range data.A {
			fmt.Fprintln(w, a)
		}
	case resp:
		for _, a := range data.A {
			fmt.Fprintf(w, "%s [A] [%s]\n", target, a)
		}
		for _, a := range data.AAAA {
			fmt.Fprintf(w, "%s [AAAA] [%s]\n", target, a)
		}
		for _, cname := range data.CNAME {
			fmt.Fprintf(w, "%s [CNAME] [%s]\n", target, cname)
		}
		for _, ns := range data.NS {
			fmt.Fprintf(w, "%s [NS] [%s]\n", target, ns)
		}
		for _, mx := range data.MX {
			fmt.Fprintf(w, "%s [MX] [%s]\n", target, mx)
		}
		for _, txt := range data.TXT {
			fmt.Fprintf(w, "%s [TXT] [%s]\n", target, txt)
		}
		for _, soa := range data.SOA {
			fmt.Fprintf(w, "%s [SOA] [%v]\n", target, soa)
		}
	default:
		if len(data.A) > 0 || len(data.AAAA) > 0 {
			fmt.Fprintln(w, target)
		}
	}
}
