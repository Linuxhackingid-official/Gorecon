package main

import (
	"encoding/json"
	"fmt"
	"net"

	"gorecon/internal/common"

	"github.com/projectdiscovery/cdncheck"
)

// runCDN implements CDN/Cloud/WAF detection using the cdncheck library
func runCDN(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-i", Aliases: []string{"--input"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-cdn", Aliases: []string{"--cdn"}, HasValue: false},
		{Name: "-cloud", Aliases: []string{"--cloud"}, HasValue: false},
		{Name: "-waf", Aliases: []string{"--waf"}, HasValue: false},
		{Name: "-resp", Aliases: []string{"--resp"}, HasValue: false},
		{Name: "-j", Aliases: []string{"--jsonl"}, HasValue: false},
	})

	showCDN := pf.Bools["-cdn"]
	showCloud := pf.Bools["-cloud"]
	showWAF := pf.Bools["-waf"]
	showResp := pf.Bools["-resp"]
	jsonOutput := pf.Bools["-j"]

	// Handle --help
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printCDNHelp()
			return nil
		}
	}

	// Collect targets: -i flag → -l file → stdin
	single := pf.Strings["-i"]
	if single == "" && len(pf.Args) > 0 {
		single = pf.Args[0]
	}

	targets, err := common.CollectTargets(pf.Strings["-l"], single)
	if err != nil {
		return err
	}

	// Setup output
	w, cleanup, err := common.OutputWriter(pf.Strings["-o"])
	if err != nil {
		return err
	}
	defer cleanup()

	// Create cdncheck client
	client := cdncheck.New()

	// Process targets
	for _, target := range targets {
		ip := net.ParseIP(target)
		if ip == nil {
			ips, err := net.LookupHost(target)
			if err != nil || len(ips) == 0 {
				if !showCDN && !showCloud && !showWAF {
					fmt.Fprintln(w, target)
				}
				continue
			}
			ip = net.ParseIP(ips[0])
			if ip == nil {
				continue
			}
		}

		matched, value, itemType, err := client.Check(ip)
		if err != nil || !matched {
			if !showCDN && !showCloud && !showWAF {
				fmt.Fprintln(w, target)
			}
			continue
		}

		// Apply filters
		if showCDN && itemType != "cdn" {
			continue
		}
		if showCloud && itemType != "cloud" {
			continue
		}
		if showWAF && itemType != "waf" {
			continue
		}

		if jsonOutput {
			entry := map[string]string{"host": target, "provider": value, "type": itemType}
			if jsonBytes, err := json.Marshal(entry); err == nil {
				fmt.Fprintln(w, string(jsonBytes))
			}
		} else if showResp {
			fmt.Fprintf(w, "%s [%s] [%s]\n", target, itemType, value)
		} else {
			fmt.Fprintln(w, target)
		}
	}

	return nil
}
