package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"gorecon/internal/common"

	tlsxlib "github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// runTLS implements TLS analysis using the tlsx public pkg/tlsx
func runTLS(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-u", Aliases: []string{"--host"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-p", Aliases: []string{"--port"}, HasValue: true},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
		{Name: "-j", Aliases: []string{"--json"}, HasValue: false},
		{Name: "-san", Aliases: []string{"--san"}, HasValue: false},
		{Name: "-cn", Aliases: []string{"--cn"}, HasValue: false},
		{Name: "-so", Aliases: []string{"--so"}, HasValue: false},
		{Name: "-tv", Aliases: []string{"--tv", "--tls-version"}, HasValue: false},
		{Name: "-cipher", Aliases: []string{"--cipher"}, HasValue: false},
		{Name: "-jarm", Aliases: []string{"--jarm"}, HasValue: false},
		{Name: "-ex", Aliases: []string{"--ex", "--expired"}, HasValue: false},
		{Name: "-ss", Aliases: []string{"--ss", "--self-signed"}, HasValue: false},
		{Name: "-mm", Aliases: []string{"--mm", "--mismatched"}, HasValue: false},
		{Name: "-sm", Aliases: []string{"--sm", "--scan-mode"}, HasValue: true},
		{Name: "-c", Aliases: []string{"--c", "--concurrency"}, HasValue: true},
		{Name: "-timeout", Aliases: []string{"--timeout"}, HasValue: true},
	})

	port := pf.Strings["-p"]
	scanMode := pf.Strings["-sm"]
	jsonOutput := pf.Bools["-j"]
	if port == "" {
		port = "443"
	}
	if scanMode == "" {
		scanMode = "auto"
	}

	concurrency := parseIntArg(pf, "-c", 300)
	timeout := parseIntArg(pf, "-timeout", 5)

	// Handle --help
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printTLSHelp()
			return nil
		}
	}

	// Collect targets: positional arg → -u flag → -l file → stdin
	single := pf.Strings["-u"]
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

	// Create tlsx service
	opts := clients.Options{
		ScanMode:    scanMode,
		Retries:     3,
		Timeout:     timeout,
		Concurrency: concurrency,
		ProbeStatus: true,
		SAN:         pf.Bools["-san"],
		CN:          pf.Bools["-cn"],
		SO:          pf.Bools["-so"],
		TLSVersion:  pf.Bools["-tv"],
		Cipher:      pf.Bools["-cipher"],
		Jarm:        pf.Bools["-jarm"],
		Expired:     pf.Bools["-ex"],
		SelfSigned:  pf.Bools["-ss"],
		MisMatched:  pf.Bools["-mm"],
		JSON:        jsonOutput,
	}

	service, err := tlsxlib.New(&opts)
	if err != nil {
		return fmt.Errorf("could not create tlsx service: %s", err)
	}

	// Process targets
	for _, target := range targets {
		targetHost := target
		targetPort := port

		if h, p, err := net.SplitHostPort(target); err == nil {
			targetHost = h
			if p != "" {
				targetPort = p
			}
		}

		resp, err := service.Connect(targetHost, "", targetPort)
		if err != nil || resp == nil {
			continue
		}

		if jsonOutput {
			data := map[string]interface{}{
				"host": resp.Host,
				"port": resp.Port,
			}
			if resp.Version != "" {
				data["tls_version"] = resp.Version
			}
			if opts.CN && resp.SubjectCN != "" {
				data["cn"] = resp.SubjectCN
			}
			if opts.SAN && len(resp.SubjectAN) > 0 {
				data["san"] = resp.SubjectAN
			}
			if opts.Jarm && resp.JarmHash != "" {
				data["jarm"] = resp.JarmHash
			}
			if opts.Cipher && resp.Cipher != "" {
				data["cipher"] = resp.Cipher
			}
			if opts.SO && len(resp.SubjectOrg) > 0 {
				data["organization"] = resp.SubjectOrg
			}
			if jsonBytes, err := json.Marshal(data); err == nil {
				fmt.Fprintln(w, string(jsonBytes))
			}
		} else {
			parts := []string{net.JoinHostPort(targetHost, targetPort)}
			if opts.TLSVersion && resp.Version != "" {
				parts = append(parts, resp.Version)
			}
			if opts.CN && resp.SubjectCN != "" {
				parts = append(parts, "CN:"+resp.SubjectCN)
			}
			if opts.SAN && len(resp.SubjectAN) > 0 {
				parts = append(parts, "SAN:"+strings.Join(resp.SubjectAN, ","))
			}
			if opts.Jarm && resp.JarmHash != "" {
				parts = append(parts, "JARM:"+resp.JarmHash)
			}
			if opts.Cipher && resp.Cipher != "" {
				parts = append(parts, "Cipher:"+resp.Cipher)
			}
			if opts.SO && len(resp.SubjectOrg) > 0 {
				parts = append(parts, "Org:"+strings.Join(resp.SubjectOrg, ","))
			}
			fmt.Fprintln(w, strings.Join(parts, " "))
		}
	}

	return nil
}
