package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"gorecon/internal/common"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// runVuln implements vulnerability scanning using the nuclei SDK (public lib/)
func runVuln(args []string) error {
	pf := common.ParseFlags(args, []common.FlagDef{
		{Name: "-u", Aliases: []string{"--target"}, HasValue: true},
		{Name: "-l", Aliases: []string{"--list"}, HasValue: true},
		{Name: "-t", Aliases: []string{"--templates"}, HasValue: true},
		{Name: "-w", Aliases: []string{"--workflows"}, HasValue: true},
		{Name: "-tags", Aliases: []string{"--tags"}, HasValue: true},
		{Name: "-s", Aliases: []string{"--severity"}, HasValue: true},
		{Name: "-j", Aliases: []string{"--jsonl"}, HasValue: false},
		{Name: "-silent", Aliases: []string{"--silent"}, HasValue: false},
		{Name: "-o", Aliases: []string{"--output"}, HasValue: true},
	})

	jsonl := pf.Bools["-j"]
	silent := pf.Bools["-silent"]
	if silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	// Handle --help
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printVulnHelp()
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

	// Setup output writer (-o flag support)
	outputWriter, cleanup, err := common.OutputWriter(pf.Strings["-o"])
	if err != nil {
		return err
	}
	defer cleanup()

	// Build nuclei SDK options
	var sdkOpts []nuclei.NucleiSDKOptions

	if t := pf.Strings["-t"]; t != "" {
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{t},
		}))
	}
	if w := pf.Strings["-w"]; w != "" {
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Workflows: []string{w},
		}))
	}

	severity := pf.Strings["-s"]
	tags := pf.Strings["-tags"]
	if severity != "" || tags != "" || silent {
		filters := nuclei.TemplateFilters{}
		if severity != "" {
			filters.Severity = severity
		}
		if tags != "" {
			filters.Tags = strings.Split(tags, ",")
		}
		sdkOpts = append(sdkOpts, nuclei.WithTemplateFilters(filters))
	}

	engine, err := nuclei.NewNucleiEngine(sdkOpts...)
	if err != nil {
		return fmt.Errorf("could not create nuclei engine: %s", err)
	}
	defer engine.Close()

	for _, tgt := range targets {
		engine.LoadTargets([]string{tgt}, false)
	}

	gologger.Info().Msgf("Starting vulnerability scan on %d targets...\n", len(targets))

	err = engine.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		if jsonl {
			if jsonData, err := json.Marshal(event); err == nil {
				fmt.Fprintln(outputWriter, string(jsonData))
			}
		} else {
			severityStr := event.Info.SeverityHolder.Severity.String()
			fmt.Fprintf(outputWriter, "[%s] [%s] %s\n", event.TemplateID, severityStr, event.Matched)
		}
	})
	if err != nil {
		return err
	}

	gologger.Info().Msgf("Vulnerability scan complete!\n")
	return nil
}
