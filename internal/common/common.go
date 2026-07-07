// Package common provides shared utilities for gorecon subcommands.
package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// FlagDef describes a command-line flag definition.
type FlagDef struct {
	Name     string   // primary flag, e.g. "-l"
	Aliases  []string // aliases, e.g. ["--list"]
	HasValue bool     // whether this flag expects a value argument
}

// ParsedFlags holds the result of flag parsing.
type ParsedFlags struct {
	Strings map[string]string // flag name → string value
	Bools   map[string]bool   // flag name → bool value
	Args    []string          // remaining positional arguments
}

// ParseFlags parses args using the given flag definitions.
// Returns parsed flags and positional args.
func ParseFlags(args []string, defs []FlagDef) *ParsedFlags {
	pf := &ParsedFlags{
		Strings: make(map[string]string),
		Bools:   make(map[string]bool),
	}

	// Build lookup: every alias → canonical name and whether it takes a value
	type entry struct {
		name     string
		hasValue bool
	}
	lookup := make(map[string]entry)
	for _, d := range defs {
		names := append([]string{d.Name}, d.Aliases...)
		for _, n := range names {
			lookup[strings.ToLower(n)] = entry{name: d.Name, hasValue: d.HasValue}
		}
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		e, ok := lookup[strings.ToLower(arg)]
		if !ok {
			pf.Args = append(pf.Args, arg)
			continue
		}
		if e.hasValue {
			if i+1 < len(args) {
				pf.Strings[e.name] = args[i+1]
				i++
			}
		} else {
			pf.Bools[e.name] = true
		}
	}
	return pf
}

// CollectTargets collects targets from multiple sources: positional args,
// -l/--list file, --domain (or any key), and stdin pipe.
//
// Sources are checked in order:
//  1. listFile: read targets from a file (one per line)
//  2. singleTarget: a single target passed directly
//  3. stdin: if piped, read targets line-by-line
//
// Returns nil slice and an error message string if no targets are found.
func CollectTargets(listFile, singleTarget string) ([]string, error) {
	var targets []string

	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("could not open list file: %s", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				targets = append(targets, line)
			}
		}
	} else if singleTarget != "" {
		// Support comma-separated targets
		for _, t := range strings.Split(singleTarget, ",") {
			if t = strings.TrimSpace(t); t != "" {
				targets = append(targets, t)
			}
		}
	} else {
		// Try stdin pipe
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					targets = append(targets, line)
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	return targets, nil
}

// OutputWriter returns os.Stdout or a file if outputFile is set.
// Caller should close the returned file if it is not os.Stdout.
func OutputWriter(outputFile string) (*os.File, func(), error) {
	if outputFile == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { f.Close() }
	return f, cleanup, nil
}
