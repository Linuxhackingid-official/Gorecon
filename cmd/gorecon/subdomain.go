package main

import (
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// runSubdomain delegates to the subfinder runner (public pkg/runner)
func runSubdomain(args []string) error {
	// Fix: if first arg is a positional (domain, not a flag) and no -d present,
	// inject -d so subfinder receives the domain correctly.
	hasDFlag := false
	for _, a := range args {
		if a == "-d" || a == "-domain" || a == "-dL" || a == "-list" {
			hasDFlag = true
			break
		}
	}
	if !hasDFlag && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append([]string{"-d", args[0]}, args[1:]...)
	}

	original := os.Args
	os.Args = append([]string{"subfinder"}, args...)
	defer func() { os.Args = original }()

	options := runner.ParseOptions()
	if options == nil {
		return nil
	}

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		return err
	}

	return newRunner.RunEnumeration()
}
