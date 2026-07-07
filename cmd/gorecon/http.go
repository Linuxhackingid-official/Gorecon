package main

import (
	"os"

	"github.com/projectdiscovery/httpx/runner"
)

// runHTTP delegates to the httpx runner (public runner/)
func runHTTP(args []string) error {
	// Inject fast defaults for timeout and retries if not explicitly set.
	// Default httpx timeout is 10s per host — too slow for recon pipelines.
	hasTimeout := false
	hasRetries := false
	for _, a := range args {
		if a == "-timeout" || a == "--timeout" {
			hasTimeout = true
		}
		if a == "-retries" || a == "--retries" {
			hasRetries = true
		}
	}
	if !hasTimeout {
		args = append(args, "-timeout", "5")
	}
	if !hasRetries {
		args = append(args, "-retries", "1")
	}

	// Pass through to httpx
	httpxArgs := append([]string{"httpx", "--silent"}, args...)
	original := os.Args
	os.Args = httpxArgs
	defer func() { os.Args = original }()

	options := runner.ParseOptions()
	if options == nil {
		return nil
	}

	// Apply fast defaults directly on options (belt-and-suspenders with CLI flags above)
	if options.Timeout == 10 {
		options.Timeout = 5
	}
	if options.Retries == 0 {
		options.Retries = 1
	}

	newRunner, err := runner.New(options)
	if err != nil {
		return err
	}
	newRunner.RunEnumeration()
	return nil
}
