package main

import (
	"context"
	"os"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// runPortScan delegates to the naabu runner (public pkg/runner)
func runPortScan(args []string) error {
	// Fix: if first arg is a positional (host, not a flag) and no -host/-l present,
	// inject -host so naabu receives the target correctly.
	hasInputFlag := false
	for _, a := range args {
		if a == "-host" || a == "-l" || a == "-list" {
			hasInputFlag = true
			break
		}
	}
	if !hasInputFlag && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append([]string{"-host", args[0]}, args[1:]...)
	}

	naabuArgs := append([]string{"naabu", "--silent"}, args...)
	original := os.Args
	os.Args = naabuArgs
	defer func() { os.Args = original }()

	options := runner.ParseOptions()
	if options == nil {
		return nil
	}

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		return err
	}
	newRunner.RunEnumeration(context.Background())
	return nil
}
