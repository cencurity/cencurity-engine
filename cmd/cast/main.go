package main

import (
	"fmt"
	"os"

	"cencurity-engine/internal/cli"
)

// main starts the CAST CLI.
func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
