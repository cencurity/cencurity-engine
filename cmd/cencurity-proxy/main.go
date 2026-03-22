package main

import (
	"fmt"
	"os"

	"cencurity-engine/internal/cli"
)

// main starts the legacy proxy entrypoint by delegating to `serve`.
func main() {
	if err := cli.Run(append([]string{"serve"}, os.Args[1:]...)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
