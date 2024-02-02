package main

import (
	"apc-p15-tool/pkg/app"
	"os"
)

// a version of the tool that always calls the `install` subcommand
func main() {
	// insert install command
	args := []string{os.Args[0], "install"}
	args = append(args, os.Args[1:]...)

	app.Start(args)
}
