package app

import (
	"os"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const (
	environmentVarPrefix = "APC_P15_TOOL"
)

// app's config options from user
type config struct {
	logLevel        *string
	keyPemFilePath  *string
	certPemFilePath *string
}

// getConfig returns the app's configuration from either command line args,
// or environment variables
func (app *app) getConfig() {
	// make config and flag set
	cfg := &config{}
	fs := ff.NewFlagSet("apc-p15-tool")

	// define options
	cfg.logLevel = fs.StringEnum('l', "loglevel", "log level: debug, info, warn, error, dpanic, panic, or fatal",
		"info", "debug", "warn", "error", "dpanic", "panic", "fatal")

	cfg.keyPemFilePath = fs.StringLong("keyfile", "", "path and filename of the rsa-2048 key in pem format")
	cfg.certPemFilePath = fs.StringLong("certfile", "", "path and filename of the rsa-2048 key in pem format")
	// TODO key and pem directly in a flag/env var

	// parse using args and/or ENV vars
	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix(environmentVarPrefix))
	if err != nil {
		app.logger.Fatal(ffhelp.Flags(fs))
		// FATAL
	}

	// set app config
	app.config = cfg
}
