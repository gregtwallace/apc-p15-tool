package app

import (
	"errors"

	"github.com/peterbourgon/ff/v4"
)

var (
	ErrExtraArgs = errors.New("extra args present")
)

// app's config options from user
type config struct {
	logLevel *string
	create   struct {
		keyPemFilePath  *string
		certPemFilePath *string
		outFilePath     *string
	}
}

// getConfig returns the app's configuration from either command line args,
// or environment variables
func (app *app) getConfig() {
	// make config
	cfg := &config{}

	// commands:
	// create
	// TODO:
	// upload
	// unpack (both key & key+cert)

	// apc-p15-tool -- root command
	rootFlags := ff.NewFlagSet("apc-p15-tool")

	cfg.logLevel = rootFlags.StringEnum('l', "loglevel", "log level: debug, info, warn, error, dpanic, panic, or fatal",
		"info", "debug", "warn", "error", "dpanic", "panic", "fatal")

	rootCmd := &ff.Command{
		Name:  "apc-p15-tool",
		Usage: "apc-p15-tool [FLAGS] SUBCOMMAND ...",
		Flags: rootFlags,
	}

	// create -- subcommand
	createFlags := ff.NewFlagSet("create").SetParent(rootFlags)

	cfg.create.keyPemFilePath = createFlags.StringLong("keyfile", "", "path and filename of the rsa-2048 key in pem format")
	cfg.create.certPemFilePath = createFlags.StringLong("certfile", "", "path and filename of the rsa-2048 key in pem format")
	cfg.create.outFilePath = createFlags.StringLong("outfile", createDefaultOutFilePath, "path and filename to write the p15 file to")

	createCmd := &ff.Command{
		Name:      "create",
		Usage:     "apc-p15-tool create --keyfile key.pem --certfile cert.pem [--outfile apctool.p15]",
		ShortHelp: "create an apc p15 file from the specified key and cert pem files",
		Flags:     createFlags,
		Exec:      app.cmdCreate,
	}

	rootCmd.Subcommands = append(rootCmd.Subcommands, createCmd)

	// set app cmd & cfg
	app.cmd = rootCmd
	app.config = cfg
}
