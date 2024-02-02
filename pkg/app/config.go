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
	install struct {
		keyPemFilePath  *string
		certPemFilePath *string
		hostAndPort     *string
		fingerprint     *string
		username        *string
		password        *string
	}
}

// getConfig returns the app's configuration from either command line args,
// or environment variables
func (app *app) getConfig(args []string) error {
	// make config
	cfg := &config{}

	// commands:
	// create
	// install
	// TODO:
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
	cfg.create.certPemFilePath = createFlags.StringLong("certfile", "", "path and filename of the certificate in pem format")
	cfg.create.outFilePath = createFlags.StringLong("outfile", createDefaultOutFilePath, "path and filename to write the p15 file to")

	createCmd := &ff.Command{
		Name:      "create",
		Usage:     "apc-p15-tool create --keyfile key.pem --certfile cert.pem [--outfile apctool.p15]",
		ShortHelp: "create an apc p15 file from the specified key and cert pem files",
		Flags:     createFlags,
		Exec:      app.cmdCreate,
	}

	rootCmd.Subcommands = append(rootCmd.Subcommands, createCmd)

	// install -- subcommand
	installFlags := ff.NewFlagSet("install").SetParent(rootFlags)

	cfg.install.keyPemFilePath = installFlags.StringLong("keyfile", "", "path and filename of the rsa-2048 key in pem format")
	cfg.install.certPemFilePath = installFlags.StringLong("certfile", "", "path and filename of the certificate in pem format")
	cfg.install.hostAndPort = installFlags.StringLong("apchost", "", "hostname:port of the apc ups to install the certificate on")
	cfg.install.fingerprint = installFlags.StringLong("fingerprint", "", "the SHA256 fingerprint value of the ups' ssh server")
	cfg.install.username = installFlags.StringLong("username", "", "username to login to the apc ups")
	cfg.install.password = installFlags.StringLong("password", "", "password to login to the apc ups")

	installCmd := &ff.Command{
		Name:      "install",
		Usage:     "apc-p15-tool upload --keyfile key.pem --certfile cert.pem --apchost example.com:22 --fingerprint 123abc --username apc --password test",
		ShortHelp: "install the specified key and cert pem files on an apc ups (they will be converted to a comaptible p15 file)",
		Flags:     installFlags,
		Exec:      app.cmdInstall,
	}

	rootCmd.Subcommands = append(rootCmd.Subcommands, installCmd)

	// set cfg & parse
	app.config = cfg
	app.cmd = rootCmd
	err := app.cmd.Parse(args[1:], ff.WithEnvVarPrefix(environmentVarPrefix))
	if err != nil {
		return err
	}

	return nil
}
