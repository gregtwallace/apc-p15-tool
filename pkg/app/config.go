package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v4"
)

var (
	ErrExtraArgs = errors.New("extra args present")

	environmentVarPrefix = "APC_P15_TOOL"
)

// keyCertPemCfg contains values common to subcommands that need to use key
// and cert pem
type keyCertPemCfg struct {
	keyPemFilePath  *string
	certPemFilePath *string
	keyPem          *string
	certPem         *string
}

// app's config options from user
type config struct {
	debugLogging *bool
	create       struct {
		keyCertPemCfg
		outFilePath    *string
		makeKeyP15     *bool
		outKeyFilePath *string
	}
	install struct {
		keyCertPemCfg
		hostAndPort    *string
		fingerprint    *string
		username       *string
		password       *string
		restartWebUI   *bool
		insecureCipher *bool
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

	cfg.debugLogging = rootFlags.BoolLong("debug", "set this flag to enable additional debug logging messages and files")

	rootCmd := &ff.Command{
		Name:  "apc-p15-tool",
		Usage: "apc-p15-tool [FLAGS] SUBCOMMAND ...",
		Flags: rootFlags,
	}

	// create -- subcommand
	createFlags := ff.NewFlagSet("create").SetParent(rootFlags)

	cfg.create.keyPemFilePath = createFlags.StringLong("keyfile", "", "path and filename of the rsa-1024 or rsa-2048 key in pem format")
	cfg.create.certPemFilePath = createFlags.StringLong("certfile", "", "path and filename of the certificate in pem format")
	cfg.create.keyPem = createFlags.StringLong("keypem", "", "string of the rsa-1024 or rsa-2048 key in pem format")
	cfg.create.certPem = createFlags.StringLong("certpem", "", "string of the certificate in pem format")
	cfg.create.outFilePath = createFlags.StringLong("outfile", createDefaultOutFilePath, "path and filename to write the key+cert p15 file to")
	cfg.create.makeKeyP15 = createFlags.BoolLong("keyp15", "create a second p15 file with just the private key")
	cfg.create.outKeyFilePath = createFlags.StringLong("outkeyfile", createDefaultOutKeyFilePath, "path and filename to write the key p15 file to")

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

	cfg.install.keyPemFilePath = installFlags.StringLong("keyfile", "", "path and filename of the rsa-1024 or rsa-2048 key in pem format")
	cfg.install.certPemFilePath = installFlags.StringLong("certfile", "", "path and filename of the certificate in pem format")
	cfg.install.keyPem = installFlags.StringLong("keypem", "", "string of the rsa-1024 or rsa-2048 key in pem format")
	cfg.install.certPem = installFlags.StringLong("certpem", "", "string of the certificate in pem format")
	cfg.install.hostAndPort = installFlags.StringLong("apchost", "", "hostname:port of the apc ups to install the certificate on")
	cfg.install.fingerprint = installFlags.StringLong("fingerprint", "", "the SHA256 fingerprint value of the ups' ssh server")
	cfg.install.username = installFlags.StringLong("username", "", "username to login to the apc ups")
	cfg.install.password = installFlags.StringLong("password", "", "password to login to the apc ups")
	cfg.install.restartWebUI = installFlags.BoolLong("restartwebui", "some devices may need a webui restart to begin using the new cert, enabling this option sends the restart command after the p15 is installed")
	cfg.install.insecureCipher = installFlags.BoolLong("insecurecipher", "allows the use of insecure ssh ciphers (NOT recommended)")

	installCmd := &ff.Command{
		Name:      "install",
		Usage:     "apc-p15-tool install --keyfile key.pem --certfile cert.pem --apchost example.com:22 --fingerprint 123abc --username apc --password test",
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

// GetPemBytes returns the key and cert pem bytes as specified in keyCertPemCfg
// or an error if it cant get the bytes of both
func (kcCfg *keyCertPemCfg) GetPemBytes(subcommand string) (keyPem, certPem []byte, err error) {
	// key pem (from arg or file)
	if kcCfg.keyPem != nil && *kcCfg.keyPem != "" {
		// error if filename is also set
		if kcCfg.keyPemFilePath != nil && *kcCfg.keyPemFilePath != "" {
			return nil, nil, fmt.Errorf("%s: failed, both key pem and key file specified", subcommand)
		}

		// use pem
		keyPem = []byte(*kcCfg.keyPem)
	} else {
		// pem wasn't specified, try reading file
		if kcCfg.keyPemFilePath == nil || *kcCfg.keyPemFilePath == "" {
			return nil, nil, fmt.Errorf("%s: failed, neither key pem nor key file specified", subcommand)
		}

		// read file to get pem
		keyPem, err = os.ReadFile(*kcCfg.keyPemFilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: failed to read key file (%w)", subcommand, err)
		}
	}

	// cert pem (repeat same process)
	if kcCfg.certPem != nil && *kcCfg.certPem != "" {
		// error if filename is also set
		if kcCfg.certPemFilePath != nil && *kcCfg.certPemFilePath != "" {
			return nil, nil, fmt.Errorf("%s: failed, both cert pem and cert file specified", subcommand)
		}

		// use pem
		certPem = []byte(*kcCfg.certPem)
	} else {
		// pem wasn't specified, try reading file
		if kcCfg.certPemFilePath == nil || *kcCfg.certPemFilePath == "" {
			return nil, nil, fmt.Errorf("%s: failed, neither cert pem nor cert file specified", subcommand)
		}

		// read file to get pem
		certPem, err = os.ReadFile(*kcCfg.certPemFilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: failed to read cert file (%w)", subcommand, err)
		}
	}

	return keyPem, certPem, nil
}
