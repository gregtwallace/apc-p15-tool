package app

import (
	"context"
	"errors"
	"io"
	"log"
	"os"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const (
	appVersion = "0.5.0"
)

// struct for receivers to use common app pieces
type app struct {
	stdLogger   *log.Logger
	debugLogger *log.Logger
	errLogger   *log.Logger
	cmd         *ff.Command
	config      *config
}

// actual application start
func Start(args []string) {
	// make app w/ logger
	app := &app{
		stdLogger:   log.New(os.Stdout, "", 0),
		debugLogger: log.New(io.Discard, "", 0), // discard debug logging by default
		errLogger:   log.New(os.Stderr, "", 0),
	}

	// log start
	app.stdLogger.Printf("apc-p15-tool v%s", appVersion)

	// get os.Args if args unspecified in func
	if args == nil {
		args = os.Args
	}

	// get & parse config
	err := app.getConfig(args)

	// if debug logging, make real debug logger
	if app.config.debugLogging != nil && *app.config.debugLogging {
		app.debugLogger = log.New(os.Stdout, "debug: ", 0)
	}

	// deal with config err (after logger re-init)
	if err != nil {
		exitCode := 0

		if errors.Is(err, ff.ErrHelp) {
			// help explicitly requested
			app.stdLogger.Printf("\n%s\n", ffhelp.Command(app.cmd))

		} else if errors.Is(err, ff.ErrDuplicateFlag) ||
			errors.Is(err, ff.ErrUnknownFlag) ||
			errors.Is(err, ff.ErrNoExec) ||
			errors.Is(err, ErrExtraArgs) {
			// other error that suggests user needs to see help
			exitCode = 1
			app.errLogger.Print(err)
			app.stdLogger.Printf("\n%s\n", ffhelp.Command(app.cmd))

		} else {
			// any other error
			exitCode = 1
			app.errLogger.Print(err)
		}

		os.Exit(exitCode)
	}

	// run it
	exitCode := 0
	err = app.cmd.Run(context.Background())
	if err != nil {
		exitCode = 1
		app.errLogger.Print(err)

		// if extra args, show help
		if errors.Is(err, ErrExtraArgs) {
			app.stdLogger.Printf("\n%s\n", ffhelp.Command(app.cmd))
		}
	}

	app.stdLogger.Print("apc-p15-tool done")
	os.Exit(exitCode)
}
