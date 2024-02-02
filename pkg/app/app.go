package app

import (
	"context"
	"errors"
	"os"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"go.uber.org/zap"
)

const (
	appVersion = "0.2.0"

	environmentVarPrefix = "APC_P15_TOOL"
)

// struct for receivers to use common app pieces
type app struct {
	logger *zap.SugaredLogger
	cmd    *ff.Command
	config *config
}

// actual application start
func Start(args []string) {
	// make app w/ initial logger pre-config
	initLogLevel := "debug"
	app := &app{
		logger: makeZapLogger(&initLogLevel),
	}

	// log start
	app.logger.Infof("apc-p15-tool v%s", appVersion)

	// get os.Args if args unspecified in func
	if args == nil {
		args = os.Args
	}

	// get & parse config
	err := app.getConfig(args)

	// re-init logger with configured log level
	app.logger = makeZapLogger(app.config.logLevel)

	// deal with config err (after logger re-init)
	if err != nil {
		exitCode := 0

		if errors.Is(err, ff.ErrHelp) {
			// help explicitly requested
			app.logger.Info("\n\n", ffhelp.Command(app.cmd))

		} else if errors.Is(err, ff.ErrDuplicateFlag) ||
			errors.Is(err, ff.ErrUnknownFlag) ||
			errors.Is(err, ff.ErrNoExec) ||
			errors.Is(err, ErrExtraArgs) {
			// other error that suggests user needs to see help
			exitCode = 1
			app.logger.Error(err)
			app.logger.Info("\n\n", ffhelp.Command(app.cmd))

		} else {
			// any other error
			exitCode = 1
			app.logger.Error(err)
		}

		os.Exit(exitCode)
	}

	// run it
	exitCode := 0
	err = app.cmd.Run(context.Background())
	if err != nil {
		exitCode = 1
		app.logger.Error(err)
	}

	app.logger.Info("apc-p15-tool done")
	os.Exit(exitCode)
}
