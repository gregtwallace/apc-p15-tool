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
	appVersion = "0.1.0"

	environmentVarPrefix = "APC_P15_TOOL"
)

// struct for receivers to use common app pieces
type app struct {
	logger *zap.SugaredLogger
	cmd    *ff.Command
	config *config
}

// actual application start
func Start() {
	// make app w/ initial logger pre-config
	initLogLevel := "debug"
	app := &app{
		logger: makeZapLogger(&initLogLevel),
	}

	// get config
	app.getConfig()

	// re-init logger with configured log level
	app.logger = makeZapLogger(app.config.logLevel)

	// log start
	app.logger.Infof("apc-p15-tool v%s", appVersion)

	// get config
	app.getConfig()

	// run it
	exitCode := 0
	err := app.cmd.ParseAndRun(context.Background(), os.Args[1:], ff.WithEnvVarPrefix(environmentVarPrefix))
	if err != nil {
		exitCode = 1

		if errors.Is(err, ff.ErrHelp) {
			// help explicitly requested
			exitCode = 0
			app.logger.Info("\n\n", ffhelp.Command(app.cmd))

		} else if errors.Is(err, ErrExtraArgs) {
			// extra args (will log elsewhere, so no need to log err again)
			app.logger.Info("\n\n", ffhelp.Command(app.cmd))

		} else if errors.Is(err, ff.ErrDuplicateFlag) ||
			errors.Is(err, ff.ErrUnknownFlag) ||
			errors.Is(err, ff.ErrNoExec) {
			// other error that suggests user needs to see help
			app.logger.Error(err)
			app.logger.Info("\n\n", ffhelp.Command(app.cmd))

		} else {
			// any other error
			app.logger.Error(err)
		}
	}

	app.logger.Info("apc-p15-tool done")
	os.Exit(exitCode)
}
