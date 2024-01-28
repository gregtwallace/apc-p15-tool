package app

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// makeZapLogger creates a logger for the app; if log level is nil or does not parse
// the default 'Info' level will be used.
func makeZapLogger(logLevel *string) *zap.SugaredLogger {
	// default info level
	zapLevel := zapcore.InfoLevel
	var parseErr error

	// try to parse specified level (if there is one)
	if logLevel != nil {
		parseLevel, err := zapcore.ParseLevel(*logLevel)
		if err != nil {
			parseErr = err
		} else {
			zapLevel = parseLevel
		}
	}

	// make zap config
	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.LineEnding = "\n"

	// no stack trace
	config.StacktraceKey = ""

	// make logger
	consoleEncoder := zapcore.NewConsoleEncoder(config)
	core := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapLevel)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)).Sugar()

	// log deferred parse error if there was one
	if logLevel != nil && parseErr != nil {
		logger.Errorf("failed to parse requested log level \"%s\" (%s)", *logLevel, parseErr)
	}

	return logger
}
