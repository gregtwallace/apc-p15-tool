package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"encoding/base64"
	"os"

	"go.uber.org/zap"
)

// struct for receivers to use common app pieces
type app struct {
	logger *zap.SugaredLogger
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

	// break point for building additional alternate functions

	// function: make p15 from pem files

	// Read in PEM files
	keyPem, err := os.ReadFile(*app.config.keyPemFilePath)
	if err != nil {
		app.logger.Fatalf("failed to read key file (%s)", err)
		// FATAL
	}

	certPem, err := os.ReadFile(*app.config.certPemFilePath)
	if err != nil {
		app.logger.Fatalf("failed to read cert file (%s)", err)
		// FATAL
	}

	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		app.logger.Fatalf("failed to parse pem files (%s)", err)
		// FATAL
	}

	// TEMP TEMP TEMP
	p15File, err := p15.ToP15File()
	if err != nil {
		app.logger.Fatalf("failed to make p15 file (%s)", err)
		// FATAL
	}

	// app.logger.Debug(hex.EncodeToString(p15File))
	app.logger.Debug(base64.RawStdEncoding.EncodeToString(p15File))

	// TEMP TEMP TEMP
}
