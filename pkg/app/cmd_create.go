package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"context"
	"errors"
	"fmt"
	"os"
)

const createDefaultOutFilePath = "apctool.p15"

// cmdCreate is the app's command to create an apc p15 file from key and cert
// pem files
func (app *app) cmdCreate(_ context.Context, args []string) error {
	// extra args == error
	if len(args) != 0 {
		app.logger.Errorf("create: failed, extra args (%d) present", len(args))
		return ErrExtraArgs
	}

	// key must be specified
	if app.config.create.keyPemFilePath == nil || *app.config.create.keyPemFilePath == "" {
		return errors.New("create: failed, key not specified")
	}

	// cert must be specified
	if app.config.create.certPemFilePath == nil || *app.config.create.certPemFilePath == "" {
		return errors.New("create: failed, cert not specified")
	}

	// validation done
	app.logger.Infof("create: making apc p15 file from pem files")

	// Read in PEM files
	keyPem, err := os.ReadFile(*app.config.create.keyPemFilePath)
	if err != nil {
		return fmt.Errorf("create: failed to read key file (%s)", err)
	}

	certPem, err := os.ReadFile(*app.config.create.certPemFilePath)
	if err != nil {
		return fmt.Errorf("create: failed to read cert file (%s)", err)
	}

	// make p15 struct
	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		return fmt.Errorf("create: failed to parse pem files (%s)", err)
	}

	app.logger.Infof("create: successfully loaded pem files")

	// make file bytes
	p15File, err := p15.ToP15File()
	if err != nil {
		return fmt.Errorf("create: failed to make p15 file (%s)", err)
	}

	// make header for file bytes
	apcHeader, err := makeFileHeader(p15File)
	if err != nil {
		return fmt.Errorf("create: failed to make p15 file header (%s)", err)
	}

	// combine header with file
	apcFile := append(apcHeader, p15File...)

	// determine file name (should already be done by flag parsing, but avoid nil just in case)
	fileName := createDefaultOutFilePath
	if app.config.create.outFilePath != nil && *app.config.create.outFilePath != "" {
		fileName = *app.config.create.outFilePath
	}

	// write file
	err = os.WriteFile(fileName, apcFile, 0777)
	if err != nil {
		return fmt.Errorf("create: failed to write apc p15 file (%s)", err)
	}

	app.logger.Infof("create: apc p15 file %s written to disk", fileName)

	return nil
}
