package app

import (
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
		return fmt.Errorf("create: failed, %w (%d)", ErrExtraArgs, len(args))
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

	// make p15 file
	apcFile, err := app.pemToAPCP15(*app.config.create.keyPemFilePath, *app.config.create.certPemFilePath, "create")
	if err != nil {
		return err
	}

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
