package app

import (
	"context"
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

	keyPem, certPem, err := app.config.create.keyCertPemCfg.GetPemBytes("create")
	if err != nil {
		return err
	}

	// validation done

	// make p15 file
	apcFile, err := app.pemToAPCP15(keyPem, certPem, "create")
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

	app.stdLogger.Printf("create: apc p15 file %s written to disk", fileName)

	return nil
}
