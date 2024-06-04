package app

import (
	"context"
	"fmt"
	"os"
)

const (
	createDefaultOutFilePath    = "apctool.p15"
	createDefaultOutKeyFilePath = "apctool.key.p15"
)

// cmdCreate is the app's command to create an apc p15 file from key and cert
// pem files
func (app *app) cmdCreate(_ context.Context, args []string) error {
	// done
	defer app.stdLogger.Println("create: done")

	// extra args == error
	if len(args) != 0 {
		return fmt.Errorf("create: failed, %w (%d)", ErrExtraArgs, len(args))
	}

	keyPem, certPem, err := app.config.create.keyCertPemCfg.GetPemBytes("create")
	if err != nil {
		return err
	}

	// validation done

	// make p15 files
	apcKeyCertFile, keyFile, err := app.pemToAPCP15s(keyPem, certPem, "create")
	if err != nil {
		return err
	}

	// determine file name (should already be done by flag parsing, but avoid nil just in case)
	keyCertFileName := createDefaultOutFilePath
	if app.config.create.outFilePath != nil && *app.config.create.outFilePath != "" {
		keyCertFileName = *app.config.create.outFilePath
	}

	keyFileName := createDefaultOutFilePath
	if app.config.create.outKeyFilePath != nil && *app.config.create.outKeyFilePath != "" {
		keyFileName = *app.config.create.outKeyFilePath
	}

	// write files
	err = os.WriteFile(keyCertFileName, apcKeyCertFile, 0777)
	if err != nil {
		return fmt.Errorf("create: failed to write apc p15 key+cert file (%s)", err)
	}
	app.stdLogger.Printf("create: apc p15 key+cert file %s written to disk", keyCertFileName)

	err = os.WriteFile(keyFileName, keyFile, 0777)
	if err != nil {
		return fmt.Errorf("create: failed to write apc p15 key file (%s)", err)
	}
	app.stdLogger.Printf("create: apc p15 key file %s written to disk", keyFileName)

	return nil
}
