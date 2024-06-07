package app

import (
	"context"
	"encoding/base64"
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
	keyFile, apcKeyCertFile, err := app.pemToAPCP15(keyPem, certPem, "create")
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

	// write file(s)
	err = os.WriteFile(keyCertFileName, apcKeyCertFile, 0600)
	if err != nil {
		return fmt.Errorf("create: failed to write apc p15 key+cert file (%s)", err)
	}
	app.stdLogger.Printf("create: apc p15 key+cert file %s written to disk", keyCertFileName)

	// if debug, write additional debug files (b64 format to make copy/paste into asn1 decoder
	// easy to do e.g., https://lapo.it/asn1js)
	if app.config.debugLogging != nil && *app.config.debugLogging {
		keyCertFileNameDebug := keyCertFileName + ".noheader.b64"
		err = os.WriteFile(keyCertFileNameDebug, []byte(base64.StdEncoding.EncodeToString(apcKeyCertFile[apcHeaderLen:])), 0600)
		if err != nil {
			return fmt.Errorf("create: failed to write apc p15 key+cert file (%s)", err)
		}
		app.debugLogger.Printf("create: apc p15 key+cert file %s written to disk", keyCertFileNameDebug)

		keyCertFileNameHeaderDebug := keyCertFileName + ".header.b64"
		err = os.WriteFile(keyCertFileNameHeaderDebug, []byte(base64.StdEncoding.EncodeToString(apcKeyCertFile[:apcHeaderLen])), 0600)
		if err != nil {
			return fmt.Errorf("create: failed to write apc p15 key+cert file (%s)", err)
		}
		app.debugLogger.Printf("create: apc p15 key+cert file header %s written to disk", keyCertFileNameHeaderDebug)

	}

	// make key p15 ?
	if app.config.create.makeKeyP15 != nil && *app.config.create.makeKeyP15 {
		err = os.WriteFile(keyFileName, keyFile, 0600)
		if err != nil {
			return fmt.Errorf("create: failed to write apc p15 key file (%s)", err)
		}
		app.stdLogger.Printf("create: apc p15 key file %s written to disk", keyFileName)

		// debug file ?
		if app.config.debugLogging != nil && *app.config.debugLogging {
			keyFileNameDebug := keyFileName + ".b64"
			err = os.WriteFile(keyFileNameDebug, []byte(base64.StdEncoding.EncodeToString(keyFile)), 0600)
			if err != nil {
				return fmt.Errorf("create: failed to write apc p15 key file (%s)", err)
			}
			app.debugLogger.Printf("create: apc p15 key file %s written to disk", keyFileNameDebug)
		}
	}

	return nil
}
