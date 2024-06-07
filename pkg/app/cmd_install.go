package app

import (
	"apc-p15-tool/pkg/apcssh"
	"context"
	"errors"
	"fmt"
)

// cmdInstall is the app's command to create apc p15 file content from key and cert
// pem files and upload the p15 to the specified APC UPS
func (app *app) cmdInstall(cmdCtx context.Context, args []string) error {
	// extra args == error
	if len(args) != 0 {
		return fmt.Errorf("install: failed, %w (%d)", ErrExtraArgs, len(args))
	}

	// must have username
	if app.config.install.username == nil || *app.config.install.username == "" {
		return errors.New("install: failed, username not specified")
	}

	// must have password
	if app.config.install.password == nil || *app.config.install.password == "" {
		return errors.New("install: failed, password not specified")
	}

	// must have fingerprint
	if app.config.install.fingerprint == nil || *app.config.install.fingerprint == "" {
		return errors.New("install: failed, fingerprint not specified")
	}

	keyPem, certPem, err := app.config.install.keyCertPemCfg.GetPemBytes("install")
	if err != nil {
		return err
	}

	// host to install on must be specified
	if app.config.install.hostAndPort == nil || *app.config.install.hostAndPort == "" {
		return errors.New("install: failed, apc host not specified")
	}

	// validation done

	// make p15 file
	keyP15, keyCertP15, err := app.pemToAPCP15(keyPem, certPem, "install")
	if err != nil {
		return err
	}

	// log warning if insecure cipher
	if app.config.install.insecureCipher != nil && *app.config.install.insecureCipher {
		app.stdLogger.Println("WARNING: install: insecure ciphers are enabled (--insecurecipher). SSH with an insecure cipher is NOT secure and should NOT be used.")
	}

	// make APC SSH client
	cfg := &apcssh.Config{
		Hostname:          *app.config.install.hostAndPort,
		Username:          *app.config.install.username,
		Password:          *app.config.install.password,
		ServerFingerprint: *app.config.install.fingerprint,
		InsecureCipher:    *app.config.install.insecureCipher,
	}

	client, err := apcssh.New(cfg)
	if err != nil {
		return fmt.Errorf("install: failed to connect to host (%w)", err)
	}

	// install SSL Cert
	err = client.InstallSSLCert(keyP15, certPem, keyCertP15)
	if err != nil {
		return fmt.Errorf("install: failed to send file to ups over scp (%w)", err)
	}

	// installed
	app.stdLogger.Printf("install: apc p15 file installed on %s", *app.config.install.hostAndPort)

	// restart UPS webUI
	if app.config.install.restartWebUI != nil && *app.config.install.restartWebUI {
		app.stdLogger.Println("install: sending restart command")

		err = client.RestartWebUI()
		if err != nil {
			return fmt.Errorf("install: failed to send webui restart command (%w)", err)
		}

		app.stdLogger.Println("install: sent webui restart command")
	}

	return nil
}
