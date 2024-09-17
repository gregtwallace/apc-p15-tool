package app

import (
	"apc-p15-tool/pkg/apcssh"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"
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
	if app.config.install.hostname == nil || *app.config.install.hostname == "" ||
		app.config.install.sshport == nil || *app.config.install.sshport == 0 {

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
		Hostname:          *app.config.install.hostname + ":" + strconv.Itoa(*app.config.install.sshport),
		Username:          *app.config.install.username,
		Password:          *app.config.install.password,
		ServerFingerprint: *app.config.install.fingerprint,
		InsecureCipher:    *app.config.install.insecureCipher,
	}

	client, err := apcssh.New(cfg)
	if err != nil {
		return fmt.Errorf("install: failed to connect to host (%w)", err)
	}
	app.stdLogger.Println("install: connected to ups ssh, installing ssl key and cert...")

	// install SSL Cert
	err = client.InstallSSLCert(keyP15, certPem, keyCertP15)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}

	// installed
	app.stdLogger.Printf("install: apc p15 file installed on %s", *app.config.install.hostname)

	// restart UPS webUI
	if app.config.install.restartWebUI != nil && *app.config.install.restartWebUI {
		app.stdLogger.Println("install: sending restart command")

		err = client.RestartWebUI()
		if err != nil {
			return fmt.Errorf("install: failed to send webui restart command (%w)", err)
		}

		app.stdLogger.Println("install: sent webui restart command")
	}

	// check the new certificate is installed
	if app.config.install.skipVerify != nil && !*app.config.install.skipVerify &&
		app.config.install.webUISSLPort != nil && *app.config.install.webUISSLPort != 0 {

		app.stdLogger.Println("install: attempting to verify certificate install...")

		// sleep for UPS to finish anything it might be doing
		time.Sleep(5 * time.Second)

		// if UPS web UI was restarted, sleep longer
		if app.config.install.restartWebUI != nil && *app.config.install.restartWebUI {
			app.stdLogger.Println("install: waiting for ups webui restart...")
			time.Sleep(25 * time.Second)
		}

		// connect to the web UI to get the current certificate
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", *app.config.install.hostname+":"+strconv.Itoa(*app.config.install.webUISSLPort), conf)
		if err != nil {
			return fmt.Errorf("install: failed to dial webui for verification (%s)", err)
		}
		defer conn.Close()

		// get top cert
		leafCert := conn.ConnectionState().PeerCertificates[0]
		if leafCert == nil {
			return fmt.Errorf("install: failed to get web ui leaf cert for verification (%s)", err)
		}

		// convert pem to DER for comparison
		pemBlock, _ := pem.Decode(certPem)

		// verify cert is the correct one
		certVerified := bytes.Equal(leafCert.Raw, pemBlock.Bytes)
		if !certVerified {
			return errors.New("install: web ui leaf cert does not match new cert")
		}

		app.stdLogger.Println("install: ups web ui cert verified")
	}

	return nil
}
