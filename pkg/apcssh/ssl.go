package apcssh

import (
	"errors"
	"fmt"
	"strings"
)

var errSSLMissingData = errors.New("apcssh: ssl cert install: cant install nil data (unsupported key/nmc version/nmc firmware combo?)")

// InstallSSLCert installs the specified p15 key and p15 cert files on the
// UPS. It has logic to deduce if the NMC is a newer version (e.g., NMC3 with
// newer firmware) and acts accordingly.
func (cli *Client) InstallSSLCert(keyP15 []byte, certPem []byte, keyCertP15 []byte) error {
	// run `ssl` command to check if it exists
	result, err := cli.cmd("ssl")
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to test ssl cmd (%w)", err)
	}
	// E101 is the code for "Command Not Found"
	supportsSSLCmd := !strings.EqualFold(result.code, "e101")

	// if SSL is supported, use that method
	if supportsSSLCmd {
		return cli.installSSLCertModern(keyP15, certPem)
	}

	// fallback to legacy
	return cli.installSSLCertLegacy(keyCertP15)
}

// installSSLCertModern installs the SSL key and certificate using the UPS built-in
// command `ssl`. This command is not present on older devices (e.g., NMC2) or firmwares.
func (cli *Client) installSSLCertModern(keyP15 []byte, certPem []byte) error {
	// fail if required data isn't present
	if len(keyP15) <= 0 || len(certPem) <= 0 {
		return errSSLMissingData
	}

	// upload the key P15 file
	err := cli.UploadSCP("/ssl/nmc.key", keyP15, 0600)
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send nmc.key file to ups over scp (%w)", err)
	}

	// upload the cert PEM file
	err = cli.UploadSCP("/ssl/nmc.crt", certPem, 0666)
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send nmc.key file to ups over scp (%w)", err)
	}

	// run `ssl` install commands
	result, err := cli.cmd("ssl key -i /ssl/nmc.key")
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send ssl key install cmd (%w)", err)
	} else if !strings.EqualFold(result.code, "e000") {
		return fmt.Errorf("apcssh: ssl cert install: ssl key install cmd returned error code (%s: %s)", result.code, result.codeText)
	}

	result, err = cli.cmd("ssl cert -i /ssl/nmc.crt")
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send ssl cert install cmd (%w)", err)
	} else if !strings.EqualFold(result.code, "e000") {
		return fmt.Errorf("apcssh: ssl cert install: ssl cert install cmd returned error code (%s: %s)", result.code, result.codeText)
	}

	return nil
}

// installSSLCertLegacy installs the SSL key and certificate by directly uploading
// them to a .p15 file on the UPS. This is used for older devices (e.g., NMC2) and
// firmwares that do not support the `ssl` command.
func (cli *Client) installSSLCertLegacy(keyCertP15 []byte) error {
	// fail if required data isn't present
	if len(keyCertP15) <= 0 {
		return errSSLMissingData
	}

	// upload/install keyCert P15 file
	err := cli.UploadSCP("/ssl/defaultcert.p15", keyCertP15, 0600)
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send defaultcert.p15 file to ups over scp (%w)", err)
	}

	return nil
}
