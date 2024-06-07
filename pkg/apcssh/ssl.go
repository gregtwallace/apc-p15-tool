package apcssh

import "fmt"

// InstallSSLCert installs the specified p15 cert file on the UPS. This
// function currently only works on NMC2.
func (cli *Client) InstallSSLCert(keyCertP15 []byte) error {
	// install NMC2 P15 file
	err := cli.UploadSCP("/ssl/defaultcert.p15", keyCertP15, 0600)
	if err != nil {
		return fmt.Errorf("apcssh: ssl cert install: failed to send file to ups over scp (%w)", err)
	}

	return nil
}
