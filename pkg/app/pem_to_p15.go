package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"fmt"
	"os"
)

// pemToAPCP15 reads the specified pem files and returns the apc p15 bytes
func (app *app) pemToAPCP15(keyFileName, certFileName, parentCmdName string) ([]byte, error) {
	app.logger.Infof("%s: making apc p15 file from pem files", parentCmdName)

	// Read in PEM files
	keyPem, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read key file (%w)", parentCmdName, err)
	}

	certPem, err := os.ReadFile(certFileName)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read cert file (%w)", parentCmdName, err)
	}

	// make p15 struct
	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse pem files (%w)", parentCmdName, err)
	}

	app.logger.Infof("%s: successfully loaded pem files", parentCmdName)

	// make file bytes
	p15File, err := p15.ToP15File()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to make p15 file (%w)", parentCmdName, err)
	}

	// make header for file bytes
	apcHeader, err := makeFileHeader(p15File)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to make p15 file header (%w)", parentCmdName, err)
	}

	// combine header with file
	apcFile := append(apcHeader, p15File...)

	app.logger.Infof("%s: apc p15 file data succesfully generated", parentCmdName)

	return apcFile, nil
}
