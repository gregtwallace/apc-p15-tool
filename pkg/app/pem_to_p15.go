package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"fmt"
)

// pemToAPCP15 reads the specified pem files and returns the apc p15 bytes
func (app *app) pemToAPCP15(keyPem, certPem []byte, parentCmdName string) ([]byte, error) {
	app.stdLogger.Printf("%s: making apc p15 file from pem", parentCmdName)

	// make p15 struct
	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse pem files (%w)", parentCmdName, err)
	}

	app.stdLogger.Printf("%s: successfully loaded pem files", parentCmdName)

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

	app.stdLogger.Printf("%s: apc p15 file data succesfully generated", parentCmdName)

	return apcFile, nil
}
