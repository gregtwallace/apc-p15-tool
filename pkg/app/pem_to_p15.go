package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"fmt"
)

// pemToAPCP15 reads the specified pem files and returns the apc p15 files (both a
// p15 file with just the private key, and also a p15 file with both the private key
// and certificate). The key+cert file includes the required APC header, prepended.
func (app *app) pemToAPCP15(keyPem, certPem []byte, parentCmdName string) (keyFile []byte, apcKeyCertFile []byte, err error) {
	app.stdLogger.Printf("%s: making apc p15 file from pem", parentCmdName)

	// make p15 struct
	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to parse pem files (%w)", parentCmdName, err)
	}

	app.stdLogger.Printf("%s: successfully loaded pem files", parentCmdName)

	// make file bytes
	keyCertFile, keyFile, err := p15.ToP15Files()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to make p15 file (%w)", parentCmdName, err)
	}

	// make header for file bytes
	apcHeader, err := makeFileHeader(keyCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to make p15 file header (%w)", parentCmdName, err)
	}

	// combine header with file
	apcKeyCertFile = append(apcHeader, keyCertFile...)

	app.stdLogger.Printf("%s: apc p15 file data succesfully generated", parentCmdName)

	return keyFile, apcKeyCertFile, nil
}
