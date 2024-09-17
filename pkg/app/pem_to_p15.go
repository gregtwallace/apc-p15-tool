package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"fmt"
	"slices"
)

// list of keys supported by the NMC2
var nmc2SupportedKeyTypes = []pkcs15.KeyType{
	pkcs15.KeyTypeRSA1024,
	pkcs15.KeyTypeRSA2048,
	pkcs15.KeyTypeRSA3072, // officially not supported but works
}

// pemToAPCP15 reads the specified pem files and returns the apc p15 file(s). If the
// key type of the key is not supported by NMC2, the combined key+cert file is not
// generated and nil is returned instead for that file. If the key IS supported by
// NMC2, the key+cert file is generated and the proper header is prepended.
func (app *app) pemToAPCP15(keyPem, certPem []byte, parentCmdName string) (keyFile []byte, apcKeyCertFile []byte, err error) {
	app.stdLogger.Printf("%s: making apc p15 file(s) content from pem", parentCmdName)

	// make p15 struct
	p15, err := pkcs15.ParsePEMToPKCS15(keyPem, certPem)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to parse pem files (%w)", parentCmdName, err)
	}

	app.stdLogger.Printf("%s: successfully parsed pem files", parentCmdName)

	// make key file (always)
	keyFile, err = p15.ToP15Key()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed to make p15 key file (%w)", parentCmdName, err)
	}

	app.stdLogger.Printf("%s: successfully generated p15 key file content", parentCmdName)

	// check key type for compat with NMC2
	if slices.Contains(nmc2SupportedKeyTypes, p15.KeyType()) {
		app.stdLogger.Printf("%s: key type is supported by NMC2, generating p15 key+cert file content...", parentCmdName)

		// make file bytes
		keyCertFile, err := p15.ToP15KeyCert()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: failed to make p15 key+cert file content (%w)", parentCmdName, err)
		}

		// make header for file bytes
		apcHeader, err := makeFileHeader(keyCertFile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: failed to make p15 key+cert file header (%w)", parentCmdName, err)
		}

		// combine header with file
		apcKeyCertFile = append(apcHeader, keyCertFile...)
	} else {
		// NMC2 unsupported
		app.stdLogger.Printf("%s: key type is not supported by NMC2, skipping p15 key+cert file content", parentCmdName)
	}

	app.stdLogger.Printf("%s: apc p15 file(s) data succesfully generated", parentCmdName)

	return keyFile, apcKeyCertFile, nil
}
