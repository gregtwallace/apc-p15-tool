package app

import (
	"apc-p15-tool/pkg/pkcs15"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"
)

// list of keys supported by the NMC2
var nmc2SupportedKeyTypes = []pkcs15.KeyType{
	pkcs15.KeyTypeRSA1024,
	pkcs15.KeyTypeRSA2048,
	pkcs15.KeyTypeRSA3072, // officially not supported but works
}

// known good signing algorithms
var knownSupportedNMC2SigningAlgs = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA,
}

var knownSupportedNMC3SigningAlgs = append(knownSupportedNMC2SigningAlgs, []x509.SignatureAlgorithm{
	x509.ECDSAWithSHA384,
}...)

// known supported cert extensions
var knownSupportedCriticalOIDs = []asn1.ObjectIdentifier{
	{2, 5, 29, 15}, // keyUsage
	{2, 5, 29, 19}, // basicConstraints
	{2, 5, 29, 17}, // subjectAltName
}

var knownSupportedOIDs = append(knownSupportedCriticalOIDs, []asn1.ObjectIdentifier{
	{2, 5, 29, 37},                     // extKeyUsage
	{2, 5, 29, 14},                     // subjectKeyIdentifier
	{2, 5, 29, 35},                     // authorityKeyIdentifier
	{1, 3, 6, 1, 5, 5, 7, 1, 1},        // authorityInfoAccess
	{2, 5, 29, 32},                     // certificatePolicies
	{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, // googleSignedCertificateTimestamp
	{2, 5, 29, 31},                     // cRLDistributionPoints
}...)

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
	nmc2KeyType := false
	if slices.Contains(nmc2SupportedKeyTypes, p15.KeyType()) {
		nmc2KeyType = true

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
	}

	// check various parts of cert and log compatibility warnings
	warned := false

	// key not supported for NMC2
	if !nmc2KeyType {
		app.stdLogger.Printf("WARNING: %s: key type is %s and is not supported by NMC2.", parentCmdName, p15.KeyType().String())
		warned = true
	}

	// signature algorithm (see: https://github.com/gregtwallace/apc-p15-tool/issues/18)
	if !nmc2KeyType {
		// definitely not for NMC2
		if !slices.Contains(knownSupportedNMC3SigningAlgs, p15.Cert.SignatureAlgorithm) {
			app.stdLogger.Printf("WARNING: %s: Certificate signing algorithm is %s and it is not known if NMC3 supports this algorithm.", parentCmdName, p15.Cert.SignatureAlgorithm.String())
			warned = true
		}
	} else {
		// could be for either NMC2 or NMC3
		if !slices.Contains(knownSupportedNMC2SigningAlgs, p15.Cert.SignatureAlgorithm) {
			if !slices.Contains(knownSupportedNMC3SigningAlgs, p15.Cert.SignatureAlgorithm) {
				// not in NMC2 or NMC3 list
				app.stdLogger.Printf("WARNING: %s: Certificate signing algorithm is %s and is not supported by NMC2. It is also not known if NMC3 supports this algorithm.", parentCmdName, p15.Cert.SignatureAlgorithm.String())
			} else {
				// not in NMC2 list, but is in NMC3 list
				app.stdLogger.Printf("WARNING: %s: Certificate signing algorithm is %s and it does not support NMC2.", parentCmdName, p15.Cert.SignatureAlgorithm.String())
			}
			warned = true
		}
	}

	// if support by 2, check 2 list
	// if not found on 2 list, check 3 list

	// check validity dates
	if time.Now().Before(p15.Cert.NotBefore) {
		app.stdLogger.Printf("WARNING: %s: Current time (%s) is before certificate's NotBefore time (%s).",
			parentCmdName, time.Now().Format(timeLoggingFormat), p15.Cert.NotBefore.Format(timeLoggingFormat))
		warned = true
	}

	if time.Now().After(p15.Cert.NotAfter) {
		app.stdLogger.Printf("WARNING: %s: Current time (%s) is after certificate's NotAfter time (%s).",
			parentCmdName, time.Now().Format(timeLoggingFormat), p15.Cert.NotAfter.Format(timeLoggingFormat))
		warned = true
	}

	// check extensions against known working extensions
	for _, extension := range p15.Cert.Extensions {
		// critical or not?
		okOIDs := knownSupportedCriticalOIDs
		criticalLogMsg := "Critical "
		if !extension.Critical {
			okOIDs = knownSupportedOIDs
			criticalLogMsg = ""
		}

		// validate OIDs
		ok := false
		for _, okOID := range okOIDs {
			if okOID.Equal(extension.Id) {
				ok = true
				break
			}
		}

		if !ok {
			app.stdLogger.Printf("WARNING: %s: %sExtension %s may not be supported by NMC.", parentCmdName, criticalLogMsg, extension.Id.String())
		}
	}

	// log a message about possible failure
	if warned {
		app.stdLogger.Printf("WARNING: %s: Possible certificate compatibility issues were detected. If the resulting p15 file "+
			"does not work with your NMC (e.g., a self-signed certificate is regenerated after you try to install the p15), "+
			"modify your certificate to resolve the warnings and try again.", parentCmdName)
	}

	// end compatibility warnings

	app.stdLogger.Printf("%s: apc p15 file(s) data succesfully generated", parentCmdName)

	return keyFile, apcKeyCertFile, nil
}
