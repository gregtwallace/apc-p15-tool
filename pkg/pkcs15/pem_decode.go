package pkcs15

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	errPemKeyBadBlock       = errors.New("pkcs15: pem key: failed to decode pem block")
	errPemKeyFailedToParse  = errors.New("pkcs15: pem key: failed to parse key")
	errPemKeyWrongBlockType = errors.New("pkcs15: pem key: unsupported pem block type (only pkcs1 and pkcs8 supported)")
	errPemKeyWrongType      = errors.New("pkcs15: pem key: unsupported key type (only rsa 1,024 or 2,048 supported)")

	errPemCertBadBlock      = errors.New("pkcs15: pem cert: failed to decode pem block")
	errPemCertFailedToParse = errors.New("pkcs15: pem cert: failed to parse cert")
)

// pemKeyDecode attempts to decode a pem encoded byte slice and then attempts
// to parse an RSA private key from the decoded pem block. an error is returned
// if any of these steps fail OR if the key is not RSA and of bitlen 1,024 or 2,048
func pemKeyDecode(keyPem []byte) (*rsa.PrivateKey, error) {
	// decode
	pemBlock, _ := pem.Decode([]byte(keyPem))
	if pemBlock == nil {
		return nil, errPemKeyBadBlock
	}

	// parsing depends on block type
	var rsaKey *rsa.PrivateKey

	switch pemBlock.Type {
	case "RSA PRIVATE KEY": // PKCS1
		var err error

		rsaKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errPemKeyFailedToParse
		}

		// basic sanity check
		err = rsaKey.Validate()
		if err != nil {
			return nil, fmt.Errorf("pkcs15: pem key: failed sanity check (%s)", err)
		}

		// verify proper bitlen
		if rsaKey.N.BitLen() != 1024 && rsaKey.N.BitLen() != 2048 {
			return nil, errPemKeyWrongType
		}

		// good to go

	case "PRIVATE KEY": // PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errPemKeyFailedToParse
		}

		switch pkcs8Key := pkcs8Key.(type) {
		case *rsa.PrivateKey:
			rsaKey = pkcs8Key

			// basic sanity check
			err = rsaKey.Validate()
			if err != nil {
				return nil, fmt.Errorf("pkcs15: pem key: failed sanity check (%s)", err)
			}

			// verify proper bitlen
			if rsaKey.N.BitLen() != 1024 && rsaKey.N.BitLen() != 2048 {
				return nil, errPemKeyWrongType
			}

			// good to go

		default:
			return nil, errPemKeyWrongType
		}

	default:
		return nil, errPemKeyWrongBlockType
	}

	// if rsaKey is nil somehow, error
	if rsaKey == nil {
		return nil, errors.New("pkcs15: pem key: rsa key unexpectedly nil (report bug to project repo)")
	}

	// success!
	return rsaKey, nil
}

// pemCertDecode attempts to decode a pem encoded byte slice and then attempts
// to parse a certificate from it. The certificate is also check against the
// key that is passed in to verify the key matches the certificate.
func pemCertDecode(certPem, keyPem []byte) (*x509.Certificate, error) {
	// verify key and cert make a valid key pair
	_, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	// discard rest, apc tool only bundles end cert
	block, _ := pem.Decode(certPem)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errPemCertBadBlock
	}

	// Get the cert struct
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errPemCertFailedToParse
	}

	return cert, nil
}
