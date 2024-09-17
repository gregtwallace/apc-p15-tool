package pkcs15

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

var (
	errPemKeyBadBlock       = errors.New("pkcs15: pem key: failed to decode pem block")
	errPemKeyFailedToParse  = errors.New("pkcs15: pem key: failed to parse key")
	errPemKeyWrongBlockType = errors.New("pkcs15: pem key: unsupported pem block type")
	errKeyWrongType         = errors.New("pkcs15: pem key: unsupported key type")

	errPemCertBadBlock      = errors.New("pkcs15: pem cert: failed to decode pem block")
	errPemCertFailedToParse = errors.New("pkcs15: pem cert: failed to parse cert")
)

var (
	supportedRSASizes    = []int{1024, 2048, 3072, 4096}
	supportedECDSACurves = []string{"P-256", "P-384", "P-521"}
)

// pemKeyDecode attempts to decode a pem encoded byte slice and then attempts
// to parse a private key from the decoded pem block. an error is returned
// if any of these steps fail OR if the key is not supported.
func pemKeyDecode(keyPem []byte) (crypto.PrivateKey, error) {
	// decode
	pemBlock, _ := pem.Decode([]byte(keyPem))
	if pemBlock == nil {
		return nil, errPemKeyBadBlock
	}

	// parsing depends on block type
	var privateKey crypto.PrivateKey

	switch pemBlock.Type {
	case "RSA PRIVATE KEY": // PKCS1
		rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errPemKeyFailedToParse
		}

		// basic sanity check
		err = rsaKey.Validate()
		if err != nil {
			return nil, fmt.Errorf("pkcs15: pem key: failed sanity check (%s)", err)
		}

		// verify supported rsa bitlen
		if !slices.Contains(supportedRSASizes, rsaKey.N.BitLen()) {
			return nil, errKeyWrongType
		}

		// good to go
		privateKey = rsaKey

	case "EC PRIVATE KEY": // SEC1, ASN.1
		ecdKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errPemKeyFailedToParse
		}

		// verify supported curve name
		if !slices.Contains(supportedECDSACurves, ecdKey.Curve.Params().Name) {
			return nil, errKeyWrongType
		}

		// good to go
		privateKey = ecdKey

	case "PRIVATE KEY": // PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errPemKeyFailedToParse
		}

		switch pkcs8Key := pkcs8Key.(type) {
		case *rsa.PrivateKey:
			// basic sanity check
			err = pkcs8Key.Validate()
			if err != nil {
				return nil, fmt.Errorf("pkcs15: pem key: failed sanity check (%s)", err)
			}

			// verify supported rsa bitlen
			if !slices.Contains(supportedRSASizes, pkcs8Key.N.BitLen()) {
				return nil, errKeyWrongType
			}

			// good to go
			privateKey = pkcs8Key

		case *ecdsa.PrivateKey:
			// verify supported curve name
			if !slices.Contains(supportedECDSACurves, pkcs8Key.Curve.Params().Name) {
				return nil, errKeyWrongType
			}

			// good to go
			privateKey = pkcs8Key

		default:
			return nil, errKeyWrongType
		}

	default:
		return nil, errPemKeyWrongBlockType
	}

	// if rsaKey is nil somehow, error
	if reflect.ValueOf(privateKey).IsNil() {
		return nil, errors.New("pkcs15: pem key: rsa key unexpectedly nil (report bug to project repo)")
	}

	// success!
	return privateKey, nil
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
