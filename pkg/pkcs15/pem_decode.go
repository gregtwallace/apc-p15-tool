package pkcs15

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
)

var (
	errPemKeyBadBlock       = errors.New("pkcs15: pem key: failed to decode pem block")
	errPemKeyFailedToParse  = errors.New("pkcs15: pem key: failed to parse key")
	errPemKeyWrongBlockType = errors.New("pkcs15: pem key: unsupported pem block type (only pkcs1 and pkcs8 supported)")
	errPemKeyWrongType      = errors.New("pkcs15: pem key: unsupported key type (only rsa 1,024, 2,048, and 3,072 supported)")

	errPemCertBadBlock      = errors.New("pkcs15: pem cert: failed to decode pem block")
	errPemCertFailedToParse = errors.New("pkcs15: pem cert: failed to parse cert")
)

// pemKeyDecode attempts to decode a pem encoded byte slice and then attempts
// to parse an RSA private key from the decoded pem block. an error is returned
// if any of these steps fail OR if the key is not RSA and of bitlen 1,024 or 2,048
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

		// verify proper bitlen
		if rsaKey.N.BitLen() != 1024 && rsaKey.N.BitLen() != 2048 && rsaKey.N.BitLen() != 3072 {
			return nil, errPemKeyWrongType
		}

		// good to go
		privateKey = rsaKey

	// case "EC PRIVATE KEY": // SEC1, ASN.1
	// 	var ecdKey *ecdsa.PrivateKey
	// 	ecdKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	// 	if err != nil {
	// 		return nil, errPemKeyFailedToParse
	// 	}

	// 	// verify acceptable curve name
	// 	if ecdKey.Curve.Params().Name != "P-256" && ecdKey.Curve.Params().Name != "P-384" {
	// 		return nil, errPemKeyWrongType
	// 	}

	// 	// good to go
	// 	privateKey = ecdKey

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

			// verify proper bitlen
			if pkcs8Key.N.BitLen() != 1024 && pkcs8Key.N.BitLen() != 2048 && pkcs8Key.N.BitLen() != 3072 {
				return nil, errPemKeyWrongType
			}

			// good to go
			privateKey = pkcs8Key

		// case *ecdsa.PrivateKey:
		// 	// verify acceptable curve name
		// 	if pkcs8Key.Curve.Params().Name != "P-256" && pkcs8Key.Curve.Params().Name != "P-384" {
		// 		return nil, errPemKeyWrongType
		// 	}

		// 	// good to go
		// 	privateKey = pkcs8Key

		default:
			return nil, errPemKeyWrongType
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
