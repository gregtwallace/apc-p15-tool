package pkcs15

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
)

// pkcs15KeyCert holds the data for a key and certificate pair; it provides
// various methods to transform pkcs15 data
type pkcs15KeyCert struct {
	key  crypto.PrivateKey
	cert *x509.Certificate
	// store the encrypted enveloped Private Key for re-use
	envelopedPrivateKey []byte
}

// KeyType is used by consumers to check for compatibility
type KeyType int

const (
	KeyTypeRSA1024 KeyType = iota
	KeyTypeRSA2048
	KeyTypeRSA3072
	KeyTypeRSA4096

	KeyTypeECP256
	KeyTypeECP384
	KeyTypeECP521

	KeyTypeUnknown
)

// KeyType returns the private key type
func (p15 *pkcs15KeyCert) KeyType() KeyType {
	switch pKey := p15.key.(type) {
	case *rsa.PrivateKey:
		switch pKey.N.BitLen() {
		case 1024:
			return KeyTypeRSA1024
		case 2048:
			return KeyTypeRSA2048
		case 3072:
			return KeyTypeRSA3072
		case 4096:
			return KeyTypeRSA4096

		default:
		}

	case *ecdsa.PrivateKey:
		switch pKey.Curve.Params().Name {
		case "P-256":
			return KeyTypeECP256
		case "P-384":
			return KeyTypeECP384
		case "P-521":
			return KeyTypeECP521

		default:
		}

	default:
	}

	return KeyTypeUnknown
}

// ParsePEMToPKCS15 parses the provide pem files to a pkcs15 struct; it also does some
// basic sanity check; if any of this fails, an error is returned
func ParsePEMToPKCS15(keyPem, certPem []byte) (*pkcs15KeyCert, error) {
	// decode / check key
	key, err := pemKeyDecode(keyPem)
	if err != nil {
		return nil, err
	}

	// decode / check cert
	cert, err := pemCertDecode(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	// create p15 struct
	p15 := &pkcs15KeyCert{
		key:  key,
		cert: cert,
	}

	// pre-calculate encrypted envelope
	err = p15.computeEncryptedKeyEnvelope()
	if err != nil {
		return nil, err
	}

	return p15, nil
}
