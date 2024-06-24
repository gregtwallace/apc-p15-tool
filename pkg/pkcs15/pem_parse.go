package pkcs15

import (
	"crypto"
	"crypto/x509"
)

// pkcs15KeyCert holds the data for a key and certificate pair; it provides
// various methods to transform pkcs15 data
type pkcs15KeyCert struct {
	key  crypto.PrivateKey
	cert *x509.Certificate
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

	p15 := &pkcs15KeyCert{
		key:  key,
		cert: cert,
	}

	return p15, nil
}
