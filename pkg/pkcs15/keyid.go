package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/sha1"
	"encoding/asn1"
	"math/big"
)

// keyId returns the keyId for the overall key object
func (p15 *pkcs15KeyCert) keyId() []byte {
	// Create Object to hash
	hashObj := asn1obj.Sequence([][]byte{
		asn1obj.Sequence([][]byte{
			// Key is RSA
			asn1obj.ObjectIdentifier(asn1obj.OIDrsaEncryptionPKCS1),
			asn1.NullBytes,
		}),
		// BIT STRING of rsa key public key
		asn1obj.BitString(
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(p15.key.N),
				asn1obj.Integer((big.NewInt(int64(p15.key.E)))),
			}),
		),
	})

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(hashObj)
	if err != nil {
		panic(err)
	}

	return hasher.Sum(nil)
}

// keyIdInt2 returns the sequence for keyId with INT val of 2
// For APC, this appears to be the same value is the base keyId
// but this isn't compliant with the spec which actually seems
// to call for SKID (skid octet value copied directly out of the
// certificate's x509 extension)
func (p15 *pkcs15KeyCert) keyIdInt2() []byte {
	// Create Object
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(2)),
		// Note: This is for APC, doesn't seem compliant with spec though
		asn1obj.OctetString(p15.keyId()),
	})

	return obj
}
