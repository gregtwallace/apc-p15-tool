package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"math/big"
)

const (
	apcKeyLabel = "Private key"
)

// ToP15File turns the key and cert into a properly formatted and encoded
// p15 file
func (p15 *pkcs15KeyCert) ToP15File() ([]byte, error) {
	// private key object
	pkey, err := p15.toP15PrivateKey()
	if err != nil {
		return nil, err
	}

	// ContentInfo
	p15File := asn1obj.Sequence([][]byte{

		// contentType: OID: 1.2.840.113549.1.15.3.1 pkcs15content (PKCS #15 content type)
		asn1obj.ObjectIdentifier(asn1obj.OIDPkscs15Content),

		// content
		asn1obj.Explicit(0,
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(big.NewInt(0)),
				asn1obj.Sequence([][]byte{
					asn1obj.Explicit(0,
						asn1obj.Explicit(0,
							pkey,
						),
					),
				}),
			}),
		),
	})

	return p15File, nil
}

// toP15PrivateKey creates the encoded private key. it is broken our from the larger p15
// function for readability
func (p15 *pkcs15KeyCert) toP15PrivateKey() ([]byte, error) {
	// key object
	key := asn1obj.Sequence([][]byte{
		// commonObjectAttributes - Label
		asn1obj.Sequence([][]byte{
			asn1obj.UTF8String(apcKeyLabel),
		}),
		// CommonKeyAttributes
		asn1obj.Sequence([][]byte{
			// CommonKeyAttributes - iD - uses keyId that is SHA1( SubjectPublicKeyInfo SEQUENCE )
			asn1obj.OctetString(p15.keyId()),
			// CommonKeyAttributes - usage (trailing 0s will drop)
			asn1obj.BitString([]byte{byte(0b11100010)}),
			// CommonKeyAttributes - accessFlags (trailing 0s will drop)
			asn1obj.BitString([]byte{byte(0b10110000)}),
		}),
	})

	return key, nil
}
