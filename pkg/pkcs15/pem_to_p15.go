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

	cert, err := p15.toP15Cert()
	if err != nil {
		return nil, err
	}

	// ContentInfo
	p15File := asn1obj.Sequence([][]byte{

		// contentType: OID: 1.2.840.113549.1.15.3.1 pkcs15content (PKCS #15 content type)
		asn1obj.ObjectIdentifier(asn1obj.OIDPkscs15Content),

		// content
		asn1obj.ExplicitCompound(0, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(big.NewInt(0)),
				asn1obj.Sequence([][]byte{
					asn1obj.ExplicitCompound(0, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							pkey,
						}),
					}),
					asn1obj.ExplicitCompound(4, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							cert,
						}),
					}),
				}),
			}),
		}),
	})

	return p15File, nil
}

// toP15PrivateKey creates the encoded private key. it is broken our from the larger p15
// function for readability
// NOTE: Do not use this to try and turn just a private key into a p15, the format isn't
// quite the same.
func (p15 *pkcs15KeyCert) toP15PrivateKey() ([]byte, error) {
	// rsa encrypted key in encrypted envelope
	envelope, err := p15.encryptedKeyEnvelope()
	if err != nil {
		return nil, err
	}

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
			// CommonKeyAttributes - startDate
			asn1obj.GeneralizedTime(p15.cert.NotBefore),
			// CommonKeyAttributes - [0] endDate
			asn1obj.GeneralizedTimeExplicitValue(0, p15.cert.NotAfter),
		}),
		// ObjectValue - indirect-protected
		asn1obj.ExplicitCompound(1, [][]byte{
			asn1obj.Sequence([][]byte{
				// AuthEnvelopedData Type ([4])
				asn1obj.ExplicitCompound(4, [][]byte{
					envelope,
				}),
			}),
		}),
	})

	return key, nil
}

// toP15Cert creates the encoded certificate. it is broken our from the larger p15
// function for readability
// NOTE: Do not use this to try and turn just a cert into a p15. I don't believe,
// such a thing is permissible under the spec.
func (p15 *pkcs15KeyCert) toP15Cert() ([]byte, error) {

	// cert object
	cert := asn1obj.Sequence([][]byte{
		// commonObjectAttributes - Label
		asn1obj.Sequence([][]byte{
			asn1obj.UTF8String(apcKeyLabel),
		}),
		// keyIds of various types
		asn1obj.Sequence([][]byte{
			asn1obj.OctetString(p15.keyId()),
			// additional keyids
			asn1obj.ExplicitCompound(2, [][]byte{
				p15.keyIdInt2(),
				// p15.keyIdInt3(),
				// p15.keyIdInt6(),
				// p15.keyIdInt7(),
				// p15.keyIdInt8(),
				// p15.keyIdInt9(),
			}),
		}),
	})

	return cert, nil
}
