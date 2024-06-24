package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
)

const (
	apcKeyLabel = "Private key"
)

// toP15KeyCert creates a P15 file with both the private key and certificate, mirroring the
// final p15 file an APC UPS expects (though without the header)
func (p15 *pkcs15KeyCert) toP15KeyCert(keyEnvelope []byte) (keyCert []byte, err error) {
	// private key object
	privateKey := asn1obj.Sequence([][]byte{
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
					keyEnvelope,
				}),
			}),
		}),
	})

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
				p15.keyIdInt3(),
				p15.keyIdInt6(),
				p15.keyIdInt7(),
				p15.keyIdInt8(),
				p15.keyIdInt9(),
			}),
			// CommonKeyAttributes - startDate
			asn1obj.GeneralizedTime(p15.cert.NotBefore),
			// CommonKeyAttributes - [4] endDate
			asn1obj.GeneralizedTimeExplicitValue(4, p15.cert.NotAfter),
		}),
		// actual certificate itself
		asn1obj.ExplicitCompound(1, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.ExplicitCompound(0, [][]byte{
					p15.cert.Raw,
				}),
			}),
		}),
	})

	// build the file

	// ContentInfo
	keyCert = asn1obj.Sequence([][]byte{

		// contentType: OID: 1.2.840.113549.1.15.3.1 pkcs15content (PKCS #15 content type)
		asn1obj.ObjectIdentifier(asn1obj.OIDPkscs15Content),

		// content
		asn1obj.ExplicitCompound(0, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(big.NewInt(0)),
				asn1obj.Sequence([][]byte{
					asn1obj.ExplicitCompound(0, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							privateKey,
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

	return keyCert, nil
}

// toP15Key creates a P15 file with just the private key, mirroring the p15 format
// the APC tool uses when generating a new private key (Note: no header is used on
// this file)
func (p15 *pkcs15KeyCert) toP15Key(keyEnvelope []byte) (key []byte, err error) {
	// create public key object
	var pubKeyObj []byte

	switch privKey := p15.key.(type) {
	case *rsa.PrivateKey:
		pubKeyObj = asn1obj.ExplicitCompound(1, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.ExplicitCompound(0, [][]byte{
					asn1obj.ExplicitCompound(1, [][]byte{
						asn1obj.Sequence([][]byte{
							asn1obj.ObjectIdentifier(asn1obj.OIDrsaEncryptionPKCS1),
							asn1.NullBytes,
						}),
						// RSAPublicKey SubjectPublicKeyInfo
						asn1obj.BitString(
							asn1obj.Sequence([][]byte{
								asn1obj.Integer(privKey.PublicKey.N),
								asn1obj.Integer(big.NewInt(int64(privKey.PublicKey.E))),
							}),
						),
					}),
				}),
				// not 100% certain but appears to be rsa key byte len
				asn1obj.Integer(big.NewInt(int64(privKey.PublicKey.N.BitLen() / 8))),
			}),
		})

	default:
		// panic if non-RSA key
		panic("p15 key file for non-rsa key is unexpected and unsupported")
	}

	// private key object (slightly different than the key+cert format)
	privateKey := asn1obj.Sequence([][]byte{
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

		//
		asn1obj.ExplicitCompound(0, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.ExplicitCompound(0, [][]byte{
					p15.keyIdInt2(),
					p15.keyIdInt8(),
					p15.keyIdInt9(),
				}),
			}),
		}),

		// ObjectValue - indirect-protected
		asn1obj.ExplicitCompound(1, [][]byte{
			asn1obj.Sequence([][]byte{
				// AuthEnvelopedData Type ([4])
				asn1obj.ExplicitCompound(4, [][]byte{
					keyEnvelope,
				}),
			}),
		}),
	})

	// ContentInfo
	key = asn1obj.Sequence([][]byte{

		// contentType: OID: 1.2.840.113549.1.15.3.1 pkcs15content (PKCS #15 content type)
		asn1obj.ObjectIdentifier(asn1obj.OIDPkscs15Content),

		// content
		asn1obj.ExplicitCompound(0, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(big.NewInt(0)),
				asn1obj.Sequence([][]byte{
					// [0] Private Key
					asn1obj.ExplicitCompound(0, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							privateKey,
						}),
					}),
					// [1] Public Key
					asn1obj.ExplicitCompound(1, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							asn1obj.Sequence([][]byte{
								// commonObjectAttributes - Label
								asn1obj.Sequence([][]byte{
									asn1obj.UTF8String(apcKeyLabel),
								}),
								// CommonKeyAttributes
								asn1obj.Sequence([][]byte{
									asn1obj.OctetString(p15.keyId()),
									asn1obj.BitString([]byte{byte(0b10000010)}),
									asn1obj.BitString([]byte{byte(0b01000000)}),
								}),

								pubKeyObj,
							}),
						}),
					}),
				}),
			}),
		}),
	})

	return key, nil
}

// ToP15File turns the key and cert into a properly formatted and encoded
// p15 file
func (p15 *pkcs15KeyCert) ToP15Files() (keyCertFile []byte, keyFile []byte, err error) {
	// rsa encrypted key in encrypted envelope (will be shared by both output files)
	envelope, err := p15.encryptedKeyEnvelope()
	if err != nil {
		return nil, nil, err
	}

	// key + cert file
	keyCertFile, err = p15.toP15KeyCert(envelope)
	if err != nil {
		return nil, nil, err
	}

	// key only file
	keyFile, err = p15.toP15Key(envelope)
	if err != nil {
		return nil, nil, err
	}

	return keyCertFile, keyFile, nil
}
