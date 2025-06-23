package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

const (
	apcKeyLabel = "Private key"
)

// toP15KeyCert creates a P15 file with both the private key and certificate, mirroring the
// final p15 file an APC UPS expects (though without the header)
func (p15 *pkcs15KeyCert) ToP15KeyCert() (keyCert []byte, err error) {
	// encrypted envelope is required
	err = p15.computeEncryptedKeyEnvelope()
	if err != nil {
		return nil, err
	}

	// create private key object
	var privKeyObj []byte

	switch p15.key.(type) {
	case *rsa.PrivateKey:
		// private key object
		privKeyObj =
			asn1obj.Sequence([][]byte{
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
					asn1obj.GeneralizedTime(p15.Cert.NotBefore),
					// CommonKeyAttributes - [0] endDate
					asn1obj.GeneralizedTimeExplicitValue(0, p15.Cert.NotAfter),
				}),
				// ObjectValue - indirect-protected
				asn1obj.ExplicitCompound(1, [][]byte{
					asn1obj.Sequence([][]byte{
						// AuthEnvelopedData Type ([4])
						asn1obj.ExplicitCompound(4, [][]byte{
							p15.envelopedPrivateKey,
						}),
					}),
				}),
			})

	case *ecdsa.PrivateKey:
		privKeyObj =
			asn1obj.ExplicitCompound(0, [][]byte{
				// commonObjectAttributes - Label
				asn1obj.Sequence([][]byte{
					asn1obj.UTF8String(apcKeyLabel),
				}),
				// CommonKeyAttributes
				asn1obj.Sequence([][]byte{
					// CommonKeyAttributes - iD - uses keyId that is SHA1( SubjectPublicKeyInfo SEQUENCE )
					asn1obj.OctetString(p15.keyId()),
					// CommonKeyAttributes - usage (trailing 0s will drop)
					asn1obj.BitString([]byte{byte(0b00100010)}),
					// CommonKeyAttributes - accessFlags (trailing 0s will drop)
					asn1obj.BitString([]byte{byte(0b10110000)}),
					// CommonKeyAttributes - startDate
					asn1obj.GeneralizedTime(p15.Cert.NotBefore),
					// CommonKeyAttributes - [0] endDate
					asn1obj.GeneralizedTimeExplicitValue(0, p15.Cert.NotAfter),
				}),
				// ObjectValue - indirect-protected
				asn1obj.ExplicitCompound(1, [][]byte{
					asn1obj.Sequence([][]byte{
						// AuthEnvelopedData Type ([4])
						asn1obj.ExplicitCompound(4, [][]byte{
							p15.envelopedPrivateKey,
						}),
					}),
				}),
			})

	default:
		// bad key type
		return nil, errKeyWrongType
	}

	// cert object
	certObj := asn1obj.Sequence([][]byte{
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
				// 8 & 9 will return nil for EC keys (effectively omitting them)
				p15.keyIdInt8(),
				p15.keyIdInt9(),
			}),
			// CommonKeyAttributes - startDate
			asn1obj.GeneralizedTime(p15.Cert.NotBefore),
			// CommonKeyAttributes - [4] endDate
			asn1obj.GeneralizedTimeExplicitValue(4, p15.Cert.NotAfter),
		}),
		// actual certificate itself
		asn1obj.ExplicitCompound(1, [][]byte{
			asn1obj.Sequence([][]byte{
				asn1obj.ExplicitCompound(0, [][]byte{
					p15.Cert.Raw,
				}),
			}),
		}),
	})

	// build the object

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
							privKeyObj,
						}),
					}),
					asn1obj.ExplicitCompound(4, [][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							certObj,
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
func (p15 *pkcs15KeyCert) ToP15Key() (key []byte, err error) {
	// encrypted envelope is required
	err = p15.computeEncryptedKeyEnvelope()
	if err != nil {
		return nil, err
	}

	// create private and public key objects
	var pubKeyObj, privKeyObj []byte

	switch privKey := p15.key.(type) {
	case *rsa.PrivateKey:
		// private key object (slightly different than the key+cert format)
		privKeyObj =
			asn1obj.Sequence([][]byte{
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

				// Key IDs
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
							p15.envelopedPrivateKey,
						}),
					}),
				}),
			})

		// pub key stub
		pubKeyObj =
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

				asn1obj.ExplicitCompound(1, [][]byte{
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
				}),
			})

	case *ecdsa.PrivateKey:
		// private key object (slightly different than the key+cert format)
		privKeyObj =
			asn1obj.ExplicitCompound(0, [][]byte{
				// commonObjectAttributes - Label
				asn1obj.Sequence([][]byte{
					asn1obj.UTF8String(apcKeyLabel),
				}),
				// CommonKeyAttributes
				asn1obj.Sequence([][]byte{
					// CommonKeyAttributes - iD - uses keyId that is SHA1( SubjectPublicKeyInfo SEQUENCE )
					asn1obj.OctetString(p15.keyId()),
					// CommonKeyAttributes - usage (trailing 0s will drop)
					asn1obj.BitString([]byte{byte(0b00100010)}),
					// CommonKeyAttributes - accessFlags (trailing 0s will drop)
					asn1obj.BitString([]byte{byte(0b10110000)}),
				}),

				// Key IDs
				asn1obj.ExplicitCompound(0, [][]byte{
					asn1obj.Sequence([][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							p15.keyIdInt2(),
						}),
					}),
				}),

				// ObjectValue - indirect-protected
				asn1obj.ExplicitCompound(1, [][]byte{
					asn1obj.Sequence([][]byte{
						// AuthEnvelopedData Type ([4])
						asn1obj.ExplicitCompound(4, [][]byte{
							p15.envelopedPrivateKey,
						}),
					}),
				}),
			})

		// convert ec pub key to a form that provides a public key bytes function
		ecdhKey, err := privKey.PublicKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to parse ec public key (%s)", err)
		}

		// select correct OID for curve
		var curveOID asn1.ObjectIdentifier
		switch privKey.Curve.Params().Name {
		case "P-256":
			curveOID = asn1obj.OIDprime256v1
		case "P-384":
			curveOID = asn1obj.OIDsecp384r1
		case "P-521":
			curveOID = asn1obj.OIDsecp521r1
		default:
			// bad curve name
			return nil, errKeyWrongType
		}

		// pub key stub
		pubKeyObj =
			asn1obj.ExplicitCompound(0, [][]byte{
				// commonObjectAttributes - Label
				asn1obj.Sequence([][]byte{
					asn1obj.UTF8String(apcKeyLabel),
				}),
				// CommonKeyAttributes
				asn1obj.Sequence([][]byte{
					asn1obj.OctetString(p15.keyId()),
					asn1obj.BitString([]byte{byte(0b00000010)}),
					asn1obj.BitString([]byte{byte(0b01000000)}),
				}),

				asn1obj.ExplicitCompound(1, [][]byte{
					asn1obj.Sequence([][]byte{
						asn1obj.ExplicitCompound(0, [][]byte{
							asn1obj.Sequence([][]byte{
								asn1obj.Sequence([][]byte{
									asn1obj.ObjectIdentifier(asn1obj.OIDecPublicKey),
									asn1obj.ObjectIdentifier(curveOID),
								}),
								asn1obj.BitString(ecdhKey.Bytes()),
							}),
						}),
					}),
				}),
			})

	default:
		// bad key type
		return nil, errKeyWrongType
	}

	// assemble complete object
	key =
		asn1obj.Sequence([][]byte{
			// contentType: OID: 1.2.840.113549.1.15.3.1 pkcs15content (PKCS #15 content type)
			asn1obj.ObjectIdentifier(asn1obj.OIDPkscs15Content),
			// content
			asn1obj.ExplicitCompound(0, [][]byte{
				asn1obj.Sequence([][]byte{
					asn1obj.Integer(big.NewInt(0)),
					asn1obj.Sequence([][]byte{
						// [0] Private Keys
						asn1obj.ExplicitCompound(0, [][]byte{
							asn1obj.ExplicitCompound(0, [][]byte{
								privKeyObj,
							}),
						}),
						// [1] Public Keys
						asn1obj.ExplicitCompound(1, [][]byte{
							asn1obj.ExplicitCompound(0, [][]byte{
								pubKeyObj,
							}),
						}),
					}),
				}),
			}),
		})

	return key, nil
}
