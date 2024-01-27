package asn1obj

import (
	"encoding/asn1"
	"time"
)

// GeneralizedTime returns the specified time as a GeneralizedTime
func GeneralizedTime(t time.Time) []byte {
	// should never error
	asn1result, err := asn1.MarshalWithParams(t, "generalized")
	if err != nil {
		panic(err)
	}

	return asn1result
}

// helper funcs from golang asn1 package
func appendTwoDigits(dst []byte, v int) []byte {
	return append(dst, byte('0'+(v/10)%10), byte('0'+v%10))
}

func appendFourDigits(dst []byte, v int) []byte {
	var bytes [4]byte
	for i := range bytes {
		bytes[3-i] = '0' + byte(v%10)
		v /= 10
	}
	return append(dst, bytes[:]...)
}

// generalizedTimevalue returns the specified time encoded as a
// GeneralizedTime but WITHOUT the ASN.1 headers (class/tag/length)
func generalizedTimevalue(t time.Time) []byte {
	dst := []byte{}

	year := t.Year()
	if year < 0 || year > 9999 {
		panic("cannot represent time as GeneralizedTime (invalid year)")
	}

	dst = appendFourDigits(dst, year)

	_, month, day := t.Date()

	dst = appendTwoDigits(dst, int(month))
	dst = appendTwoDigits(dst, day)

	hour, min, sec := t.Clock()

	dst = appendTwoDigits(dst, hour)
	dst = appendTwoDigits(dst, min)
	dst = appendTwoDigits(dst, sec)

	_, offset := t.Zone()

	switch {
	case offset/60 == 0:
		return append(dst, 'Z')
	case offset > 0:
		dst = append(dst, '+')
	case offset < 0:
		dst = append(dst, '-')
	}

	offsetMinutes := offset / 60
	if offsetMinutes < 0 {
		offsetMinutes = -offsetMinutes
	}

	dst = appendTwoDigits(dst, offsetMinutes/60)
	dst = appendTwoDigits(dst, offsetMinutes%60)

	return dst
}

// helper funcs from golang asn1 package - END

// GeneralizedTimeExplicitValue returns t encoded as a GeneralizedTime, however
// instead of tagging it with GeneralizedTime it is instead tagged with an
// explicit tag of the specified tag number
func GeneralizedTimeExplicitValue(explicitTagNumber int, t time.Time) []byte {
	return ExplicitValue(explicitTagNumber, generalizedTimevalue(t))
}
