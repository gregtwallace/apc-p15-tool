package tools

// BitwiseComplimentOf returns the bitwise compliment of data
func BitwiseComplimentOf(data []byte) []byte {
	compliment := []byte{}

	for i := range data {
		compliment = append(compliment, ^data[i])
	}

	return compliment
}

// IsBitwiseCompliment returns true if data1 and data2 are bitwise compliments,
// otherwise it returns false
func IsBitwiseCompliment(data1, data2 []byte) bool {
	// if not same length, definitely not compliments
	if len(data1) != len(data2) {
		return false
	}

	// check each byte
	for i := range data1 {
		// if any byte is NOT the bitwise compliment of the matching byte in other data
		// set, then the full set is not bitwise compliment and false
		if data1[i] != ^data2[i] {
			return false
		}
	}

	return true
}
