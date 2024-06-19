package apcssh

import (
	"io"
	"regexp"
)

// scanAPCShell is a SplitFunc to capture shell output after each interactive
// shell command is run
func scanAPCShell(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// EOF is not an expected response and should error (e.g., when the output pipe
	// gets closed by timeout)
	if atEOF {
		return len(data), dropCR(data), io.ErrUnexpectedEOF
	} else if len(data) == 0 {
		// no data to process, request more data
		return 0, nil, nil
	}

	// regex for shell prompt (e.g., `apc@apc>`, `apc>`, `some@dev>`, `other123>`, etc.)
	re := regexp.MustCompile(`(\r\n|\r|\n)([A-Za-z0-9.]+@?)?[A-Za-z0-9.]+>`)
	// find match for prompt
	if index := re.FindStringIndex(string(data)); index != nil {
		// advance starts after the prompt; token is everything before the prompt
		return index[1], dropCR(data[0:index[0]]), nil
	}

	// no match, request more data
	return 0, nil, nil
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}
