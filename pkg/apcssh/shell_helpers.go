package apcssh

import (
	"regexp"
)

// scanAPCShell is a SplitFunc to capture shell output after each interactive
// shell command is run
func scanAPCShell(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// regex for shell prompt (e.g., `apc@apc>`, `apc>`, `some@dev>`, `other123>`, etc.)
	re := regexp.MustCompile(`(\r\n|\r|\n)([A-Za-z0-9.]+@?)?[A-Za-z0-9.]+>`)

	// find match for prompt
	if index := re.FindStringIndex(string(data)); index != nil {
		// advance starts after the prompt; token is everything before the prompt
		return index[1], dropCR(data[0:index[0]]), nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), dropCR(data), nil
	}

	// Request more data.
	return 0, nil, nil
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}
