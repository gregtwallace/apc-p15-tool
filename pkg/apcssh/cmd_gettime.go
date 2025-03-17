package apcssh

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// GetTime sends the APC `system` command and then attempts to parse the
// response to determine the UPS current date/time.
func (cli *Client) GetTime() (time.Time, error) {
	result, err := cli.cmd("date")
	if err != nil {
		return time.Time{}, fmt.Errorf("apcssh: failed to get time (%s)", err)
	} else if !strings.EqualFold(result.code, "e000") {
		return time.Time{}, fmt.Errorf("apcssh: failed to get time (%s: %s)", result.code, result.codeText)
	}

	// capture each portion of the date information
	regex := regexp.MustCompile(`Date:\s*(\S*)\s*[\r\n]Time:\s*(\S*)\s*[\r\n]Format:\s*(\S*)\s*[\r\n]Time Zone:\s*(\S*)\s*[\r\n]?`)
	datePieces := regex.FindStringSubmatch(result.resultText)
	if len(datePieces) != 5 {
		return time.Time{}, fmt.Errorf("apcssh: failed to get time (length of datetime value pieces was %d (expected: 5))", len(datePieces))
	}
	dateVal := datePieces[1]
	timeVal := datePieces[2]
	formatUPSVal := datePieces[3]
	timeZoneVal := datePieces[4]

	// GMT time requires + prefix
	if timeZoneVal == "00:00" {
		timeZoneVal = "+" + timeZoneVal
	}

	// known APC UPS format strings
	dateFormatVal := ""
	switch formatUPSVal {
	case "mm/dd/yyyy":
		dateFormatVal = "01/02/2006"
	case "dd.mm.yyyy":
		dateFormatVal = "02.01.2006"
	case "mmm-dd-yy":
		dateFormatVal = "Jan-02-06"
	case "dd-mmm-yy":
		dateFormatVal = "02-Jan-06"
	case "yyyy-mm-dd":
		dateFormatVal = "2006-01-02"

	default:
		return time.Time{}, fmt.Errorf("apcssh: failed to get time (ups returned unknown format string (%s)", formatUPSVal)
	}

	// convert to time.Time
	t, err := time.Parse(dateFormatVal+" 15:04:05 -07:00", dateVal+" "+timeVal+" "+timeZoneVal)
	if err != nil {
		return time.Time{}, fmt.Errorf("apcssh: failed to get time (time parse failed: %s)", err)
	}

	return t, nil
}
