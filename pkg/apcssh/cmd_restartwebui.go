package apcssh

import (
	"fmt"
	"strings"
)

// RestartWebUI sends the APC command to restart the web ui
// WARNING: Sending a command directly after this one will cause issues.
// This command will cause SSH to also restart after a slight delay, therefore
// any command right after this will start to run but then get stuck / fail
// somewhere in the middle.
func (cli *Client) RestartWebUI() error {
	result, err := cli.cmd("reboot -Y")
	if err != nil {
		return err
	}

	if strings.ToLower(result.code) != "e000" {
		return fmt.Errorf("apcssh: failed to restart web ui (%s: %s)", result.code, result.codeText)
	}

	return nil
}
