package app

import (
	"bufio"
	"fmt"
	"io"
)

// sshCheckResponse reads the output from the remote and returns an error
// if the remote output was not 0
func sshCheckResponse(remoteOutPipe io.Reader) error {
	buffer := make([]uint8, 1)
	_, err := remoteOutPipe.Read(buffer)
	if err != nil {
		return fmt.Errorf("ssh: failed to make read output buffer (%w)", err)
	}

	responseType := buffer[0]
	message := ""
	if responseType > 0 {
		bufferedReader := bufio.NewReader(remoteOutPipe)
		message, err = bufferedReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ssh: failed to read output buffer (%w)", err)
		}
	}

	// if not 0 (aka OK)
	if responseType != 0 {
		return fmt.Errorf("ssh: remote returned error (%d: %s)", responseType, message)
	}

	return nil
}
