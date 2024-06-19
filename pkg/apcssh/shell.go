package apcssh

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Abort shell connection if UPS doesn't send a recognizable response within
// the specified timeouts; Cmd timeout is very long as it is unlikely to be
// needed but still exists to avoid an indefinite hang in the unlikely event
// something does go wrong at that part of the app
const (
	shellTimeoutLogin = 20 * time.Second
	shellTimeoutCmd   = 5 * time.Minute
)

// upsCmdResult is a structure that holds all of a shell commands results
type upsCmdResult struct {
	command    string
	code       string
	codeText   string
	resultText string
}

// cmd creates an interactive shell and executes the specified command
func (cli *Client) cmd(command string) (*upsCmdResult, error) {
	// connect
	sshClient, err := ssh.Dial("tcp", cli.hostname, cli.sshCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to dial client (%w)", err)
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session (%w)", err)
	}
	defer session.Close()

	// pipes to send shell command to; and to receive repsonse
	sshInput, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to make shell input pipe (%w)", err)
	}
	sshOutput, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to make shell output pipe (%w)", err)
	}

	// make scanner to read shell output continuously
	scanner := bufio.NewScanner(sshOutput)
	scanner.Split(scanAPCShell)

	// start interactive shell
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("failed to start shell (%w)", err)
	}

	// use a timer to close the session early in case Scan() hangs (which can
	// happen if the UPS provides output this app does not understand)
	cancelAbort := make(chan struct{})
	defer close(cancelAbort)
	go func() {
		select {
		case <-time.After(shellTimeoutLogin):
			_ = session.Close()

		case <-cancelAbort:
			// aborted cancel (i.e., succesful Scan())
		}
	}()

	// check shell response after connect
	scannedOk := scanner.Scan()
	// if failed to scan (e.g., timer closed the session after timeout)
	if !scannedOk {
		return nil, errors.New("shell did not return parsable login response")
	}
	// success; cancel abort timer
	cancelAbort <- struct{}{}
	// discard the initial shell response (login message(s) / initial shell prompt)
	_ = scanner.Bytes()

	// send command
	_, err = fmt.Fprint(sshInput, command+"\n")
	if err != nil {
		return nil, fmt.Errorf("failed to send shell command (%w)", err)
	}

	// use a timer to close the session early in case Scan() hangs (which can
	// happen if the UPS provides output this app does not understand);
	// since initial login message Scan() was okay, it is relatively unlikely this
	// will hang
	go func() {
		select {
		case <-time.After(shellTimeoutCmd):
			_ = session.Close()

		case <-cancelAbort:
			// aborted cancel (i.e., succesful Scan())
		}
	}()

	// check shell response to command
	scannedOk = scanner.Scan()
	// if failed to scan (e.g., timer closed the session after timeout)
	if !scannedOk {
		return nil, fmt.Errorf("shell did not return parsable response to cmd '%s'", command)
	}
	// success; cancel abort timer
	cancelAbort <- struct{}{}

	// parse the UPS response into result struct and return
	upsRawResponse := string(scanner.Bytes())
	result := &upsCmdResult{}

	cmdIndx := strings.Index(upsRawResponse, "\n")
	result.command = upsRawResponse[:cmdIndx-1]
	upsRawResponse = upsRawResponse[cmdIndx+1:]

	codeIndx := strings.Index(upsRawResponse, ": ")
	result.code = upsRawResponse[:codeIndx]
	upsRawResponse = upsRawResponse[codeIndx+2:]

	codeTxtIndx := strings.Index(upsRawResponse, "\n")
	result.codeText = upsRawResponse[:codeTxtIndx-1]

	// avoid out of bounds if no result text
	if codeTxtIndx+1 <= len(upsRawResponse)-2 {
		result.resultText = upsRawResponse[codeTxtIndx+1 : len(upsRawResponse)-2]
	}

	return result, nil
}
