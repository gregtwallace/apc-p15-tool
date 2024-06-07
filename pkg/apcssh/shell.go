package apcssh

import (
	"bufio"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// upsCmdResponse is a structure that holds all of a shell commands results
type upsCmdResponse struct {
	command    string
	code       string
	codeText   string
	resultText string
}

// cmd creates an interactive shell and executes the specified command
func (cli *Client) cmd(command string) (*upsCmdResponse, error) {
	// connect
	sshClient, err := ssh.Dial("tcp", cli.hostname, cli.sshCfg)
	if err != nil {
		return nil, fmt.Errorf("apcssh: failed to dial session (%w)", err)
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("apcssh: failed to create session (%w)", err)
	}
	defer session.Close()

	// pipes to send shell command to; and to receive repsonse
	sshInput, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("apcssh: failed to make shell input pipe (%w)", err)
	}
	sshOutput, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("apcssh: failed to make shell output pipe (%w)", err)
	}

	// make scanner to read shell continuously
	scanner := bufio.NewScanner(sshOutput)
	scanner.Split(scanAPCShell)

	// start interactive shell
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("apcssh: failed to start shell (%w)", err)
	}
	// discard the initial shell response (login message(s) / initial shell prompt)
	for {
		if token := scanner.Scan(); token {
			_ = scanner.Bytes()
			break
		}
	}

	// send command
	_, err = fmt.Fprint(sshInput, command+"\n")
	if err != nil {
		return nil, fmt.Errorf("apcssh: failed to send shell command (%w)", err)
	}

	res := &upsCmdResponse{}
	for {
		if tkn := scanner.Scan(); tkn {
			result := string(scanner.Bytes())

			cmdIndx := strings.Index(result, "\n")
			res.command = result[:cmdIndx-1]
			result = result[cmdIndx+1:]

			codeIndx := strings.Index(result, ": ")
			res.code = result[:codeIndx]
			result = result[codeIndx+2:]

			codeTxtIndx := strings.Index(result, "\n")
			res.codeText = result[:codeTxtIndx-1]

			res.resultText = result[codeTxtIndx+1 : len(result)-2]
			break
		}
	}

	return res, nil
}
