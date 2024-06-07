package apcssh

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"golang.org/x/crypto/ssh"
)

// UploadSCP uploads a file to the destination specified (e.g., "/ssl/file.key")
// containing the file content specified. An existing file at the destination
// will be overwritten without warning.
func (cli *Client) UploadSCP(destination string, fileContent []byte, filePermissions fs.FileMode) error {
	// connect
	sshClient, err := ssh.Dial("tcp", cli.hostname, cli.sshCfg)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to dial session (%w)", err)
	}
	defer sshClient.Close()

	// make session to use for SCP
	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to create session (%w)", err)
	}
	defer session.Close()

	// attach pipes
	out, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	w, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer w.Close()

	// send execute cmd --
	// build cmd to send as request
	// Go implementation sends additional 0x22 bytes when using Run() (as
	// compared to putty's scp tool). these additional bytes seem to cause the
	// apc ups to fail execution of the command
	payload := []byte(fmt.Sprintf("scp -q -t %s", destination))
	payloadLen := uint8(len(payload))
	payload = append([]byte{0, 0, 0, payloadLen}, payload...)

	ok, err := session.SendRequest("exec", true, payload)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to execute scp cmd (%w)", err)
	}
	if !ok {
		return errors.New("apcssh: scp: execute scp cmd not ok")
	}

	// check remote response
	// Note: File upload may not work if the client doesn't actually read from
	// the remote output.
	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send scp cmd (bad remote response 1) (%w)", err)
	}

	// just file name (without path)
	filename := path.Base(destination)

	// send file header
	_, err = fmt.Fprintln(w, "C"+fmt.Sprintf("%04o", filePermissions.Perm()), len(fileContent), filename)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send file info (%w)", err)
	}

	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send file info (bad remote response 2) (%w)", err)
	}

	// send actual file
	_, err = io.Copy(w, bytes.NewReader(fileContent))
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send file(%w)", err)
	}

	// send file end
	_, err = fmt.Fprint(w, "\x00")
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send final 00 byte (%w)", err)
	}

	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("apcssh: scp: failed to send file (bad remote response 3) (%w)", err)
	}

	// done
	return nil
}

// scpCheckResponse reads the output from the remote and returns an error
// if the remote output was not 0
func scpCheckResponse(remoteOutPipe io.Reader) error {
	buffer := make([]uint8, 1)
	_, err := remoteOutPipe.Read(buffer)
	if err != nil {
		return fmt.Errorf("apcssh: failed to read output buffer (%w)", err)
	}

	responseType := buffer[0]
	message := ""
	if responseType > 0 {
		bufferedReader := bufio.NewReader(remoteOutPipe)
		message, err = bufferedReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("apcssh: failed to read output buffer (%w)", err)
		}
	}

	// if not 0 (aka OK)
	if responseType != 0 {
		return fmt.Errorf("apcssh: remote returned error (%d: %s)", responseType, message)
	}

	return nil
}
