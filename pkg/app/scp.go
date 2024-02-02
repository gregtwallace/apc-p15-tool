package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"golang.org/x/crypto/ssh"
)

// APC UPS won't except Go's SSH "Run()" command as the format isn't quite
// the same. Therefore, write a custom implementation to send the desired
// command instead of relying on something like github.com/bramvdbogaerde/go-scp

const (
	scpP15Destination    = "/ssl/defaultcert.p15"
	scpP15PermissionsStr = "0600"

	scpTimeout = 90 * time.Second
)

// scpSendFileToUPS sends the p15File to the APC UPS via the SCP protocol. it is
// automatically placed in the correct directory and will overwrite any existing
// file
func scpSendFileToUPS(client *ssh.Client, p15File []byte) error {
	// make session to use for SCP
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("scp: failed to create session (%w)", err)
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
	payload := []byte(fmt.Sprintf("scp -v -t %s", scpP15Destination))
	payloadLen := uint8(len(payload))
	payload = append([]byte{0, 0, 0, payloadLen}, payload...)

	ok, err := session.SendRequest("exec", true, payload)
	if err != nil {
		return fmt.Errorf("scp: failed to execute scp cmd (%w)", err)
	}
	if !ok {
		return errors.New("scp: execute scp cmd not ok")
	}

	// check remote response
	// Note: File upload may not work if the client doesn't actually read from
	// the remote output.
	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("scp: failed to send scp cmd (bad remote response) (%w)", err)
	}

	// just file name (without path)
	filename := path.Base(scpP15Destination)

	// send file header
	_, err = fmt.Fprintln(w, "C"+scpP15PermissionsStr, len(p15File), filename)
	if err != nil {
		return fmt.Errorf("scp: failed to send file info (%w)", err)
	}

	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("scp: failed to send file info (bad remote response) (%w)", err)
	}

	// send actual file
	_, err = io.Copy(w, bytes.NewReader(p15File))
	if err != nil {
		return fmt.Errorf("scp: failed to send file(%w)", err)
	}

	// send file end
	_, err = fmt.Fprint(w, "\x00")
	if err != nil {
		return fmt.Errorf("scp: failed to send final 00 byte (%w)", err)
	}

	err = scpCheckResponse(out)
	if err != nil {
		return fmt.Errorf("scp: failed to send file (bad remote response) (%w)", err)
	}

	// done
	return nil
}
