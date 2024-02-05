package app

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// sshResetUPSWebUI sends a command to the UPS to restart the WebUI. This
// command is supposed to be required to load the new cert, but that
// doesn't seem to be true (at least it isn't on my UPS). Adding the
// option though, in case other UPS might need it.
func sshResetUPSWebUI(client *ssh.Client) error {
	// make session to use for restart command
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh: restart: failed to create session (%w)", err)
	}
	defer session.Close()

	// start shell
	err = session.Shell()
	if err != nil {
		return fmt.Errorf("ssh: restart: failed to start shell (%w)", err)
	}

	// execure reboot via SendRequest
	payload := []byte("reboot -Y")
	payloadLen := uint8(len(payload))
	payload = append([]byte{0, 0, 0, payloadLen}, payload...)

	ok, err := session.SendRequest("exec", true, payload)
	if err != nil {
		return fmt.Errorf("ssh: scp: failed to execute scp cmd (%w)", err)
	}
	if !ok {
		return errors.New("ssh: scp: execute scp cmd not ok")
	}

	// don't read remote output, as nothing interesting actually outputs

	// done
	return nil
}
