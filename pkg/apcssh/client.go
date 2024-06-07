package apcssh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	apcSSHVer = 1

	sshTimeout = 90 * time.Second
)

// APC UPS won't except Go's SSH "Run()" command as the format isn't quite
// the same. Therefore, write a custom implementation instead of relying on
// something like github.com/bramvdbogaerde/go-scp

type Config struct {
	Hostname          string
	Username          string
	Password          string
	ServerFingerprint string
	InsecureCipher    bool
}

// Client is an APC UPS SSH client
type Client struct {
	hostname string
	sshCfg   *ssh.ClientConfig
}

// New creates a new SSH Client for the APC UPS.
func New(cfg *Config) (*Client, error) {
	// make host key callback
	hk := func(_hostname string, _remote net.Addr, key ssh.PublicKey) error {
		// calculate server's key's SHA256
		hasher := sha256.New()
		_, err := hasher.Write(key.Marshal())
		if err != nil {
			return err
		}
		actualHash := hasher.Sum(nil)

		// log fingerprint for debugging
		actualHashB64 := base64.RawStdEncoding.EncodeToString(actualHash)
		actualHashHex := hex.EncodeToString(actualHash)

		// check for fingerprint match (b64 or hex)
		if actualHashB64 != cfg.ServerFingerprint && actualHashHex != cfg.ServerFingerprint {
			log.Printf("apcssh: remote server key fingerprint (b64): %s", actualHashB64)
			log.Printf("apcssh: remote server key fingerprint (hex): %s", actualHashHex)

			return errors.New("apcssh: fingerprint didn't match")
		}

		return nil
	}

	// kex algos
	// see defaults: https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.18.0:ssh/common.go;l=62
	kexAlgos := []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
	}
	// extra for some apc ups
	kexAlgos = append(kexAlgos, "diffie-hellman-group-exchange-sha256")

	// ciphers
	// see defaults: https://cs.opensource.google/go/x/crypto/+/master:ssh/common.go;l=37
	ciphers := []string{
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
	}

	// insecure cipher options?
	if cfg.InsecureCipher {
		log.Println("WARNING: insecure ciphers are enabled (--insecurecipher). SSH with an insecure cipher is NOT secure and should NOT be used.")
		ciphers = append(ciphers, "aes128-cbc", "3des-cbc")
	}

	// install file on UPS
	// ssh config
	config := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.Password),
		},
		// APC seems to require `Client Version` string to start with "SSH-2" and must be at least
		// 13 characters long
		// working examples from other clients:
		// ClientVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		// ClientVersion: "SSH-2.0-PuTTY_Release_0.80",
		ClientVersion: fmt.Sprintf("SSH-2.0-apcssh_v%d %s-%s", apcSSHVer, runtime.GOOS, runtime.GOARCH),
		Config: ssh.Config{
			KeyExchanges: kexAlgos,
			Ciphers:      ciphers,
		},
		HostKeyCallback: hk,

		// reasonable timeout for file copy
		Timeout: sshTimeout,
	}

	// if hostname missing a port, add default
	if !strings.Contains(cfg.Hostname, ":") {
		cfg.Hostname = cfg.Hostname + ":22"
	}

	// connect to ups over SSH (to verify everything works)
	sshClient, err := ssh.Dial("tcp", cfg.Hostname, config)
	if err != nil {
		return nil, err
	}
	_ = sshClient.Close()

	// return Client (note: new ssh Dial will be done for each action as the UPS
	// seems to not do well with more than one Session per Dial)
	return &Client{
		hostname: cfg.Hostname,
		sshCfg:   config,
	}, nil
}
