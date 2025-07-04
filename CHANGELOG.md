# APC P15 Tool Changelog

## [v1.3.0] - 2025-06-23

This release attempts to detect and warn of possible incompatibilies with a
spcecified certificate. NMCs do not warn or error when a bad file is installed,
instead they silently fail and generally just generate a new self-signed
certificate. This release checks some properties of the specified certificate
and produces warning messages that can be referenced if the cert installation
appears to work but ultimately doesn't prododuce the expected result.

- Add warnings based on key type, signature algorithm, validity dates, and
  extensions.
- Minor lint.


## [v1.2.3] - 2025-06-19

Minor updates to the application. Large updates to the build process to
improve building, releasing, and maintainability.

- Go updated to 1.24.4 and all dependencies updated.
- Added FreeBSD arm64 and amd64 builds.
- Build process overhauled for simplicity. Build is now OS agnostic. PowerShell
  script was removed and replaced with a python script.
- Build instructions added to README.
- GitHub build action now only runs in one Ubuntu container and cross-compiles.
- Release windows and macos as zip files and all others as gztar.
- Add file permissions for non-windows and non-macos releases.


## [v1.2.2] - 2025-04-22

All dependencies updated.

Add darwin arm64 and amd64 builds.


## [v1.2.1] - 2025-03-17

Fix time check for UPS when it is set to GMT timezone.

All dependencies updated.


## [v1.2.0] - 2025-01-27

Add a new feature to `install` that checks the time of the UPS to confirm
it is accurate. A log message is added that advises either way. Even if
the check fails, the install still proceeds with attempting to install
the new certificate.

Dependencies were also all updated.


## [v1.1.0] - 2024-09-17

> [!IMPORTANT]
> The flag `apchost` on the `install` command has been renamed to
> `hostname`. This flag should contain the hostname only. If a non-
> default SSH port is needed, specify it in the `sshport` flag.

This version brings support for for RSA 4,092 bit and EC keys. These 
keys are only compatible with NMC3 running newer firmwares. To know 
if your firmware is new enough, SSH into your UPS and type `ssh` and enter.
If the UPS responds `Command Not Found` the firmware is too old or
otherwise incompatible.

This version also adds a post `install` check that connects to the web
ui and verifies the certificate served is the expected one. You can
specify a non standard ssl port with the `sslport` flag or skip the check
entirely with the `skipverify` flag.


## [v1.0.0] - 2024-07-01

First official stable release.

Fixes Go version in Github action.


## [v0.5.3] - 2024-06-24

Add 3,072 bit RSA key support.


## [v0.5.2] - 2024-06-19

Minor tweak to the previous version. Add timeout for shell
commands that don't execute as expected.


## [v0.5.1] - 2024-06-18

Both NMC2 and NMC3 should now be fully supported.

### Added
- Add proper NMC3 support. 
- The `create` function now also generates a .p15 formatted key file.
  The format of this file matches that of what is generated by the NMC 
  Security Wizard.
- Add additional b64 formatted output files when using the `--debug`
  flag with `create`. These files can easily be pasted into an ASN1 
  decoder for inspection (except for the header file, as the header is
  not ASN1 encoded).

### Fixed
- Fix `install` function for NMC3 on newer firmware version by 
  leveraging the native `ssl` command to install the key and cert, if
  it is available. If not available, fallback to the 'old' way of
  installing the SSL cert.
- Fix PowerShell build script in repo. Posted builds were not impacted
  by this as the script is not used by the GitHub Action.

### Changed
- Move APC SSH functions to a separate package and change how commands
  are sent. In particular, leverage the interactive shell to send
  commands and read back the result of those commands.
- Set output file permissions to `0600` instead of `0777`.
- Minor logging updates.
- Leverage `strings.EqualFold` as a more robust alternative to using
  `strings.ToLower` for string comparisons.
- Update Go version to 1.22.4.
- Update readme to clarify tool's purpose, current state, and 
  compatibility.

### Removed
N/A


## [v0.4.2] - 2024-03-29

Fix usage message. Thanks @k725.


## [v0.4.1] - 2024-03-06

Update to Go 1.22.1, which includes some security fixes.


## [v0.4.0] - 2024-02-05

Add `--restartwebui` flag to issue a reboot command to the webui
after a new certificate is installed. This was not needed with
my NMC2, but I suspect some might need it to get the new certificate
to actually load.


## [v0.3.3] - 2024-02-04

Add `--insecurecipher` flag to enable aes128-cbc and 3des-cbc for
older devices/firmwares. These ciphers are considered insecure and
should be avoided. A better alternative is to update the device
firmware if possible.


## [v0.3.2] - 2024-02-04

Add support for 1,024 bit RSA keys. These are not recommended! RSA
1024 is generally considered to not be completely secure anymore.

Add `diffie-hellman-group-exchange-sha256` key exchange algorithm
which may be needed by some UPSes to connect via SSH to use the
install command.


## [v0.3.1] - 2024-02-03

Fixes debug logging always being on. App now accurately reflects
the state of the --debug flag.


## [v0.3.0] - 2024-02-03

Initial release.
