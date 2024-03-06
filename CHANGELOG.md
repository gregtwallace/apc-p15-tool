# APC P15 Tool Changelog

## [v0.4.1] - 2024.03.06

Update to Go 1.22.1, which includes some security fixes.


## [v0.4.0] - 2024.02.05

Add `--restartwebui` flag to issue a reboot command to the webui
after a new certificate is installed. This was not needed with 
my NMC2, but I suspect some might need it to get the new certificate
to actually load.


## [v0.3.3] - 2024.02.04

Add `--insecurecipher` flag to enable aes128-cbc and 3des-cbc for
older devices/firmwares. These ciphers are considered insecure and
should be avoided. A better alternative is to update the device 
firmware if possible.


## [v0.3.2] - 2024.02.04

Add support for 1,024 bit RSA keys. These are not recommended! RSA
1024 is generally considered to not be completely secure anymore.

Add `diffie-hellman-group-exchange-sha256` key exchange algorithm
which may be needed by some UPSes to connect via SSH to use the 
install command.


## [v0.3.1] - 2024.02.03

Fixes debug logging always being on. App now accurately reflects
the state of the --debug flag.


## [v0.3.0] - 2024.02.03

Initial release.
