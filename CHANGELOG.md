# APC P15 Tool Changelog

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
