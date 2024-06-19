# APC P15 Tool
A tool to create APC p15 formatted certificates from pem files, without
having to use APC's closed-source tool, APC generated keys, or other 
proprietary tools (such as cryptlib).

## Compatibility Notice

This tool's create functionality is modeled from the APC NMCSecurityWizardCLI 
aka `NMC Security Wizard CLI Utility`. The files it generates should be 
comaptible with any UPS that accepts p15 files from that tool. Only RSA 1,024
and 2,048 bit keys are accepted. 1,024 bit RSA is no longer considered 
completely secure; avoid keys of this size if possible. Most (all?) public 
ACME services won't accept keys of this size anyway.

The install functionality is a custom creation of mine so it may or may not 
work depending on your exact setup. My setup (and therefore the testing 
setup) is:
- APC Smart-UPS 1500VA RM 2U SUA1500RM2U (Firmware Revision 667.18.D)
- AP9631 NMC2 Hardware Revision 05 running AOS v7.0.4 and Boot Monitor 
  v1.0.9.

If you have problems you can post the log in an issue and I can try to fix it
but it may be difficult without your particular hardware to test with.

In particular, if you are experiencing `ssh: handshake failed:` first try
using the `--insecurecipher` flag. If this works, you should upgrade your
NMC to a newer firmware which includes secure ciphers. You should NOT automate
your environment using this flag as SSH over these ciphers is broken and
exploitable. If this also does not work, please run `ssh -vv myups.example.com`
and include the `peer server KEXINIT proposal` in your issue. For example:

```
debug2: peer server KEXINIT proposal
debug2: KEX algorithms: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,ecdh-sha2-nistp256
debug2: host key algorithms: ssh-rsa
debug2: ciphers ctos: aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc
debug2: ciphers stoc: aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc
debug2: MACs ctos: hmac-sha2-256,hmac-sha1
debug2: MACs stoc: hmac-sha2-256,hmac-sha1
debug2: compression ctos: none
debug2: compression stoc: none
debug2: languages ctos:
debug2: languages stoc:
```

## Usage

Currently the tool contains two commands: create and install. The tool 
can be run with the --help flag to see options.

i.e. `./apc-p15-tool --help`

Help can also be run on a subcommand to see the options for that 
subcommand.

e.g. `./apc-p15-tool install --help`

### Create

Create creates an apc p15 file from given key and cert pem files or 
content.

e.g. `./apc-p15-tool create --keyfile ./apckey.pem --certfile ./apccert.pem`

The command outputs ./apctool.p15 by default. This file can be 
directly loaded on to an APC NMC2 (Network Management Card 2).

### Install

Install works similarly to create except it doesn't save the p15 file 
to disk. It instead uploads the p15 file directly to the specified 
remote host, via scp.

e.g. `./apc-p15-tool install --keyfile ./apckey.pem --certfile ./apccert.pem --apchost myapc.example.com:22 --username apc --password someSecret --fingerprint 123abc`

## Note About Install Automation

The application supports passing all args instead as environment 
variables by prefixing the flag name with `APC_P15_TOOL`. 

e.g. `APC_P15_TOOL_KEYPEM`

Additionally, there is a second binary built with just the install
command so the subcommand is not needed.

There are mutually exclusive flags that allow specifying the pem 
as either filenames or directly as strings. The strings are useful 
for passing the pem content from another application without having 
to save the pem files to disk.

Putting all of this together, you can combine the install binary with 
a tool like Cert Warden (https://www.certwarden.com/) to call the 
install binary, with environment variables, to directly upload new 
certificates as they're issued by Cert Warden, without having to write a 
separate script.

![Cert Warden with APC P15 Tool](https://raw.githubusercontent.com/gregtwallace/apc-p15-tool/main/img/apc-p15-tool.png)

## Thanks

Special thanks to the following people and resources which helped me 
deduce how all of this works:

https://github.com/dnlmengs/pemtrans

https://github.com/freddy36/apc_tools

http://lapo.it/asn1js/
