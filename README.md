# APC P15 Tool
A tool to create APC p15 formatted certificates from pem files, without
having to use APC's closed-source tool, APC generated keys, or other 
proprietary tools (such as cryptlib).

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
a tool like LeGo CertHub (https://www.legocerthub.com/) to call the 
install binary, with environment variables, to directly upload new 
certificates as they're issued by LeGo, without having to write a 
separate script.

![LeGo CertHub with APC P15 Tool](https://raw.githubusercontent.com/gregtwallace/apc-p15-tool/main/img/apc-p15-tool.png)

## Thanks

Special thanks to the following people and resources which helped me 
deduce how all of this works:

https://github.com/dnlmengs/pemtrans

https://github.com/freddy36/apc_tools

http://lapo.it/asn1js/
