# APC P15 Tool
A tool to create APC p15 formatted certificates from pem files, without
having to use APC's closed-source tool, APC generated keys, or other 
proprietary tools (such as cryptlib).

## Usage

./apc-p15-tool --keyfile ./key.pem --certfile ./cert.pem

Command outputs ./apctool.p15 which can be directly loaded on to an 
APC NMC2 (Network Management Card 2).
