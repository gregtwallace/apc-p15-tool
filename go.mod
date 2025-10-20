module apc-p15-tool

go 1.25.3

require (
	github.com/peterbourgon/ff/v4 v4.0.0-beta.1
	github.com/sigurn/crc16 v0.0.0-20240131213347-83fcde1e29d1
	golang.org/x/crypto v0.43.0
)

require golang.org/x/sys v0.37.0 // indirect

replace apc-p15-tool/cmd/install_only => /cmd/install_only

replace apc-p15-tool/cmd/tool => /cmd/tool

replace apc-p15-tool/pkg/apcssh => /pkg/apcssh

replace apc-p15-tool/pkg/app => /pkg/app

replace apc-p15-tool/pkg/pkcs15 => /pkg/pkcs15

replace apc-p15-tool/pkg/tools => /pkg/tools

replace apc-p15-tool/pkg/tools/asn1obj => /pkg/tools/asn1obj
