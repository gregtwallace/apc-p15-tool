# Parent dir is root
$scriptDir = Get-Location
$outDir = Join-Path -Path $scriptDir -ChildPath "/_out"

# Windows x64
$env:GOARCH = "amd64"
$env:GOOS = "windows"
go build -o $outDir/apc-p15-tool-amd64.exe ./cmd/tool

# Linux x64
$env:GOARCH = "amd64"
$env:GOOS = "linux"
go build -o $outDir/apc-p15-tool-amd64 ./cmd/tool

# Linux x64 install only
$env:GOARCH = "amd64"
$env:GOOS = "linux"
go build -o $outDir/apc-p15-install-amd64 ./cmd/install_only
