# Parent dir is root
$scriptDir = Get-Location
$outDir = Join-Path -Path $scriptDir -ChildPath "/_out"

# Windows x64
$env:GOARCH = "amd64"
$env:GOOS = "windows"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-tool-amd64.exe ./cmd/tool

$env:GOARCH = "amd64"
$env:GOOS = "windows"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-install-amd64.exe ./cmd/install_only

# Linux x64
$env:GOARCH = "amd64"
$env:GOOS = "linux"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-tool-amd64 ./cmd/tool

$env:GOARCH = "amd64"
$env:GOOS = "linux"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-install-amd64 ./cmd/install_only

# Linux arm64
$env:GOARCH = "arm64"
$env:GOOS = "linux"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-tool-arm64 ./cmd/tool

$env:GOARCH = "arm64"
$env:GOOS = "linux"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-install-arm64 ./cmd/install_only

# Darwin (MacOS) amd64
$env:GOARCH = "amd64"
$env:GOOS = "darwin"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-tool-darwin-amd64 ./cmd/tool

$env:GOARCH = "amd64"
$env:GOOS = "darwin"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-install-darwin-amd64 ./cmd/install_only

# Darwin (MacOS) arm64
$env:GOARCH = "arm64"
$env:GOOS = "darwin"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-tool-darwin-arm64 ./cmd/tool

$env:GOARCH = "arm64"
$env:GOOS = "darwin"
$env:CGO_ENABLED = 0
go build -o $outDir/apc-p15-install-darwin-arm64 ./cmd/install_only
