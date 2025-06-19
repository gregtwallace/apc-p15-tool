# base build path, relative to script
$outRelativeDir = "\_out"

###

# Script dir is root
$scriptDir = Get-Location
$outBaseDir = Join-Path -Path $scriptDir -ChildPath $outRelativeDir
$outReleaseDir = Join-Path -Path $outBaseDir -ChildPath "\_release"

# ensure release path exists
New-Item -ItemType Directory -Force -Path $outReleaseDir | Out-Null

# get version number (tag)
$gitTag = $(git describe --tags --abbrev=0)

# GOOS_GOARCH to build for
$targets = @(
  "windows_amd64",
  "linux_amd64",
  "linux_arm64",
  "darwin_amd64",
  "darwin_arm64"
)

# loop through and build all targets
foreach ($target in $targets) {
  # environment vars
  $split = $target.split("_")
  $env:GOOS = $split[0]
  $env:GOARCH = $split[1]
  $env:CGO_ENABLED = 0

  # send build product to GOOS_GOARCH subfolders
  $targetOutDir = Join-Path -Path $outBaseDir -ChildPath "$($env:GOOS)_$($env:GOARCH)"

  # special case to add file extensions
  $extension = ""
  if ($env:GOOS -eq "windows") {
    $extension = ".exe"
  }

  # build binary and install only binary
  go build -o "$($targetOutDir)\apc-p15-tool$($extension)" .\cmd\tool
  go build -o "$($targetOutDir)\apc-p15-install$($extension)" .\cmd\install_only

  # copy other important files for release
  Copy-Item .\README.md $targetOutDir
  Copy-Item .\CHANGELOG.md $targetOutDir
  Copy-Item .\LICENSE.md $targetOutDir

  # zip and drop into release folder
  Compress-Archive -Path "$($targetOutDir)\*" -CompressionLevel Optimal -DestinationPath "$($outReleaseDir)\apc-p15-tool-$($gitTag)_$($target).zip" -Force
}
