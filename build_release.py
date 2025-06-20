#!/usr/bin/env python3
import os.path
import shutil
import subprocess
import tarfile

# Configuration
# output path (relative to this script)
outRelativeDir = "_out"

# target strings must be in the format:
#   `GOOS_GOARCH`
# see: https://github.com/golang/go/blob/master/src/internal/syslist/syslist.go
# or unofficially: https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63
targets = [
   "windows_amd64",
   "linux_amd64",
   "linux_arm64",
   "darwin_amd64",
   "darwin_arm64",
   "freebsd_amd64",
   "freebsd_arm64",
]

###

# Script
# relative dir is root
scriptDir = dirname = os.path.dirname(__file__)
outBaseDir = os.path.join(scriptDir, outRelativeDir)
releaseDir = os.path.join(outBaseDir, "_release")

# recreate paths
if os.path.exists(outBaseDir):
  shutil.rmtree(outBaseDir)
os.makedirs(outBaseDir)
os.makedirs(releaseDir)

# get version number / tag
gitTag = subprocess.check_output(["git", "describe", "--tags", "--abbrev=0"]).decode('utf-8').strip()

# loop through and build all targets
for target in targets:
  # environment vars
  split = target.split("_")
  GOOS = split[0]
  GOARCH = split[1]
  os.environ["GOOS"] = GOOS
  os.environ["GOARCH"] = GOARCH
  os.environ["CGO_ENABLED"] = "0"

  # send build product to GOOS_GOARCH subfolders
  targetOutDir = os.path.join(outBaseDir, target)
  if not os.path.exists(targetOutDir):
    os.makedirs(targetOutDir)

  # special case for windows to add file extensions
  extension = ""
  if GOOS.lower() == "windows":
    extension = ".exe"

  # build binary and install only binary
  subprocess.run(["go", "build", "-o", f"{targetOutDir}/apc-p15-tool{extension}", "./cmd/tool"])
  subprocess.run(["go", "build", "-o", f"{targetOutDir}/apc-p15-install{extension}", "./cmd/install_only"])

  # copy other important files for release
  shutil.copy("README.md", targetOutDir)
  shutil.copy("CHANGELOG.md", targetOutDir)
  shutil.copy("LICENSE.md", targetOutDir)

  # compress release file
  # special case for windows & mac to use zip format
  if GOOS.lower() == "windows" or GOOS.lower() == "darwin":
    shutil.make_archive(f"{releaseDir}/apc-p15-tool-{gitTag}_{target}", "zip", targetOutDir)
  else:
    # for others, use gztar and set permissions on the files

    # filter for setting permissions
    def set_permissions(tarinfo):
      if tarinfo.name == "apc-p15-tool" or tarinfo.name == "apc-p15-install":
        tarinfo.mode = 0o0755
      else:
        tarinfo.mode = 0o0644
      return tarinfo

    # make tar
    with tarfile.open(f"{releaseDir}/apc-p15-tool-{gitTag}_{target}.tar.gz", "w:gz") as tar:
        for file in os.listdir(targetOutDir):
          tar.add(os.path.join(targetOutDir, file), arcname=file, recursive=False, filter=set_permissions)
