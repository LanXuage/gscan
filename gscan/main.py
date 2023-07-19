import os
import sys
import stat
import platform
import subprocess


def main():
    b, _ = platform.architecture()
    if "aarch64" in platform.platform():
        arch = "arm64"
    else:
        if "64" in b:
            arch = "amd64"
        else:
            arch = "386"
    pkgpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
    filename = "gscan-" + platform.system().lower() + "-" + arch
    if platform.system().lower() == "windows":
        filename += ".exe"
    filepath = os.path.join(pkgpath, filename)
    if not os.path.isfile(filepath):
        raise Exception("gscan bin file not found. Pls check install. ")
    if not os.access(filepath, os.X_OK | os.R_OK):
        os.chmod(filepath, stat.S_IROTH | stat.S_IXOTH | stat.S_IRGRP | stat.S_IXGRP | stat.S_IRWXU)
    cmd = [filepath]
    cmd.extend(sys.argv[1:])
    return subprocess.call(cmd, shell=False)


if __name__ == "__main__":
    sys.exit(main())
