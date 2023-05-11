import sys
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
    cmd = ["gscan-" + platform.system().lower() + "-" + arch]
    cmd.extend(sys.argv[1:])
    print(subprocess.call(cmd, shell=False))


if __name__ == '__main__':
    main()
