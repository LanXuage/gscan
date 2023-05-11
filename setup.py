from setuptools import setup


bin_files= []

windows = ["bin/gscan-windows-amd64.exe", "bin/gscan-windows-386.exe"]
linux = ["bin/gscan-linux-amd64", "bin/gscan-linux-386", "bin/gscan-linux-arm64"]
darwin = ["bin/gscan-darwin-amd64", "bin/gscan-darwin-arm64"]

bin_files.extend(windows)
bin_files.extend(linux)
bin_files.extend(darwin)

setup(
    data_files=[("bin/", bin_files)],
)
