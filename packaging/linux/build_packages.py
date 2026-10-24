#!/usr/bin/env python3
"""Build OpenDisco's Linux packages, on a Mac or a Linux PC with Docker.

- A .deb for Ubuntu 24.04 LTS (and Mint 22, Pop!_OS 24.04) and an .rpm for Fedora 44, made by
  Briefcase inside a container of that release. Each bundles Toga and a PyGObject compiled for
  that release's Python, so each fits its own distro release.
- A portable .tar.gz for any distro: the command-line tool runs on any Python 3.8+, and the app
  sets up its own Python environment the first time it opens (see README-LINUX.md).

    .venv/bin/python packaging/linux/build_packages.py                  # all three, x86-64
    .venv/bin/python packaging/linux/build_packages.py --arch arm64     # ARM PCs, Raspberry Pi 5
    .venv/bin/python packaging/linux/build_packages.py --only tar.gz

The sources are copied into the container and the package copied out, rather than shared:
Docker on a Mac shares folders unreliably under a build's file churn. On a Mac, Docker can come
from colima (brew install colima docker docker-buildx); x86-64 builds then run emulated. Use
QEMU (colima start --vz-rosetta=false): under Rosetta, Ubuntu's Python 3.12 crashes while
installing. Emulated compilers occasionally crash under heavy parallel load, so each build gets
two CPUs; if one still fails with "internal compiler error", run it again.
"""
import argparse
import datetime
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
NEEDED = ("src", "pyproject.toml", "LICENSE")  # with CHANGELOG.md, all Briefcase reads
# format -> (container image, the release's name in the file name, how to install packages)
TARGETS = {
    "deb": ("ubuntu:24.04", "ubuntu-24.04",
            "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq "
            "python3-dev python3-venv git build-essential pkg-config dpkg-dev {requires} >/dev/null"),
    "rpm": ("fedora:44", "fedora-44",
            "dnf install -y -q python3-devel git gcc make rpm-build pkgconf-pkg-config {requires} >/dev/null"),
}
DISTRO_KEY = {"deb": "debian", "rpm": "rhel"}  # pyproject's [tool.briefcase.app.*.linux.system.<key>]
NAME = "OpenDisco"


def app_version() -> str:
    text = (ROOT / "src" / "opendisco" / "__init__.py").read_text()
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def rpm_changelog(markdown: str) -> str:
    """CHANGELOG.md in RPM's format (Briefcase copies it into the .spec as it is): an entry per
    version, "* <date> <who> - <version>-1", then its points as "- " lines."""
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["briefcase"]
    date = datetime.date.today().strftime("%a %b %d %Y")
    entries, points = [], None
    for line in markdown.splitlines():
        if line.startswith("## "):
            points = []
            entries.append((line[3:].strip(), points))
        elif points is not None and line.startswith("- "):
            points.append(line[2:].strip())
        elif points and line.startswith("  ") and line.strip():  # a point wrapped onto the next line
            points[-1] += " " + line.strip()
    return "\n".join(f"* {date} {meta['author']} <{meta['author_email']}> - {version}-1\n"
                     + "".join(f"- {point}\n" for point in points) for version, points in entries)


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def build_system_package(fmt: str, arch: str, out: Path, version: str) -> Path:
    """Run Briefcase natively inside a container of the target release."""
    image, label, install = TARGETS[fmt]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    distro = project["tool"]["briefcase"]["app"]["opendisco"]["linux"]["system"][DISTRO_KEY[fmt]]
    requires = distro["system_requires"] + distro["system_runtime_requires"]  # Briefcase checks both
    briefcase = subprocess.run([sys.executable, "-m", "pip", "show", "briefcase"], capture_output=True,
                               text=True).stdout
    briefcase = re.search(r"^Version: (\S+)", briefcase, re.M).group(1)  # the same Briefcase as here
    name = f"opendisco-build-{fmt}-{arch}"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    print(f"--- {image} ({arch}): Briefcase {briefcase}", flush=True)
    emulated = ["--cpuset-cpus", "0,1"] if sys.platform == "darwin" else []  # see the notes above
    docker("run", "-d", "--name", name, "--platform", f"linux/{arch}", *emulated,
           image, "sleep", "infinity", stdout=subprocess.DEVNULL)
    try:
        docker("exec", name, "mkdir", "-p", "/src")
        for item in NEEDED:
            docker("cp", str(ROOT / item), f"{name}:/src/{item}")
        changelog = (ROOT / "CHANGELOG.md").read_text()
        docker("exec", "-i", name, "sh", "-c", "cat > /src/CHANGELOG.md",
               input=(rpm_changelog(changelog) if fmt == "rpm" else changelog).encode())
        docker("exec", name, "sh", "-c", "find /src -name __pycache__ -prune -exec rm -rf {} + ; "
                                         "find /src -name .DS_Store -delete")
        docker("exec", name, "sh", "-c", install.format(requires=" ".join(requires)))
        docker("exec", name, "sh", "-c",
               f"python3 -m venv /briefcase && /briefcase/bin/pip install -q briefcase=={briefcase} && cd /src && "
               "for step in create build package; do "
               "/briefcase/bin/briefcase $step linux system $([ $step = package ] && echo --adhoc-sign) --no-input "
               "|| exit 1; done")
        made = docker("exec", name, "sh", "-c", f"ls /src/dist/*.{fmt}", capture_output=True,
                      text=True).stdout.split()
        dest = out / (f"{NAME}-{version}-{label}-{arch}.deb" if fmt == "deb"
                      else f"{NAME}-{version}-{label}-{'x86_64' if arch == 'amd64' else 'aarch64'}.rpm")
        docker("cp", f"{name}:{made[-1]}", str(dest))
        return dest
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def build_tarball(out: Path, version: str) -> Path:
    """The portable version: the app's source with a launcher, for any distro."""
    top = f"opendisco-{version}"
    dest = out / f"{NAME}-{version}-linux.tar.gz"

    def clean(info: tarfile.TarInfo):
        if "__pycache__" in info.name or info.name.endswith((".pyc", ".DS_Store", ".icns", ".ico")):
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        if info.isfile() and not info.name.endswith((".sh", "opendisco")):
            info.mode = 0o644
        elif info.isfile() or info.isdir():
            info.mode = 0o755
        return info

    with tarfile.open(dest, "w:gz") as tar:
        tar.add(ROOT / "src" / "opendisco", f"{top}/src/opendisco", filter=clean)
        for path in (HERE / "opendisco", HERE / "install-desktop-entry.sh", HERE / "README-LINUX.md",
                     ROOT / "LICENSE", ROOT / "NOTICE"):
            tar.add(path, f"{top}/{path.name}", filter=clean)
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Linux .deb, .rpm and portable .tar.gz.")
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64",
                        help="CPU to build the .deb and .rpm for (default amd64: x86-64 PCs)")
    parser.add_argument("--only", choices=("deb", "rpm", "tar.gz"), action="append",
                        help="build just this format (repeatable)")
    parser.add_argument("--out", default=str(ROOT / "dist"), help="where the packages go (default dist/)")
    args = parser.parse_args()
    formats = args.only or ["deb", "rpm", "tar.gz"]
    version = app_version()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if {"deb", "rpm"} & set(formats) and not shutil.which("docker"):
        sys.exit("error: building the .deb and .rpm needs Docker (on a Mac: brew install colima docker)")
    built = [build_system_package(fmt, args.arch, out, version) for fmt in formats if fmt in TARGETS]
    if "tar.gz" in formats:
        built.append(build_tarball(out, version))
    for path in built:
        print(f"Built {path} ({path.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
