# OpenDisco for Linux (portable version)

This folder runs on any Linux distribution, from wherever it's extracted.

    tar -xzf OpenDisco-*-linux.tar.gz
    cd opendisco-*
    ./opendisco              # the app
    ./opendisco --quick      # the command-line tool (see --help)
    ./install-desktop-entry.sh  # optional: adds the app to the desktop's menu

On Ubuntu 24.04 or Fedora 44, the `.deb` or `.rpm` from the same release is easier: it
installs everything it needs.

## The command-line tool

It needs only Python 3.8 or newer, which every current distribution has. Sniffing, temporary
addresses and VLANs (`--sniff`, `-a`, `--vlans`, `--direct`) also need `tcpdump`, `ip` and `sudo`,
and `iw` names the access point a Wi-Fi interface is joined to.

## The app

The app needs Python 3.11 or newer, GTK 3 and WebKitGTK 4.1 (for the Terminal tab). The first
time it opens, it sets up its own Python environment in `~/.local/share/opendisco` with Toga,
the toolkit it's written in, and asyncssh, an SSH client in Python. That compiles PyGObject
(GTK's Python bindings), so it needs a compiler and a few development packages once. Install
these first:

**Debian 13, Ubuntu 24.04 or newer, Linux Mint 22**

    sudo apt install python3-venv python3-dev gcc pkg-config libgirepository-2.0-dev libcairo2-dev \
        gir1.2-gtk-3.0 gir1.2-webkit2-4.1 tcpdump iproute2 iw openssh-client

**Fedora 41 or newer**

    sudo dnf install python3-devel gcc pkgconf-pkg-config glib2-devel gobject-introspection-devel \
        cairo-gobject-devel gtk3 webkit2gtk4.1 tcpdump iproute iw openssh-clients

**Arch, Manjaro**

    sudo pacman -S --needed python gcc pkgconf gobject-introspection cairo gtk3 webkit2gtk-4.1 \
        tcpdump iproute2 iw openssh

Then run `./opendisco`. Setting up takes a minute or two the first time; after that it opens
straight away. If it stops with "Couldn't set up Toga", a package above is missing: install
it and run `./opendisco` again.

Open SSH… and the device tools use the system's `ssh` and `scp` (the openssh package above).
Without them, they use asyncssh from that environment instead. If asyncssh couldn't be
installed (no connection to PyPI the first time), `./opendisco` tries again the next time.

Debian 12 and Ubuntu 22.04 are too old for the app (their GLib can't build current PyGObject).
The command-line tool works on them.

## Removing it

Delete the folder, `~/.local/share/opendisco`, and the menu entry
(`./install-desktop-entry.sh --remove`).
