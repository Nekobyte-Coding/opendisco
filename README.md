# OpenDisco

One tool for finding and diagnosing Ubiquiti devices (UniFi, airMAX, EdgeMAX, UISP, AmpliFi).
It combines the discovery methods of three Ubiquiti tools, merges what they find by MAC
address, and checks each device for common problems.

| Borrowed from | Method | What it finds |
|---|---|---|
| Legacy Device Discovery Tool (Java) | UBNT discovery v1 probe, broadcast to UDP 10001 | airMAX, EdgeMAX, older UniFi |
| WiFiman | v1 + v2 probes, **unicast sweep** of a subnet, ARP table vendor (OUI) match | devices behind routers/VPNs; Ubiquiti gear that has discovery turned off |
| UniFi Network app / controller | multicast probe to 233.89.188.1, **passive listening** for adoption announcements, mDNS + SSDP, UniFi OS console API | unadopted devices, consoles, other controllers on the LAN |

It comes two ways:
- **A native app** for macOS, Windows, Linux, iPhone and Android (see [The app](#the-app)).
- **The command-line tool,** which needs only Python 3.8 or newer with no packages to
  install, and runs on macOS, Linux and Windows.

## The app

- **Mac:** open `dist/OpenDisco-1.3.2.dmg` and drag the app to Applications.
- **Windows:** run `dist/OpenDisco-1.3.2-setup.exe`. It installs for the current user
  (no admin rights), with Start menu and desktop shortcuts and an uninstaller in Apps.
  - **SmartScreen:** the installer isn't code-signed, so the first time Windows shows
    "Windows protected your PC": click **More info**, then **Run anyway**.
  - **Firewall:** the first scan may bring up a Windows Firewall prompt about **Python**
    (the app runs on its own bundled copy). Allow it on private networks, or devices'
    replies can't get back to it.
  - **Command line:** for the CLI on Windows, run `opendisco.cmd` from the install
    folder (`%LOCALAPPDATA%\Programs\OpenDisco`), for example `opendisco.cmd --quick`.
- **Linux:**
  - **Ubuntu 24.04 LTS, Linux Mint 22, Pop!_OS 24.04:**
    `sudo apt install ./OpenDisco-<version>-ubuntu-24.04_amd64.deb`
  - **Fedora 44:** `sudo dnf install ./OpenDisco-<version>-fedora-44.x86_64.rpm`
  - **Any other distro** (Debian 13, Arch, newer Ubuntu or Fedora...): the portable
    `OpenDisco-<version>-linux.tar.gz`. Extract it and run
    `./opendisco`; its `README-LINUX.md` lists the packages to install first.

  The `.deb` and `.rpm` install the app's own copy of Toga and PyGObject, built for that
  release, and pull in GTK, WebKitGTK, tcpdump and the ssh client. Run it from your app menu,
  or `opendisco` in a terminal (with options, that's the command-line tool).

**The window:**
- Pick a mode and a port, then press Start.
- Devices fill the table as they're found. Select one to see everything it reported and what
  to check.
- **Right-click a device** (or use the **Device** menu) to open its web UI, SSH to it, ping
  it, rescan it, copy its IP or MAC, forget its saved SSH key, or hide it. See
  [Right-click menu and the Terminal tab](#right-click-menu-and-the-terminal-tab).
- **Packets** shows the packets the selected device sent, decoded field by field with their
  hex dumps, and checked for damage (see [Damaged packets and loss](#damaged-packets-and-loss)).
- **Terminal** holds your SSH and ping sessions. Selecting a device shows its session.
- The other tabs show what was heard on the wire, notes, the log, and your networks file, which
  you can edit in the app.
- **Hidden devices…** lists the devices you've hidden, so you can bring them back.
- **Export…** saves an HTML report (opens on any phone), CSV or JSON.
- **Keep addresses** holds the temporary addresses that reached gear until you release them,
  so you can open its web UI.

Modes that need administrator rights (sniffing, temporary addresses, VLANs, direct) ask for
your password in a small window, pass it straight to `sudo`, and don't store it. You're asked
at most once every 5 minutes.

To use Touch ID instead, turn it on for `sudo`. macOS ships the switch:
`/etc/pam.d/sudo_local.template` says to uncomment its `pam_tid.so` line. Save a copy as
`/etc/pam.d/sudo_local` with that line uncommented (you'll need admin rights to write there).
From then on the app uses Touch ID, and so does `sudo` in Terminal. The password window still
appears if you cancel the fingerprint prompt.

The first time, macOS also asks to let the app reach devices on your local network: say yes,
or discovery and the ARP table are blocked.

**HTTPS and SSH ports.** The **HTTPS** and **SSH** columns show the ports each device says it
uses, so a fat-fingered port shows up as whatever the device really has. Nothing needs to be
entered first. A device can say so in four places, and Details lists each one it used:
- its discovery reply (UniFi gear reports both ports);
- where its plain-HTTP page redirects, which shows the HTTPS port (airOS, EdgeOS and UniFi OS
  send `http://ip/` to `https://ip:<port>/`);
- its mDNS service records (`_ssh._tcp`, `_https._tcp`);
- its UPnP description.

To catch a typo without a list to check against, each device is compared with the rest of
the same kind of gear in the scan. If most of your Ubiquiti radios use SSH 2222 and one says
2223, that one gets an `SSH-PORT` warning, which says when the port is one digit off. Consoles
are compared with consoles. A device that gives different ports in different places gets a
warning too.

**Deep checks** connect to those ports and confirm what answers: `✓` means the right service
answered there, and `✗` means nothing did. They also try the common ports and every port the
rest of your gear uses, so a device that says nothing is still found on your usual ports.
They don't search every port: a port that no device mentions and that isn't one of those
can't be found. The command line also takes your standard ports, `--https-port 8443
--ssh-port 2222`, and warns about any device that isn't on one of them.

**What each platform can do.** Phones don't allow apps to capture traffic, add addresses or
tag VLANs, so the app only offers the modes the platform supports:

| | Quick / Full scan | Sniff the wire | Temporary addresses | Trunk VLANs, Direct |
|---|---|---|---|---|
| macOS, Linux | yes | yes | yes | yes |
| Windows | yes | yes, with Npcap | yes, as administrator (Windows 10 2004 or later) | listens for VLANs; probes untagged only |
| Android | yes, broadcast and subnet sweep | no | no | no |
| iPhone | subnet sweep; broadcast needs Apple's multicast entitlement | no | no | no |

**Windows details:**
- **Npcap** captures packets for Sniff, Trunk VLANs and Direct. Its license doesn't allow
  bundling it, so the installer has an optional **Npcap** step (ticked when it's missing, like
  Wireshark's). The step downloads the current official installer from npcap.com, checks that
  it's signed by the Nmap Project, and starts it for you to click through. The app offers the
  same the first time you pick one of those modes. Wireshark installs Npcap too. Npcap's free
  license covers 5 computers (virtual machines count); more need Npcap OEM from the Nmap
  Project. Leave "Restrict Npcap driver's access to Administrators only" unticked, so
  sniffing works without administrator rights.
- **Temporary addresses** (Probe my networks, Keep addresses, Trunk VLANs, Direct) change
  your network adapter, which Windows only lets administrators do. The app offers to restart
  as administrator (one UAC prompt, which Windows Hello can approve). On the command line, run
  it from an Administrator terminal. Addresses are added with `netsh`, alongside DHCP's
  (DHCP/static coexistence, Windows 10 2004 and later, put back afterwards), and only until
  the next restart, so none can be left behind.
- **VLANs:** Windows can't tag VLANs itself; only some network cards' own drivers (Intel
  PROSet, Realtek) or a Hyper-V virtual switch can. So Trunk VLANs lists the VLANs and gear
  it hears, and probes the untagged network. Many network card drivers also remove VLAN tags
  before Npcap sees them: if no tagged VLANs show up on a trunk, look for a "Packet Priority
  & VLAN" setting on the adapter (Device Manager > Advanced) and turn VLAN off there.

### Right-click menu and the Terminal tab

Right-click a device in the table (or select it and use the **Device** menu):

- **Open Web UI** opens `https://ip:port/` in your browser: the port a deep check found
  HTTPS on, else the one the device says.
- **Open SSH…** asks for a username and password, with the port filled in (and where it came
  from), then opens a session in the **Terminal** tab. The app types the password when ssh
  asks for it. It's kept in memory for that session only, so if the device reboots, press
  Enter in the terminal to log in again. Leave it empty to type it yourself or to use your
  SSH key. The username is remembered.
- **Ping** pings it continuously in the Terminal tab. Ctrl+C stops it and prints the summary,
  and Enter starts it again.
- **Rescan device** probes just that device again (discovery sent straight to it from both
  source ports, then its ports, web redirect and console API), and updates its row, Details
  and Packets.
- **Copy IP address**, **Copy MAC address**.
- **Forget SSH key**: see below.
- **Hide device** takes it out of the table, by MAC address, in every scan until you unhide it
  under **Hidden devices…**. Exports still include it.

**Sessions stay open.** Each device's SSH and ping sessions keep running when you select
another device, and selecting it again shows its session with its history. The **Session**
list switches between all of them, and **Close session** ends one. They're real terminals
(xterm.js, bundled), so full-screen programs, colours, resizing and Ctrl+C work.

**SSH host keys** are saved in the app's own known-hosts file, under each device's MAC address
rather than its IP. So the next factory-reset radio at 192.168.1.20 isn't mistaken for the last
one, and a key that changes on the *same* device is still caught: the terminal says so and
won't connect. If you expect it (you reset or replaced the device), choose **Forget SSH key**
and press Enter. Old firmware that only offers SHA-1 key exchange, `ssh-rsa` keys or CBC
ciphers is allowed, as far as your ssh still supports them.

**Windows:** sessions run in the app through pywinpty (bundled), using Windows' built-in
OpenSSH client (Settings > Optional features > OpenSSH Client, if it's missing).

### Building it

Everything is packaged with [Briefcase](https://briefcase.readthedocs.io) from
`pyproject.toml`. Set up once:

```bash
python3 -m venv .venv && .venv/bin/pip install briefcase toga
```

- **Run from source:** `.venv/bin/briefcase dev`
- **Mac (.dmg):** `.venv/bin/python packaging/macos/build_dmg.py`. Your Documents folder
  syncs with iCloud, and iCloud's file attributes break macOS code signing. So this copies the
  sources to `~/Library/Caches/opendisco`, builds there, and puts the `.dmg` in `dist/`.
  The ad-hoc signature is fine for your own Macs. To hand it to others without Gatekeeper
  warnings, sign and notarize it with an Apple Developer ID.
- **Windows (setup.exe), from this Mac:** run `.venv/bin/python packaging/windows/build_installer.py`
  (needs `brew install makensis` once). Briefcase can't build Windows apps from a Mac, so this
  script assembles the same parts:
  - Python 3.13 for Windows, the official embeddable build from python.org;
  - Toga's Windows backend, installed from Windows wheels;
  - the app's code.

  NSIS then turns them into `dist/OpenDisco-<version>-setup.exe`. On a Windows PC,
  `briefcase package windows` makes an `.msi` instead.
- **Linux (.deb, .rpm, .tar.gz), from this Mac or a Linux PC:**
  `.venv/bin/python packaging/linux/build_packages.py` (`--arch arm64` for ARM PCs). It runs
  Briefcase inside Ubuntu 24.04 and Fedora 44 containers, so it needs Docker. On a Mac:
  `brew install colima docker docker-buildx`, then `colima start --vz-rosetta=false`, since x86-64 builds
  run emulated and Rosetta crashes Ubuntu's Python. Emulated compilers occasionally crash: if
  a build fails with "internal compiler error", run it again. The portable `.tar.gz` needs no
  Docker (`--only tar.gz`).
- **Android (.apk):** `.venv/bin/briefcase build android` (works on a Mac). The first run
  downloads Java and Google's Android SDK and asks you to accept Google's SDK license. The
  APK lands in `build/` and can be sideloaded; `briefcase package android` makes a Play
  Store bundle.
- **iPhone:** needs a Mac with Xcode installed. Run `.venv/bin/briefcase run iOS` for the
  simulator, or `briefcase open iOS` to sign and install it on a phone from Xcode. A free
  Apple ID can sideload to your own phone for 7 days at a time. For broadcast discovery,
  request the `com.apple.developer.networking.multicast` entitlement from Apple and add it
  in Xcode; without it the app still finds gear by sweeping the Wi-Fi subnet.

The Mac and Windows build scripts do their work in `~/Library/Caches/opendisco`, and
the Linux one inside containers, so nothing big ends up in iCloud. Finished installers go in
`dist/`. `CHANGELOG.md` lists what changed in each version.

**Project layout:**

| Path | What it is |
|---|---|
| `src/opendisco/core.py` | The scanner, shared by the app and the CLI |
| `src/opendisco/app.py` | The GUI |
| `src/opendisco/terminal.py` | The Terminal tab: SSH and ping sessions |
| `src/opendisco/resources/` | App icon (redraw with `packaging/make_icons.py`) and the default networks file |
| `src/opendisco/resources/xterm/` | xterm.js 5.5.0 (MIT), the terminal emulator; `packaging/fetch_xterm.py` fetches it from npm and checks it |
| `packaging/windows/` | The Windows installer build script and NSIS installer definition |
| `packaging/linux/` | The Linux build script, and the portable version's launcher, menu-entry script and README |
| `opendisco.py` | The command-line launcher |
| `networks.txt` | Your networks file for the CLI: not in git, made from the default (`src/opendisco/resources/networks.txt`) the first time you run it. The app keeps its own copy in its data folder |

## Quick start

```bash
python3 opendisco.py
```

```
IP          MAC                MODEL        NAME         FIRMWARE      UPTIME  VIA         STATUS
10.8.6.20   74:ac:b9:11:22:33  UAP-AC-Lite  UAP-AC-Lite  6.5.28.14491  2m00s   ubnt,arp    DEFAULT FALLBACK-IP NO-LEASE REBOOTED
10.8.6.250  8c:30:66:5a:10:fa  UXMAX        Front-Desk   5.2.10        18d04h  ubnt,mcast  console
```

Every problem it finds is listed below the table. Add `-v` to see every field each device
reported.

## Common uses

| Command | What it does |
|---|---|
| `opendisco.py` | Full scan: broadcast, multicast, a sweep of local subnets up to /22, mDNS, SSDP and the ARP table |
| `opendisco.py -v` | The same, plus every field each device reported and the full diagnostics |
| `opendisco.py --quick` | Broadcast and multicast only, like the old Java tool |
| `opendisco.py 10.20.0.0/24` | Also unicast-probes a routed subnet (another VLAN, a site over VPN) |
| `opendisco.py --deep` | Adds TCP port checks (22, 80, 443, 8080, 8443, your standard ports, and the ports each device reports, naming what answers) and the UniFi OS console API (`/api/system`, installed apps) |
| `opendisco.py --deep --ssh-port 2222 --https-port 8443` | The same, flagging any device whose SSH or web UI isn't on your standard port |
| `opendisco.py --listen -t 60` | Sends nothing. Picks up adoption announcements and other hosts' discovery probes |
| `opendisco.py --watch` | Live monitor that prints NEW, LOST, BACK, REBOOT, IP and CHANGED events |
| `opendisco.py --raw` | Decodes and hex-dumps every UBNT packet as it arrives |
| `opendisco.py -v --raw` | Also lists each device's packets at the end, checked for damage and loss |
| `opendisco.py --json > scan.json` | Machine-readable output |
| `opendisco.py --export report.html` | Also saves a report: `.html` opens on any phone; `.csv` and `.json` work too |
| `opendisco.py --interfaces` | Shows the active Ethernet/Wi-Fi interfaces it found, including ones with link but no address |
| `opendisco.py -a` | Also probes your usual networks (`networks.txt`) through temporary IP aliases. See below |
| `opendisco.py -a --hold` | The same, then keeps the aliases that reached gear so you can open it, until Ctrl+C |
| `opendisco.py -a --dry-run` | Prints the exact alias commands without running anything |
| `opendisco.py --vlans` | On a trunk port: finds the VLANs it carries by listening, then probes each one through a temporary tagged interface |
| `opendisco.py --vlan 20,30` | Probes these VLANs on your wired ports, without listening first |
| `opendisco.py --sniff` | Listens on every port, Wi-Fi included, for ARP, LLDP/CDP and broadcasts, and lists the gear it hears on any subnet |
| `opendisco.py --sniff -a` | The same, then probes that gear through temporary addresses in its subnets |
| `opendisco.py --direct -i en7` | Wired straight into one radio: finds its IP and VLAN from what it says, live, and tells you whether its config survived |

Other options: `-i en0` (only use one interface), `-t 10` (listen longer), `--no-sweep`,
`--no-mdns`, `--no-ssdp`, `--no-arp`, `--rate 200` (slow the sweep), `--oui 245A4C`
(recognise another vendor prefix). Run `--help` for all of them.

## Finding gear on other subnets: temporary aliases (`-a`)

Old airOS answers a discovery broadcast from any sender. Newer firmware only replies when the
sender's address is inside its own subnet, so from a laptop on another subnet (or with no
address at all, because the network has no DHCP) it stays silent. `-a` solves that without
any manual IP setup:

1. It finds every **active** Ethernet and Wi-Fi interface: link up, with or without an IPv4
   address. On macOS that's the hardware ports from `networksetup` with `status: active`; on
   Linux it's the physical NICs with carrier.
2. For each interface, one at a time, it adds a temporary address in each network listed in
   `networks.txt`, probes, reads the ARP table, and removes the address again. It takes a few
   seconds per round.
3. Each device is reported with how it was reached. `ALIAS` means it only answered through an
   alias. `OFF-SUBNET` means it answered from another subnet anyway, which is old-firmware
   behaviour. This lets you check the old/new difference against your own gear.

Edit `networks.txt` to list your networks:

```
192.168.1.0/24             # Ubiquiti's factory subnet (192.168.1.20)
10.20.30.0/24
172.16.10.1-20/30          # every /30 with an address in .1-.20: .0, .4, .8, .12, .16
192.168.5.0/24 alias=192.168.5.199   # pin the alias address yourself
```

Or give networks on the command line: `--alias 10.0.0.0/24` (repeatable).

**Rounds per interface:**

| Round | What it probes |
|---|---|
| 1. Whole subnets | Takes a free address near the top (.250, then lower if that's taken), broadcasts, and unicast-sweeps the subnet. The sweep fills the ARP table, which shows which addresses are already in use. |
| 2. /30 (and /29) blocks | Takes an address in each block that nothing answered on. If both addresses of a /30 answer ARP (a live point-to-point pair), the block is skipped rather than borrowing one of their IPs. |
| 3. Silent blocks | Retries any block that stayed silent from its other address. A lone device that ignores ARP from other subnets may have been sitting on the address round 2 borrowed. |

**Safety:**
- Aliases are only added through `sudo` (you're asked once), and only on physical
  Ethernet/Wi-Fi ports. VPN, bridge and virtual interfaces never get one.
- Every alias is written to `~/.opendisco_aliases.json` before it's added. They're all
  removed on exit, Ctrl+C or `kill`. If a run dies hard (power loss, `kill -9`), the next `-a`
  run removes the leftovers, or you can run `opendisco.py --cleanup-aliases`.
- A network that overlaps a subnet this computer already has gets no alias; it's probed
  normally instead. If your gear is on another port with the same subnet as your Wi-Fi, turn
  Wi-Fi off first.
- Adding an alias briefly announces that address on the network. If a device secretly owns
  it (it didn't answer ARP or discovery), the two clash for a few seconds; the tool reports
  this as `ALIAS-CONFLICT`. On networks you don't control, try `--dry-run` first.
- `--hold` re-adds only the aliases that reached gear, choosing a different address if a
  device turned out to use the original. It removes them when you press Ctrl+C.

macOS and Linux only. Windows won't add a second address to a DHCP interface.

## Trunk ports and VLANs (`--vlans`, `--vlan`)

Plug into a trunked switch port without tagging and run:

```bash
python3 opendisco.py --vlans
```

This replaces the manual System Settings routine (create a VLAN interface, set its tag,
then set its IP):

1. **Listen.** For 20 seconds (`--vlan-listen` to change), `sudo tcpdump` captures the
   broadcast and multicast frames arriving on each wired port. Untagged frames are captured
   too. From those it learns:
   - which VLAN tags the port carries, and which subnets live on each (from ARP and IP
     senders);
   - what the switch says over LLDP: its name, the port, the **native VLAN**, and any VLAN
     names it advertises;
   - any Ubiquiti gear chattering on any VLAN (`sniff` in the VIA column), before anything
     is probed.
2. **Tag and probe.** For each VLAN found, it creates a temporary tagged interface:
   `ifconfig vlan200 create` / `vlan 20 vlandev en7` on macOS, or `ip link add ... type vlan`
   on Linux. It then runs the alias rounds on the subnets heard on that VLAN plus your
   `networks.txt`, and destroys the interface. Untagged subnets heard on the port are
   probed on the port itself.
3. **Report.** Each device shows the VLAN it was found on. Untagged shows as **1**, or as
   the port's native VLAN if the switch announced it over LLDP. A "VLANs heard on wired
   ports" section summarises what each port carries, which also tells you what VLAN an
   access port is on.

```
VLANs heard on wired ports
  en7 (Thunderbolt Ethernet), listened 20s: switch USW-Pro-24-PoE port Port 7
    untagged = VLAN 10 (LLDP) "Default"  192.168.10.0/24 (2 hosts)
    VLAN 20 "Cameras"                    10.20.0.0/24 (2 hosts)
    VLAN 30 "Mgmt"                       listed by the switch, no traffic seen
```

Other details:

- **Probing VLANs you already know:** `--vlan 20,30,100-105` probes those VLANs directly.
  It can be combined with `--vlans`.
- **A silent VLAN** (nothing heard, but listed by the switch or given with `--vlan`) is
  still probed with your `networks.txt`. That's how a factory-default device sitting on
  192.168.1.20 gets found.
- **Created interfaces** start at `vlan200` on macOS, so they never collide with the vlan0,
  vlan1... that System Settings makes. They're recorded and removed exactly like aliases,
  including by `--cleanup-aliases`. If a VLAN interface for that tag already exists, it's
  reused and left in place.
- **`--hold`** recreates the tagged interfaces that reached gear and keeps them until Ctrl+C.
- **VLAN labels are exact:** every reply is tied to the interface it arrived on
  (`IP_PKTINFO`), so the VLAN column reflects where a device actually answered. This also
  works for VLAN interfaces you set up yourself.
- **The switch's LLDP** is sent about every 30 seconds. Use `--vlan-listen 35` if you want
  to be sure of catching the native VLAN and VLAN names.

## Gear on subnets you're not on (`--sniff`)

Your computer's own ARP table only ever holds addresses on its own subnets: the OS never
ARPs for anything else. But ARP requests are layer-2 broadcasts, so every device on the wire
hears every device's ARPs, whatever subnet it's on. `--sniff` listens for them on every
active port (Wi-Fi included) for 20 seconds (`--vlan-listen` to change).

```bash
python3 opendisco.py --sniff
```

```
IP             VLAN  VENDOR    MAC                MODEL                  NAME        VIA    STATUS
10.8.6.2       1     Cisco     00:1b:54:aa:bb:cc  cisco WS-C2960X-48FPD  SW-CORE-1   sniff  ok
10.50.0.2      1     Siklu     00:24:a4:00:50:02  ?                                  sniff  OTHER-SUBNET
192.168.1.20   30    Mimosa    90:70:bf:00:01:20  ?                                  sniff  FALLBACK-IP OTHER-SUBNET
192.168.77.40  1     Ubiquiti  74:ac:b9:00:77:40  ?                                  sniff  OTHER-SUBNET
```

What it picks up:
- **ARP:** "who has X, tell Y" gives Y's IP and MAC, plus the VLAN tag if the port is a trunk.
- **LLDP and CDP:** give names, models and management IPs.
- **UBNT announcements:** broadcast by Ubiquiti gear.
- **Other broadcasts:** DHCP requests and the like.

Anything from a vendor this tool knows is added to the list, whatever its subnet; other hosts
are left out. That includes gear that never uses an IPv4 address on the wire, such as a
switch that only sends CDP and STP: it gets a row with its MAC, name and model, and IP `-`. With `-a`, the subnets where that gear was heard are probed through temporary
addresses, so Ubiquiti gear on someone else's subnet answers discovery with its model and
firmware. It works out the subnet the same way `--direct` does, from who the gear ARPs for.
`--sniff` needs `sudo` (for tcpdump) but changes nothing on your computer unless you add `-a`.

Options while listening:
- **`-v`:** lists every talker on each port: MAC, vendor, VLAN, addresses, what it sent (ARP,
  CDP, LLDP, STP, IPv6...) and its CDP/LLDP identity.
- **`--pcap PREFIX`:** saves each port's capture as `PREFIX-<interface>.pcap` for Wireshark.

**The access point your Wi-Fi is on.** An AP's management address lives on its management
VLAN, which usually isn't bridged to the Wi-Fi VLAN you're a client on. So nothing from its
management side reaches your Wi-Fi.
- **Identifying it from your connection:** while listening, the tool asks `sudo wdutil info`
  which access point the Wi-Fi interface is joined to, and works out its vendor from the BSSID
  (APs derive BSSIDs from their own MAC).
- **When its management side was found elsewhere** (say, heard tagged on a wired trunk), it's
  the same row, marked `WIFI-AP`.
- **When it wasn't:** the AP gets a row of its own, with no IP.
- **Getting its IP and details:** run `--sniff --vlans` from a wired port whose trunk carries
  the management VLAN, so the tool can tag that VLAN and probe it.
- **Caveat:** macOS hides the BSSID from most programs, and if it also hides it from `wdutil`,
  the tool says so.

## Other vendors

Ubiquiti gets full discovery. These get identified wherever they turn up (a sniffed port,
the ARP table, a direct wire), shown in the VENDOR column:

| Vendor | Identified by |
|---|---|
| Cisco, Meraki | MAC prefix, plus CDP or LLDP: name, platform, software version, management IP, native VLAN |
| Mimosa, Siklu, Ceragon, IgniteNet, Baicells, Tarana | MAC prefix, plus LLDP where the device sends it |

**MAC prefixes** come from Wireshark's vendor database. That covers 1,259 Cisco, 59 Meraki,
6 Mimosa, 4 Ceragon, and 1 each for Siklu, IgniteNet, Baicells (plus a /28 block) and
Tarana.

**`--direct` with these vendors:** a direct-wired one is identified and its IP, VLAN and
gateway reported the same way as a Ubiquiti radio. `--direct` also probes these factory
defaults (from installer guides, not vendor documentation), and the verdict says when a
device is sitting on one:

- Siklu: 192.168.0.1
- Mimosa: 192.168.1.20 (A5x/A6), 192.168.1.10 (A5/A5c)
- IgniteNet MetroLinq: DHCP, falling back to 192.168.1.20
- Baicells: 192.168.150.1

I couldn't confirm defaults for Ceragon IP-20 or Tarana, so none are assumed.

None of these vendors has an open discovery protocol like Ubiquiti's, so there's no model or
firmware for them unless they announce it over LLDP or CDP.

## Plugged straight into a radio (`--direct`)

Use this when a radio won't come up and you don't know its IP or VLAN. For example, it was
configured, aligned, powered down while cable was pulled, and then never re-linked to the
tower. Plug your laptop straight into it and run:

```bash
python3 opendisco.py --direct -i en7
```

`-i` names the port you're plugged into. Without it, the tool picks wired ports that have
link but no real IP address, and refuses ports that have one, so it never listens on your
office LAN by accident. If the port has no link yet, it listens anyway: plug in, or re-seat
the cable, once it's running. Devices talk the most right after link comes up.

On a direct wire, whatever is talking is the radio, so the tool listens to it like a trunk
port (up to 45 seconds) and prints what it learns as it happens:

```
Listening on en7 (Thunderbolt Ethernet, 1000baseT full-duplex) for up to 45s.
  74:83:c2:aa:bb:01 (Ubiquiti) announces itself over LLDP: "CityHall-STA", Wave-Micro, management 10.100.5.23
  74:83:c2:aa:bb:01 (Ubiquiti) uses 10.100.5.23 on VLAN 100, looking for 10.100.5.1
```

A radio that kept its config keeps ARPing for its gateway, tagged with its management VLAN
and from its own IP, and that gives both away. Other clues it picks up:
- **LLDP:** the radio's name, model and management address.
- **DHCP:** requests (and the address it last had), which mean its management is set to DHCP.
- **192.168.1.20:** traffic from this address means it was reset or never got a lease.

About five seconds after the radio first uses an address, the tool stops listening. It then
tags that VLAN and takes a temporary address inside the radio's real subnet:
- **Where the alias goes:** the radio only ARPs for addresses in its own subnet, so the
  smallest block holding its IP and its gateway must sit inside that subnet. A radio on a
  /27 gets an alias in its /27, where a guessed .250 would be ignored.
- **The probe:** discovery from that address gives the model, firmware and settings.
- **The verdict:**

```
Plugged directly into
  en7 (Thunderbolt Ethernet, 1000baseT full-duplex), listened 6.9s
    74:83:c2:aa:bb:01  Ubiquiti  "CityHall-STA"  Wave-Micro
      untagged   -                                                   IPv6, LLDP
      VLAN 100   10.100.5.23        looking for 10.100.5.1           ARP
      => Management is 10.100.5.23 on VLAN 100, and it keeps asking for 10.100.5.1 (its
         gateway or server), which isn't on this cable. Its network settings look intact,
         so look at the wireless side (alignment, frequency, the far end) rather than a lost config.
```

Other verdicts:
- **Factory defaults** (it reports default state): re-apply the config.
- **Asking for DHCP:** management is set to DHCP and nothing on the cable answers.
- **Talking on a VLAN but no IPv4 yet:** re-seat the cable, or listen longer with
  `--vlan-listen 90`.
- **Nothing heard:** check PoE, power and the cable.

If the radio's management is a /30 shared with its gateway, there's no spare address to
borrow, so the tool reports the IP and VLAN and stops there. With the wireless link down the
gateway isn't using its address, so you can take it yourself to reach the radio.

Add `--hold` to keep the tagged interface and address up afterwards, so you can open the
radio's web UI.

## Reading the output

**VIA** shows how each device was found:

- `ubnt`: answered UBNT discovery (broadcast or unicast)
- `mcast`: answered the multicast probe
- `announce`: sent an unsolicited announcement (`--listen`)
- `sniff`: heard in traffic on a port (`--sniff`, `--vlans`, `--direct`)
- `wifi`: the access point your Wi-Fi is joined to
- `mdns`: found by mDNS/Bonjour
- `ssdp`: found by UPnP/SSDP
- `arp`: its MAC is in this computer's ARP table with a Ubiquiti prefix

**STATUS** tags:

| Tag | Meaning | What to check |
|---|---|---|
| `console` | UniFi OS console (answered v2, echoed probes, or has the console API) | |
| `DEFAULT` | Factory default and not adopted | Adopt it, or SSH in and run `set-inform http://<controller>:8080/inform` |
| `LINK-LOCAL` | Has a 169.254.x.x address | It never got a DHCP lease |
| `FALLBACK-IP` | Sitting on 192.168.1.20 without a lease | DHCP. Several devices like this will conflict |
| `NO-LEASE` | DHCP client is on but not bound | DHCP server, VLAN tagging, switch port profile |
| `IP-CONFLICT` | Another MAC reports the same IP | Static assignments, duplicate fallback IPs |
| `OFF-SUBNET` | Answered from another subnet (old firmware does this), but you can't reach it | `-a --hold` with its subnet in `networks.txt`, or fix its IP/VLAN |
| `ALIAS` | Only answered through a temporary alias | `-a --hold` to keep the alias while you manage it |
| `ALIAS-CONFLICT` | Uses an address the tool briefly borrowed | Pin another alias with `alias=` |
| `WIFI-AP` | The access point your Wi-Fi is joined to | Its management VLAN: `--sniff --vlans` from a wired trunk |
| `HTTPS-PORT`, `SSH-PORT` | Reports a web UI or SSH port that isn't one of yours, or that nothing answers on | A typo in its config; the message says where the service actually answers |
| `OTHER-SUBNET` | Heard on the wire, outside your computer's subnets | `--sniff -a` probes it through a temporary address |
| `NOT-PROBED` | Both addresses of its /30 are in use, so it wasn't probed | Reach it through its peer, or plug in directly |
| `WAN-DOWN` | A console's WAN port reports no link | Cable or ISP handoff |
| `REBOOTED` | Uptime under 5 minutes | If it keeps happening: PoE budget, cabling, firmware |
| `LOCATING` | Locate LED is flashing | |
| `NO-DISCOVERY` | Seen via ARP/mDNS/SSDP but silent on UDP 10001 | Discovery turned off, firewall, or Wi-Fi client isolation |
| `NO-PORTS` | `--ports`/`--deep` found no open management ports | Firewall, still booting, or no layer-3 path |
| `NOT-SET-UP` | Console API says the console hasn't been set up | |
| `DAMAGED` | Some of its discovery packets arrived damaged | Cable, connectors, switch port, speed/duplex. See [Damaged packets and loss](#damaged-packets-and-loss) |
| `LOSS` | Missed 10% or more of the rounds of probes (at least 2) while in view | Wi-Fi interference, a bad cable or port, a busy link or device |

**Notes** at the bottom cover the scan itself: UDP 10001 already in use, broadcasts blocked,
or other hosts sending discovery probes. More than one controller probing the same network
is worth a look, because controllers can adopt each other's devices.

## Damaged packets and loss

Every UBNT packet a device sends is kept: the latest 60 for each device, with damaged ones
kept in preference to sound ones. The **Packets** tab (or `-v --raw`) shows when each arrived,
from which address and port, on which interface and VLAN, its kind (`v1 cmd 0`, `v2 cmd 9`…),
its size, and what the checks found. Below the list come the latest reply of each kind and
every damaged one, field by field. Each field has its offset (`@0041`) so you can find it in
the hex dump.

Ethernet's CRC catches most damage, and the network card throws those frames away before any
program sees them. So the evidence is in three places:

- **The interface's error counters.** They're read before and after each scan: input errors
  (bad CRC, runts), output errors, collisions and drops (macOS `netstat -i`; Linux
  `/sys/class/net`; Windows, all adapters together). The Packets tab shows them for the
  interfaces the device was heard on, and a note appears when any went up. Collisions on a
  full-duplex link mean the two ends disagree on duplex.
- **This computer's IP and UDP checksum counters.** The OS drops packets that fail these, and
  counts them.
- **The packets themselves,** for damage the checksums don't catch:
  - the header's length against what arrived (cut short, or extra bytes);
  - fields running past the end, or stray bytes after the last one;
  - fixed-size fields at the wrong size (MAC addresses, IPs, uptime);
  - unreadable text (hostname, model, firmware);
  - fields that should appear once appearing twice;
  - broken JSON in port records;
  - a field that changes for one packet and changes back;
  - uptime that jumps by minutes or more, or runs backwards without a reboot (firmware only
    refreshes it every half-minute or so, so smaller drift is normal).

  Packets captured off the wire (`--sniff`, `--vlans`, `--direct`) are seen before the OS
  checks them, so their IP and UDP checksums are checked too.

**Damage or firmware?** Damage on the path comes and goes. If every packet of a kind has the
same oddity, it's how that firmware writes them: it's listed as such, not flagged. A damaged
packet's fields aren't taken once the device has sent a sound one, and a packet with a broken
MAC or a failed checksum is never taken at face value. Either way, corruption doesn't change
what the table shows or create phantom devices. Packets too damaged to say whose they are are
kept by sender and listed in the notes.

**Loss.** The tool probes every 2 seconds. A device in view should answer every round, so
`Answered 28 of 30 rounds` means 2 rounds got no reply. Rounds are only counted while the
device was in view: from its first answer to its last, and only rounds sent to a network it's
on. Loss of 10% or more, and at least 2 rounds, gets a `LOSS` warning.

## Platform notes

- **macOS 15 and later:** your terminal app needs Local Network access (System Settings >
  Privacy & Security > Local Network). Without it, broadcasts can fail, and macOS hides MAC
  addresses and the ARP table from the tool, which turns off Ubiquiti-MAC detection. On some
  setups Python stays filtered even after you grant access. Modes that already use sudo
  (`-a`, `--sniff`, `--vlans`, `--direct`) then read the ARP table as root, and the notes say
  which happened.
- **Firewalls:** to hear replies and announcements, allow inbound UDP 10001. For example:
  `sudo ufw allow 10001/udp` on Linux, or accept the Windows Defender prompt.
- **UDP 10001 already in use:** the UniFi Network application or WiFiman running on the same
  computer holds the port. Active probes still work, but `--listen` doesn't, and unsolicited
  announcements are missed.
- No root or admin rights needed, except for `-a`, which runs `ifconfig`/`ip` through sudo.

## Protocol notes

**The 255.255.255.255 broadcast** is sent out of every interface, including alias, VLAN and
direct-wire ports. A plain send to 255.255.255.255 only leaves through the interface with the
default route. Yet it's the only broadcast that old gear on *another* subnet accepts: it
throws away other subnets' directed broadcasts like 10.8.6.255. macOS scopes a socket per
interface with `IP_BOUND_IF`; Linux sends it out of the interface that owns the socket's
address.

UBNT discovery packets are a 4-byte header (`version`, `command`, big-endian `length`)
followed by TLVs (`type` u8, `length` u16 BE, value). The probes are `01 00 00 00` (v1)
and `02 08 00 00` (v2). They go to UDP 10001 as broadcast, as multicast to 233.89.188.1,
or as unicast. Replies are v1 command 0, v2 command 6 or 9, or v0 (seen on UNVR).

The field table follows Wireshark's `packet-ubdp.c` and Home Assistant's `unifi-discovery`.
A real UniFi Express on the test network also showed these:

- `0x32`: port record. MAC + IPv4 + JSON, for example `{"type":"WAN","name":"eth1","plugged":true}`.
- `0x33`: a UUID string.
- `0x0F`: web UI as u16 flags + u16 port (`0001 01bb` = 443).
- One device sends **different reply shapes** depending on the probe: a full reply to
  multicast, and a short v2 reply to broadcast. Each formats firmware differently (`5.2.10`
  vs `UXMAX.ipq5322.v5.2.10...`). The tool tracks each shape separately so `--watch`
  doesn't report false changes.
- UniFi OS gear **ignores unicast probes sent from port 10001**, and answers ones from any
  other port. Some legacy gear answers only probes from 10001. So the unicast sweep (local
  subnets, routed subnets you name, alias rounds) sends each probe from both.

Any field the tool doesn't recognise shows up under "Unknown TLVs" in `-v`. Use `--raw` to
capture a packet for decoding.

## Limitations

- IPv4 only.
- The alias, VLAN, `--sniff` and `--direct` logic and the other-vendor parsing (CDP, LLDP)
  were tested against simulated networks and devices, not yet on real ones. The
  per-interface 255.255.255.255 broadcast was tested live. Run `-a --dry-run` or `--vlan 20 --dry-run` to
  review the commands.
- Some built-in NICs strip VLAN tags in hardware before a capture can see them. If
  `--vlans` reports several subnets as untagged on a port you know is a trunk, name the
  VLANs with `--vlan` instead. USB Ethernet adapters normally don't strip tags.
- It doesn't do the Bluetooth (BLE) setup discovery that the UniFi mobile app uses for
  brand-new consoles.
- Some field meanings come from observation rather than documentation: `0x0F` flags,
  `0x1B`, `0x20`, `0x33`.
- The OUI list is a snapshot from Wireshark's vendor database (October 2026). Add new
  prefixes with `--oui`.
