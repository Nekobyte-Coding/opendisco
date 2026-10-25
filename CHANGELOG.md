# Changelog

Installers for 1.1.0 to 1.3.2 were rebuilt in October 2026 from each version's own source, under
the current name, license and app ID. No fixes were back-ported, so each one behaves as it did
when it came out. The Linux packages of 1.1.0 to 1.3.1 were added then too; those versions were
never released for Linux. README.md's "Versions and platforms" lists each version's platforms
and known issues.

## 1.6.1 (2026-10-25)

- **Terms of use:** OpenDisco shows its terms of use (TERMS.md) when it first opens and after
  each upgrade, and they must be accepted before it's used. On macOS, Windows, Linux and Android
  they take the place of the main window, with the app's own menu items and title-bar buttons
  off until **I agree**; Quit, closing the window or Android's Back leaves. iOS shows them over
  everything, with I agree only. **Terms of Use…** shows them again (the OpenDisco menu on a
  Mac, Help on Windows and Linux, Settings on phones).
- The command line asks too, before anything runs: `I agree` typed in a terminal, or
  `--accept-terms` for scripts and other runs without one. `--terms` prints them. One
  acceptance counts for both the app and the command line.
- Each acceptance is kept in `terms.json` in the app's data folder: the version, the time (UTC),
  the SHA-256 of the terms' text, and whether the app or the command line accepted them. Terms
  whose text changes are asked again.
- The confirmations for installing firmware, saving, applying, uploading or restoring a config,
  changing a login and rebooting say what can go wrong, and that the device tools have been
  tested only on simulated devices so far.
- **Open-source licenses…** (beside Terms of Use…) lists the licenses of the components each
  build bundles.
- The update offer says the new version asks for its terms of use, with **Read the terms** on
  desktops.
- macOS and Linux: the app's data folder (config backups hold password hashes and shared
  secrets) is readable by its own account only.
- Windows and Linux: the main window starts wider when the screen has room (up to 1500 pixels,
  centred), and each column of the device list gets the width its contents need. Too narrow
  for them all, the widest columns give up width first, and the IP and MAC addresses stay whole.
  At the first size, Linux had cut Name, Model and Via to a few characters, and Windows the
  firmware, names and statuses. On a screen smaller than the window, it opens at the top left.
- Linux: the app no longer hangs when it opens with a page of text to show (the terms of use).
- Android: Quit closes the app.
- Details says "1 packet", not "1 packets", for a device heard once.

## 1.6.0 (2026-10-25)

**Device configs** (airMAX, airFiber, LTU, GigaBeam and EdgeOS; not UniFi, whose controller owns
its config, nor EdgeSwitch, whose web UI does)
- **Back up config** and **Config backups…**: copies of a device's config, kept in the app's
  data folder by MAC address with the date, address, model and firmware, with Restore…, Save a
  copy…, Delete… and Show folder.
- **Upload config…**: a config file from this computer, or a backup, for the same model only.
  What changes is shown line by line first, then Save or Apply now; the device's current config
  is backed up before it's replaced.
- **Edit config…** covers airFiber, LTU, GigaBeam and EdgeOS too. On EdgeOS, Save makes the
  file the boot config once EdgeOS has checked it loads, and Apply loads, commits and saves it.
- **Reboot…** (airMAX, airFiber, LTU, GigaBeam, EdgeOS, UniFi access points and switches, UniFi
  OS consoles), asked first, waiting until the device answers again.
- **Locate (blink LED)** for UniFi access points and switches, until Stop locating.
- **Scan from device…** with no device selected (on phones, the title bar's +): log in to a
  device by its address, one the scan didn't find (over a VPN, say), and list it (Via `ssh`)
  with what it sees under it.

**Firmware and latency**
- The Firmware column names a newer release when Ubiquiti's firmware server lists one:
  "8.7.11 (latest: 8.7.25)". It's looked up during each scan (Settings: **Check firmware
  versions during scans**, on) and kept about a day. Details gives the release's date, and the
  CSV export a Latest firmware column.
- A **Latency** column: every device is pinged when a scan ends, with no administrator rights
  needed. High latency (100 ms or more on average) and packet loss (20% or more) are flagged; a
  device that never answers pings isn't. **Measure latency** (right-click) and **Measure latency
  to all devices** (the Device menu) measure again.
- Command line: `--no-latency` and `--no-firmware-check`; `-v`, `--json` and `--export` show
  the latest release.

**Search, notes and exports**
- **Search** above the device list: IP, MAC (in any spelling), model, name, vendor, firmware,
  Status, Via and note. A device found through another keeps the devices above it in view.
- **Note…**: a note per device, kept by MAC address, shown first in Details and as ✎ after its
  name, searched and exported (the command line's `-v` and exports show it too).
- **Export device…**: one device's report as HTML, or a .zip with its config backups too.
- **Export…** offers, after the scan report, a security report (known CVEs and outdated
  firmware), every config backup (.zip), every device note and the Log.

**The app**
- **Settings** holds the networks probed through temporary addresses (the Networks tab is gone)
  and **Also sweep these subnets**: routed or VPN subnets every scan also probes, on every
  platform, phones included.
- **Tablets and iPads:** the device list and a device's page side by side, in either
  orientation (Android tablets; an iPad full screen or on the larger side of Split View).
- **Phones:** Tools adds Backups, Reboot, Locate, Note and Export device; each row in the list
  shows a newer firmware release and the latency; Export offers the reports above.
- The adapter picker is labelled **Interface**, with "Any interface" ("Port" and "Any port"
  before), and the command line's help and messages say interface for the computer's network
  adapters. "Port" now means only a TCP/UDP port or a switch port.
- Notes the app shows name its controls next to the command-line flags: Probe listed networks
  (-a), Trunk VLANs (--vlans).
- Status says "Self-assigned IP" for a device on a 169.254.x.x address ("No IP address"
  before).
- Fixed: the CVE check didn't recognise EdgeRouters whose firmware string reads
  `EdgeRouter.ER-e50.v…` (the way EdgeOS names its own firmware), so it didn't check them
  (1.5.0). The new firmware check and config tools know them too.

## 1.5.0

**Finding ports**
- **Find HTTP port, Find HTTPS port, Find SSH port** in the right-click and Device menus: the
  deep check first, then every TCP port of that one device, likeliest first (the usual ports,
  the ones the rest of the gear uses and typos of those), until the service answers.
- **Scan all ports** lists every open port and what answers on it: the SSH banner, the web
  page's status, server and title, the TLS certificate's name.
- A warning first that intrusion prevention may take a port search for a port scan.
  Command line: `--all-ports` for the addresses given.
- An **HTTP** column; the columns read HTTP, HTTPS, SSH and show any other port the service was
  found on.

**Status and diagnostics**
- **Status** names the finding in a word or two, or "Multiple issues (N)". Hovering lists the
  issues; double-click or **Show issues…** opens the list with links to each CVE's page.
- **CVE check:** each device's firmware is checked against known CVEs for Ubiquiti gear (84 at
  release, from the NVD and Ubiquiti's security advisories). A match shows a red ❗ and names
  the version that fixes it. The list can refresh itself about once a day (Settings), and
  `--update-cves` refreshes it from the command line.
- **TFTP recovery mode:** gear that's silent to discovery but answers TFTP is reported as
  waiting for firmware.

**Device tools over SSH** (macOS, Windows, Linux and the phones)
- **Check for firmware update** and **Update firmware…** (airMAX, UniFi access points and
  switches, UniFi OS consoles): the download is checked against Ubiquiti's SHA-256, copied to
  the device and installed.
- **Edit config…** (airMAX): `/tmp/system.cfg` in an editor, with Save (to flash) and Apply.
- **Change login…** (airMAX), and logins remembered per device in the system's own credential
  store (Keychain, Credential Manager, Secret Service) when asked.
- **Scan from device…:** what a device sees (its stations, LLDP neighbours, ARP table) is
  added to the list, indented under it, as deep as the chain goes. Devices behind other
  devices get SSH, ping, Web UI, port searches and the device tools through the ones before
  them.

**The app**
- **Settings:** check for OpenDisco updates when opening (download, check and install in the
  app, on macOS, Windows, Linux and Android) and check for new CVEs when opening.
- **Phones:** a new layout shared by Android and iPhone/iPad: Quick Scan, Full Scan and Stop
  above the device list; a page per device with Details, Packets and Tools (ping, SSH, port
  finder, Scan from device, firmware, config, login). Android now also uses mDNS and SSDP.
- The iPhone/iPad app is in the source, with Apple's multicast entitlement for broadcast and
  multicast discovery, but isn't released yet.
- Fixed: on a Mac with an older OpenDisco (another app ID) or another app built with
  Briefcase, macOS's Local Network privacy could mistake OpenDisco for it and block its
  traffic without asking, and a scan found nothing. The app's launcher now has its own ID.
  When nothing answers on a Mac, the scan's note points to the Local Network setting.

## 1.4.2

- Fixed: picking Direct to a device or Trunk VLANs turned on "Probe listed networks", and it
  stayed on after switching back to Full scan or Sniff the wire, so the next scan added
  temporary addresses (and asked for an administrator password) nobody asked for (1.1.0 to
  1.4.1 on macOS and Linux, 1.4.0 and 1.4.1 on Windows; the switch was "Probe my networks"
  before 1.4.1). Leaving those modes now sets the switch back to how it was.
- Fixed: a scan started while Keep addresses was still adding its addresses lost track of them,
  and they stayed until the app quit. Start now waits until they're in place.
- Fixed: on Android, a second export in the same minute was reported under the first one's file
  name; Android had saved it as "… (1).html". The message now names the file that was saved.
- The Networks tab says when a line isn't a network ("unknown option" before).
- The installed command-line tool calls itself `opendisco` in `--help` and `--version`
  (`opendisco.py` before).
- README-LINUX.md lists `ip` (iproute2) with the packages to install.

## 1.4.1

- The Android app is signed with OpenDisco's own release key instead of Android's debug key,
  so later versions install over it. Android won't replace the debug-signed 1.4.0 with it:
  uninstall 1.4.0 first (nothing is lost: the phone app saves nothing).
- Android: the device list shows just IP, Model and Name, in larger text. Its twelve columns
  ran off a phone's screen. Tapping a device shows everything else in Details.
- Fixed: on Android, Export did nothing. It now saves the HTML report to the Downloads folder.
- Fixed: on Windows, Keep addresses failed and stayed greyed out (it looked for sudo).
- Fixed: on Windows, picking a Port whose adapter name has a space ("Ethernet 2", "Wi-Fi 2")
  scanned the adapter named by its first word, or none.
- Fixed: on Windows, the About box showed no version, and saved data went into a folder named
  "Unknown". It's now in `%LOCALAPPDATA%\Nekobyte-Coding\OpenDisco`, and 1.4.1 brings the
  earlier data over.
- Fixed: on Windows 11, the access point a Wi-Fi adapter is joined to wasn't named (Windows 11
  labels its BSSID "AP BSSID").
- Fixed: Excel showed the ✓ and ✗ in CSV exports as garbled characters.
- Fixed: on Debian and openSUSE, Sniff the wire over Wi-Fi didn't name the access point: they
  keep `iw` in an sbin folder, outside an ordinary user's PATH. Tools are now looked for there
  too.
- macOS: an argument Finder can add when it opens an app (`-psn_…`) is ignored rather than
  read as a command-line option.
- The app's messages describe the computer and the gear instead of addressing the reader:
  "Probe my networks" is now "Probe listed networks".

## 1.4.0

- New full name: Open Discovery Tool for Ubiquiti Devices, OpenDisco for short. An independent
  project, not affiliated with Ubiquiti Inc.
- Licensed under the Apache License 2.0 (LICENSE, with NOTICE).
- Saved data (the networks file, hidden devices and SSH host keys) is retained when 1.4.0 is
  installed over an earlier version, and the Windows installer replaces the earlier install.
- Windows can do what the macOS and Linux versions do: the Sniff the wire, Trunk VLANs and
  Direct modes capture packets through Npcap (the installer offers to download it from
  npcap.com), the "Probe my networks" switch adds temporary addresses (as administrator), and
  discovery broadcasts go out of every adapter. Windows can't tag VLANs, so Trunk VLANs finds
  them by listening and probes the untagged network only.
- First Android release, with a layout that fits a phone. Phones can run Quick and Full scans.
- Fixed: the Windows app stopped at startup in 1.3.0 to 1.3.2 (it read a bundled file with
  Windows' default text encoding).
- Fixed: on Windows, the device table's columns opened too narrow to read, with no headings
  (1.1.0 and 1.2.0; the 1.3.x Windows app didn't open).
- Fixed: on Linux, the Listen box's − and + buttons were drawn partly outside it.
- Sniff, Trunk VLANs and Direct report it when there's no wired or Wi-Fi port to listen on.
- Installers are named by system and CPU, e.g. OpenDisco-1.4.0-macos-universal.dmg.

## 1.3.2

- Fixed: a UCG Fiber (and other gear that does the same) showed port 7080 in the HTTPS column,
  with HTTPS-PORT warnings (1.1.0 to 1.3.1). Its discovery reply carries 7080 without the flag
  that marks the web UI port, so that port is no longer used; the HTTPS port comes from the
  device's HTTP redirect instead.
- First Linux release: a .deb for Ubuntu 24.04, an .rpm for Fedora 44 and a portable .tar.gz,
  with the right-click menu and copying working on Linux.
- The default networks list holds only 192.168.1.0/24, Ubiquiti's factory subnet.

## 1.3.1

- Popup windows (SSH login, administrator password, hidden devices) open centred over the
  app's window, on whichever screen it's on.
- Open Web UI uses the port the device reports when a deep check found nothing answering.

## 1.3.0

- A right-click menu for each device (also under the Device menu): Open Web UI, Open SSH,
  Ping, Rescan device, Copy IP/MAC, Forget SSH key, Hide device. On macOS and Windows.
- Terminal tab: SSH and ping sessions that keep running per device. SSH host keys are pinned
  to each device's MAC address, and old airOS ciphers are allowed.
- HTTPS and SSH ports come from what each device reports (discovery, HTTP redirect, mDNS,
  UPnP), with no ports to enter. A port that differs from the rest of the gear in the scan is
  flagged as a likely typo.
- Hidden devices.

## 1.2.0

- Packets tab: each device's discovery packets, decoded and checked for damage.
- Missed-reply counting, and interface and checksum error counters.
- Sharp tab labels after dragging the divider (macOS).
- Fixed: the unicast sweep missed UniFi OS gear, which ignores probes sent from port 10001.

## 1.1.0

- First app release: a macOS and Windows window over the command-line scanner.
- Touch ID for sudo on macOS, and HTTPS/SSH port columns checked against standard ports
  entered in the window.
