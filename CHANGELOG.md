# Changelog

Installers for 1.1.0 to 1.3.2 were rebuilt in October 2026 from each version's own source, under
the current name, license and app ID. No fixes were back-ported, so each one behaves as it did
when it came out. The Linux packages of 1.1.0 to 1.3.1 were added then too; those versions were
never released for Linux. README.md's "Versions and platforms" lists each version's platforms
and known issues.

## 1.4.2

- Fixed: picking Direct to a device or Trunk VLANs turned on "Probe listed networks", and it
  stayed on after switching back to Full scan or Sniff the wire, so the next scan added
  temporary addresses (and asked for an administrator password) nobody asked for (1.1.0 to
  1.4.1). Leaving those modes now sets the switch back to how it was.
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
