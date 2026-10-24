# Changelog

## 1.4.0

- The full name is now Open Discovery Tool for Ubiquiti Devices, OpenDisco for short. It's an
  independent project, not affiliated with Ubiquiti. Your networks file, hidden devices and SSH
  keys come along from the earlier version, and the Windows installer replaces the earlier
  install.
- Windows does what the Mac and Linux versions do: Sniff the wire, Trunk VLANs and Direct
  capture through Npcap (the installer offers to download it from npcap.com), Probe my
  networks through temporary addresses (as administrator), and discovery broadcasts out of
  every adapter. Windows can't tag VLANs itself, so it finds them by listening and probes
  untagged only.
- Fixed: the Windows app didn't open in 1.3.0 to 1.3.2.
- Android: the mode description has its own line, so the top row fits a phone.
- Linux: the Listen box's − and + buttons fit inside it.

## 1.3.2

- Fixed: a UCG Fiber (and any gear that does the same) showed port 7080 in the HTTPS column
  with HTTPS-PORT warnings. Its discovery reply carries 7080 without the flag that marks the
  web UI port, so that port is no longer used; its HTTPS port comes from its HTTP redirect.
- Linux: a .deb for Ubuntu 24.04, an .rpm for Fedora 44 and a portable .tar.gz, and the
  right-click menu and copying work there too.
- The default networks list is just 192.168.1.0/24, Ubiquiti's factory subnet.

## 1.3.1

- Renamed to OpenDisco.
- Popup windows (SSH login, administrator password, hidden devices) open centred over the
  app's window, on whichever screen it's on.
- Open Web UI uses the port the device says when a deep check found nothing answering.

## 1.3.0

- Right-click a device (or use the Device menu): Open Web UI, Open SSH, Ping, Rescan device,
  Copy IP/MAC, Forget SSH key, Hide device.
- Terminal tab: SSH and ping sessions that keep running per device. SSH host keys are pinned
  to each device's MAC, and old airOS crypto is allowed.
- HTTPS and SSH ports come from what each device reports (discovery, HTTP redirect, mDNS,
  UPnP), with no ports to enter. A port that differs from the rest of your gear is flagged as
  a likely typo.
- Hidden devices.

## 1.2.0

- Packets tab: each device's discovery packets, decoded and checked for damage.
- Missed-reply counting, and interface and checksum error counters.
- Sharp tab labels after dragging the divider.
- The unicast sweep reaches UniFi OS gear (it ignores probes from port 10001).

## 1.1.0

- The first app release: a Mac and Windows GUI over the scanner.
- Touch ID for sudo, and HTTPS/SSH port columns.
