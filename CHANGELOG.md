# Changelog

Installers for 1.1.0 to 1.3.2 were rebuilt in October 2026 from each version's own source, under
the current name, license and app ID. No fixes were back-ported, so each one behaves as it did
when it came out. The Linux packages of 1.1.0 to 1.3.1 were added then too; those versions were
never released for Linux. README.md's "Versions and platforms" lists each version's platforms
and known issues.

## 1.7.1 (2026-10-30)

Fixes from a review of all the code.

**Phones and tablets**
- Android: Settings opens again, and so do the terms of use in Spanish, Portuguese and Japanese
  (1.7.0 stopped at a switch Android has no line-wrapping step for).
- One device job at a time, for real: a second tap during a firmware check could start a second
  install on the same radio. Config Save and Apply and Back up now count as the job too, so
  Reboot and Firmware wait for them.
- An SSH session closed while it was still connecting stays closed (a command typed on another
  device's page went to the first one).
- Stop locating with a login that changed asks for it again instead of staying stuck; Upload a
  file says why a file couldn't be opened; Scan from an address no longer lists the phone itself.

**Device tools**
- Through other devices, a password is typed only for the device that asks for it, in route
  order: a device further along that printed a hop's prompt was typed the hop's password (and on
  the phone console, `passwd` could set a device's password to its hop's).
- The tools log in with the username and password given only: not over a connection shared
  through `~/.ssh/config` (ControlMaster), which skipped the password so a changed one passed
  unchecked, and not with this account's SSH keys, which could use up a device's login attempts.
- A firmware update of a device behind others always ended "hasn't come back after 15 minutes":
  its restart is now read from its uptime, through the devices on the way. An installer still at
  work after 5 minutes is waited for.
- Reboot reported a restart that didn't happen (one lost answer counted as "went down").
- Two radios of one model updated at once could get a damaged firmware copy; a copy that fails is
  removed from the device's memory.
- Through a hop's own SSH client (Dropbear), its messages no longer spoil what a command printed,
  and a changed key, a refused login or a device that's down are told as such.
- An EdgeOS rename could say the config wasn't changed although it was.
- A MAC address a device reports is checked before it names a backup folder or a host key.

**Scans and the command line**
- One malformed SSDP reply on the network ended every Full scan and lost its results; so could
  a crafted discovery reply or frame. Each is now ignored.
- The command line runs on Python 3.8 and 3.9 again (Windows, and `--demo` everywhere).
- Linux: existing VLAN interfaces are found without root; tcpdump stops when a capture ends with
  older sudo.
- Temporary addresses: a clean-up that fails keeps them on record; another running OpenDisco's
  are left alone; the app removes them when told to end; Stop keeps what earlier rounds found.
- Old gear's HTTPS (TLS 1.0) is recognised again.
- Windows: adapters named in other scripts, and Wi-Fi access points when Windows speaks another
  language, are read right.

**Desktop**
- macOS: the selection stays with its device when the list changes (the Device menu could act on
  the device that moved into the selected row).
- The demo network doesn't start while a device tool works on real gear (a Back up all's backups
  went to the demo's folder and were deleted with it); declining Npcap or administrator rights
  no longer leaves the demo's devices on the real network's tools.
- The config editor's Close asks about unsaved edits; Settings… while it's open brings it to the
  front; a port search waits for a scan that started meanwhile, and Stop ends one run from another
  device sooner; a Back up all that finished hidden shows its results.
- settings.json and terms.json can't be left half-written by a crash or a full disk.
- Faster and lighter: the scan's progress, the Terminal tab once its sessions end, the phone
  console's output, and the keychain asked off the window's thread (a locked keychain froze it).

**Reports and exports**
- The CVE fix named for a UniFi console is its firmware's, not the UniFi Network application's;
  the Site Report's CVE table lists each model's fix.
- CSV exports: a device name a spreadsheet would run as a formula starts with '.
- The Site Report's latency note, its file name in other scripts, and the CVE list's refresh
  failures are fixed; the demo's note and store name are translated.

**Installers**
- Windows: installs only into a folder of its own (typed as the Programs folder, it removed other
  programs' `python` and `app` folders). Linux portable version: set up again after the system's
  Python changes version.

## 1.7.0 (2026-10-26)

**Demo network**
- A sixth scan mode lists a made-up WISP tower (the README pictures' one) at once, sending
  nothing on the network, for trying the app without any gear. Help › Try the demo network opens
  it on computers; phones and tablets have Try the demo network over the empty list and in
  Settings, and a scan that finds nothing suggests it. `opendisco --demo` prints it on the
  command line.
- Its device tools work, on simulated devices: firmware check and update (the release and the
  file are simulated too; the EdgeRouter goes from EdgeOS 2.0.9 to 3.0.1), Edit config, Change
  login, Link health (one sector has a weak station), config backups, Back up all, Compare,
  Restore and Upload, Reboot, Scan from device (with a station only its sector reaches), SSH and
  ping, latency, Rescan and the port search. Log in as demo / demo; the bench spare takes its
  factory login (ubnt / ubnt) and shows FACTORY-LOGIN.
- Kept apart and labelled: the demo's notes, backups, SSH host keys, remembered logins, hidden
  devices, link readings and factory-login flags live in a temporary folder and in memory,
  deleted when it ends (a real scan, or quitting), never in the app's data or settings. The
  title says Demo, and every export from it is named opendisco-demo-… and stamped "Demo network:
  made-up devices".

**Site Report and exports**
- **Site Report:** Export's scan report is now the Site Report, one page that opens on any phone
  or computer and prints cleanly (or saves as a PDF): the site's name (typed in Export, kept for
  next time), when and how it was scanned and the networks covered; a summary of issues by level,
  devices by vendor and family and the devices needing attention first; every device with its
  firmware and the latest firmware; then known CVEs with their NVD pages, factory logins and
  factory defaults, firmware updates, latency, airMAX link health, every other issue and the
  devices' notes.
- **Scan data…** saves the device table as CSV or JSON (the scan report's CSV and JSON before).
- Phones ask for the site's name before sharing the Site Report, and offer Scan data (CSV).
- Command line: `--export FILE.html` writes the Site Report; `--site NAME` names the site.

**Config backups**
- **Back up all configs** (Device menu; **Back up all** on the phones' Tools): every device in
  the table that keeps a config (airMAX, airFiber, LTU, GigaBeam, EdgeOS), with its remembered
  login, three at a time in the background and never two SSH sessions on one device; devices
  behind others go through the logins of the devices on the way. Each says backed up, unchanged
  since its last backup (no second copy kept), or failed and why. Devices without a saved login
  are skipped and listed at the end, each with its own Back up… button that asks for the login.
  Stop cancels the rest.
- **Compare** (Config backups) shows what differs, line by line, between two backups or between
  one and the device's config now, which can then be kept as a backup. On desktops select two
  (or one); on phones pick the other from a list.
- Fixed: Config backups' Close button left the window remembered, so the menu item later tried
  to show the closed window.

**Link health (airMAX)**
- Device > **Link health…** (a phone's Tools: **Link health**) logs in to an airMAX radio
  (airOS 8 on AC, airOS 5 and 6 on M) and reads its wireless link from airOS's own `mca-status`
  and `wstalist`. For each link (each station on an access point, the AP on a station) it shows
  the signal at both ends with each chain's, the noise floor, SNR and CINR, the capacity down and
  up against what airOS expects (airOS 8) or the rates with airMAX Quality and Capacity (airMAX
  M), airtime, distance and latency. Details shows it in a Link section, the JSON export as each
  device's `link`, and the Site Report in its airMAX link health section. It lasts while the app
  is open: Rescan device and new scans keep it.
- Weak links are flagged with Ubiquiti's own figures (UISP Help Center): `WEAK-SIGNAL` (weaker
  than −65 dBm), `HOT-SIGNAL` (−40 dBm or stronger) and `CHAIN-IMBALANCE` (chains 4 dB apart) as
  notes; `LOW-SNR` (under 25 dB), `LOW-CAPACITY` (under half the expected capacity, or airMAX
  Capacity under 50%) and `LOW-QUALITY` (airMAX Quality under 80%) as warnings. An access point's
  issue names its stations.

**EdgeRouters**
- **Firmware updates:** Update firmware… (Firmware on phones) installs the latest EdgeOS release
  from Ubiquiti's firmware server the way Ubiquiti's help center gives it for the command line:
  checked (size and SHA-256), copied to the router and added with EdgeOS's `add system image`;
  the router is restarted only once EdgeOS lists the new image as the one it boots. The question
  says which of EdgeOS's two images stays as the backup and which is deleted. An update is
  refused while the router has config changes committed but not saved, which EdgeOS's installer
  would stop for.
- **Change login:** a new password, or a new username and password, through EdgeOS's own config
  commands (`set system login user … plaintext-password`, `commit`, `save`); EdgeOS hashes the
  password itself. A new name is made first, with the old login's level and settings, and the old
  login is deleted only once the app has logged in with the new one. EdgeOS 3's password rules
  are checked before anything is sent.
- Phones keep a config backup before a login change, as desktops do.

**Factory logins**
- When a device tool logs in with a factory login (ubnt/ubnt, ui/ui, root/ubnt or root/ui),
  OpenDisco says so once and flags the device `FACTORY-LOGIN` (Status: Factory login), on
  desktops and phones. The flag is kept by MAC address, so rescans and restarts keep it, until
  the login changes. Change login no longer takes a factory password.
- A device that reports factory defaults over discovery (`DEFAULT`) is a warning now (a note on
  UniFi OS consoles): until it's set up or adopted it takes its factory login, so anyone who can
  reach it can log in.

**Languages**
- The app speaks Spanish, Brazilian Portuguese and Japanese besides English: windows, menus,
  dialogs, the status line, issue messages and Status labels, Details, link health, the device
  tools' confirmations and errors, the Site Report and the demo network. It follows the system's
  language; Settings > Language (System, English, Español, Português (Brasil), 日本語) picks
  another, from the next start. The command line, the Log tab's scan lines, the Packets tab and
  CSV/JSON field names, Status values and tags stay English.
- **Terms of use in each language:** TERMS.es.md, TERMS.pt-BR.md and TERMS.ja.md, each saying
  that the English TERMS.md binds and controls. The terms window shows the app's language with a
  switch to the English original; the English text is still what's accepted and hashed (TERMS.md
  is unchanged).

**Linux**
- On a system without `ssh` and `scp`, the AppImage and the portable version use the app's own
  SSH client (asyncssh, as on phones) for Open SSH… and the device tools, where Open SSH… did
  nothing and the tools said they needed ssh and scp. Sessions stay in the Terminal tab with the
  same host keys; a password not given, or not taken, is asked for in the terminal, as ssh asks.
  SSH, Ping and Open Web UI through other devices work the same way. With no SSH client at all,
  Open SSH… says "(needs ssh)".
- The AppImage brings asyncssh 2.23.1 with cryptography 47.0.0 and cffi 2.1.1 (listed in
  THIRD-PARTY-NOTICES.md), and the portable version's first run installs asyncssh into its
  environment (into an earlier version's too).
- The AppImage updates itself: the new AppImage replaces it under its own name. (1.6.2's
  AppImage can't, and points to the release page.) Its Help > Visit homepage and About work.
- Forget SSH key works where `ssh-keygen` isn't installed.

**Command line**
- The terms message names the command that runs that copy: the AppImage file, the portable
  version's `opendisco` launcher, `opendisco.cmd` on Windows, `opendisco` from the .deb and .rpm;
  on macOS it says to accept them in the app. It always said `opendisco`.
- A target name too long to look up says it can't be resolved, where the command line ended
  with a Python traceback.

## 1.6.2 (2026-10-25)

- Linux: the .deb and the .rpm name the project's homepage,
  https://github.com/Nekobyte-Coding/opendisco, where `apt show` and `dnf info` gave "None".
  Nothing else changes; the terms of use are asked for again, as after every upgrade.
- Linux: an AppImage (`OpenDisco-1.6.2-linux-x86_64.AppImage`), added to the release afterwards
  and built from 1.6.2's source. It brings its own Python and Toga and uses the system's GTK 3
  and WebKitGTK 4.1, saying what to install where they're missing. It runs on Ubuntu 24.04,
  Debian 13, Fedora 40, Linux Mint 22 and later.

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
  secrets) is readable by its own account only, whether the app or the command line made it.
- Windows and Linux: the main window starts wider when the screen has room (up to 1500 pixels,
  centred), and each column of the device list gets the width its contents need. Too narrow
  for them all, the widest columns give up width first, and the IP and MAC addresses stay whole.
  At the first size, Linux had cut Name, Model and Via to a few characters, and Windows the
  firmware, names and statuses. On a screen smaller than the window, it opens at the top left.
- Linux: the app no longer hangs when it opens with a page of text to show (the terms of use).
- Android: Quit closes the app.
- iOS (beta): long texts (the terms, the licenses, Details) scroll under a finger.
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
