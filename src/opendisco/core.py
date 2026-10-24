#!/usr/bin/env python3
"""opendisco - find and diagnose Ubiquiti devices from one tool.

Combines the discovery methods of three Ubiquiti tools:

  Legacy Device Discovery Tool (Java)   UBNT discovery v1 probe, UDP 10001 broadcast
  WiFiman                               UBNT v1 + v2 probes, unicast subnet sweep,
                                        ARP/neighbour table vendor (OUI) matching
  UniFi Network app / controller        multicast 233.89.188.1 probe, passive listening
                                        for adoption announcements, mDNS + SSDP console
                                        discovery, UniFi OS console API

Every result is merged by MAC address and run through diagnostic checks (factory
default, no DHCP lease, fallback IP, wrong subnet, IP conflicts, recent reboot,
discovery blocked, competing controllers, ...).

Standard library only. Python 3.8+ on macOS, Linux and Windows.
"""
from __future__ import annotations

import argparse
import atexit
import bisect
import copy
import http.client
import ipaddress
import json
import os
import random
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from opendisco import __version__  # one version for the app, the CLI and the installers

UBNT_PORT = 10001
UBNT_MCAST = "233.89.188.1"
UBNT_V1_PROBE = b"\x01\x00\x00\x00"  # legacy Java tool, airOS, UniFi devices
UBNT_V2_PROBE = b"\x02\x08\x00\x00"  # UniFi OS consoles
MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)
FALLBACK_IP = "192.168.1.20"  # where UniFi/airOS devices sit without a DHCP lease
CHECK_PORTS = (22, 80, 443, 8080, 8443)
# Where a device can say which port its web UI or SSH is on, best source first.
PORT_SOURCES = {"discovery": "its discovery reply", "redirect": "its HTTP redirect",
                "mDNS": "its mDNS services", "UPnP": "its UPnP description"}
IS_WINDOWS = sys.platform.startswith("win")

STOP = threading.Event()  # a GUI's Stop button: ends the scan early, the way Ctrl+C does
SUDO_ASKPASS = None  # a GUI sets this to fn(reason) -> password or None; the CLI lets sudo prompt


def platform_name() -> str:
    if sys.platform == "ios" or getattr(sys.implementation, "_multiarch", "").endswith(("iphoneos", "iphonesimulator")):
        return "ios"
    if sys.platform == "android" or hasattr(sys, "getandroidapilevel"):
        return "android"
    if sys.platform == "darwin":
        return "macos"
    return "windows" if IS_WINDOWS else "linux"


def capabilities() -> dict:
    """What this platform lets the scanner do. Phones can't capture traffic, add addresses or
    tag VLANs; iOS also blocks broadcasts unless Apple grants the app the multicast entitlement."""
    plat = platform_name()
    unix_desktop = plat in ("macos", "linux")
    caps = {"platform": plat, "mobile": plat in ("ios", "android"),
            "aliases": unix_desktop, "listen": unix_desktop and bool(shutil.which("tcpdump")),
            "vlan_tagging": unix_desktop, "arp": plat in ("macos", "linux", "windows")}
    if plat == "windows":  # netsh adds addresses (as administrator); Npcap captures
        from opendisco import winnet
        caps["aliases"] = winnet.supports_temporary_addresses()
        caps["listen"] = winnet.npcap() is not None
    return caps

# Ubiquiti IEEE OUIs, from Wireshark's manuf database (Oct 2026). Add new ones with --oui.
UBNT_OUIS = {
    "00156D", "002722", "0418D6", "0CEA14", "18E829", "1C0B8B", "1C6A1B", "245A4C",
    "24A43C", "28704E", "2CE5BD", "44D9E7", "58D61F", "602232", "682E3C", "687251",
    "68D79A", "6C63F8", "70A741", "7483C2", "74ACB9", "74F92C", "74FA29", "784558",
    "788A20", "802AA8", "847848", "8C3066", "8CEDE1", "9041B2", "942A6F", "9C05D6",
    "A4F8FF", "A89C6C", "AC8BA9", "B4FBE4", "CC35D9", "D021F9", "D489C1", "D8B370",
    "D8C262", "DC9FDB", "E063DA", "E43883", "F09FC2", "F492BF", "F4E2C6", "FCECDA",
}

# Other vendors' IEEE OUIs, from Wireshark's manuf database (Oct 2026). These are identified by
# MAC address, LLDP and CDP only; UBNT discovery is never expected from them.
OTHER_VENDOR_OUIS = {
    "Meraki": """
        00180A 00841E 086A0B 08711C 08F1B3 0C7BC8 0C8DDB 149F43 1CE587 2C3F0B 303B49 3456FE 388479
        4027A8 4870D4 4CC8A1 5C0610 683A1E 684992 6C7DB7 6C7F0C 6CC3B2 6CDEA9 6CEFBD 780F81 881544
        8C8881 981888 9CE330 A04E8D A05911 A8469D AC17C8 AC69CF ACBDF7 ACC3E5 ACD31D B4DF91 B80756
        B8AB61 B8B4C9 BC3340 BCB1D3 BCDB09 C414A2 C48BA3 C4D666 C86340 CC03D9 CC6E2A CC9C3E D853AD
        DCBBFA E0553D E0CBBC E0D3B4 E455A8 F89E28 FC942E
    """,
    "Cisco": """
        00000C 000142 000143 000163 000164 000196 000197 0001C7 0001C9 000216 000217 00023D 00024A
        00024B 00027D 00027E 0002B9 0002BA 0002FC 0002FD 000331 000332 00036B 00036C 00039F 0003A0
        0003E3 0003E4 0003FD 0003FE 000427 000428 00044D 00044E 00046D 00046E 00049A 00049B 0004C0
        0004C1 0004DD 0004DE 000500 000501 000531 000532 00055E 00055F 000573 000574 00059A 00059B
        0005DC 0005DD 000628 00062A 000652 000653 00067C 0006C1 0006D6 0006D7 0006F6 00070D 00070E
        00074F 000750 00077D 000784 000785 0007B3 0007B4 0007EB 0007EC 000820 000821 00082F 000830
        000831 000832 00087C 00087D 0008A3 0008A4 0008C2 0008E2 0008E3 000911 000912 000943 000944
        00097B 00097C 0009B6 0009B7 0009E8 0009E9 000A41 000A42 000A8A 000A8B 000AB7 000AB8 000AF3
        000AF4 000B45 000B46 000B5F 000B60 000B85 000BBE 000BBF 000BFC 000BFD 000C30 000C31 000C85
        000C86 000CCE 000CCF 000D28 000D29 000D65 000D66 000DBC 000DBD 000DEC 000DED 000E38 000E39
        000E83 000E84 000ED6 000ED7 000F23 000F24 000F34 000F35 000F8F 000F90 000FF7 000FF8 001007
        00100B 00100D 001011 001014 00101F 001029 00102F 001054 001079 00107B 0010A6 0010F6 0010FF
        001120 001121 00115C 00115D 001192 001193 0011BB 0011BC 001200 001201 001243 001244 00127F
        001280 0012D9 0012DA 001319 00131A 00135F 001360 00137F 001380 0013C3 0013C4 00141B 00141C
        001469 00146A 0014A8 0014A9 0014F1 0014F2 00152B 00152C 001562 001563 0015C6 0015C7 0015F9
        0015FA 001646 001647 00169C 00169D 0016C7 0016C8 00170E 00170F 00173B 001759 00175A 001794
        001795 0017DF 0017E0 001818 001819 001873 001874 0018B9 0018BA 001906 001907 00192F 001930
        001955 001956 0019A9 0019AA 0019E7 0019E8 001A2F 001A30 001A6C 001A6D 001AA1 001AA2 001AE2
        001AE3 001B0C 001B0D 001B2A 001B2B 001B53 001B54 001B67 001B8F 001B90 001BD4 001BD5 001C0E
        001C0F 001C57 001C58 001CB0 001CB1 001CF6 001CF9 001D45 001D46 001D70 001D71 001DA1 001DA2
        001DE5 001DE6 001E13 001E14 001E49 001E4A 001E79 001E7A 001EBD 001EBE 001EF6 001EF7 001F26
        001F27 001F6C 001F6D 001F9D 001F9E 001FC9 001FCA 00211B 00211C 002155 002156 0021A0 0021A1
        0021D7 0021D8 00220C 00220D 002255 002256 002290 002291 0022BD 0022BE 002304 002305 002333
        002334 00235D 00235E 0023AB 0023AC 0023EA 0023EB 002413 002414 002450 002451 002497 002498
        0024C3 0024C4 0024F7 0024F9 002545 002546 002583 002584 0025B4 0025B5 00260A 00260B 002651
        002652 002698 002699 0026CA 0026CB 00270C 00270D 002790 0027E3 0029C2 002A10 002A6A 002CC8
        002F5C 003019 003024 003040 003071 003078 00307B 003080 003085 003094 003096 0030A3 0030B6
        0030F2 003217 00351A 0038DF 003A7D 003A98 003A99 003A9A 003A9B 003A9C 003C10 00400B 004096
        0041D2 00425A 004268 00451D 00500B 00500F 005014 00502A 00503E 005050 005053 005054 005073
        005080 0050A2 0050A7 0050BD 0050D1 0050E2 0050F0 00562B 0057D2 00596C 0059DC 005D73 005F86
        006009 00602F 00603E 006047 00605C 006070 006083 0062EC 006440 006BF1 006CBC 007278 007686
        00778D 007888 007E95 0081C4 008731 008764 008A96 008E73 00900C 009021 00902B 00905F 00906D
        00906F 009086 009092 0090A6 0090AB 0090B1 0090BF 0090D9 0090F2 009AD2 009E1E 00A289 00A2EE
        00A38E 00A3D1 00A5BF 00A6CA 00A742 00AA6E 00AF1F 00B04A 00B064 00B08E 00B0C2 00B0E1 00B1E3
        00B670 00B771 00B8B3 00BC60 00BE75 00BF77 00C164 00C1B1 00C88B 00CAE5 00CCFC 00D006 00D058
        00D063 00D079 00D090 00D097 00D0BA 00D0BB 00D0BC 00D0C0 00D0D3 00D0E4 00D0FF 00D6FE 00D78F
        00DA55 00DEFB 00DF1D 00E014 00E01E 00E034 00E04F 00E08F 00E0A3 00E0B0 00E0F7 00E0F9 00E0FE
        00E16D 00EABD 00EBD5 00EEAB 00F28B 00F663 00F82C 00FCBA 00FD22 00FEC8 042AE2 0430FA 045FB9
        046273 046C9D 0476B0 04A741 04BD97 04C5A4 04DAD2 04E387 04EB40 04FE7F 080FE5 081735 081FF3
        0845D1 084FA9 084FF9 08638A 087B87 0896AD 089707 08CC68 08CCA7 08D09F 08ECF5 08F3FB 08F4F0
        0ACD8F 0C1167 0C2643 0C2724 0C6803 0C72FB 0C75BD 0C8525 0CAF31 0CD0F8 0CD5D3 0CD996 0CF5A4
        1005CA 1006ED 105725 108CCF 1096C6 10A829 10B3C6 10B3D5 10B3D6 10BD18 10E376 10E676 10F311
        10F920 14169D 141923 148473 14A2A0 14BC68 14E22A 18339D 1859F5 188090 188B45 188B9D 189C5D
        18E728 18EF63 18F935 1C17D3 1C1D86 1C2226 1C6A7A 1C84A6 1CAA07 1CD1E0 1CDEA7 1CDF0F 1CE6C7
        1CE85D 1CFC17 200BC5 203706 203A07 204C9E 20BBC0 20CC27 20CFAE 20DBEA 20F120 2401C7 24161B
        24169D 242A04 2436DA 246C84 247121 247E12 24813B 24B657 24BA23 24D5E4 24D79C 24E9B3 2834A2
        285261 286B5C 286F7F 2893FE 28940F 28AC9E 28AFFD 28B591 28C7CE 2C01B5 2C0BE9 2C1A05 2C3124
        2C3311 2C36F8 2C3ECF 2C3F38 2C4F52 2C542D 2C5741 2C5A0F 2C658D 2C73A0 2C86D2 2CA2E5 2CABEB
        2CD02D 2CE38E 2CF814 2CF89B 3001AF 3037A6 308BB2 30E4DB 30F70D 30FEFA 341B2D 3454EF 34588A
        345DA8 346288 346F90 347069 34732D 348818 34A84E 34B883 34BDC8 34C3FD 34DBFD 34ED1B 34F8E7
        380E4D 381C1A 382056 3890A5 3891B7 38AA09 38ED18 38FDF8 3C08F6 3C0E23 3C13CC 3C26E4 3C410E
        3C510E 3C5731 3C5EC3 3C8B7F 3CCE73 3CDF1E 3CFEAC 40017A 4006D5 400999 401482 404244 405539
        406792 40A6E8 40B5C1 40CE24 40F078 40F49F 40F4EC 4403A7 441A5C 442B03 44643C 448816 448DD5
        44ADD9 44AE25 44B6BE 44C20C 44D3CA 44E4D9 4800B3 481BA4 482E72 487410 488002 488B0A 4891D5
        48A170 4C0082 4C01F7 4C421E 4C4E35 4C5D3C 4C710C 4C710D 4C776D 4C7A88 4CA64D 4CBC48 4CD0F9
        4CE175 4CE176 4CEC0F 5000E0 500604 5006AB 500F80 5017FF 501CB0 501CBF 502FA8 503DE5 504921
        5057A8 505C88 5061BF 5067AE 507164 508789 50BA84 50F722 544A00 5451DE 5475D0 54781A 547C69
        547FEE 5486BC 5488DE 548ABA 549FC6 54A274 580A20 5835D9 58569F 588B1C 588D09 58971E 5897BD
        58AC78 58BC27 58BFEA 58DF59 58F39C 5C3192 5C3E06 5C5015 5C5AC7 5C64F1 5C710D 5C838F 5CA48A
        5CA62D 5CB12E 5CE176 5CFC66 6026AA 60735C 60A954 60B9C0 60D178 6400F1 640864 641225 64168D
        643AEA 648F3E 649EF3 64A0E7 64AE0C 64D814 64D989 64E950 64F69D 680489 6815E4 681C52 682C7B
        683B78 687161 687909 687DB4 6886A7 6887C6 6899CD 689CE2 689E0B 68BC0C 68BDAB 68CAE4 68D972
        68E59E 68EFBD 6C0309 6C03B5 6C13D5 6C2056 6C29D2 6C310E 6C410E 6C416A 6C4EF6 6C4FA1 6C504D
        6C5E3B 6C6CD3 6C710D 6C8BD3 6C8D77 6C9989 6C9CED 6CAB05 6CB2AE 6CD6E3 6CDD30 6CFA89 7001B5
        700B4F 700F6A 70105C 7018A7 701F53 703509 70617B 70695A 706BB9 706D15 706E6D 70708B 7079B3
        707DB9 708105 70A983 70B317 70BC48 70BD96 70C9C6 70CA9B 70D379 70DA48 70DB98 70DF2F 70E422
        70EA1A 70F096 70F35A 740C2E 7411B2 7426AC 74860B 7488BB 748FC2 74A02F 74A2E6 74AD98 74E2E7
        7802B1 780CF0 78119D 7824BE 7864A0 78725D 788517 78BAF9 78BC1A 78DA6E 78F1C6 7C0ECE 7C210D
        7C210E 7C310E 7C62E7 7C69F6 7C8767 7C95F3 7CAD4F 7CAD74 7CB353 7CF880 80248F 80276C 802DBF
        806132 806A00 80E01D 80E86F 840C6D 843DC6 845A3E 8478AC 847CEE 847D7E 84802D 848A8D 84B261
        84B517 84B802 84DD84 84EBEF 84F147 84FFC2 881DFC 8843E1 884F59 885A92 887556 887ABC 88908D
        889CAD 88F031 88F077 88FC5D 8C142A 8C1E80 8C44A5 8C604F 8C8442 8C941F 8C9461 8CB50E 8CB64F
        905671 9077EE 908855 908A80 90E95E 90EB50 940D4B 9433D8 944667 94AEF0 94D469 98A2C0 98D7E1
        98F04C 9C098B 9C3818 9C4DC2 9C4E20 9C5416 9C57AD 9C6697 9CA9B8 9CAFCA 9CD57D 9CE176 A00F37
        A0239F A0334F A03D6E A03D6F A0554F A09351 A0A47F A0B439 A0BC6F A0C7D2 A0CF5B A0E0AF A0ECF9
        A0F849 A4004E A40CC3 A410B6 A411BB A41875 A44C11 A4530E A45630 A46C2A A47806 A48873 A4934C
        A49700 A49BCD A4A584 A4B239 A4B439 A4DCD5 A80C0D A84FB1 A89D21 A8B1D4 A8B456 AC2AA1 AC3A67
        AC4A56 AC4A67 AC7A56 AC7E8A ACA016 ACBCD9 ACD400 ACF2C5 ACF5E6 B000B4 B01BFC B02680 B02B64
        B07D47 B08BCF B08BD0 B08D57 B0907E B0A651 B0AA77 B0C53C B0FAEB B40216 B41489 B44C90 B4A4E3
        B4A8B9 B4CADD B4DE31 B4E9B0 B8114B B83861 B857D6 B8621F B8A377 B8BEBF B8C924 B8FE90 BC1665
        BC16F5 BC26C7 BC2CE6 BC4A56 BC5A56 BC671C BC8D1F BCABF5 BCB30E BCC493 BCD295 BCE712 BCF1F2
        BCFAEB C014FE C0255C C02897 C02C17 C0582E C0626B C064E4 C067AF C07BBC C08B2A C08C60 C0F87F
        C40ACB C4143C C418FC C444A0 C44606 C44B31 C44D84 C46413 C471FE C47295 C47D4F C47EE0 C4AA43
        C4AB4D C4B239 C4B36A C4B9CD C4C603 C4F7D5 C80084 C828E5 C834E5 C84709 C84C75 C8608F C878F7
        C88234 C884A1 C89C1D C8F9F9 CC167E CC36CF CC46D6 CC5A53 CC6A33 CC70ED CC79D7 CC7F75 CC7F76
        CC8E71 CC9070 CC9891 CCB6C8 CCD342 CCD539 CCD8C1 CCDB93 CCED4D CCEF48 D009C8 D02C39 D0574C
        D072DC D08543 D0A5A6 D0C282 D0C789 D0D0FD D0DC2C D0E042 D0EC35 D42B6F D42C44 D46624 D46A35
        D46D50 D47798 D4789B D47F35 D48CB5 D4A02A D4AD71 D4ADBD D4C93C D4D748 D4E880 D4EB68 D824BD
        D862CA D867D9 D8B190 DC0539 DC0B09 DC3979 DC5D89 DC774C DC7B94 DC8C37 DCA5F4 DCCEC1 DCD83B
        DCEB94 DCF719 E00EDA E02A66 E02F6D E05FB9 E069BA E0899D E08C3C E0ACF1 E0D173 E0D491 E4135C
        E41F7B E4379F E4387E E43A85 E44E2D E462C4 E489CA E4A41C E4AA5D E4C722 E4D3F1 E80462 E80AB9
        E84040 E85C0A E86549 E879A3 E8B748 E8BA70 E8BCE4 E8D322 E8DC6C E8EB34 E8EDF3 EC01D5 EC192E
        EC1D8B EC3091 EC4476 ECA1CC ECA78D ECBB78 ECBD1D ECC018 ECC882 ECCE13 ECDD24 ECE1A9 ECF40C
        F003BC F01D2D F02572 F02929 F04A02 F07816 F07F06 F09E63 F0B2E5 F0D805 F0F755 F40F1B F41FC2
        F43392 F44E05 F45BB4 F47470 F47F35 F48974 F4ACC1 F4B821 F4BD9E F4CFE2 F4DBE6 F4EA67 F4EE31
        F80BCB F80F6F F814DD F83918 F84F57 F866F2 F868FF F86BD9 F872EA F87A41 F87B20 F8A5C5 F8A73A
        F8B7E2 F8C288 F8C650 F8E57E F8E94F FC2120 FC589A FC5B39 FC7288 FC9947 FCFBFB
    """,
    "Mimosa": "20B5C6 849CA4 8CB6C5 9070BF CC54FE D0B0DF",
    "Siklu": "0024A4",
    "Ceragon": "000A25 08BAB7 3C4CD0 F4B5BB",
    "IgniteNet": "287610",
    "Baicells": "48BF74",
    "Tarana": "04F17D",
}
# Smaller IEEE blocks (MA-M /28, MA-S /36), matched on the first 7 or 9 hex digits.
OTHER_VENDOR_PREFIXES = {"8002F4B": "Baicells"}
_OUI_VENDOR = {oui: vendor for vendor, ouis in OTHER_VENDOR_OUIS.items() for oui in ouis.split()}

# Vendor names as they show up in LLDP/CDP system descriptions and platforms.
_VENDOR_WORDS = (
    ("Ubiquiti", re.compile(r"ubiquiti|ubnt|unifi|airos|uisp|edge(?:switch|router|max)", re.I)),
    ("Meraki", re.compile(r"meraki", re.I)),
    ("Cisco", re.compile(r"cisco|ios-xe|nx-os", re.I)),
    ("Mimosa", re.compile(r"mimosa", re.I)),
    ("Siklu", re.compile(r"siklu|etherhaul|multihaul", re.I)),
    ("Ceragon", re.compile(r"ceragon|fibeair", re.I)),
    ("IgniteNet", re.compile(r"ignitenet|metrolinq", re.I)),
    ("Baicells", re.compile(r"baicells", re.I)),
    ("Tarana", re.compile(r"tarana", re.I)),
)

# Factory-default management addresses, from installer guides (not vendor documentation):
# Siklu 192.168.0.1; Mimosa A5x/A6 192.168.1.20, A5/A5c 192.168.1.10; IgniteNet MetroLinq
# DHCP falling back to 192.168.1.20; Baicells eNB 192.168.150.1. --direct probes these subnets.
DEFAULT_ADDRESSES = {
    "Ubiquiti": ("192.168.1.20",),
    "Mimosa": ("192.168.1.20", "192.168.1.10"),
    "IgniteNet": ("192.168.1.20",),
    "Siklu": ("192.168.0.1",),
    "Baicells": ("192.168.150.1",),
}

# Names that mark an mDNS/SSDP responder as Ubiquiti when nothing else does.
UBNT_HINT = re.compile(
    r"ubnt|ubiquiti|unifi|amplifi|wifiman|edgerouter|edgeswitch|airos|airmax"
    r"|\b(?:udm|ucg|uck|unvr|uxg|udr|uap|usw|uvc)(?:[-_ ]|pro|\b)",
    re.I,
)

VIA_ORDER = ("ubnt", "mcast", "announce", "sniff", "wifi", "mdns", "ssdp", "arp")


# ---------------------------------------------------------------------------
# UBNT discovery protocol
# ---------------------------------------------------------------------------
# Packet: version(u8) command(u8) length(u16 BE), then TLVs of type(u8) length(u16 BE)
# value. Requests are an empty v1 or v2 header. Replies are v1/cmd 0, v2/cmd 6 or 9,
# or v0 (seen on UNVR). Field IDs follow Wireshark's packet-ubdp.c and Home
# Assistant's unifi-discovery library.

WLAN_MODES = {0: "none", 2: "station", 3: "access point"}


def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace").rstrip("\x00")


def _text_or_hex(b: bytes) -> str:
    s = b.rstrip(b"\x00")
    if s and all(32 <= c < 127 for c in s):
        return s.decode("ascii")
    return b.hex()


def _uint(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _flag(b: bytes) -> bool:
    return int.from_bytes(b, "big") != 0


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6]) if len(b) >= 6 else b.hex()


def _ipv4(b: bytes) -> str:
    return socket.inet_ntoa(b[:4]) if len(b) >= 4 else b.hex()


def _mac_ip(b: bytes):
    return {"mac": _mac(b[:6]), "ip": _ipv4(b[6:10])} if len(b) >= 10 else b.hex()


def _port_info(b: bytes):
    # MAC(6) + IPv4(4) + JSON, e.g. {"type":"WAN","name":"eth1","plugged":true}
    if len(b) < 10:
        return b.hex()
    out = {"mac": _mac(b[:6]), "ip": _ipv4(b[6:10])}
    try:
        extra = json.loads(b[10:].decode("utf-8"))
        if isinstance(extra, dict):
            out.update(extra)
    except ValueError:
        out["data"] = b[10:].hex()
    return out


def _webui(b: bytes):
    if len(b) == 4:  # u16 flags + u16 port (observed 0x0001 0x01bb = 443)
        flags, port = struct.unpack(">HH", b)
        return {"port": port, "flags": flags}
    return _text_or_hex(b)


def _sysid(b: bytes) -> str:
    return f"0x{int.from_bytes(b, 'little'):04x}" if len(b) == 2 else b.hex()


def _wlan_mode(b: bytes) -> str:
    n = _uint(b)
    return WLAN_MODES.get(n, f"mode {n}")


def _guid(b: bytes) -> str:
    try:
        return str(uuid.UUID(b.decode("ascii")))
    except (ValueError, UnicodeDecodeError):
        return b.hex()  # non-console devices reuse 0x2b for a binary blob


# type -> (key, label, decoder, may repeat)
TLV = {
    0x01: ("mac", "MAC address", _mac, False),
    0x02: ("interfaces", "Interface MAC/IP", _mac_ip, True),
    0x03: ("firmware", "Firmware", _text, False),
    0x04: ("ip_addr", "IP address", _ipv4, False),
    0x05: ("mac_alt", "MAC address (alt)", _mac, False),
    0x06: ("display_name", "Display name", _text, False),
    0x07: ("salt", "Salt", bytes.hex, False),
    0x08: ("rnd_challenge", "Random challenge", bytes.hex, False),
    0x09: ("challenge", "Challenge", bytes.hex, False),
    0x0A: ("uptime", "Uptime", _uint, False),
    0x0B: ("hostname", "Hostname", _text, False),
    0x0C: ("platform", "Platform", _text, False),
    0x0D: ("essid", "ESSID", _text, False),
    0x0E: ("wlan_mode", "Wireless mode", _wlan_mode, False),
    0x0F: ("webui", "Web UI", _webui, False),
    0x10: ("sysid", "System ID", _sysid, False),
    0x12: ("seq", "Sequence counter", _uint, False),
    0x13: ("serial_mac", "MAC address (serial)", _mac, False),
    0x14: ("model", "Model", _text, False),
    0x15: ("product_name", "Product name", _text, False),
    0x16: ("version", "Version", _text, False),
    0x17: ("is_default", "Factory default", _flag, False),
    0x18: ("locating", "Locating (LED blink)", _flag, False),
    0x19: ("dhcp_client", "DHCP client", _flag, False),
    0x1A: ("dhcp_bound", "DHCP lease bound", _flag, False),
    0x1B: ("platform_version", "Platform version", _text_or_hex, False),
    0x1C: ("ssh_port", "SSH port", _uint, False),
    0x20: ("device_id", "Device ID", _text_or_hex, False),
    0x2B: ("guid", "Console GUID", _guid, False),
    0x2F: ("primary_addr", "Primary address", _mac_ip, False),
    0x30: ("direct_connect_domain", "Direct-connect domain", _text, False),
    0x32: ("ports", "Port", _port_info, True),
    0x33: ("uuid", "UUID", _guid, False),
}
TLV_LABELS = {spec[0]: spec[1] for spec in TLV.values()}


@dataclass
class Packet:
    version: int
    command: int
    length: int
    fields: list
    raw: bytes

    @property
    def is_request(self) -> bool:
        return self.length == 0 and not self.fields


def parse_packet(data: bytes) -> Packet | None:
    if len(data) < 4:
        return None
    version, command, length = struct.unpack_from(">BBH", data)
    if version > 2:
        return None
    body = data[4:4 + length]
    fields, p = [], 0
    while p + 3 <= len(body):
        ftype, flen = struct.unpack_from(">BH", body, p)
        p += 3
        if p + flen > len(body):
            break
        fields.append((ftype, body[p:p + flen]))
        p += flen
    if version == 0 and not fields:
        return None
    return Packet(version, command, length, fields, data)


def decode_fields(pkt: Packet):
    info, unknown = {}, {}
    for ftype, raw in pkt.fields:
        spec = TLV.get(ftype)
        if spec is None:
            unknown[f"0x{ftype:02x}"] = raw.hex()
            continue
        key, _label, decoder, repeats = spec
        try:
            value = decoder(raw)
        except Exception:
            value = raw.hex()
        if repeats:
            info.setdefault(key, []).append(value)
        else:
            info[key] = value
    return info, unknown


# ---------------------------------------------------------------------------
# Packet checks
# ---------------------------------------------------------------------------
# Ethernet's CRC catches most damage before the OS sees a frame, and the OS drops IP and UDP
# packets with bad checksums (the interface and protocol error counters count both). What
# gets through can still be cut short or garbled, so each discovery packet is checked against
# the protocol's own structure. Damage that comes and goes points at the path; the same
# oddity in every packet of a kind is just how that firmware writes it.

TLV_SIZES = {0x01: 6, 0x02: 10, 0x04: 4, 0x05: 6, 0x0A: 4, 0x0E: 1, 0x10: 2, 0x12: 4, 0x13: 6, 0x2F: 10}
TEXT_TLVS = (0x03, 0x06, 0x0B, 0x0C, 0x0D, 0x14, 0x15, 0x16, 0x30)
PACKETS_KEPT = 60  # per device; damaged ones are kept in preference to sound ones
FRAMING = {"short", "version", "cut-short", "overrun"}  # where its fields start and end is lost
SOUND_ENOUGH = {"trailing", "stray", "fragment"}  # extra bytes, or not checkable: the fields still read right
UNTRUSTED = FRAMING | {"ip-short", "udp-short", "udp-length", "udp-checksum",  # known damaged, or whose is unclear
                       "size-01", "size-02", "size-05", "size-13", "size-2f"}
SNAPLEN = 1600  # tcpdump's capture length (TCPDUMP_ARGS): longer frames arrive cut


@dataclass
class PacketRecord:
    """One packet a device sent, kept so it can be inspected."""
    at: float  # time.time() when it arrived
    proto: str  # "UBNT", "mDNS", "SSDP", or what a captured frame carried (LLDP, CDP, ARP, DHCP...)
    src: str  # "ip:port", or the source MAC of a frame without IP
    via: str
    iface: str = ""  # the interface it came in on, when known
    vlan: int | None = None  # 0 = untagged, None = unknown
    data: bytes = b""  # the UDP payload; for a captured frame of another kind, the whole frame
    frame: bytes = b""  # the whole Ethernet frame, when it was captured off the wire
    problems: list = field(default_factory=list)  # (code, message)
    n: int = 0  # its number among the device's UBNT packets

    @property
    def kind(self) -> str:
        if self.proto != "UBNT" or len(self.data) < 4:
            return self.proto
        return f"v{self.data[0]} cmd {self.data[1]}"


def _tlv_walk(data: bytes):
    """A UBNT packet's fields as [(offset, type, value)], plus what's wrong with its framing.
    Offsets count from the start of the packet, as in the hex dump."""
    if len(data) < 4:
        return [], [("short", f"only {len(data)} bytes: too short for a UBNT header")]
    version, _command, length = struct.unpack_from(">BBH", data)
    if version > 2:
        return [], [("version", f"the version byte is {version}: not a UBNT discovery packet, or its "
                                "header is damaged")]
    fields, problems = [], []
    if 4 + length > len(data):
        problems.append(("cut-short", f"the header says {length} bytes of fields follow, but only "
                                      f"{len(data) - 4} arrived: cut short"))
    elif 4 + length < len(data):
        problems.append(("trailing", f"{len(data) - 4 - length} byte(s) after the {length} the header declares"))
    end, p = min(len(data), 4 + length), 4
    while p + 3 <= end:
        ftype, flen = struct.unpack_from(">BH", data, p)
        if p + 3 + flen > end:
            problems.append(("overrun", f"field 0x{ftype:02x} at byte 0x{p:04x} says it's {flen} bytes, "
                                        f"but only {end - p - 3} are left"))
            return fields, problems
        fields.append((p, ftype, data[p + 3:p + 3 + flen]))
        p += 3 + flen
    if p < end and 4 + length <= len(data):  # (when it was cut short, that's the next field's start)
        problems.append(("stray", f"{end - p} stray byte(s) after the last field"))
    return fields, problems


def check_packet(data: bytes) -> list:
    """What's wrong with a UBNT discovery packet, as [(code, message)]; [] when it's sound."""
    fields, problems = _tlv_walk(data)
    seen = Counter()
    for off, ftype, value in fields:
        seen[ftype] += 1
        name = TLV[ftype][1] if ftype in TLV else f"field 0x{ftype:02x}"
        want = TLV_SIZES.get(ftype)
        if want and len(value) != want:
            problems.append((f"size-{ftype:02x}", f"{name} at byte 0x{off:04x} is {len(value)} bytes, not {want}"))
        elif ftype in TEXT_TLVS:
            try:
                bad = any(ord(c) < 32 or ord(c) == 127 for c in value.rstrip(b"\x00").decode("utf-8"))
            except UnicodeDecodeError:
                bad = True
            if bad:
                problems.append((f"text-{ftype:02x}", f"{name} at byte 0x{off:04x} has unreadable characters"))
        elif ftype == 0x32 and len(value) > 10:
            try:
                json.loads(value[10:].decode("utf-8"))
            except ValueError:
                problems.append(("json-32", f"{name} at byte 0x{off:04x} carries broken JSON"))
    problems += [(f"twice-{t:02x}", f"{TLV[t][1]} appears {n} times") for t, n in seen.items()
                 if n > 1 and t in TLV and not TLV[t][3]]
    return problems


def _ones_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def check_ip_udp(ip: bytes, cut: bool = False):
    """Check a captured IPv4/UDP packet's lengths and checksums (the OS drops packets that
    fail these before any program sees them, so only a capture shows them). Returns
    (problems, UDP payload); the payload is None when it can't be trusted to be whole.
    cut: the capture kept only the start of the frame."""
    ihl = (ip[0] & 0x0F) * 4
    total, frag = struct.unpack_from(">H", ip, 2)[0], struct.unpack_from(">H", ip, 6)[0]
    problems = []
    if ihl < 20 or _ones_sum(ip[:ihl]) != 0xFFFF:
        problems.append(("ip-checksum", "bad IPv4 header checksum"))
    if frag & 0x3FFF:
        return problems + [("fragment", "arrived in IP fragments, so only the first could be checked")], None
    if total > len(ip):
        if not cut:
            problems.append(("ip-short", f"the IPv4 header says {total} bytes, but only {len(ip)} arrived"))
        return problems, None
    udp = ip[ihl:total]
    if len(udp) < 8:
        return problems + [("udp-short", "too short for a UDP header")], None
    ulen, csum = struct.unpack_from(">HH", udp, 4)
    if ulen != len(udp):
        problems.append(("udp-length", f"the UDP header says {ulen} bytes, the IPv4 packet carries {len(udp)}"))
        return problems, None
    if csum and _ones_sum(ip[12:20] + struct.pack(">BBH", 0, 17, ulen) + udp) != 0xFFFF:
        problems.append(("udp-checksum", "bad UDP checksum: the payload was damaged on the way"))
    return problems, udp[8:]


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

def norm_mac(mac: str) -> str:
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.strip())).lower()


def is_ubnt_mac(mac: str | None) -> bool:
    return bool(mac) and norm_mac(mac).replace(":", "")[:6].upper() in UBNT_OUIS


def vendor_of(mac: str | None) -> str:
    """Vendor from a MAC address: Ubiquiti or one of the other vendors this tool knows."""
    try:
        hexs = norm_mac(mac).replace(":", "").upper() if mac else ""
    except (ValueError, AttributeError):
        return ""
    if hexs[:6] in UBNT_OUIS:
        return "Ubiquiti"
    return (OTHER_VENDOR_PREFIXES.get(hexs[:9]) or OTHER_VENDOR_PREFIXES.get(hexs[:7])
            or _OUI_VENDOR.get(hexs[:6], ""))


def vendor_from_text(text: str) -> str:
    return next((vendor for vendor, words in _VENDOR_WORDS if text and words.search(text)), "")


def fmt_uptime(sec) -> str:
    if not isinstance(sec, int):
        return ""
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d{h:02d}h"
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


@dataclass
class Device:
    key: str
    mac: str | None = None
    ips: list = field(default_factory=list)
    other_macs: set = field(default_factory=set)
    info: dict = field(default_factory=dict)  # decoded UBNT TLVs, merged across reply variants
    variants: dict = field(default_factory=dict)  # (version, command, field types) -> latest TLVs
    unknown_tlvs: dict = field(default_factory=dict)
    via: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    console: bool = False
    mdns: dict = field(default_factory=dict)
    ssdp: dict = field(default_factory=dict)
    api: dict = field(default_factory=dict)
    ports: list | None = None  # TCP ports that answered a deep check (None = not checked)
    services: dict = field(default_factory=dict)  # port -> "ssh" / "https" / "http" / "open"
    port_hints: dict = field(default_factory=dict)  # "https"/"ssh" -> {source: port}, beyond discovery
    alias: dict = field(default_factory=dict)  # the temporary alias it was reached through
    direct: bool = False  # answered without an alias (old firmware answers other subnets)
    seen_on: set = field(default_factory=set)  # interfaces its UBNT replies arrived on
    vlan: int | None = None  # 0 = untagged, None = unknown
    vlan_parent: str = ""  # physical interface the VLAN rides on
    vlan_label: str = ""  # what the VLAN column shows (untagged -> native VLAN, default 1)
    lldp: dict = field(default_factory=dict)  # what it announced over LLDP (heard with --vlans/--direct)
    wifi: dict = field(default_factory=dict)  # set when it's the access point a Wi-Fi port is joined to
    ubnt_packets: int = 0
    last_packet: bytes = b""
    packets: list = field(default_factory=list)  # its latest UBNT packets (PacketRecord)
    samples: list = field(default_factory=list)  # the first packet of each other kind it was found from
    reply_times: list = field(default_factory=list)  # when each answer to our probes arrived
    kind_counts: Counter = field(default_factory=Counter)  # packet kind -> UBNT packets received
    problem_counts: Counter = field(default_factory=Counter)  # (kind, problem code) -> packets with it
    sound_kinds: set = field(default_factory=set)  # kinds it has sent at least one sound packet of
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    issues: list = field(default_factory=list)  # (level, tag, message)

    def add_ip(self, ip: str | None) -> None:
        if ip and ip != "0.0.0.0" and ip not in self.ips:
            self.ips.append(ip)

    def add_sample(self, rec: "PacketRecord") -> None:
        if len(self.samples) < 8 and all(s.proto != rec.proto for s in self.samples):
            self.samples.append(rec)

    @property
    def ip(self) -> str:
        return self.ips[0] if self.ips else ""

    @property
    def system(self) -> dict:
        sysinfo = self.api.get("system")
        return sysinfo if isinstance(sysinfo, dict) else {}

    @property
    def model(self) -> str:
        i = self.info
        hw = self.system.get("hardware")
        hw = hw if isinstance(hw, dict) else {}
        return (i.get("model") or i.get("product_name") or i.get("platform") or hw.get("shortname")
                or self.ssdp.get("modelName") or self.ssdp.get("modelDescription")
                or self.lldp.get("platform") or self.lldp.get("description", "").split(",")[0]
                or ("Wi-Fi access point" if self.wifi else ""))

    @property
    def web_port(self) -> int | None:
        """The HTTPS web UI port the device reports in UBNT discovery. Flag bit 0 marks the port
        as the web UI: a UniFi Express sends 0x0001 with 443, while a UCG Fiber sends 0x0000 with
        7080, which nothing outside answers on."""
        webui = self.info.get("webui")
        if isinstance(webui, dict) and webui.get("port") and webui.get("flags", 0) & 1:
            return webui["port"]
        return None

    @property
    def reported_ssh_port(self) -> int | None:
        """The SSH port the device reports in UBNT discovery."""
        port = self.info.get("ssh_port")
        return port if isinstance(port, int) and port else None

    def said_ports(self, kind: str) -> dict:
        """What the device says its "https" or "ssh" port is, {source: port}, best source first."""
        reported = self.web_port if kind == "https" else self.reported_ssh_port
        said = dict(self.port_hints.get(kind, {}), **({"discovery": reported} if reported else {}))
        return {source: said[source] for source in PORT_SOURCES if source in said}

    def said_port(self, kind: str) -> int | None:
        """The port the device says its web UI ("https") or SSH ("ssh") is on, if it says."""
        return next(iter(self.said_ports(kind).values()), None)

    def port(self, kind: str) -> int:
        """The port to connect to: one a deep check found the service on (the one the device
        says, when it's there), else the one it says, else the standard one."""
        said = self.said_port(kind)
        found = sorted((p for p, k in self.services.items() if k == kind), key=lambda p: p != said)
        return found[0] if found else said or (443 if kind == "https" else 22)

    @property
    def vendor(self) -> str:
        if self.ubnt_packets or self.console:
            return "Ubiquiti"
        for mac in (self.mac, self.lldp.get("chassis_mac"), *sorted(self.other_macs)):
            if vendor_of(mac):
                return vendor_of(mac)
        return (vendor_from_text(" ".join(self.lldp.get(k, "") for k in ("description", "platform", "system")))
                or self.wifi.get("vendor", ""))

    @property
    def name(self) -> str:
        i = self.info
        mdns_host = next(iter(self.mdns.get("hostnames", [])), "")
        if mdns_host.endswith(".local"):
            mdns_host = mdns_host[:-6]
        return (i.get("hostname") or i.get("display_name") or self.system.get("name")
                or mdns_host or self.ssdp.get("friendlyName") or self.lldp.get("system")
                or (f'SSID "{self.wifi["ssid"]}"' if self.wifi.get("ssid") else "") or "")

    @property
    def firmware(self) -> str:
        # 0x03 is the device firmware ("BZ.qca956x.v6.5.28..." or plain "5.2.10" on UniFi OS);
        # on consoles 0x16 is the Network application version, so it's only a fallback.
        fw = self.info.get("firmware") or ""
        m = re.search(r"\.v(\d+(?:\.\d+){1,3})", fw)
        return m.group(1) if m else (fw or self.info.get("version") or "")

    def merge(self, other: "Device") -> None:
        for ip in other.ips:
            self.add_ip(ip)
        self.other_macs |= other.other_macs
        for k, v in other.info.items():
            self.info.setdefault(k, v)
        for k, v in other.variants.items():
            self.variants.setdefault(k, v)
        self.unknown_tlvs.update(other.unknown_tlvs)
        self.via |= other.via
        self.protocols |= other.protocols
        self.console = self.console or other.console
        for kind, hints in other.port_hints.items():
            self.port_hints.setdefault(kind, {}).update(hints)
        self.mdns = self.mdns or other.mdns
        self.ssdp = self.ssdp or other.ssdp
        self.api = self.api or other.api
        self.alias = self.alias or other.alias
        self.direct = self.direct or other.direct
        self.seen_on |= other.seen_on
        self.lldp = self.lldp or other.lldp
        self.wifi = self.wifi or other.wifi
        if self.vlan is None:
            self.vlan, self.vlan_parent = other.vlan, other.vlan_parent
        self.ubnt_packets += other.ubnt_packets
        self.last_packet = self.last_packet or other.last_packet
        self.packets = sorted(self.packets + other.packets, key=lambda r: r.at)[-PACKETS_KEPT:]
        for rec in other.samples:
            self.add_sample(rec)
        self.reply_times = sorted(self.reply_times + other.reply_times)
        self.kind_counts += other.kind_counts
        self.problem_counts += other.problem_counts
        self.sound_kinds |= other.sound_kinds
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)


WATCH_KEYS = ("is_default", "locating", "dhcp_bound", "firmware", "version", "hostname")


class Inventory:
    """All devices seen, keyed by MAC (or "ip:<addr>" until a MAC turns up)."""

    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.requesters: dict[str, set] = {}  # ip -> source ports of bare discovery probes
        self.garbled: dict[str, list] = {}  # ip -> packets on UDP 10001 too damaged to tell whose
        self.rounds: list = []  # (time, [(network, interface)]) of each round of probes sent

    def keep_packet(self, dev: Device | None, rec: PacketRecord) -> None:
        """Keep a UBNT packet to inspect later: with its device, or by sender when it was too
        damaged to tell whose it is."""
        if dev is None:
            kept = self.garbled.setdefault(rec.src.rsplit(":", 1)[0], [])
            kept.append(rec)
            del kept[:-20]
            return
        rec.n = dev.ubnt_packets
        dev.kind_counts[rec.kind] += 1
        codes = {code for code, _ in rec.problems}
        for code in codes:
            dev.problem_counts[(rec.kind, code)] += 1
        if not codes - SOUND_ENOUGH:
            dev.sound_kinds.add(rec.kind)
        if rec.via in ("ubnt", "mcast"):  # answers to our probes, for counting missed rounds
            dev.reply_times.append(rec.at)
            del dev.reply_times[:-20000]
        dev.packets.append(rec)
        if len(dev.packets) > PACKETS_KEPT:  # drop the oldest sound one, so damaged ones stay to be seen
            del dev.packets[next((i for i, r in enumerate(dev.packets) if not r.problems), 0)]

    def find(self, mac: str | None = None, ip: str | None = None) -> Device | None:
        if mac:
            mac = norm_mac(mac)
            if mac in self.devices:
                return self.devices[mac]
            for d in self.devices.values():
                if mac in d.other_macs:
                    return d
        if ip:
            for d in self.devices.values():
                if ip in d.ips:
                    return d
        return None

    def lookup(self, mac: str | None = None, ip: str | None = None) -> Device:
        """Return the device for this MAC/IP, creating or re-keying records as needed."""
        if mac:
            mac = norm_mac(mac)
            dev = self.find(mac=mac)
            orphan = next((d for d in self.devices.values() if d.mac is None and ip in d.ips), None) if ip else None
            if dev is None and orphan is not None:
                del self.devices[orphan.key]
                orphan.key = orphan.mac = mac
                self.devices[mac] = orphan
                return orphan
            if dev is None:
                dev = self.devices[mac] = Device(key=mac, mac=mac)
            elif orphan is not None and orphan is not dev:
                dev.merge(orphan)
                del self.devices[orphan.key]
            return dev
        dev = self.find(ip=ip)
        if dev is None:
            dev = self.devices["ip:" + ip] = Device(key="ip:" + ip)
            dev.add_ip(ip)
        return dev

    def attach(self, ip: str, mac: str | None, via: str) -> Device:
        """Attach a sighting from a non-UBNT source (ARP, mDNS, SSDP) by IP first."""
        dev = self.find(ip=ip)
        if dev is None or (dev.mac is None and mac):
            dev = self.lookup(mac=mac, ip=ip)
        elif mac and dev.mac and norm_mac(mac) != dev.mac:
            dev.other_macs.add(norm_mac(mac))
        dev.add_ip(ip)
        dev.via.add(via)
        return dev

    def ingest_checked(self, pkt: Packet, rec: PacketRecord, addr, via: str):
        """ingest_ubnt for a checked packet, which is then kept with its device. A damaged
        packet's fields are only taken while they're all there is: not when they can't be
        trusted (a broken MAC would show up as a phantom device), and not once the device has
        sent a sound packet of that kind (then the damage happened on the way, rather than
        being how its firmware writes them). One with a bad IP header is kept by sender."""
        damage = {code for code, _ in rec.problems} - SOUND_ENOUGH
        if "ip-checksum" in damage:  # even the sender's address may be wrong
            self.keep_packet(None, rec)
            return None, []
        known = self.find(ip=addr[0])
        if damage and (damage & UNTRUSTED or (known is not None and rec.kind in known.sound_kinds)):
            dev, changes = self.lookup(ip=addr[0]), []
            dev.via.add(via)
            dev.protocols.add(f"v{pkt.version}")
            dev.ubnt_packets += 1
            dev.last_seen = time.time()
        else:
            dev, changes = self.ingest_ubnt(pkt, addr, via)
        self.keep_packet(dev, rec)
        return dev, changes

    def ingest_ubnt(self, pkt: Packet, addr, via: str):
        info, unknown = decode_fields(pkt)
        ip = addr[0]
        ifaces = [x for x in info.get("interfaces", []) if isinstance(x, dict)]
        primary = info.get("primary_addr") if isinstance(info.get("primary_addr"), dict) else None
        mac = (info.get("mac")
               or (primary or {}).get("mac")
               or next((x["mac"] for x in ifaces if x["ip"] == ip), None)
               or (ifaces[0]["mac"] if ifaces else None)
               or info.get("serial_mac") or info.get("mac_alt"))
        if mac and not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            mac = None
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            mac = None

        dev = self.lookup(mac=mac, ip=ip)
        # One device can send differently shaped replies (a UniFi Express answers multicast
        # with a full reply and broadcast with a short v2 one) that format the same field
        # differently (firmware "5.2.10" vs "UXMAX.ipq5322.v5.2.10..."). Track each shape
        # separately so watch mode compares like with like; the richest one wins in .info.
        variant = (pkt.version, pkt.command, tuple(sorted({t for t, _ in pkt.fields})))
        prev = dev.variants.get(variant, {})
        before = {k: prev.get(k) for k in WATCH_KEYS}
        before["uptime"] = dev.info.get("uptime")  # same meaning in every variant
        old_ips = list(dev.ips)
        is_new = dev.ubnt_packets == 0

        dev.add_ip(ip)
        if primary:
            dev.add_ip(primary["ip"])
        for x in ifaces:
            dev.add_ip(x["ip"])
        dev.variants[variant] = info
        dev.info = {}
        for _, fields in sorted(dev.variants.items(), key=lambda kv: len(kv[0][2])):
            dev.info.update(fields)
        dev.unknown_tlvs.update(unknown)
        dev.via.add(via)
        dev.protocols.add(f"v{pkt.version}")
        if pkt.version in (0, 2):
            dev.console = True  # v0/v2 responders are UniFi OS consoles
        dev.ubnt_packets += 1
        dev.last_packet = pkt.raw
        dev.last_seen = time.time()

        changes = []
        if is_new:
            changes.append(("NEW", ""))
        else:
            if old_ips and ip not in old_ips:
                changes.append(("IP", f"{old_ips[0]} -> {ip}"))
            ou, nu = before["uptime"], info.get("uptime")
            if isinstance(ou, int) and isinstance(nu, int) and nu + 30 < ou:
                changes.append(("REBOOT", f"uptime {fmt_uptime(ou)} -> {fmt_uptime(nu)}"))
            for k in WATCH_KEYS:
                if k in info and before[k] is not None and info[k] != before[k]:
                    changes.append(("CHANGED", f"{TLV_LABELS.get(k, k)}: {before[k]} -> {info[k]}"))
        return dev, changes


# ---------------------------------------------------------------------------
# Local network information
# ---------------------------------------------------------------------------

@dataclass
class Iface:
    name: str
    ip: str
    prefix: int
    label: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.ip}/{self.prefix}", strict=False)

    @property
    def broadcast(self) -> str | None:
        return str(self.network.broadcast_address) if self.prefix < 31 else None

    def __str__(self) -> str:
        name = f"{self.name} ({self.label})" if self.label else self.name
        return f"{name} {self.ip}/{self.prefix}"


@dataclass
class Link:
    """A physical Ethernet or Wi-Fi interface with link up, whether or not it has an address."""
    name: str
    label: str
    wireless: bool = False
    addrs: list = field(default_factory=list)
    vlan: int | None = None  # set for a tagged interface this tool creates on `parent`
    parent: str = ""
    active: bool = True  # has link

    @property
    def tag(self) -> str:
        return f"VLAN {self.vlan} on {self.parent}" if self.vlan else self.name

    def __str__(self) -> str:
        if self.vlan:
            return self.tag
        addrs = ", ".join(f"{i.ip}/{i.prefix}" for i in self.addrs) or "no IPv4"
        return f"{self.name} ({self.label}, {addrs})"


def _run(cmd) -> str:
    # In the Windows GUI (pythonw, no console) each ipconfig/arp would otherwise flash a console window.
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                              errors="replace", creationflags=flags).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _mask_to_prefix(mask: str) -> int | None:
    try:
        if mask.lower().startswith("0x"):
            mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ValueError, OverflowError):
        return None


def _parse_ip_addr(text: str) -> list:
    out = []
    for line in text.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            out.append(Iface(m.group(1), m.group(2), int(m.group(3))))
    return out


def _parse_ifconfig(text: str) -> list:
    out, name = [], "?"
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split()[0].rstrip(":")
        m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+).*?(?:netmask|Mask:)\s*"
                      r"(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", line)
        if m:
            prefix = _mask_to_prefix(m.group(2))
            if prefix is not None:
                out.append(Iface(name, m.group(1), prefix))
    return out


def _parse_ipconfig(text: str) -> list:
    out, name, pending = [], "?", None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            name, pending = line.strip().rstrip(":"), None
            continue
        m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            pending = m.group(1)
            continue
        m = re.search(r":\s*(255\.\d+\.\d+\.\d+)\s*$", line)
        if m and pending:
            prefix = _mask_to_prefix(m.group(1))
            if prefix is not None:
                out.append(Iface(name, pending, prefix))
            pending = None
    return out


def local_interfaces() -> list:
    if IS_WINDOWS:
        from opendisco import winnet
        ifaces = ([Iface(name, ip, prefix) for name, ip, prefix in winnet.ipv4_addresses()]
                  or _parse_ipconfig(_run(["ipconfig"])))
    else:
        ifaces = _parse_ip_addr(_run(["ip", "-o", "-4", "addr", "show"])) or _parse_ifconfig(_run(["ifconfig"]))
    ifaces = [i for i in ifaces if not i.ip.startswith("127.")]
    if not ifaces:
        try:  # last resort: the address of the default route, assume a /24
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))
                ifaces = [Iface("default", s.getsockname()[0], 24)]
        except OSError:
            pass
    seen, unique = set(), []
    for i in ifaces:
        if i.ip not in seen:
            seen.add(i.ip)
            unique.append(i)
    return unique


def _parse_hardware_ports(text: str) -> dict:
    """macOS `networksetup -listallhardwareports` -> {device: port name}."""
    ports, label = {}, None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            label = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and label:
            ports[line.split(":", 1)[1].strip()] = label
            label = None
    return ports


def _parse_ifconfig_status(text: str) -> dict:
    """macOS `ifconfig` -> {interface: True if "status: active"}."""
    status, name = {}, None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split()[0].rstrip(":")
            continue
        m = re.match(r"\s+status:\s+(\w+)", line)
        if m and name:
            status[name] = m.group(1) == "active"
    return status


# Hardware ports that are never where gear is plugged in (Thunderbolt bridge members, tethering).
_SKIP_PORTS = re.compile(r"bridge|bluetooth|iphone|ipad|^thunderbolt \d+$", re.I)


def active_links(all_ifaces) -> list:
    """Ethernet/Wi-Fi interfaces with link up, wired first. Empty on Windows."""
    return [l for l in hardware_links(all_ifaces) if l.active]


def hardware_links(all_ifaces) -> list:
    """Every Ethernet/Wi-Fi port, with .active saying whether it has link."""
    links = []
    if IS_WINDOWS:
        from opendisco import winnet
        links = [Link(a["name"], a["description"] or ("Wi-Fi" if a["wireless"] else "Ethernet"), a["wireless"],
                      active=a["up"]) for a in winnet.adapters()]
    elif sys.platform == "darwin":
        status = _parse_ifconfig_status(_run(["ifconfig"]))
        for name, label in _parse_hardware_ports(_run(["networksetup", "-listallhardwareports"])).items():
            if name in status and not _SKIP_PORTS.search(label):
                links.append(Link(name, label, label.lower() in ("wi-fi", "airport"), active=status[name]))
    elif sys.platform.startswith("linux"):
        base = "/sys/class/net"
        try:
            names = sorted(os.listdir(base))
        except OSError:
            names = []
        for name in names:
            path = os.path.join(base, name)
            if not os.path.exists(os.path.join(path, "device")):  # virtual: lo, docker0, veth, tun...
                continue
            try:
                with open(os.path.join(path, "carrier")) as f:
                    carrier = f.read().strip() == "1"
            except OSError:  # reading carrier on an interface that's down raises EINVAL
                carrier = False
            wireless = os.path.isdir(os.path.join(path, "wireless"))
            links.append(Link(name, "Wi-Fi" if wireless else "Ethernet", wireless, active=carrier))
    for link in links:
        link.addrs = [i for i in all_ifaces if i.name == link.name]
    return sorted(links, key=lambda l: (l.wireless, l.name))


def link_media(name: str) -> str:
    """Negotiated speed/duplex, e.g. "1000baseT full-duplex"."""
    if IS_WINDOWS:
        from opendisco import winnet
        a = next((a for a in winnet.adapters() if a["name"] == name), None)
        return " ".join(x for x in (a["speed"], a["duplex"]) if x) if a else ""
    if sys.platform == "darwin":
        m = re.search(r"media: \S+(?: <[^>]*>)? \(([^)<]+?)\s*(?:<([^>]*)>)?\)", _run(["ifconfig", name]))
        return " ".join(x for x in (m.group(1), m.group(2)) if x) if m else ""
    try:
        with open(f"/sys/class/net/{name}/speed") as f:
            speed = int(f.read().strip())
        with open(f"/sys/class/net/{name}/duplex") as f:
            duplex = f.read().strip()
        return f"{speed} Mb/s {duplex}-duplex" if speed > 0 else ""
    except (OSError, ValueError):
        return ""


_MASKED_MAC = "02:00:00:00:00:00"


def local_macs() -> set:
    """This computer's own MAC addresses, so captures can ignore its own frames. On macOS
    networksetup still reports them when Local Network privacy masks ifconfig's."""
    macs = set()
    if IS_WINDOWS:
        from opendisco import winnet
        macs = {norm_mac(a["mac"]) for a in winnet.adapters() if a["mac"]}
    elif os.path.isdir("/sys/class/net"):
        for name in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{name}/address") as f:
                    macs.add(norm_mac(f.read().strip()))
            except (OSError, ValueError):
                pass
    elif sys.platform == "darwin":
        found = re.findall(r"(?:\bether|Ethernet Address:) ((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})",
                           _run(["ifconfig"]) + _run(["networksetup", "-listallhardwareports"]))
        macs = {norm_mac(m) for m in found}
    return macs - {"00:00:00:00:00:00", _MASKED_MAC}


def macs_hidden() -> bool:
    """True when macOS is masking MAC addresses (and the ARP table) from this process."""
    if sys.platform != "darwin":
        return False
    found = re.findall(r"\bether (\S+)", _run(["ifconfig"]))
    return bool(found) and all(norm_mac(m) == _MASKED_MAC for m in found)


def wifi_association(iface: str, sudo) -> dict:
    """SSID and BSSID of the access point a Wi-Fi interface is joined to. macOS hides both
    from ordinary programs (they need Location Services); `wdutil info` run as root may not."""
    info = {"iface": iface}
    if IS_WINDOWS:
        from opendisco import winnet
        found = winnet.wifi_association(iface)
        if found.get("bssid"):
            info["bssid"] = norm_mac(found["bssid"])
            info["vendor"] = bssid_vendor(info["bssid"])
        if found.get("ssid"):
            info["ssid"] = found["ssid"]
        return info
    if sys.platform == "darwin":
        out = _run((["sudo", "-n"] if sudo else []) + ["wdutil", "info"])
        bssid = re.search(r"^\s*BSSID\s*:\s*((?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2})\s*$", out, re.M)
        ssid = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", out, re.M)
    else:
        out = _run(["iw", "dev", iface, "link"])
        bssid = re.search(r"Connected to ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", out)
        ssid = re.search(r"SSID: (.+)", out)
    if bssid:
        info["bssid"] = norm_mac(bssid.group(1))
        info["vendor"] = bssid_vendor(info["bssid"])
    if ssid and "redacted" not in ssid.group(1):
        info["ssid"] = ssid.group(1).strip()
    return info


def bssid_vendor(bssid: str) -> str:
    """Vendor behind a BSSID. APs derive BSSIDs from their own MAC, usually by setting the
    locally-administered bit and a couple of low bits in the first octet, so try those."""
    first, rest = int(bssid[:2], 16), bssid[2:]
    for octet in [first] + [(first & ~0x0E) | bits for bits in range(0, 16, 2)]:
        vendor = vendor_of(f"{octet:02x}{rest}")
        if vendor:
            return vendor
    return ""


def describe_wifi(info: dict) -> str:
    if info.get("bssid"):
        who = f"{info['vendor']} access point" if info.get("vendor") else "access point (vendor unknown)"
        ssid = f' "{info["ssid"]}"' if info.get("ssid") else ""
        return f"joined to {who}{ssid}, BSSID {info['bssid']}"
    return "joined to an access point macOS won't name: it hides the BSSID, even from wdutil"


def place_wifi_ap(inv: "Inventory", trunks) -> None:
    """Show the access point each Wi-Fi port is joined to: on the device it belongs to when one
    was found (BSSIDs share the AP MAC's last octets), otherwise as a row of its own."""
    for tr in trunks:
        info = tr.wifi
        if not info.get("bssid"):
            continue
        b = bytes.fromhex(info["bssid"].replace(":", ""))

        def related(mac):
            m = bytes.fromhex(norm_mac(mac).replace(":", ""))
            return m[3:5] == b[3:5] and abs(m[5] - b[5]) <= 16

        match = next((d for d in inv.devices.values() for mac in [d.mac, *d.other_macs]
                      if mac and related(mac) and (not info.get("vendor") or d.vendor == info["vendor"])), None)
        if match is None:
            key = f"bssid:{info['bssid']}"
            match = inv.devices.setdefault(key, Device(key=key))
        match.wifi = info
        match.via.add("wifi")


def os_vlan_map() -> dict:
    """VLAN interfaces that already exist: {interface: (vlan id, parent)}."""
    out = {}
    if sys.platform == "darwin":
        name = None
        for line in _run(["ifconfig"]).splitlines():
            if line and not line[0].isspace():
                name = line.split()[0].rstrip(":")
            m = re.search(r"vlan: (\d+) parent interface: (\S+)", line)
            if m and name:
                out[name] = (int(m.group(1)), m.group(2))
    elif os.path.exists("/proc/net/vlan/config"):
        try:
            with open("/proc/net/vlan/config") as f:
                for line in f.read().splitlines()[2:]:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) == 3 and parts[1].isdigit():
                        out[parts[0]] = (int(parts[1]), parts[2])
        except OSError:
            pass
    return out


_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2})(?![0-9A-Fa-f:-])")
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


ARP_SUDO: list = []  # ["sudo", "-n"] once this run holds sudo: macOS may filter the ARP table for Python


COUNTER_LABELS = {
    "in_errors": "input errors (damaged frames: bad CRC, runts)",
    "out_errors": "output errors",
    "collisions": "collisions",
    "drops": "dropped packets",
    "crc_errors": "CRC errors",
    "frame_errors": "framing errors",
    "length_errors": "length errors",
    "overruns": "overruns",
    "ip_checksum": "IP packets with a bad header checksum",
    "ip_header": "IP packets with a bad header",
    "ip_short": "IP packets shorter than their header says",
    "udp_checksum": "UDP datagrams with a bad checksum",
    "udp_length": "UDP datagrams with a bad length",
}


def interface_counters(names) -> dict:
    """This computer's error counters: {"interfaces": {name: {counter: n}}, "system": {counter: n}}.
    Damaged frames never reach a program, so these are the only place they show up. Windows
    only gives totals for all adapters together."""
    names, plat = set(names), platform_name()
    out = {"interfaces": {}, "system": {}}
    try:
        if plat == "macos":
            for line in _run(["netstat", "-i", "-d", "-n"]).splitlines():
                cols = line.split()  # Name Mtu Network [Address] Ipkts Ierrs Opkts Oerrs Coll Drop
                name = cols[0].rstrip("*") if cols else ""
                if name in names and len(cols) >= 9 and cols[2].startswith("<Link#") and all(
                        c.isdigit() for c in cols[-6:]):
                    _ipkts, ierrs, _opkts, oerrs, coll, drop = map(int, cols[-6:])
                    out["interfaces"][name] = {"in_errors": ierrs, "out_errors": oerrs, "collisions": coll,
                                               "drops": drop}
            stats = _run(["netstat", "-s", "-p", "ip"]) + _run(["netstat", "-s", "-p", "udp"])
            for key, pattern in (("ip_checksum", r"(\d+) bad header checksum"),
                                 ("ip_short", r"(\d+) with data size < data length"),
                                 ("udp_checksum", r"(\d+) with bad checksum"),
                                 ("udp_length", r"(\d+) with bad data length field")):
                m = re.search(pattern, stats)
                if m:
                    out["system"][key] = int(m.group(1))
        elif plat == "linux":
            for name in names:
                values = {}
                for key, stat in (("in_errors", "rx_errors"), ("out_errors", "tx_errors"),
                                  ("collisions", "collisions"), ("drops", "rx_dropped"),
                                  ("crc_errors", "rx_crc_errors"), ("frame_errors", "rx_frame_errors"),
                                  ("length_errors", "rx_length_errors"), ("overruns", "rx_over_errors")):
                    try:
                        with open(f"/sys/class/net/{name}/statistics/{stat}") as f:
                            values[key] = int(f.read())
                    except (OSError, ValueError):
                        pass
                if values:
                    out["interfaces"][name] = values
            with open("/proc/net/snmp") as f:
                lines = f.read().splitlines()
            table = {}
            for head, nums in zip(lines[::2], lines[1::2]):
                proto, keys = head.split(":", 1)
                table[proto] = dict(zip(keys.split(), nums.split(":", 1)[1].split()))
            for key, proto, stat in (("ip_header", "Ip", "InHdrErrors"), ("udp_checksum", "Udp", "InCsumErrors")):
                if stat in table.get(proto, {}):
                    out["system"][key] = int(table[proto][stat])
        elif plat == "windows":  # "Errors <received> <sent>" and "Discards ..." for all adapters
            text = _run(["netstat", "-e"])
            errors = re.search(r"^Errors\s+(\d+)\s+(\d+)", text, re.M)
            discards = re.search(r"^Discards\s+(\d+)", text, re.M)
            if errors:
                out["interfaces"]["all adapters"] = {"in_errors": int(errors.group(1)),
                                                     "out_errors": int(errors.group(2))}
                if discards:
                    out["interfaces"]["all adapters"]["drops"] = int(discards.group(1))
    except (OSError, ValueError, IndexError):
        pass
    return out


def counter_changes(before: dict, after: dict) -> dict:
    """The counters that went up between two interface_counters() snapshots. Every interface
    read both times gets an entry (empty when nothing went up)."""
    def up(was: dict, now: dict) -> dict:
        return {k: n - was[k] for k, n in now.items() if k in was and n > was[k]}

    return {"interfaces": {name: up(before["interfaces"][name], now) for name, now in after["interfaces"].items()
                           if name in before["interfaces"]},
            "system": up(before["system"], after["system"]),
            "system_read": bool(before["system"] and after["system"])}


def counter_text(up: dict) -> str:
    return ", ".join(f"{n} {COUNTER_LABELS.get(k, k)}" for k, n in up.items())


def counter_notes(changes: dict) -> list:
    notes = []
    for name, up in changes.get("interfaces", {}).items():
        errors = {k: n for k, n in up.items() if k != "drops"}
        if errors:
            hint = ("collisions on a full-duplex link mean the two ends disagree on duplex: set both to auto"
                    if "collisions" in errors else
                    "damaged frames point to the cable or a connector, the switch port, or a speed/duplex mismatch")
            notes.append(("warn", f"{name} counted {counter_text(errors)} during this scan: {hint}."))
        elif up.get("drops") and name != "all adapters":  # Windows' total also counts ignored protocols
            notes.append(("note", f"{name} dropped {up['drops']} packet(s) during this scan."))
    if changes.get("system"):
        notes.append(("warn", f"This computer counted {counter_text(changes['system'])} during this scan (all "
                              "interfaces and programs): packets are arriving damaged. The interface counts "
                              "above show which port, if they went up too."))
    return notes


def _parse_arp(text: str) -> dict:
    table = {}
    for line in text.splitlines():
        ip, mac = _IP_RE.search(line), _MAC_RE.search(line)
        if ip and mac:
            table[ip.group(1)] = norm_mac(mac.group(1))
    return table


def read_arp_table() -> dict:
    """IP -> MAC from the OS neighbour table (populated as a side effect of probing)."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0":
                        table[parts[0]] = norm_mac(parts[3])
        except OSError:
            pass
    else:
        cmd = ["arp", "-a"] if IS_WINDOWS else ["arp", "-an"]
        table = _parse_arp(_run(cmd))
        if ARP_SUDO and (not table or all(m == _MASKED_MAC for m in table.values())):
            table = _parse_arp(_run(ARP_SUDO + cmd)) or table
    return {ip: mac for ip, mac in table.items()
            if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", _MASKED_MAC)
            and not int(mac[:2], 16) & 1}  # drop multicast MACs


# ---------------------------------------------------------------------------
# mDNS and SSDP (how the UniFi app and UniFi OS consoles find each other)
# ---------------------------------------------------------------------------

def build_dns_query(qid: int, questions) -> bytes:
    out = bytearray(struct.pack(">6H", qid, 0, len(questions), 0, 0, 0))
    for name, qtype in questions:
        for label in name.strip(".").split("."):
            enc = label.encode("utf-8")[:63]
            out.append(len(enc))
            out += enc
        out.append(0)
        out += struct.pack(">HH", qtype, 1)
    return bytes(out)


def _read_name(buf: bytes, off: int):
    labels, end, hops = [], None, 0
    while True:
        length = buf[off]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 64:
                raise ValueError("compression loop")
            continue
        off += 1
        if length == 0:
            break
        labels.append(buf[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def parse_dns(buf: bytes):
    """Return (flags, [(name, type, value)]) or None. Handles A, PTR, SRV, TXT."""
    try:
        _qid, flags, qd, an, ns, ar = struct.unpack_from(">6H", buf)
        off = 12
        for _ in range(qd):
            _, off = _read_name(buf, off)
            off += 4
        records = []
        for _ in range(an + ns + ar):
            name, off = _read_name(buf, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", buf, off)
            off += 10
            rdata, end = off, off + rdlen
            value = None
            if rtype == 1 and rdlen == 4:
                value = socket.inet_ntoa(buf[rdata:end])
            elif rtype == 12:
                value = _read_name(buf, rdata)[0]
            elif rtype == 33 and rdlen >= 7:
                port = struct.unpack_from(">H", buf, rdata + 4)[0]
                value = (port, _read_name(buf, rdata + 6)[0])
            elif rtype == 16:
                strings, p = [], rdata
                while p < end:
                    n = buf[p]
                    strings.append(buf[p + 1:p + 1 + n].decode("utf-8", "replace"))
                    p += 1 + n
                value = [s for s in strings if s]
            records.append((name, rtype, value))
            off = end
        return flags, records
    except (struct.error, IndexError, ValueError):
        return None


def _set_mcast_if(sock: socket.socket, ip: str) -> bool:
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        return True
    except OSError:
        return False


class MdnsBrowser:
    META = "_services._dns-sd._udp.local"

    def __init__(self, ifaces, local_ips):
        self.ifaces, self.local_ips = ifaces, local_ips
        self.sock = udp_socket(0)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        except OSError:
            pass
        self.qid = random.randint(1, 0xFFFF)
        self.types: set = set()
        self.hosts: dict = {}
        self.raw: dict = {}  # ip -> (time, "ip:port", its first answer)

    def _host(self, ip: str) -> dict:
        return self.hosts.setdefault(ip, {"hostnames": set(), "services": set(), "instances": set(),
                                          "srv": {}, "txt": {}})

    def query(self, names) -> None:
        names = list(names)
        for i in range(0, len(names), 12):
            pkt = build_dns_query(self.qid, [(n, 12) for n in names[i:i + 12]])
            for iface in self.ifaces:
                if _set_mcast_if(self.sock, iface.ip):
                    try:
                        self.sock.sendto(pkt, MDNS_ADDR)
                    except OSError:
                        pass

    def start(self) -> None:
        self.query([self.META])

    def handle(self, data: bytes, addr) -> None:
        if addr[0] in self.local_ips:
            return
        msg = parse_dns(data)
        if not msg or not msg[0] & 0x8000:
            return
        self.raw.setdefault(addr[0], (time.time(), f"{addr[0]}:{addr[1]}", data))
        host, new_types = self._host(addr[0]), []
        for name, rtype, value in msg[1]:
            if value is None:
                continue
            lname = name.lower()
            if rtype == 12 and lname == self.META:
                t = value.lower()
                if t not in self.types:
                    self.types.add(t)
                    new_types.append(t)
            elif rtype == 12:
                host["services"].add(lname)
                host["instances"].add(value)
            elif rtype == 33:
                host["srv"][name] = f"{value[1]}:{value[0]}"
                host["hostnames"].add(value[1].lower())
            elif rtype == 16 and value:
                host["txt"][name] = value
            elif rtype == 1 and value not in self.local_ips:
                self._host(value)["hostnames"].add(lname)
        if new_types:
            self.query(new_types)


_INSECURE_CTX = None


def _insecure_ctx() -> ssl.SSLContext:
    """TLS without certificate checks: LAN gear uses self-signed certificates."""
    global _INSECURE_CTX
    if _INSECURE_CTX is None:
        _INSECURE_CTX = ssl.create_default_context()
        _INSECURE_CTX.check_hostname = False
        _INSECURE_CTX.verify_mode = ssl.CERT_NONE
    return _INSECURE_CTX


def _http_get(url: str, timeout: float, limit: int = 262144) -> bytes:
    """GET without proxies or certificate checks (LAN devices use self-signed certs)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=_insecure_ctx()))
    req = urllib.request.Request(url, headers={"User-Agent": f"opendisco/{__version__}",
                                               "Accept": "application/json, text/xml, */*"})
    with opener.open(req, timeout=timeout) as resp:
        return resp.read(limit)


UPNP_FIELDS = ("friendlyName", "manufacturer", "modelName", "modelDescription", "modelNumber",
               "serialNumber", "presentationURL")


def parse_upnp_description(body: bytes) -> dict:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {}
    out = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in UPNP_FIELDS and tag not in out and el.text and el.text.strip():
            out[tag] = el.text.strip()[:200]
    return out


class SsdpBrowser:
    def __init__(self, ifaces, local_ips):
        self.ifaces, self.local_ips = ifaces, local_ips
        self.sock = udp_socket(0)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        self.responders: dict = {}
        self.raw: dict = {}  # ip -> (time, "ip:port", its first answer)

    def start(self) -> None:
        for st in ("ssdp:all", "upnp:rootdevice"):
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n').encode()
            for iface in self.ifaces:
                if _set_mcast_if(self.sock, iface.ip):
                    try:
                        self.sock.sendto(msg, SSDP_ADDR)
                    except OSError:
                        pass

    def handle(self, data: bytes, addr) -> None:
        if addr[0] in self.local_ips:
            return
        lines = data.decode("latin-1", "replace").split("\r\n")
        if not lines or not lines[0].upper().startswith("HTTP/"):
            return
        self.raw.setdefault(addr[0], (time.time(), f"{addr[0]}:{addr[1]}", data))
        hdr = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        r = self.responders.setdefault(addr[0], {"server": "", "locations": set()})
        if hdr.get("server"):
            r["server"] = hdr["server"][:200]
        if hdr.get("location"):
            r["locations"].add(hdr["location"][:300])

    def describe(self, ip: str) -> dict:
        r = self.responders[ip]
        out = {"server": r["server"]} if r["server"] else {}
        for loc in sorted(r["locations"])[:3]:
            u = urllib.parse.urlparse(loc)
            if u.scheme != "http" or u.hostname != ip:  # only fetch from the responder itself
                continue
            try:
                fields = parse_upnp_description(_http_get(loc, 2.0))
            except Exception:
                continue
            if fields:
                out.update(fields)
                out["location"] = loc
                break
        return out


# ---------------------------------------------------------------------------
# Deep checks: TCP ports and the UniFi OS console API
# ---------------------------------------------------------------------------

def probe_service(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """What answers on one TCP port: "ssh", "https", "http", "open" (something else), or None
    when nothing does. SSH greets first; HTTPS and HTTP wait for the client."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(1.0)
            try:
                greeting = s.recv(64)
            except socket.timeout:
                greeting = b""
    except OSError:
        return None
    if greeting.startswith(b"SSH-"):
        return "ssh"
    if greeting:
        return "open"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _insecure_ctx().wrap_socket(raw):
                return "https"
    except OSError:  # includes ssl.SSLError
        pass
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            if s.recv(16).startswith(b"HTTP/"):
                return "http"
    except OSError:
        pass
    return "open"


def web_redirect_port(ip: str, timeout: float = 2.0) -> int | None:
    """The HTTPS port a device's plain-HTTP page sends browsers to, as curl -I would show:
    airOS, EdgeOS and UniFi OS redirect http://ip/ to https://ip:<port>/. None when it doesn't
    redirect to HTTPS on itself."""
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
        try:
            conn.request("GET", "/", headers={"User-Agent": f"opendisco/{__version__}"})
            resp = conn.getresponse()
            location = resp.getheader("Location") or ""
            body = b"" if location else resp.read(8192)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        return None
    if not location:  # some firmware redirects with a meta refresh instead
        m = re.search(rb"""(?i)<meta[^>]+http-equiv=["']?refresh[^>]*url=([^"'>\s]+)""", body)
        location = m.group(1).decode("latin-1") if m else ""
    try:
        url = urllib.parse.urlparse(location)
        port = url.port
    except ValueError:
        return None
    if url.scheme != "https" or url.hostname not in (None, ip):
        return None
    return port or 443


def check_ports(devs, opts, log, everyone=()) -> None:
    """Connect to each device's management ports and name what answers: the common ones,
    the ones it says it uses, and the ones the rest of the gear here says it uses (so a device
    that doesn't say is still checked on your ports). Then read where its HTTP page
    redirects, which shows the HTTPS port of gear that doesn't report it."""
    devs = [d for d in devs if d.ip]
    used = Counter(p for d in (list(everyone) or devs) for kind in ("https", "ssh")
                   for p in [d.said_port(kind)] if p)
    common = sorted(set(CHECK_PORTS) | set(opts.https_ports) | set(opts.ssh_ports)
                    | {p for p, _ in used.most_common(8)})
    pairs = [(d, p) for d in devs
             for p in sorted(set(common) | {q for kind in ("https", "ssh") for q in [d.said_port(kind)] if q})]
    log(f"Checking TCP {', '.join(map(str, common))} and the ports each device reports, "
        f"on {len(devs)} device(s)...")
    with ThreadPoolExecutor(64) as ex:
        results = list(ex.map(lambda dp: probe_service(dp[0].ip, dp[1]), pairs))
    for d in devs:
        d.ports, d.services = [], {}
    for (d, p), service in zip(pairs, results):
        if service:
            d.ports.append(p)
            d.services[p] = service
    web = [d for d in devs if d.services.get(80) == "http"]
    with ThreadPoolExecutor(16) as ex:
        redirects = list(ex.map(lambda d: web_redirect_port(d.ip), web))
    for d, port in zip(web, redirects):
        if port:
            d.port_hints.setdefault("https", {})["redirect"] = port
            if port not in d.services:
                service = probe_service(d.ip, port)
                if service:
                    d.ports = sorted(d.ports + [port])
                    d.services[port] = service


def mdns_port_hints(d) -> None:
    """SSH and HTTPS ports from the device's mDNS service records (_ssh._tcp, _https._tcp)."""
    for name, target in d.mdns.get("srv", {}).items():
        port = target.rsplit(":", 1)[-1]
        for kind, service in (("ssh", "._ssh._tcp."), ("https", "._https._tcp.")):
            if service in name.lower() + "." and port.isdigit():
                d.port_hints.setdefault(kind, {})["mDNS"] = int(port)


def upnp_port_hint(d) -> None:
    """The HTTPS port in the device's UPnP presentation URL (its web UI)."""
    try:
        url = urllib.parse.urlparse(d.ssdp.get("presentationURL", ""))
        if url.scheme == "https" and url.hostname in (None, d.ip):
            d.port_hints.setdefault("https", {})["UPnP"] = url.port or 443
    except ValueError:
        pass


def probe_console_api(ip: str) -> dict:
    """What the UniFi app reads from a console: /api/system plus which apps are installed."""
    out = {}
    try:
        sysinfo = json.loads(_http_get(f"https://{ip}/api/system", 3.0))
        if isinstance(sysinfo, dict) and sysinfo:
            out["system"] = sysinfo
    except Exception:
        pass
    apps = []
    for app, path in (("Network", "/proxy/network/api"), ("Protect", "/proxy/protect/api"),
                      ("Access", "/proxy/access/api")):
        try:
            _http_get(f"https://{ip}{path}", 3.0, limit=1024)
        except urllib.error.HTTPError as e:
            if e.code == 401:  # installed, wants a login
                apps.append(app)
        except Exception:
            pass
    if apps:
        out["apps"] = apps
    return out


# ---------------------------------------------------------------------------
# Scanner: sockets, probes and the receive loop
# ---------------------------------------------------------------------------

IP_BOUND_IF = 25  # macOS <netinet/in.h>; Python doesn't export it


def udp_socket(port: int = 0, broadcast: bool = False, reuse: bool = False) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        if reuse and not IS_WINDOWS:  # Windows SO_REUSEADDR would steal the port
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform == "darwin":  # lets the per-interface broadcast sockets share the port
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if broadcast:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", port))
    except OSError:
        s.close()
        raise
    s.setblocking(False)
    return s


def scoped_broadcast_socket(iface: Iface, port: int):
    """A socket whose 255.255.255.255 leaves through `iface` (or None where that can't be done).

    A plain send to 255.255.255.255 only goes out of the interface with the default route, yet
    it's the one broadcast that old gear on *another* subnet accepts (it drops other subnets'
    directed broadcasts). macOS scopes the socket with IP_BOUND_IF; Linux and Windows send a
    limited broadcast out of whichever interface owns the address the socket is bound to, and
    replies to it arrive on it, which says which interface they came in on. Port 10001 is used
    when it can be shared, since some legacy gear only answers probes from it."""
    if iface.prefix >= 32 or iface.ip.startswith("127."):
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if IS_WINDOWS:  # Windows sends it out of the adapter that owns the socket's address;
            addr = iface.ip  # SO_REUSEADDR would let it take the port from another program
        elif sys.platform == "darwin":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(iface.name))
            addr = ""
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            addr = iface.ip
        try:
            s.bind((addr, port))
        except OSError:
            s.bind((addr, 0))
        s.setblocking(False)
        return s
    except OSError:
        s.close()
        return None


def _enable_pktinfo(sock) -> bool:
    if IS_WINDOWS or not hasattr(socket, "IP_PKTINFO") or not hasattr(sock, "recvmsg"):
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
        return True
    except OSError:
        return False


def _ingress_name(ancdata) -> str | None:
    """Interface name from an IP_PKTINFO control message (same layout on macOS and Linux)."""
    for level, kind, data in ancdata:
        if level == socket.IPPROTO_IP and kind == socket.IP_PKTINFO and len(data) >= 4:
            try:
                return socket.if_indextoname(struct.unpack_from("I", data)[0])
            except OSError:
                return None
    return None


def hexdump(data: bytes, indent: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{i:04x}  {hx:<47}  {asc}")
    return "\n".join(lines)


def packet_lines(data: bytes, problems=None) -> list:
    """A UBNT packet field by field, each with its offset (@) to find it in the hex dump, then
    what's wrong with it and the hex dump."""
    fields, _ = _tlv_walk(data)
    lines = []
    for off, ftype, raw in fields:
        spec = TLV.get(ftype)
        try:
            value = _fmt_value(spec[0], spec[2](raw)) if spec else raw.hex()
        except Exception:
            value = raw.hex()
        lines.append(f"   @{off:04x} 0x{ftype:02x} {spec[1] if spec else 'unknown':<22} {len(raw):>4}  {value}")
    lines += [f"   !! {msg}" for _, msg in (check_packet(data) if problems is None else problems)]
    lines.append(hexdump(data))
    return lines


def describe_packet(data: bytes, pkt: Packet | None, addr, via: str, problems=None) -> str:
    head = f"<- {addr[0]}:{addr[1]} [{via}] {len(data)} bytes"
    if pkt is None:
        return f"{head}  (not a UBNT packet)\n" + "\n".join(packet_lines(data, problems))
    kind = "discovery request" if pkt.is_request else "reply"
    return "\n".join([f"{head}  UBNT v{pkt.version} cmd={pkt.command} len={pkt.length} {kind}"]
                     + packet_lines(data, problems))


class Scanner:
    def __init__(self, opts, ifaces, all_ifaces, inv: Inventory, log=None):
        self.opts, self.ifaces, self.inv = opts, ifaces, inv
        self.port = opts.port
        self.local_ips = {i.ip for i in all_ifaces} | {"127.0.0.1"}
        self.log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        self.handlers: dict = {}
        self.notes: list = []  # (level, message)
        self.replied: set = set()
        self.bcast_ok = 0
        self.bcast_errors: dict = {}
        self.main = self.mcast = self.uni = None
        self.mdns = self.ssdp = None
        self.bound_discovery_port = False
        self.browsers_started = False
        self.on_change = None
        self.probe_every = 2.0
        self.broadcasts = True  # False: only the unicast sweep (to recheck one device)
        self.limited_broadcast = not opts.interface  # 255.255.255.255 leaves via the default route only
        self.alias_routes: list = []  # (network, alias context) while an alias round runs
        self._saved_ifaces = None
        self.vlan_map: dict = os_vlan_map()  # VLAN interface -> (vlan id, parent)
        self.scoped: dict = {}  # interface -> socket that sends 255.255.255.255 out of it
        self.pktinfo_socks: set = set()  # sockets that report which interface a packet came in on
        self.last_ingress: str | None = None
        self.socket_iface: dict = {}  # scoped socket -> its interface, for replies to it
        self.sweep_hosts: list = []
        self.sweep_pass, self.sweep_i, self.sweep_last, self.sweep_pause_until = 3, 0, 0.0, 0.0

    # -- setup -------------------------------------------------------------
    def open(self) -> None:
        o = self.opts
        try:
            self.main = udp_socket(self.port, broadcast=True, reuse=True)
            self.bound_discovery_port = True
        except OSError as e:
            if o.listen:
                raise SystemExit(f"error: can't listen on UDP {self.port}: {e}\n"
                                 "Is the UniFi Network application, WiFiman or another discovery "
                                 "tool running on this computer?")
            self.main = udp_socket(0, broadcast=True)
            self.notes.append(("warn", f"UDP {self.port} is already in use on this computer (UniFi Network "
                                       "app, WiFiman or another tool?). Active probes still work, but "
                                       "unsolicited device announcements can't be heard."))
        if self.bound_discovery_port:
            for i in self.ifaces:
                try:
                    self.main.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                         socket.inet_aton(UBNT_MCAST) + socket.inet_aton(i.ip))
                except OSError:
                    pass
        main_via = "announce" if o.listen else "ubnt"
        self.handlers[self.main] = lambda d, a: self._on_ubnt(d, a, main_via)
        if o.listen:
            return
        self.scoped = self._open_scoped(self.ifaces)
        self.mcast = udp_socket(0)
        for opt, val in ((socket.IP_MULTICAST_TTL, 1), (socket.IP_MULTICAST_LOOP, 0)):
            try:
                self.mcast.setsockopt(socket.IPPROTO_IP, opt, val)
            except OSError:
                pass
        self.handlers[self.mcast] = lambda d, a: self._on_ubnt(d, a, "mcast")
        # UniFi OS gear ignores unicast probes from port 10001 (it answers ones from any other
        # port), while some legacy gear answers only those, so the sweep sends from both.
        self.uni = udp_socket(0)
        self.handlers[self.uni] = lambda d, a: self._on_ubnt(d, a, "ubnt")
        for s in (self.main, self.mcast, self.uni):
            if _enable_pktinfo(s):
                self.pktinfo_socks.add(s)
        if o.mdns:
            self.mdns = MdnsBrowser(self.ifaces, self.local_ips)
            self.handlers[self.mdns.sock] = self.mdns.handle
        if o.ssdp:
            self.ssdp = SsdpBrowser(self.ifaces, self.local_ips)
            self.handlers[self.ssdp.sock] = self.ssdp.handle

    def _open_scoped(self, ifaces) -> dict:
        out = {}
        for i in ifaces:
            if i.name not in out:
                s = scoped_broadcast_socket(i, self.port)
                if s:
                    out[i.name] = s
                    self.socket_iface[s] = i.name
                    self.handlers[s] = lambda d, a: self._on_ubnt(d, a, "ubnt")
                    if _enable_pktinfo(s):
                        self.pktinfo_socks.add(s)
        return out

    def _close_scoped(self) -> None:
        for s in self.scoped.values():
            self.handlers.pop(s, None)
            self.socket_iface.pop(s, None)
            self.pktinfo_socks.discard(s)
            s.close()
        self.scoped = {}

    def close(self) -> None:
        for s in self.handlers:
            s.close()
        self.handlers = {}

    # -- sending -----------------------------------------------------------
    def _send(self, sock, data: bytes, dest, bcast: bool = False) -> None:
        try:
            sock.sendto(data, dest)
            if bcast:
                self.bcast_ok += 1
        except OSError as e:
            if bcast:
                self.bcast_errors[e.errno] = e.strerror or str(e)

    def send_ubnt_probes(self) -> None:
        self.inv.rounds.append((time.time(), [(i.network, i.name) for i in self.ifaces if i.prefix < 32]))
        for payload in (UBNT_V1_PROBE, UBNT_V2_PROBE):
            for s in self.scoped.values():  # 255.255.255.255 out of every interface, for old gear
                self._send(s, payload, ("255.255.255.255", self.port), bcast=True)
            if self.limited_broadcast and not self.scoped:
                self._send(self.main, payload, ("255.255.255.255", self.port), bcast=True)
            for i in self.ifaces:
                if i.broadcast:
                    self._send(self.main, payload, (i.broadcast, self.port), bcast=True)
                if i.prefix < 32 and _set_mcast_if(self.mcast, i.ip):
                    self._send(self.mcast, payload, (UBNT_MCAST, self.port), bcast=True)

    def set_sweep(self, hosts) -> None:
        self.sweep_hosts = list(hosts)

    def begin_alias_round(self, alias_ifaces, routes, hosts) -> None:
        """Probe from temporary alias addresses instead of the normal ones."""
        self._saved_ifaces = (self.ifaces, self.limited_broadcast, self.scoped)
        self.ifaces, self.limited_broadcast = alias_ifaces, False
        self.scoped = self._open_scoped(alias_ifaces)  # 255.255.255.255 out of the alias's port too
        self.alias_routes = routes
        self.local_ips |= {i.ip for i in alias_ifaces}
        self.set_sweep(hosts)

    def end_alias_round(self) -> None:
        self._close_scoped()
        self.ifaces, self.limited_broadcast, self.scoped = self._saved_ifaces
        self.alias_routes = []
        self.set_sweep([])

    @property
    def sweeping(self) -> bool:
        return bool(self.sweep_hosts) and self.sweep_pass <= 2

    def _sweep_tick(self, now: float) -> None:
        # Pass 1 sends v1 to every host (and gets the OS to ARP them); pass 2 follows up
        # with v2 + v1 to hosts that haven't answered. Two passes because macOS holds only
        # one packet per unresolved neighbour and drops the rest.
        if not self.sweeping or now < self.sweep_pause_until:
            return
        budget = min(int((now - self.sweep_last) * self.opts.rate), max(1, self.opts.rate // 5))
        if budget < 1:
            return
        self.sweep_last = now
        while budget > 0 and self.sweep_i < len(self.sweep_hosts):
            ip = self.sweep_hosts[self.sweep_i]
            self.sweep_i += 1
            if self.sweep_pass == 2 and ip in self.replied:
                continue
            for payload in ((UBNT_V1_PROBE,) if self.sweep_pass == 1 else (UBNT_V2_PROBE, UBNT_V1_PROBE)):
                for sock in (self.main, self.uni):
                    self._send(sock, payload, (ip, self.port))
            budget -= 1
        if self.sweep_i >= len(self.sweep_hosts):
            self.sweep_pass += 1
            self.sweep_i = 0
            self.sweep_pause_until = now + 1.0
            self.sweep_last = self.sweep_pause_until

    def sweep_seconds(self) -> float:
        return 2 * len(self.sweep_hosts) / self.opts.rate + 1.0 if self.sweep_hosts else 0.0

    # -- receiving ---------------------------------------------------------
    def _on_ubnt(self, data: bytes, addr, via: str) -> None:
        pkt = parse_packet(data)
        if addr[0] in self.local_ips and (pkt is None or pkt.is_request):
            return  # our own probes, looped back
        # Where the OS can't say which interface it came in on (Windows), the local subnet it came from
        ingress = self.last_ingress or next((i.name for i in self.ifaces if _in_any(addr[0], [i.network])), None)
        iface = ingress or ""
        rec = PacketRecord(time.time(), "UBNT", f"{addr[0]}:{addr[1]}", via, iface,
                           self.vlan_map.get(iface, (0, ""))[0] if iface else None, data,
                           problems=check_packet(data))
        if self.opts.raw:
            self.log(describe_packet(data, pkt, addr, via, rec.problems))
        if pkt is None:
            self.inv.keep_packet(None, rec)
            return
        if pkt.is_request:
            self.inv.requesters.setdefault(addr[0], set()).add(addr[1])
            return
        self.replied.add(addr[0])
        dev, changes = self.inv.ingest_checked(pkt, rec, addr, via)
        if dev is None:
            return
        if not self.alias_routes:
            dev.direct = True
        if not dev.alias:
            dev.alias = next((ctx for net, ctx in self.alias_routes if _in_any(addr[0], [net])), {})
        if ingress:
            dev.seen_on.add(ingress)
            if dev.vlan is None:  # first interface it answered on: a VLAN interface or untagged
                dev.vlan, dev.vlan_parent = self.vlan_map.get(ingress, (0, ingress))
        if self.on_change:
            self.on_change(dev, changes)

    def _drain(self, sock) -> None:
        handler = self.handlers[sock]
        pktinfo = sock in self.pktinfo_socks
        for _ in range(512):
            try:
                if pktinfo:
                    data, anc, _flags, addr = sock.recvmsg(65535, socket.CMSG_SPACE(12))
                    self.last_ingress = _ingress_name(anc)
                else:
                    data, addr = sock.recvfrom(65535)
                    self.last_ingress = self.socket_iface.get(sock)
            except (BlockingIOError, InterruptedError):
                return
            except ConnectionResetError:  # Windows reports ICMP port-unreachable here
                continue
            except OSError:
                return
            try:
                handler(data, addr)
            except Exception as e:  # never let one malformed packet stop the scan
                if self.opts.debug:
                    self.log(f"debug: failed to handle packet from {addr}: {e!r}")

    def run(self, duration: float, progress=None) -> None:
        start = time.monotonic()
        end = start + duration
        next_probe = start
        resend_browsers = None
        if not self.browsers_started and not self.opts.listen:
            for b in (self.mdns, self.ssdp):
                if b:
                    b.start()
            self.browsers_started = True
            resend_browsers = start + 1.0
        if self.sweep_hosts:
            self.sweep_pass, self.sweep_i, self.sweep_last, self.sweep_pause_until = 1, 0, start, 0.0
        socks = list(self.handlers)
        while True:
            now = time.monotonic()
            if STOP.is_set():
                raise KeyboardInterrupt
            if now >= end:
                break
            if not self.opts.listen and self.broadcasts and now >= next_probe:
                self.send_ubnt_probes()
                next_probe = now + self.probe_every
            if resend_browsers and now >= resend_browsers:
                for b in (self.mdns, self.ssdp):
                    if b:
                        b.start()
                resend_browsers = None
            self._sweep_tick(now)
            wait = min(0.02 if self.sweeping else 0.25, end - now)
            try:
                readable, _, _ = select.select(socks, [], [], max(0.0, wait))
            except InterruptedError:
                continue
            for s in readable:
                self._drain(s)
            if progress:
                progress(time.monotonic() - start, duration)

    def finish_notes(self) -> None:
        if not self.opts.listen and self.bcast_errors and self.bcast_ok == 0:
            reason = "; ".join(sorted(set(self.bcast_errors.values())))
            msg = f"Every discovery broadcast failed to send ({reason})."
            if sys.platform == "darwin":
                msg += (" On macOS this usually means your terminal app lacks Local Network access: "
                        "System Settings > Privacy & Security > Local Network.")
            else:
                msg += " Check for a local firewall blocking outbound UDP 10001."
            self.notes.append(("error", msg))


# ---------------------------------------------------------------------------
# VLANs: listening on a trunk port
# ---------------------------------------------------------------------------
# Plugged into a trunk without tagging, a NIC still receives every allowed VLAN's broadcast
# and multicast frames, tags and all. A short capture shows which VLANs are there, which
# subnets live on each (ARP and IP senders), what the switch says about the port over LLDP
# (native VLAN, VLAN names), and any Ubiquiti gear chattering on them.

@dataclass
class Neighbor:
    """One source MAC heard on a port, and everything it gave away about itself."""
    mac: str
    frames: int = 0
    vlans: dict = field(default_factory=dict)  # vlan id (0 = untagged) -> see vlan()
    lldp: dict = field(default_factory=dict)
    first_ip_at: float = 0.0  # when it first used an IPv4 address (for --direct's early stop)
    own: bool = False  # it's this computer (sent from one of our addresses)
    samples: dict = field(default_factory=dict)  # kind -> the first frame of that kind (PacketRecord)

    def vlan(self, vid: int) -> dict:
        return self.vlans.setdefault(vid, {"ips": set(), "wants": set(), "kinds": set(), "dhcp": {}, "frames": 0})

    @property
    def vendor(self) -> str:
        return (vendor_of(self.mac) or vendor_of(self.lldp.get("chassis_mac"))
                or vendor_from_text(" ".join(self.lldp.get(k, "") for k in ("description", "platform", "system"))))

    @property
    def ubiquiti(self) -> bool:
        return self.vendor == "Ubiquiti"


@dataclass
class Trunk:
    """What a capture on one physical port showed."""
    link: Link
    seconds: float
    vlans: dict = field(default_factory=dict)  # vlan id (0 = untagged) -> {"frames": n, "ips": Counter}
    pairs: dict = field(default_factory=dict)  # vlan id -> {(sender, target)} from ARP: same subnet
    neighbors: dict = field(default_factory=dict)  # MAC -> Neighbor
    lldp: dict = field(default_factory=dict)
    error: str = ""
    fed: int = 0  # frames analysed so far
    wifi: dict = field(default_factory=dict)  # the access point a Wi-Fi port is joined to

    def tagged_ids(self) -> list:
        """Tagged VLANs seen in traffic or listed by the switch (minus the native one)."""
        ids = {v for v in self.vlans if v} | set(self.lldp.get("vlan_names", {}))
        return sorted(ids - {0, self.native()})

    def speakers(self) -> list:
        """Devices that announced themselves over LLDP/CDP on this port (not this computer)."""
        return [nb for nb in self.neighbors.values() if nb.lldp and not nb.own]

    def native(self) -> int | None:
        """The port's native VLAN, when whoever announces one agrees. One speaker is the link
        partner (the switch, or the device on a direct wire); a shared LAN may have several."""
        pvids = {nb.lldp["pvid"] for nb in self.speakers() if nb.lldp.get("pvid")}
        return pvids.pop() if len(pvids) == 1 else None

    def heard(self, vid: int, vendors_only: bool = False) -> Counter:
        """Addresses heard on a VLAN, plus LLDP management addresses of whoever talked there.
        vendors_only keeps just the gear this tool recognises (for a busy LAN)."""
        if vendors_only:
            ips = Counter({ip: 1 for nb in self.neighbors.values() if nb.vendor
                           for ip in nb.vlans.get(vid, {}).get("ips", ())})
        else:
            ips = Counter(self.vlans.get(vid, {}).get("ips", {}))
        for nb in self.neighbors.values():
            if vendors_only and not nb.vendor:
                continue
            mgmt = nb.lldp.get("mgmt_ip")
            if mgmt and vid in nb.vlans and not any(mgmt in v["ips"] for v in nb.vlans.values()):
                ips[mgmt] += 1
        return ips

    def add(self, frame: bytes, inv: Inventory, local_ips, local_macs, sniff_all: bool = False) -> None:
        """Analyse one captured frame. sniff_all adds every talker to the inventory, not just
        Ubiquiti ones (on a direct wire, whoever is talking is the device)."""
        self.fed += 1
        parsed = parse_frame(frame)
        if parsed is None or parsed[0] in local_macs:
            return
        src, vid, etype, payload = parsed
        stats = self.vlans.setdefault(vid, {"frames": 0, "ips": Counter()})
        stats["frames"] += 1
        nb = self.neighbors.setdefault(src, Neighbor(src))
        nb.frames += 1
        seen = nb.vlan(vid)
        seen["frames"] += 1
        sender = None
        try:
            if etype == 0x0806 and len(payload) >= 28:  # ARP "who has <target>, tell <sender>"
                sender, target = socket.inet_ntoa(payload[14:18]), socket.inet_ntoa(payload[24:28])
                kind = "ARP"
                if _usable_ip(target) and target != sender:
                    seen["wants"].add(target)
                    if _usable_ip(sender):
                        self.pairs.setdefault(vid, set()).add((sender, target))
            elif etype == 0x0800 and len(payload) >= 20:
                sender, ihl = socket.inet_ntoa(payload[12:16]), (payload[0] & 0x0F) * 4
                kind = "IPv4"
                if payload[9] == 17 and len(payload) >= ihl + 8:
                    sport, dport = struct.unpack_from(">HH", payload, ihl)
                    data = payload[ihl + 8:]
                    if (sport, dport) == (68, 67):
                        kind = "DHCP"
                        seen["dhcp"].update(parse_dhcp(data))
                    elif UBNT_PORT in (sport, dport) and sender not in local_ips:
                        kind = "UBNT"
                        self._ubnt(frame, payload, sender, sport, vid, inv)
            elif etype == 0x86DD:
                kind = "IPv6"
            elif etype in (0x88CC, ETH_CDP):  # LLDP / CDP: the switch on a trunk, the device on a direct wire
                info = parse_lldp(payload) if etype == 0x88CC else parse_cdp(payload)
                names = {**self.lldp.get("vlan_names", {}), **info.pop("vlan_names", {})}
                self.lldp.update(info, vlan_names=names)
                nb.lldp.update(info)
                kind = "LLDP" if etype == 0x88CC else "CDP"
            elif etype == 0:
                kind = "STP/LLC"
            else:
                kind = f"0x{etype:04x}"
        except (struct.error, ValueError, OSError):
            return
        seen["kinds"].add(kind)
        if kind not in nb.samples and kind != "UBNT" and len(nb.samples) < 6:  # what it was found from
            nb.samples[kind] = PacketRecord(time.time(), kind, sender or src, "sniff", self.link.name, vid,
                                            frame, frame)
        if sender in local_ips:
            nb.own = True
        if sender and _usable_ip(sender) and sender not in local_ips:
            stats["ips"][sender] += 1
            seen["ips"].add(sender)
            nb.first_ip_at = nb.first_ip_at or time.monotonic()
            if sniff_all or nb.vendor:
                _tag_vlan(inv.attach(sender, src, "sniff"), vid, self.link.name)

    def _ubnt(self, frame: bytes, ip: bytes, sender: str, sport: int, vid: int, inv: Inventory) -> None:
        """A discovery packet heard on the wire (an announcement, or another tool's probe):
        a capture sees it before the OS checks it, so its IP and UDP checksums are checked too."""
        problems, data = check_ip_udp(ip, cut=len(frame) >= SNAPLEN)
        if data is None:  # its length can't be trusted: decode what's there, but don't judge it
            data = ip[(ip[0] & 0x0F) * 4 + 8:]
        else:
            problems += check_packet(data)
        pkt = parse_packet(data)
        if pkt is not None and pkt.is_request:
            return
        rec = PacketRecord(time.time(), "UBNT", f"{sender}:{sport}", "sniff", self.link.name, vid, data, frame,
                           problems)
        if pkt is None:
            inv.keep_packet(None, rec)
            return
        dev = inv.ingest_checked(pkt, rec, (sender, sport), "sniff")[0]
        if dev is not None:
            _tag_vlan(dev, vid, self.link.name)

    def finish(self, inv: Inventory, sniff_all: bool = False) -> None:
        """Give devices their LLDP/CDP identity, and list recognised gear even when it never
        used an IPv4 address on the wire (a switch that only sends CDP and STP, say)."""
        for nb in self.neighbors.values():
            if nb.own:
                continue
            kinds = set().union(*(v["kinds"] for v in nb.vlans.values())) if nb.vlans else set()
            if kinds <= {"STP/LLC"} and any(  # a switch port's MAC, when the switch itself is known
                    o is not nb and o.vendor == nb.vendor and o.mac[:14] == nb.mac[:14] and (o.lldp or o.first_ip_at)
                    for o in self.neighbors.values()):
                continue
            mgmt = nb.lldp.get("mgmt_ip")
            dev = (inv.find(mac=nb.mac) or inv.find(mac=nb.lldp.get("chassis_mac"))
                   or (inv.find(ip=mgmt) if mgmt else None))
            if dev is None and (sniff_all or nb.vendor):
                dev = inv.attach(mgmt, nb.mac, "sniff") if mgmt else inv.lookup(mac=nb.mac)
                busiest = max(nb.vlans, key=lambda v: (bool(nb.vlans[v]["ips"]), nb.vlans[v]["frames"]))
                _tag_vlan(dev, busiest, self.link.name)
            if dev is None:
                continue
            dev.via.add("sniff")
            for rec in nb.samples.values():
                dev.add_sample(rec)
            if dev.mac and nb.mac != dev.mac:
                dev.other_macs.add(nb.mac)
            if nb.lldp and not dev.lldp:
                dev.lldp = nb.lldp


def _pump(stream, buf: bytearray, cap: int = 64 * 1024 * 1024) -> None:
    for chunk in iter(lambda: stream.read1(65536), b""):
        if len(buf) < cap:
            buf += chunk


TCPDUMP_ARGS = ["-w", "-", "-U", "-s", "1600", "-c", "200000", "ether multicast"]


def write_pcap(path: str, frames) -> None:
    """Frames as a pcap file Wireshark opens (Ethernet, microsecond timestamps of now)."""
    now = time.time()
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
        for frame in frames:
            f.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(frame), len(frame)) + frame)


def capture_frames(names, seconds: float, sudo, log, on_frames=None, stop=None, pcap=None) -> dict:
    """Capture broadcast/multicast frames on every interface at once with tcpdump (Npcap on
    Windows). on_frames(name, frames) is called as frames arrive; stop() can end the capture
    early; pcap saves each interface's capture as <pcap>-<interface>.pcap for Wireshark.
    Returns {interface: (frames, error)}."""
    if IS_WINDOWS:
        from opendisco import winnet
        got = winnet.capture(list(names), seconds, on_frames, lambda: bool(stop and stop()) or STOP.is_set(),
                             SNAPLEN)
        for name, (frames, _err) in got.items():
            if pcap and frames:
                path = f"{pcap}-{re.sub(r'[^A-Za-z0-9._-]+', '_', name)}.pcap"
                try:
                    write_pcap(path, frames)
                    log(f"  saved {path}")
                except OSError as e:
                    log(f"  couldn't save {path}: {e.strerror or e}")
        return got
    running = {}
    for name in names:
        r = {"proc": None, "buf": bytearray(), "pos": 0, "reader": CaptureReader(), "frames": [], "err": ""}
        try:
            r["proc"] = subprocess.Popen(sudo + ["tcpdump", "-i", name] + TCPDUMP_ARGS,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            r["pump"] = threading.Thread(target=_pump, args=(r["proc"].stdout, r["buf"]), daemon=True)
            r["pump"].start()
        except OSError as e:
            r["err"] = str(e)
        running[name] = r

    def collect():
        for name, r in running.items():
            end = len(r["buf"])
            if end > r["pos"]:
                new = r["reader"].feed(bytes(r["buf"][r["pos"]:end]))
                r["pos"] = end
                r["frames"] += new
                if new and on_frames:
                    on_frames(name, new)

    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and any(r["proc"] and r["proc"].poll() is None for r in running.values()):
            time.sleep(0.25)
            collect()
            if (stop and stop()) or STOP.is_set():
                break
    finally:
        for r in running.values():
            if r["proc"] and r["proc"].poll() is None:
                r["proc"].send_signal(signal.SIGINT)  # tcpdump flushes and exits; sudo passes it on
    for r in running.values():
        proc = r["proc"]
        if proc:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            r["pump"].join(timeout=2)
            if not r["buf"] and proc.returncode:
                lines = [l for l in proc.stderr.read().decode("utf-8", "replace").splitlines() if l.strip()]
                r["err"] = lines[-1] if lines else f"tcpdump exited with status {proc.returncode}"
    collect()
    for name, r in running.items():
        if pcap and r["buf"]:
            path = f"{pcap}-{name}.pcap"
            try:
                with open(path, "wb") as f:
                    f.write(r["buf"])
                log(f"  saved {path}")
            except OSError as e:
                log(f"  couldn't save {path}: {e.strerror or e}")
    return {name: (r["frames"], r["err"]) for name, r in running.items()}


_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")


class CaptureReader:
    """Incremental reader for the pcap or pcapng stream tcpdump writes with -w -."""

    def __init__(self):
        self.buf, self.fmt, self.e, self.linktypes = b"", None, "<", []

    def feed(self, data: bytes) -> list:
        """Add bytes; return the Ethernet frames that are now complete."""
        self.buf += data
        frames = []
        if self.fmt is None and len(self.buf) >= 24:
            magic = self.buf[:4]
            if magic in _PCAP_MAGICS:
                self.e = "<" if magic[0] in (0xD4, 0x4D) else ">"
                self.fmt = "pcap" if struct.unpack_from(self.e + "I", self.buf, 20)[0] == 1 else "other"
                self.buf = self.buf[24:]
            else:
                self.fmt = "pcapng" if magic == b"\x0a\x0d\x0d\x0a" else "other"
        off, buf = 0, self.buf
        if self.fmt == "pcap":
            while off + 16 <= len(buf):
                incl = struct.unpack_from(self.e + "I", buf, off + 8)[0]
                if off + 16 + incl > len(buf):
                    break
                frames.append(buf[off + 16:off + 16 + incl])
                off += 16 + incl
        elif self.fmt == "pcapng":
            while off + 12 <= len(buf):
                if buf[off:off + 4] == b"\x0a\x0d\x0d\x0a":  # section header carries the byte order
                    self.e = "<" if buf[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                    self.linktypes = []
                btype, blen = struct.unpack_from(self.e + "II", buf, off)
                if blen < 12:
                    self.fmt = "other"
                    break
                if off + blen > len(buf):
                    break
                if btype == 1:  # interface description
                    self.linktypes.append(struct.unpack_from(self.e + "H", buf, off + 8)[0])
                elif btype == 6 and blen >= 32:  # enhanced packet
                    ifid, _, _, caplen = struct.unpack_from(self.e + "IIII", buf, off + 8)
                    if ifid < len(self.linktypes) and self.linktypes[ifid] == 1:
                        frames.append(buf[off + 28:off + 28 + caplen])
                off += blen
        elif self.fmt == "other":
            off = len(buf)
        self.buf = buf[off:]
        return frames


def parse_capture(data: bytes) -> list:
    """Ethernet frames from a complete pcap or pcapng byte string."""
    return CaptureReader().feed(data)


def parse_frame(frame: bytes):
    """(source MAC, outer VLAN id or 0, ethertype, payload) for an Ethernet frame."""
    if len(frame) < 14:
        return None
    vid, tagged, off = 0, False, 14
    etype = struct.unpack_from(">H", frame, 12)[0]
    while etype in (0x8100, 0x88A8, 0x9100) and off + 4 <= len(frame):
        tci, etype = struct.unpack_from(">HH", frame, off)
        if not tagged:  # the outer tag is the one the port carries
            vid, tagged = tci & 0x0FFF, True
        off += 4
    if etype <= 1500:  # an 802.3 length, not an EtherType: LLC, and SNAP for Cisco's CDP
        llc = frame[off:off + etype]
        if llc[:8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
            return _mac(frame[6:12]), vid, ETH_CDP, llc[8:]
        return _mac(frame[6:12]), vid, 0, llc
    return _mac(frame[6:12]), vid, etype, frame[off:]


ETH_CDP = 0x2000  # CDP's SNAP protocol id; parse_frame reports it in place of an EtherType


def parse_cdp(data: bytes) -> dict:
    """A Cisco/Meraki CDP announcement, in the same keys as parse_lldp plus platform/version."""
    out, off = {"proto": "CDP"}, 4  # version, TTL, checksum
    while off + 4 <= len(data):
        kind, length = struct.unpack_from(">HH", data, off)
        if length < 4:
            break
        value = data[off + 4:off + length]
        off += length
        if kind == 0x01:
            out["system"] = _text(value)
        elif kind in (0x02, 0x16):  # addresses; 0x16 is the management one
            ip = _cdp_ipv4(value)
            if ip and (kind == 0x16 or "mgmt_ip" not in out):
                out["mgmt_ip"] = ip
        elif kind == 0x03:
            out["port"] = _text(value)
        elif kind == 0x05:
            out["version"] = (_text(value).strip().splitlines() or [""])[0][:100]
        elif kind == 0x06:
            out["platform"] = _text(value)
        elif kind == 0x0A and len(value) == 2:
            out["pvid"] = struct.unpack(">H", value)[0]  # native VLAN
    desc = ", ".join(out[k] for k in ("platform", "version") if out.get(k))
    if desc:
        out["description"] = desc
    return out


def _cdp_ipv4(value: bytes) -> str | None:
    """First IPv4 address in a CDP address list."""
    if len(value) < 4:
        return None
    off = 4
    for _ in range(struct.unpack_from(">I", value)[0]):
        if off + 2 > len(value):
            break
        ptype, plen = value[off], value[off + 1]
        proto, off = value[off + 2:off + 2 + plen], off + 2 + plen
        if off + 2 > len(value):
            break
        alen = struct.unpack_from(">H", value, off)[0]
        addr, off = value[off + 2:off + 2 + alen], off + 2 + alen
        if ptype == 1 and proto == b"\xcc" and alen == 4:
            return socket.inet_ntoa(addr)
    return None


def parse_lldp(data: bytes) -> dict:
    """The parts of an LLDP frame that matter here: who sent it (switch or device), its
    management address, the port's native VLAN and VLAN names."""
    out, off = {"vlan_names": {}}, 0
    while off + 2 <= len(data):
        head = struct.unpack_from(">H", data, off)[0]
        kind, length = head >> 9, head & 0x1FF
        value = data[off + 2:off + 2 + length]
        off += 2 + length
        if kind == 0:
            break
        if kind == 1 and len(value) == 7 and value[0] == 4:
            out["chassis_mac"] = _mac(value[1:])
        elif kind == 2 and value:
            out["port"] = _mac(value[1:]) if value[0] == 3 else _text(value[1:])
        elif kind == 4:
            out["port_desc"] = _text(value)
        elif kind == 5:
            out["system"] = _text(value)
        elif kind == 6:
            out["description"] = _text(value)[:120]
        elif kind == 8 and len(value) >= 6 and value[0] == 5 and value[1] == 1:
            out["mgmt_ip"] = socket.inet_ntoa(value[2:6])
        elif kind == 127 and len(value) >= 6 and value[:3] == b"\x00\x80\xc2":  # IEEE 802.1
            if value[3] == 1:
                out["pvid"] = struct.unpack_from(">H", value, 4)[0]
            elif value[3] == 3 and len(value) >= 7:
                vid = struct.unpack_from(">H", value, 4)[0]
                out["vlan_names"][vid] = _text(value[7:7 + value[6]])
    return out


def parse_dhcp(data: bytes) -> dict:
    """A DHCP client message: its type, the address it asks for, hostname and vendor class."""
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return {}
    out, off = {}, 240
    if data[12:16] != b"\0\0\0\0":
        out["ciaddr"] = socket.inet_ntoa(data[12:16])
    while off + 1 < len(data) and data[off] != 255:
        if data[off] == 0:
            off += 1
            continue
        code, value = data[off], data[off + 2:off + 2 + data[off + 1]]
        off += 2 + data[off + 1]
        if code == 53 and value:
            out["type"] = {1: "discover", 3: "request", 4: "decline", 7: "release", 8: "inform"}.get(value[0], str(value[0]))
        elif code == 50 and len(value) == 4:
            out["requested"] = socket.inet_ntoa(value)
        elif code == 12:
            out["hostname"] = _text(value)
        elif code == 60:
            out["vendor"] = _text(value)
    return out


def _usable_ip(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_unspecified or a.is_loopback or a.is_link_local or a.is_multicast
                or ip.endswith(".255") or ip.endswith(".0"))


def _tag_vlan(dev: Device, vid: int, parent: str) -> None:
    if dev.vlan is None:
        dev.vlan, dev.vlan_parent = vid, parent


def analyze_capture(link: Link, frames, seconds: float, inv: Inventory, local_ips, local_macs=(),
                    sniff_all: bool = False) -> Trunk:
    trunk = Trunk(link, seconds)
    for frame in frames:
        trunk.add(frame, inv, local_ips, local_macs, sniff_all)
    trunk.finish(inv, sniff_all)
    return trunk


def _covering(ips) -> ipaddress.IPv4Network:
    """The smallest CIDR block that holds all these addresses."""
    nums = [int(ipaddress.IPv4Address(ip)) for ip in ips]
    prefix = 32 - (min(nums) ^ max(nums)).bit_length()
    return ipaddress.IPv4Network((min(nums), min(prefix, 30)), strict=False)


def infer_targets(ips: Counter, pairs=(), known_targets=(), direct: bool = False, limit: int = 6) -> list:
    """Subnets to probe on a VLAN, from what was heard there.

    An ARP "who has T, tell S" means S thinks T is on its own subnet, so the smallest block
    holding S and everything it asked for sits inside the real subnet, whatever its mask:
    an alias in there is guaranteed to look local to S. That block comes first; the /24
    around each sender follows to reach neighbours outside it. The user's own definition
    wins when it covers the addresses. On a direct wire, a lone address with no ARP partner
    also gets its /30, whose other address is local to it for any mask up to /30."""
    groups = {}  # union-find over ARP pairs, within a /16 so a stray pair can't build a /8
    def find(a):
        while groups.get(a, a) != a:
            a = groups[a]
        return a
    for a, b in pairs:
        if int(ipaddress.IPv4Address(a)) >> 16 == int(ipaddress.IPv4Address(b)) >> 16:
            groups[find(a)] = find(b)
    members = {}
    for ip in set(ips) | {x for pair in pairs for x in pair}:
        members.setdefault(find(ip), set()).add(ip)

    out = []
    def add(target):
        if all(t.network != target.network for t in out):
            out.append(target)

    def known(addrs):
        fits = [t for t in known_targets if all(ipaddress.IPv4Address(a) in t.network for a in addrs)]
        return min(fits, key=lambda t: t.network.num_addresses) if fits else None

    for ip, _ in ips.most_common():
        group = members.get(find(ip), {ip})
        block = _covering(group)
        if len(group) > 1 and block.prefixlen >= 22:
            add(known(group) or AliasTarget(block))
        elif direct:
            add(AliasTarget(ipaddress.IPv4Network(f"{ip}/30", strict=False)))
        add(known([ip]) or AliasTarget(ipaddress.IPv4Network(f"{ip}/24", strict=False)))
        if len(out) >= limit:
            break
    return out[:limit]


def _vlan_name(vid: int) -> str:
    return f"VLAN {vid}" if vid else "untagged"


def _on_vlan(vid: int) -> str:
    return f"on VLAN {vid}" if vid else "untagged (no VLAN)"


def talkers(trunk: Trunk) -> list:
    """Who's talking on a port, this computer excluded: Ubiquiti and chattiest first."""
    return sorted((nb for nb in trunk.neighbors.values() if not nb.own),
                  key=lambda nb: (not nb.ubiquiti, not nb.vendor, -nb.frames))


def new_findings(trunk: Trunk, told: set) -> list:
    """Lines for --direct's live output: things learned since the last call."""
    lines = []
    for nb in talkers(trunk):
        who = nb.mac + (f" ({nb.vendor})" if nb.vendor else "")
        if nb.lldp and (nb.mac, "lldp") not in told:
            told.add((nb.mac, "lldp"))
            bits = [f'"{nb.lldp["system"]}"' if nb.lldp.get("system") else "", nb.lldp.get("description", "")[:50],
                    f"management {nb.lldp['mgmt_ip']}" if nb.lldp.get("mgmt_ip") else ""]
            lines.append(f"{who} announces itself over {nb.lldp.get('proto', 'LLDP')}: {', '.join(b for b in bits if b)}")
        for vid, seen in sorted(nb.vlans.items()):
            for ip in sorted(seen["ips"]):
                if (nb.mac, vid, ip) not in told:
                    told.add((nb.mac, vid, ip))
                    wants = f", looking for {', '.join(sorted(seen['wants'])[:3])}" if seen["wants"] else ""
                    lines.append(f"{who} uses {ip} {_on_vlan(vid)}{wants}")
            if seen["dhcp"] and (nb.mac, vid, "dhcp") not in told:
                told.add((nb.mac, vid, "dhcp"))
                lines.append(f"{who} is asking for a DHCP lease {_on_vlan(vid)}")
            if vid and not seen["ips"] and (nb.mac, vid) not in told:
                told.add((nb.mac, vid))
                lines.append(f"{who} is talking {_on_vlan(vid)} ({', '.join(sorted(seen['kinds']))})")
    return lines


def neighbor_verdict(nb: Neighbor, dev: Device | None) -> str:
    """One plain-English conclusion about a device on a direct wire."""
    used = [(vid, ip, sorted(seen["wants"])) for vid, seen in nb.vlans.items() for ip in sorted(seen["ips"])]
    used.sort(key=lambda u: (not u[2], u[0] == 0))  # prefer the address it's actively using, tagged first
    if dev is not None and dev.info.get("is_default"):
        return "It reports factory defaults: its configuration is gone. Re-apply it (or restore a backup)."
    if used:
        vid, ip, wants = used[0]
        text = f"Management is {ip} {_on_vlan(vid)}"
        if wants:
            text += f", and it keeps asking for {', '.join(wants[:3])} (its gateway or server), which isn't on this cable"
        if ip in DEFAULT_ADDRESSES.get(nb.vendor, ()) or ip == FALLBACK_IP:
            return text + f". {ip} is a factory default: it was reset, or it never got configured (or a DHCP lease)."
        upstream = ("the wireless link (alignment, frequency) or the far end" if nb.vendor not in ("Cisco", "Meraki")
                    else "its uplink")
        return text + f". Its network settings look intact, so look at {upstream} rather than at a lost config."
    dhcp = [(vid, seen["dhcp"]) for vid, seen in nb.vlans.items() if seen["dhcp"]]
    if dhcp:
        vid, info = dhcp[0]
        extra = "".join(f", {k} {info[k]!r}" for k in ("hostname", "vendor") if info.get(k))
        if info.get("requested"):
            extra += f", last address {info['requested']}"
        return (f"It's asking for a DHCP lease {_on_vlan(vid)}{extra}. Management is set to DHCP and "
                "nothing on this cable answers; it may also fall back to 192.168.1.20.")
    if nb.lldp.get("mgmt_ip"):
        return f"It announces management address {nb.lldp['mgmt_ip']} over LLDP but hasn't used it on the wire yet."
    defaults = DEFAULT_ADDRESSES.get(nb.vendor)
    hint = f" {nb.vendor}'s factory default is {' or '.join(defaults)}, which --direct also probes." if defaults else ""
    tagged = sorted(v for v in nb.vlans if v)
    if tagged:
        return (f"It's talking {' and '.join(_on_vlan(v) for v in tagged)} but hasn't used IPv4 yet. "
                "Re-seat the cable while listening, or listen longer (--vlan-listen 90)." + hint)
    return ("Heard, but it gave nothing away about its address. Re-seat the cable while listening, or "
            "listen longer." + hint)


def render_direct(trunks, inv: Inventory) -> str:
    lines = []
    for tr in trunks:
        media = link_media(tr.link.name)
        lines.append(f"  {tr.link.name} ({tr.link.label}{', ' + media if media else ''}), listened {tr.seconds:g}s")
        if tr.error:
            lines.append(f"    capture failed: {tr.error}")
            continue
        found = talkers(tr)
        if not found:
            lines.append("    nothing heard: check power/PoE and the cable, or re-seat it while listening")
        for nb in found[:5]:
            ident = [f'"{nb.lldp["system"]}"' if nb.lldp.get("system") else "",
                     nb.lldp.get("description", "")[:40]]
            lines.append((f"    {nb.mac}  {nb.vendor or 'unknown vendor'}  "
                          + "  ".join(i for i in ident if i)).rstrip())
            for vid, seen in sorted(nb.vlans.items()):
                addrs = ", ".join(sorted(seen["ips"])) or "-"
                wants = f"looking for {', '.join(sorted(seen['wants'])[:3])}" if seen["wants"] else ""
                lines.append(f"      {_vlan_name(vid):<10} {addrs:<18} {wants:<32} {', '.join(sorted(seen['kinds']))}".rstrip())
            dev = inv.find(mac=nb.mac)
            lines.append(f"      => {neighbor_verdict(nb, dev)}")
        if len(found) > 2:
            lines.append(f"    {len(found)} devices are talking here, so something (a switch, or a bridged wireless "
                         "link) is between you and the device.")
    return "\n".join(lines)


def direct_to_dict(tr: Trunk, inv: Inventory) -> dict:
    return {"interface": tr.link.name, "media": link_media(tr.link.name) or None, "seconds": tr.seconds,
            "error": tr.error or None,
            "talkers": [{"mac": nb.mac, "vendor": nb.vendor or None, "frames": nb.frames, "lldp": nb.lldp or None,
                         "vlans": {_vlan_name(v): {"ips": sorted(s["ips"]), "looking_for": sorted(s["wants"]),
                                                   "kinds": sorted(s["kinds"]), "dhcp": s["dhcp"] or None}
                                   for v, s in sorted(nb.vlans.items())},
                         "verdict": neighbor_verdict(nb, inv.find(mac=nb.mac))} for nb in talkers(tr)]}


def trunk_to_dict(tr: Trunk) -> dict:
    lldp = {"native_vlan": tr.native(), "vlan_names": {str(k): v for k, v in tr.lldp.get("vlan_names", {}).items()},
            "speakers": [dict(nb.lldp, mac=nb.mac) for nb in tr.speakers()]}
    vlans = {}
    for vid, stats in sorted(tr.vlans.items()):
        nets = Counter(str(ipaddress.IPv4Network(f"{ip}/24", strict=False)) for ip in stats["ips"])
        vlans["untagged" if vid == 0 else str(vid)] = {"frames": stats["frames"], "subnets": dict(nets)}
    return {"interface": tr.link.name, "label": tr.link.label, "seconds": tr.seconds,
            "error": tr.error or None, "lldp": lldp, "vlans": vlans}


def render_trunks(trunks, verbose: bool = False) -> str:
    lines = []
    for tr in trunks:
        head = f"{tr.link.name} ({tr.link.label}), listened {tr.seconds:g}s"
        speakers = tr.speakers()
        if len(speakers) == 1 and speakers[0].lldp.get("system"):
            peer = speakers[0].lldp
            port = peer.get("port_desc") or peer.get("port")
            head += f": {peer.get('proto', 'LLDP')} neighbor {peer['system']}" + (f" port {port}" if port else "")
        elif len(speakers) > 1:
            head += f": {len(speakers)} devices announce themselves over LLDP/CDP, so this is a shared segment"
        lines.append("  " + head)
        if tr.error:
            lines.append(f"    capture failed: {tr.error}")
            continue
        names = tr.lldp.get("vlan_names", {})
        pvid = tr.native()
        for vid in sorted(set(tr.vlans) | set(tr.tagged_ids()), key=lambda v: (v != 0, v)):
            stats = tr.vlans.get(vid, {"frames": 0, "ips": Counter()})
            if vid == 0:
                label = f"untagged = VLAN {pvid} (LLDP/CDP)" if pvid else "untagged"
                name = names.get(pvid)
            else:
                label, name = f"VLAN {vid}", names.get(vid)
            if name:
                label += f' "{name}"'
            nets = Counter(str(ipaddress.IPv4Network(f"{ip}/24", strict=False)) for ip in stats["ips"])
            seen = ", ".join(f"{n} ({c} host{'s' if c > 1 else ''})" for n, c in nets.most_common(4))
            if not stats["frames"]:
                seen = "listed by the switch, no traffic seen"
            lines.append(f"    {label:<36} {seen or 'no IPv4 senders seen'}")
        if not tr.vlans and not tr.lldp:
            lines.append("    nothing heard")
        if tr.wifi:
            lines.append("    " + describe_wifi(tr.wifi))
        if verbose:
            found = talkers(tr)
            lines.append(f"    talkers ({len(found)}{', first 40' if len(found) > 40 else ''}):")
            for nb in found[:40]:
                for vid, seen in sorted(nb.vlans.items()):
                    addrs = ", ".join(sorted(seen["ips"])[:4]) or "-"
                    lines.append(f"      {nb.mac}  {nb.vendor or '-':<9} {_vlan_name(vid):<9} {addrs:<34} "
                                 f"{', '.join(sorted(seen['kinds']))}".rstrip())
                if nb.lldp:
                    info = nb.lldp
                    bits = [f"{k} {info[k]}" for k in ("system", "platform", "mgmt_ip", "port_desc", "port", "pvid")
                            if info.get(k)]
                    lines.append(f"        {info.get('proto', 'LLDP')}: " + "; ".join(bits))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Temporary IP aliases
# ---------------------------------------------------------------------------
# Newer Ubiquiti firmware only answers discovery from senders in its own subnet; old
# airOS answers anyone. To find gear on networks this computer has no address in, add a
# temporary address in each target subnet to every active interface, probe, remove it.

ALIAS_STATE_FILE = os.path.join(os.path.expanduser("~"), ".opendisco_aliases.json")
DEFAULT_NETWORKS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "networks.txt")


@dataclass
class AliasTarget:
    network: ipaddress.IPv4Network
    alias: str | None = None  # address pinned in networks.txt; otherwise picked per run


def parse_alias_spec(spec: str) -> list:
    """Parse "10.0.0.0/24", "10.0.0.0/24 alias=10.0.0.199", or a range split into blocks:
    "172.16.10.1-20/30" is every /30 with a usable address between .1 and .20."""
    parts = spec.split()
    alias = None
    for opt in parts[1:]:
        if not opt.startswith("alias="):
            raise ValueError(f"unknown option {opt!r}")
        alias = opt[len("alias="):]
    m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)-(\d+(?:\.\d+\.\d+\.\d+)?)/(\d+)", parts[0])
    if m:
        if alias:
            raise ValueError("alias= can't be used with a range")
        start = ipaddress.IPv4Address(m.group(1))
        end_text = m.group(2) if "." in m.group(2) else m.group(1).rsplit(".", 1)[0] + "." + m.group(2)
        end, prefix = ipaddress.IPv4Address(end_text), int(m.group(3))
        if end < start:
            raise ValueError("range ends before it starts")
        if not 16 <= prefix <= 30:
            raise ValueError("blocks must be between /16 and /30")
        targets = []
        net = ipaddress.IPv4Network(f"{start}/{prefix}", strict=False)
        while net.network_address <= end:
            if net.network_address + 1 <= end and net.broadcast_address - 1 >= start:
                targets.append(AliasTarget(net))
            if len(targets) > 256:
                raise ValueError("range makes more than 256 blocks")
            if net.broadcast_address == ipaddress.IPv4Address("255.255.255.255"):
                break
            net = ipaddress.IPv4Network(f"{net.broadcast_address + 1}/{prefix}")
        return targets
    net = ipaddress.IPv4Network(parts[0], strict=False)
    if not 16 <= net.prefixlen <= 30:
        raise ValueError(f"{net} must be between /16 and /30 to leave room for an alias")
    if alias is not None:
        addr = ipaddress.IPv4Address(alias)
        if addr not in net or addr in (net.network_address, net.broadcast_address):
            raise ValueError(f"alias {alias} isn't a usable address in {net}")
    return [AliasTarget(net, alias)]


def load_alias_targets(path, extra, error) -> list:
    specs = []
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            error(f"can't read networks file {path}: {e.strerror or e}")
        for n, line in enumerate(lines, 1):
            line = line.split("#", 1)[0].strip()
            if line:
                specs.append((line, f"{os.path.basename(path)} line {n}"))
    specs += [(s, f"--alias {s}") for s in extra]
    targets, seen = [], set()
    for spec, where in specs:
        try:
            parsed = parse_alias_spec(spec)
        except ValueError as e:
            error(f"{where}: {e}")
        for t in parsed:
            if t.network not in seen:
                seen.add(t.network)
                targets.append(t)
    return targets


def alias_candidates(target: AliasTarget) -> list:
    """Alias addresses to try, best first."""
    if target.alias:
        return [target.alias]
    net = target.network
    first, last = int(net.network_address) + 1, int(net.broadcast_address) - 1
    if net.prefixlen >= 29:  # point-to-point sized: top host first, then the rest
        return [str(ipaddress.IPv4Address(a)) for a in range(last, first - 1, -1)]
    # Larger subnets: start a few below the top, where gateways (.254, .253) usually live.
    return [str(ipaddress.IPv4Address(a)) for a in range(last - 4, max(first, last - 40) - 1, -1)]


def sudo_uses_touch_id() -> bool:
    """True when this Mac's sudo accepts Touch ID (pam_tid enabled in /etc/pam.d)."""
    if platform_name() != "macos":
        return False
    for path in ("/etc/pam.d/sudo_local", "/etc/pam.d/sudo"):
        try:
            with open(path, encoding="utf-8") as f:
                if any("pam_tid.so" in line.split("#", 1)[0] for line in f):
                    return True
        except OSError:
            pass
    return False


def authorize_sudo(why: str, log) -> None:
    if SUDO_ASKPASS is None:
        log(why)
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            raise SystemExit("error: sudo failed")
        return
    if subprocess.run(["sudo", "-n", "-v"], capture_output=True).returncode == 0:
        return  # still authorised from earlier in this session
    if sudo_uses_touch_id():
        # sudo shows the system Touch ID prompt itself. No password is piped in, so cancelling it
        # just ends this attempt and we fall back to asking for the password.
        if subprocess.run(["sudo", "-S", "-p", "", "-v"], input="", capture_output=True, text=True).returncode == 0:
            return
    password = SUDO_ASKPASS(why)
    if password is None:
        raise SystemExit("error: this needs your administrator password")
    r = subprocess.run(["sudo", "-S", "-p", "", "-v"], input=password + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("error: sudo didn't accept that password")


def alias_context(link: Link, ip: str, net) -> dict:
    return {"interface": link.name, "label": link.label, "alias": ip, "prefix": net.prefixlen,
            "network": str(net), "vlan": link.vlan or 0, "parent": link.parent or link.name}


class AliasManager:
    """Adds and removes temporary addresses and VLAN interfaces, and never leaves one behind.

    Every change is written to ALIAS_STATE_FILE before it's made, so a run that dies hard
    can be cleaned up with --cleanup-aliases (or by the next run that uses aliases)."""

    def __init__(self, log):
        self.log = log
        # ("alias", iface, ip, prefix) / ("vlan", iface, parent, vid) / ("coexist", iface, was, 0), in order made
        self.active: list = []
        self.used: set = set()  # (iface, ip) for every alias taken during this run
        self.prepared: set = set()  # Windows adapters checked for DHCP/static coexistence
        if IS_WINDOWS or os.geteuid() == 0:
            self.sudo = []
        else:  # without a terminal (a GUI), sudo must never stop to ask: authorize() did that
            self.sudo = ["sudo", "-n"] if SUDO_ASKPASS else ["sudo"]

    @property
    def used_ips(self) -> set:
        return {ip for _, ip in self.used}

    @staticmethod
    def command(iface: str, ip: str, prefix: int, add: bool) -> list:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        if IS_WINDOWS:  # store=active: gone at the next restart even if this run dies
            if add:
                return ["netsh", "interface", "ipv4", "add", "address", iface, ip, str(net.netmask), "store=active"]
            return ["netsh", "interface", "ipv4", "delete", "address", iface, ip, "store=active"]
        if sys.platform == "darwin":
            if add:
                return ["ifconfig", iface, "alias", ip, "netmask", str(net.netmask),
                        "broadcast", str(net.broadcast_address)]
            return ["ifconfig", iface, "-alias", ip]
        # "brd +" matters: without a broadcast address Linux sends subnet broadcasts as unicast.
        return ["ip", "addr", "add" if add else "del", f"{ip}/{prefix}"] + (["brd", "+"] if add else []) + ["dev", iface]

    @staticmethod
    def vlan_commands(name: str, parent: str, vid: int, create: bool) -> list:
        if sys.platform == "darwin":
            if create:
                return [["ifconfig", name, "create"], ["ifconfig", name, "vlan", str(vid), "vlandev", parent],
                        ["ifconfig", name, "up"]]
            return [["ifconfig", name, "destroy"]]
        if create:
            return [["ip", "link", "add", "link", parent, "name", name, "type", "vlan", "id", str(vid)],
                    ["ip", "link", "set", name, "up"]]
        return [["ip", "link", "del", name]]

    @staticmethod
    def vlan_names(vid: int, taken=()) -> list:
        """Names to try for a new VLAN interface. On macOS start at vlan200, so the vlan0,
        vlan1... that System Settings creates for its own VLANs never collide with ours."""
        taken = set(taken)
        if sys.platform == "darwin":
            taken |= set(_run(["ifconfig", "-l"]).split())
            high = [f"vlan{n}" for n in range(200, 1000) if f"vlan{n}" not in taken]
            low = [f"vlan{n}" for n in range(200) if f"vlan{n}" not in taken]
            return high[:1] + low[:1]
        try:
            taken |= set(os.listdir("/sys/class/net"))
        except OSError:
            pass
        return [n for n in (f"ubnt{vid}", f"ubnt{vid}b") if n not in taken][:1]

    def authorize(self) -> None:
        if IS_WINDOWS:
            from opendisco import winnet
            if not winnet.is_admin():
                raise SystemExit("error: temporary addresses need administrator rights on Windows: run it as "
                                 "administrator (right-click > Run as administrator, or an Administrator terminal)")
            return
        if self.sudo:
            authorize_sudo("Temporary IP aliases need administrator rights; sudo may ask for your password.",
                           self.log)

    def keepalive(self) -> None:
        if self.sudo:
            subprocess.run(["sudo", "-n", "-v"], capture_output=True)

    def _load_state(self) -> list:
        try:
            with open(ALIAS_STATE_FILE, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return []
        entries = []
        for e in raw if isinstance(raw, list) else []:
            if isinstance(e, list) and len(e) == 3:  # older format: alias only
                entries.append(("alias",) + tuple(e))
            elif isinstance(e, list) and len(e) == 4 and e[0] in ("alias", "vlan", "coexist"):
                entries.append(tuple(e))
        return entries

    def _save_state(self, entries) -> None:
        try:
            if entries:
                tmp = ALIAS_STATE_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump([list(e) for e in entries], f)
                os.replace(tmp, ALIAS_STATE_FILE)
            elif os.path.exists(ALIAS_STATE_FILE):
                os.remove(ALIAS_STATE_FILE)
        except OSError:
            pass

    def _remember(self, entry) -> None:
        self._save_state(self._load_state() + [entry])

    def _forget(self, keep) -> None:
        self._save_state([e for e in self._load_state() if keep(e)])

    def _run(self, cmd) -> str | None:
        try:
            r = subprocess.run(self.sudo + cmd, capture_output=True, text=True, timeout=30, errors="replace",
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0)
        except (OSError, subprocess.SubprocessError) as e:
            return str(e)
        return None if r.returncode == 0 else ((r.stderr or r.stdout).strip() or f"exit status {r.returncode}")

    def _coexist(self, iface: str) -> None:
        """Windows refuses a static address on an adapter that uses DHCP unless DHCP/static
        coexistence is on (Windows 10 2004 and later). Turn it on, and back off afterwards if
        it was off; when Windows' wording can't be read, it's left on, which changes nothing."""
        if iface in self.prepared:
            return
        self.prepared.add(iface)
        m = re.search(r"coexistence\s*:\s*(\w+)", _run(["netsh", "interface", "ipv4", "show", "interface", iface]), re.I)
        if m and m.group(1).lower() == "enabled":
            return
        entry = ("coexist", iface, "disabled", 0)
        if m:
            self._remember(entry)
        err = self._run(["netsh", "interface", "ipv4", "set", "interface", iface, "dhcpstaticipcoexistence=enabled"])
        if err:
            self._forget(lambda e: e != entry)
            self.log(f"  couldn't allow a static address next to DHCP on {iface}: {err}")
        elif m:
            self.active.append(entry)

    def _restore_coexist(self, iface: str, was: str) -> None:
        err = self._run(["netsh", "interface", "ipv4", "set", "interface", iface, f"dhcpstaticipcoexistence={was}"])
        entry = ("coexist", iface, was, 0)
        if not err:
            self._forget(lambda e: e != entry)
        if entry in self.active:
            self.active.remove(entry)
        self.prepared.discard(iface)

    def add(self, iface: str, ip: str, prefix: int) -> bool:
        if IS_WINDOWS:
            self._coexist(iface)
        entry = ("alias", iface, ip, prefix)
        self._remember(entry)  # write it down first so a crash can't leak it
        err = self._run(self.command(iface, ip, prefix, True))
        if err:
            self._forget(lambda e: e != entry)
            self.log(f"  couldn't add {ip}/{prefix} to {iface}: {err}")
            return False
        self.active.append(entry)
        self.used.add((iface, ip))
        return True

    def remove(self, iface: str, ip: str, prefix: int) -> None:
        entry = ("alias", iface, ip, prefix)
        err = self._run(self.command(iface, ip, prefix, False))
        if err:
            self.log(f"  warning: couldn't remove {ip} from {iface} ({err}); run --cleanup-aliases")
        else:
            self._forget(lambda e: e != entry)
        if entry in self.active:
            self.active.remove(entry)

    def create_vlan(self, parent: str, vid: int) -> str | None:
        """Create a tagged interface for `vid` on `parent`; returns its name."""
        if IS_WINDOWS:
            self.log(f"  VLAN {vid} on {parent}: heard, but not probed: Windows can't tag VLANs itself (only the "
                     "network card's driver or a Hyper-V switch can)")
            return None
        err = "no free interface name"
        for name in self.vlan_names(vid, (e[1] for e in self.active if e[0] == "vlan")):
            entry = ("vlan", name, parent, vid)
            self._remember(entry)
            err = None
            for cmd in self.vlan_commands(name, parent, vid, True):
                err = self._run(cmd)
                if err:
                    break
            if err is None:
                self.active.append(entry)
                return name
            for cmd in self.vlan_commands(name, parent, vid, False):  # undo a half-made interface
                self._run(cmd)
            self._forget(lambda e: e != entry)
        self.log(f"  couldn't create VLAN {vid} on {parent}: {err}")
        return None

    def destroy_vlan(self, name: str, parent: str, vid: int) -> None:
        err = None
        for cmd in self.vlan_commands(name, parent, vid, False):
            err = self._run(cmd) or err
        on_it = lambda e: e[1] == name  # the interface and any aliases still on it
        if err:
            self.log(f"  warning: couldn't remove {name} ({err}); run --cleanup-aliases")
        else:
            self._forget(lambda e: not on_it(e))
        self.active = [e for e in self.active if not on_it(e)]

    def remove_all(self) -> None:
        for entry in reversed(list(self.active)):
            if entry not in self.active:  # went with its VLAN interface
                continue
            if entry[0] == "alias":
                self.remove(*entry[1:])
            elif entry[0] == "coexist":
                self._restore_coexist(entry[1], entry[2])
            else:
                self.destroy_vlan(*entry[1:])

    def cleanup_leftovers(self) -> int:
        leftovers = self._load_state()
        for kind, iface, a, b in reversed(leftovers):
            if kind == "alias":
                self.log(f"Removing leftover alias {a}/{b} from {iface}")
                self._run(self.command(iface, a, b, False))
            elif kind == "coexist":
                self._run(["netsh", "interface", "ipv4", "set", "interface", iface, f"dhcpstaticipcoexistence={a}"])
            else:
                self.log(f"Removing leftover VLAN {b} interface {iface} (on {a})")
                for cmd in self.vlan_commands(iface, a, b, False):
                    self._run(cmd)
        self._save_state([])
        return len(leftovers)


def run_alias_rounds(sc: Scanner, inv: Inventory, mgr: AliasManager, plans, opts, log) -> dict:
    """Probe each plan's networks from temporary addresses on its link, one link at a time
    (two interfaces holding the same subnet would make routing ambiguous). A plan for a VLAN
    first creates a tagged interface on the parent port and destroys it afterwards.

    Round 1  whole subnets, with a unicast sweep that also fills the ARP table.
    Round 2  small blocks (/29, /30) from an address nothing answered ARP or discovery on,
             so a point-to-point pair isn't disturbed. Blocks with no free address are skipped.
    Round 3  blocks that stayed silent, from their other address: a lone device sitting on
             the address round 2 borrowed would have ignored us."""
    result = {"arp": {}, "ctx": {}, "skipped": []}

    def occupied(seen) -> set:
        # Our own earlier aliases don't count as taken; anything that answered does.
        ips = set(result["arp"]) | (set(sc.local_ips) - mgr.used_ips) | set(seen)
        for d in inv.devices.values():
            ips.update(d.ips)
        return ips

    def pick(target, avoid):
        return next((ip for ip in alias_candidates(target) if ip not in avoid), None)

    def seen_in(net) -> bool:
        return (any(_in_any(ip, [net]) for d in inv.devices.values() for ip in d.ips)
                or any(_in_any(ip, [net]) for ip in result["arp"]))

    def probe(link, plan, what) -> None:
        added = [(t, ip) for t, ip in plan if mgr.add(link.name, ip, t.network.prefixlen)]
        if not added:
            return
        time.sleep(3.0 if IS_WINDOWS else 0.5)  # let the new routes settle (Windows checks for duplicates first)
        nets = [t.network for t, _ in added]
        hosts = [] if opts.quick else [str(h) for t, ip in added for h in t.network.hosts() if str(h) != ip]
        sc.begin_alias_round([Iface(link.name, ip, t.network.prefixlen, link.label) for t, ip in added],
                             [(t.network, alias_context(link, ip, t.network)) for t, ip in added], hosts)
        try:
            sc.run(max(3.0, sc.sweep_seconds() + 2.0))
        finally:
            # Read ARP before the aliases go: removing them flushes those entries.
            for ip, mac in read_arp_table().items():
                for t, alias_ip in added:
                    if ip != alias_ip and _in_any(ip, [t.network]):
                        result["arp"][ip] = mac
                        result["ctx"].setdefault(ip, alias_context(link, alias_ip, t.network))
            sc.end_alias_round()
            for t, ip in added:
                mgr.remove(link.name, ip, t.network.prefixlen)
        found = sum(1 for d in inv.devices.values() if any(_in_any(ip, nets) for ip in d.ips))
        aliases = ", ".join(f"{ip}/{t.network.prefixlen}" for t, ip in added)
        log(f"  {link.tag}: {what} via {aliases}: {found} device(s)")

    for item in plans:
        link, targets, seen = item["link"], item["targets"], item.get("busy", ())
        if not targets:
            continue
        made = None
        if link.vlan and not link.name:  # a VLAN that doesn't exist yet: tag it ourselves
            made = mgr.create_vlan(link.parent, link.vlan)
            if not made:
                continue
            link.name = made
            sc.vlan_map[made] = (link.vlan, link.parent)
            time.sleep(1.0)  # let the new interface come up
        try:
            busy, plan = occupied(seen), []
            for t in (t for t in targets if t.network.prefixlen < 29):
                ip = pick(t, busy)
                if ip:
                    plan.append((t, ip))
                else:
                    log(f"  {link.tag}: no free alias address in {t.network}, skipped")
            probe(link, plan, "subnets")

            busy, plan2 = occupied(seen), []
            for t in (t for t in targets if t.network.prefixlen >= 29):
                ip = pick(t, busy)
                if ip:
                    plan2.append((t, ip))
                elif t.network not in result["skipped"]:
                    result["skipped"].append(t.network)
            probe(link, plan2, "small blocks")

            busy, plan3 = occupied(seen), []
            for t, used in plan2:
                if not seen_in(t.network):
                    ip = pick(t, busy | {used})
                    if ip:
                        plan3.append((t, ip))
            probe(link, plan3, "silent blocks, other address")
        finally:
            if made:
                mgr.destroy_vlan(made, link.parent, link.vlan)
    return result


def hold_aliases(mgr: AliasManager, inv: Inventory, log) -> None:
    """Re-add the aliases (and VLAN interfaces) that reached gear and keep them until Ctrl+C."""
    held = hold_start(mgr, inv, log)
    if not held:
        return
    print("\n" + Style.bold("Holding temporary addresses so you can manage this gear (Ctrl+C removes them):"))
    print("\n".join(held))
    try:
        while mgr.active:
            time.sleep(60)
            mgr.keepalive()  # so removing them later doesn't need the password again
    except KeyboardInterrupt:
        print(file=sys.stderr)
    finally:
        mgr.remove_all()
        log("Temporary addresses removed.")


def hold_start(mgr: AliasManager, inv: Inventory, log) -> list:
    """Re-add the aliases (and VLAN interfaces) that reached gear; return lines describing
    what's held. mgr.remove_all() lets them go."""
    groups: dict = {}
    for d in sorted_devices(inv):
        if d.alias:
            a = d.alias
            key = (a.get("parent", a["interface"]), a.get("vlan", 0), a["alias"], a["prefix"])
            groups.setdefault(key, []).append(d)
    if not groups:
        log("\n--hold: no gear was reached through an alias, so there's nothing to hold.")
        return []
    lines, held = [], set()
    vlan_ifaces = {(p, v): n for n, (v, p) in os_vlan_map().items()}  # already there, reuse
    busy = {ip for d in inv.devices.values() for ip in d.ips}
    for (parent, vid, ip, prefix), devs in groups.items():
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        if ip in busy:  # the alias turned out to belong to a device; hold a free one instead
            ip = next((c for c in alias_candidates(AliasTarget(net)) if c not in busy), None)
        if net in held or ip is None:  # one interface per subnet, or routing gets ambiguous
            continue
        iface = parent
        if vid:
            iface = vlan_ifaces.get((parent, vid)) or mgr.create_vlan(parent, vid)
            if not iface:
                continue
            vlan_ifaces[(parent, vid)] = iface
        if not mgr.add(iface, ip, prefix):
            continue
        held.add(net)
        lines.append(f"  {ip}/{prefix} on " + (f"VLAN {vid} ({iface} on {parent})" if vid else parent))
        for d in devs:
            lines.append(f"    {d.ip or '-':<15}  {_trunc(d.model or '?', 22):<22}  {web_url(d) or 'ssh ' + (d.ip or '?')}")
    return lines


def print_alias_plan(plans, sudo, listen_on=(), listen_seconds=0.0) -> None:
    print(Style.bold("Alias plan (dry run: nothing is changed)"))
    if listen_on:
        print(f"\n  First, listen {listen_seconds:g}s on each wired port for VLAN tags, subnets and LLDP:")
        for name in listen_on:
            args = [f"'{a}'" if " " in a else a for a in TCPDUMP_ARGS]
            print("      " + " ".join(sudo + ["tcpdump", "-i", name] + args))
        print("    Each VLAN found then gets a temporary tagged interface, probed like the ones below.")
    for item in plans:
        link, targets = item["link"], item["targets"]
        print(f"\n  {link}")
        name = link.name
        if link.vlan:
            name = (AliasManager.vlan_names(link.vlan) or ["vlanN"])[0]
            print("    create the tagged interface:")
            for cmd in AliasManager.vlan_commands(name, link.parent, link.vlan, True):
                print("      " + " ".join(sudo + cmd))
        if not targets:
            print("    nothing to probe")
            continue
        wide = [t for t in targets if t.network.prefixlen < 29]
        small = [t for t in targets if t.network.prefixlen >= 29]
        for title, group in (("round 1, whole subnets (with a unicast sweep):", wide),
                             ("round 2, small blocks (first free address; silent blocks retried "
                              "from their other address in round 3):", small)):
            if group:
                print(f"    {title}")
                for t in group:
                    print("      " + " ".join(sudo + AliasManager.command(
                        name, alias_candidates(t)[0], t.network.prefixlen, True)))
        t = (wide or small)[0]
        print("    after each ~3s round the aliases are removed, e.g.")
        print("      " + " ".join(sudo + AliasManager.command(name, alias_candidates(t)[0], t.network.prefixlen, False)))
        if link.vlan:
            print("    and finally the tagged interface:")
            for cmd in AliasManager.vlan_commands(name, link.parent, link.vlan, False):
                print("      " + " ".join(sudo + cmd))


def print_interfaces(links, all_ifaces) -> None:
    print(Style.bold("Active Ethernet/Wi-Fi interfaces") + " (these get aliases)")
    for link in links:
        addrs = ", ".join(f"{i.ip}/{i.prefix}" for i in link.addrs) or "link up, no IPv4 address"
        print(f"  {link.name:<8} {link.label:<28} {addrs}")
    if not links:
        print("  none found")
    others = [i for i in all_ifaces if i.name not in {l.name for l in links}]
    if others:
        print(Style.bold("Other IPv4 interfaces") + " (VPNs, bridges...: probed, never given aliases)")
        for i in others:
            print(f"  {i.name:<8} {i.ip}/{i.prefix}")


# ---------------------------------------------------------------------------
# Enrichment and diagnostics
# ---------------------------------------------------------------------------

def enrich(inv: Inventory, sc: Scanner, opts, log, alias_result=None) -> None:
    alias_result = alias_result or {"arp": {}, "ctx": {}}
    arp = dict(alias_result["arp"], **read_arp_table()) if opts.arp else {}

    for d in list(inv.devices.values()):  # give IP-only records a MAC
        if d.mac is None:
            for ip in d.ips:
                if ip in arp:
                    inv.lookup(mac=arp[ip], ip=ip)
                    break

    if sc.mdns:
        for ip, h in sc.mdns.hosts.items():
            if ip in sc.local_ips:
                continue
            text = " ".join(list(h["hostnames"]) + list(h["instances"]) + list(h["services"])
                            + [" ".join(v) for v in h["txt"].values()])
            if inv.find(ip=ip) or is_ubnt_mac(arp.get(ip)) or UBNT_HINT.search(text):
                d = inv.attach(ip, arp.get(ip), "mdns")
                d.mdns = {k: (sorted(v) if isinstance(v, set) else v) for k, v in h.items() if v}
                mdns_port_hints(d)
                if ip in sc.mdns.raw:
                    at, src, data = sc.mdns.raw[ip]
                    d.add_sample(PacketRecord(at, "mDNS", src, "mdns", data=data))

    if sc.ssdp and sc.ssdp.responders:
        ips = list(sc.ssdp.responders)
        with ThreadPoolExecutor(16) as ex:
            descs = dict(zip(ips, ex.map(sc.ssdp.describe, ips)))
        for ip, desc in descs.items():
            text = " ".join(str(v) for v in desc.values())
            if inv.find(ip=ip) or is_ubnt_mac(arp.get(ip)) or UBNT_HINT.search(text):
                d = inv.attach(ip, arp.get(ip), "ssdp")
                d.ssdp = desc
                upnp_port_hint(d)
                if ip in sc.ssdp.raw:
                    at, src, data = sc.ssdp.raw[ip]
                    d.add_sample(PacketRecord(at, "SSDP", src, "ssdp", data=data))

    for ip, mac in arp.items():
        if vendor_of(mac) or (inv.find(ip=ip) and inv.find(ip=ip).via & {"ubnt", "mcast", "announce"}):
            inv.attach(ip, mac, "arp")

    for d in inv.devices.values():  # gear only seen in the ARP table during an alias round
        if not d.alias:
            d.alias = next((alias_result["ctx"][ip] for ip in d.ips if ip in alias_result["ctx"]), {})

    for ip, ports in inv.requesters.items():
        d = inv.find(ip=ip)
        if d and any(p != opts.port for p in ports):
            d.console = True  # consoles echo discovery requests from an ephemeral port

    if opts.ports or opts.deep:
        check_ports(inv.devices.values(), opts, log)

    if opts.deep:
        targets = [d for d in inv.devices.values()
                   if d.ip and (d.console or (d.ports and 443 in d.ports))]
        if targets:
            log(f"Querying UniFi OS console API on {len(targets)} device(s)...")
            with ThreadPoolExecutor(16) as ex:
                for d, api in zip(targets, ex.map(lambda d: probe_console_api(d.ip), targets)):
                    d.api = api
                    if d.system.get("hardware") or api.get("apps"):
                        d.console = True


def assign_vlans(inv: Inventory, all_ifaces, vlan_map, natives) -> None:
    """Settle each device's VLAN: the interface it answered on, else the alias that reached
    it, else the local subnet it's in. Untagged shows as the port's native VLAN (from LLDP),
    or 1 when the switch didn't say."""
    for d in inv.devices.values():
        if d.vlan is None and d.alias:
            d.vlan, d.vlan_parent = d.alias.get("vlan", 0), d.alias.get("parent", d.alias["interface"])
        if d.vlan is None:  # when several interfaces share the subnet, prefer one whose native VLAN is known
            candidates = [i for i in all_ifaces for ip in d.ips if _in_any(ip, [i.network])]
            iface = next((i for i in candidates if i.name in natives), candidates[0] if candidates else None)
            if iface:
                d.vlan, d.vlan_parent = vlan_map.get(iface.name, (0, iface.name))
        if d.vlan is None:
            d.vlan_label = ""
        else:
            d.vlan_label = str(d.vlan or natives.get(d.vlan_parent, 1))


def _in_any(ip: str, nets) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _one_digit_off(a: int, b: int) -> bool:
    """A typo away: one digit changed, added or dropped (2222 vs 2223, 443 vs 4443)."""
    x, y = sorted((str(a), str(b)), key=len)
    if len(x) == len(y):
        return sum(c1 != c2 for c1, c2 in zip(x, y)) == 1
    return len(y) == len(x) + 1 and any(y[:i] + y[i + 1:] == x for i in range(len(y)))


def port_outliers(devices) -> dict:
    """Spot a fat-fingered port without a list to check against: when most of one vendor's gear
    of one kind (consoles, or the rest) here uses the same web UI or SSH port, a device using
    another stands out. Returns {(device key, "https"/"ssh"): message}."""
    out = {}
    for kind in ("https", "ssh"):
        name = "web UI" if kind == "https" else "SSH"
        groups = {}
        for d in devices:
            port = d.said_port(kind)
            if port and d.vendor:
                groups.setdefault((d.vendor, d.console), []).append((d, port))
        for (vendor, console), pairs in groups.items():
            usual, n = Counter(p for _, p in pairs).most_common(1)[0]
            if n < 2 or n * 3 < len(pairs) * 2:  # no clear habit to compare with
                continue
            what = f"{vendor} {'consoles' if console else 'devices'}"
            for d, port in pairs:
                if port != usual:
                    typo = ", one digit off" if _one_digit_off(port, usual) else ""
                    out[(d.key, kind)] = (f"Its {name} is on port {port}, but the other {n} {what} here use "
                                          f"{usual}{typo}: a typo in its config?")
    return out


PROBLEM_NAMES = {
    "short": "too short", "version": "garbled header", "cut-short": "cut short",
    "trailing": "extra bytes at the end", "overrun": "a field running past the end", "stray": "stray bytes",
    "json-32": "broken port JSON", "ip-checksum": "bad IP checksum", "ip-short": "IP packet cut short",
    "udp-short": "UDP header cut short", "udp-length": "wrong UDP length", "udp-checksum": "bad UDP checksum",
    "fragment": "fragmented",
}
VOLATILE_KEYS = {"uptime", "seq", "salt", "rnd_challenge", "challenge"}  # change on every reply


def problem_name(code: str) -> str:
    prefix, _, tlv = code.partition("-")
    if prefix in ("size", "text", "twice") and len(tlv) == 2:
        label = TLV.get(int(tlv, 16), ("", f"field 0x{tlv}"))[1]
        return {"size": f"wrong-size {label}", "text": f"unreadable {label}", "twice": f"{label} twice"}[prefix]
    return PROBLEM_NAMES.get(code, code)


def reply_rounds(d: Device, rounds) -> tuple:
    """(answered, sent): our rounds of probes that reached the device, from the first it
    answered to the last, and how many of those it answered. (0, 0) when that can't be told."""
    times = sorted(d.reply_times)
    if not times or not rounds:
        return 0, 0
    sources = {r.src.rsplit(":", 1)[0] for r in list(d.packets) if r.via in ("ubnt", "mcast")}
    answered = []
    for i, (start, nets) in enumerate(rounds):
        if not any(_in_any(ip, [net]) and (not d.seen_on or name in d.seen_on) for net, name in nets for ip in sources):
            continue
        end = rounds[i + 1][0] if i + 1 < len(rounds) else start + 2.0
        j = bisect.bisect_left(times, start)
        answered.append(j < len(times) and times[j] < end)
    if True not in answered:
        return 0, 0
    first, last = answered.index(True), len(answered) - answered[::-1].index(True)
    return sum(answered[first:last]), last - first


def packet_findings(d: Device) -> dict:
    """What a device's packets say about the path to it.
    damaged: {(kind, code): packets}, damage that comes and goes (or too few packets to tell);
    quirks: {(kind, code): packets}, the same oddity in every packet of a kind: how its firmware
        writes them, not damage;
    changes: [(n, kind, field, old, new, one_off)], fields that changed between replies of the
        same shape; one_off when the next reply changed it back, which damage does and real
        changes don't;
    uptime: [(n, message)], uptime that didn't keep time with the clock."""
    kinds = dict(d.kind_counts)
    damaged, quirks = {}, {}
    for (kind, code), n in list(d.problem_counts.items()):
        if code == "fragment":
            continue
        (quirks if n == kinds.get(kind) and n >= 3 else damaged)[(kind, code)] = n
    groups = {}  # replies of one shape: (kind, field types) -> [(record, decoded fields)]
    for rec in list(d.packets):
        if any(code in FRAMING for code, _ in rec.problems):
            continue
        fields, _ = _tlv_walk(rec.data)
        pkt = parse_packet(rec.data)
        if pkt:
            groups.setdefault((rec.kind, tuple(sorted({t for _, t, _ in fields}))), []).append(
                (rec, decode_fields(pkt)[0]))
    changes, uptime = [], []
    for (kind, _), recs in groups.items():
        back = set()  # (index, key) of a change that undid a one-off
        for i in range(1, len(recs)):
            (r0, prev), (r1, cur) = recs[i - 1], recs[i]
            for key in sorted((set(prev) | set(cur)) - VOLATILE_KEYS):
                if prev.get(key) != cur.get(key) and (i, key) not in back:
                    one_off = i + 1 < len(recs) and recs[i + 1][1].get(key) == prev.get(key)
                    if one_off:
                        back.add((i + 1, key))
                    changes.append((r1.n, kind, TLV_LABELS.get(key, key), prev.get(key), cur.get(key), one_off))
        ref, odd = None, False  # the last uptime that kept time; whether the one before was off
        for rec, cur in recs:
            nu = cur.get("uptime")
            if not isinstance(nu, int):
                continue
            if ref is not None:
                (r0, ou), dt = ref, rec.at - ref[0].at
                if nu < ou and nu <= dt + 60:
                    uptime.append((rec.n, f"{kind}: rebooted (uptime {fmt_uptime(ou)} -> {fmt_uptime(nu)})"))
                elif abs((nu - ou) - dt) > 120 + dt * 0.02:  # firmware refreshes it every half-minute or so
                    if not odd:  # the next one is compared with the last good one, so a one-off shows once
                        uptime.append((rec.n, f"{kind}: uptime moved {nu - ou:+d}s in {dt:.1f}s "
                                              f"({fmt_uptime(ou)} -> {fmt_uptime(nu)})"))
                        odd = True
                        continue
            ref, odd = (rec, nu), False
    return {"damaged": damaged, "quirks": quirks, "changes": changes, "uptime": uptime}


def damage_summary(d: Device, found: dict) -> list:
    """packet_findings() as short phrases: damage, one-off changes, and uptime that jumped."""
    bad = [f"{problem_name(code)} in {n} of {d.kind_counts[kind]} {kind}"
           for (kind, code), n in sorted(found["damaged"].items())]
    bad += [f"{field} changed for one packet and back (#{n})"
            for n, _, field, _, _, one_off in found["changes"] if one_off]
    return bad + [f"#{n} {msg.split(': ', 1)[1]}" for n, msg in found["uptime"] if "rebooted" not in msg]


def diagnose(inv: Inventory, all_ifaces, scan_nets, opts, alias_used=(), skipped=(), probed_links=()) -> None:
    """alias_used: (iface, ip) aliases taken. probed_links: interfaces that had their own
    address during the normal scan, so silence there means the device ignored us."""
    local_nets = list(dict.fromkeys(i.network for i in all_ifaces if i.prefix < 32))
    odd_ports = port_outliers(inv.devices.values())
    owners: dict = {}
    for d in inv.devices.values():
        for ip in d.ips:
            owners.setdefault(ip, set()).add(d.key)

    for d in inv.devices.values():
        issues, info = [], d.info
        heard_ubnt = d.ubnt_packets > 0

        if info.get("is_default"):
            msg = "Factory default / not adopted - ready for adoption."
            if not d.console:
                msg += (f" Adopt it in the UniFi Network app, or SSH to {d.ip or 'it'} (factory login is "
                        "usually ubnt/ubnt) and run: set-inform http://<controller-ip>:8080/inform")
            issues.append(("note", "DEFAULT", msg))
        if d.system.get("isSetup") is False:
            issues.append(("note", "NOT-SET-UP", "UniFi OS console hasn't been set up yet."))
        if any(ip.startswith("169.254.") for ip in d.ips):
            issues.append(("error", "LINK-LOCAL",
                           "Has a 169.254.x.x self-assigned address: it never got a DHCP lease. "
                           "Check the DHCP server, VLAN/port profile and uplink."))
        if FALLBACK_IP in d.ips and info.get("dhcp_bound") is not True:
            issues.append(("warn", "FALLBACK-IP",
                           f"Sitting on the factory fallback address {FALLBACK_IP}, which usually means "
                           "no DHCP lease. Several devices in this state will conflict with each other."))
        if info.get("dhcp_client") is True and info.get("dhcp_bound") is False:
            issues.append(("warn", "NO-LEASE",
                           "DHCP client is on but has no lease. Check the DHCP server, VLAN tagging "
                           "and the switch port."))
        conflicts = sorted({k for ip in d.ips for k in owners.get(ip, ()) if k != d.key})
        if conflicts:
            shared = sorted({ip for ip in d.ips if len(owners.get(ip, ())) > 1})
            issues.append(("error", "IP-CONFLICT",
                           f"{', '.join(shared)} is also used by {', '.join(conflicts)}."))
        if heard_ubnt and d.alias and not d.direct:
            a = d.alias
            if a["interface"] in probed_links:
                why = (f"Only answered once this computer had an address in {a['network']} (temporary "
                       f"{a['alias']} on {a['interface']}): newer firmware ignores discovery from other subnets.")
            elif a.get("vlan"):
                why = f"Reached through temporary {a['alias']} on tagged VLAN {a['vlan']} ({a['parent']})."
            else:
                why = (f"Reached through temporary {a['alias']} on {a['interface']}, which had no address "
                       "of its own.")
            issues.append(("note", "ALIAS", why + " Add --hold to keep that address while you work on it."))
        elif (heard_ubnt and d.ips and local_nets and not any(_in_any(ip, local_nets) for ip in d.ips)
                and not any(_in_any(ip, scan_nets) for ip in d.ips)):
            nets = ", ".join(str(n) for n in local_nets)
            issues.append(("warn", "OFF-SUBNET",
                           f"Answers discovery from other subnets (older firmware does), but its address "
                           f"isn't in this computer's subnet(s) ({nets}), so you can't reach its web UI or "
                           "SSH. Run with --aliases --hold (its subnet in networks.txt), or fix its IP/VLAN."))
        if d.wifi:
            msg = f"Your Wi-Fi ({d.wifi['iface']}) is joined to this access point (BSSID {d.wifi['bssid']})."
            if not d.ip:
                msg += (" Its management address isn't on your Wi-Fi network: probe its management VLAN from a "
                        "wired trunk port with --vlans, or give its subnet with --alias.")
            issues.append(("note", "WIFI-AP", msg))
        link = d.alias.get("interface")
        clashes = sorted(ip for ip in d.ips if (link, ip) in alias_used)
        if clashes:
            issues.append(("warn", "ALIAS-CONFLICT",
                           f"Uses {', '.join(clashes)}, which this tool borrowed on {link} for a few seconds "
                           "before it knew the address was taken. For a whole subnet, pin another alias "
                           "with alias= in networks.txt."))
        for port in info.get("ports", []):
            if isinstance(port, dict) and port.get("type") == "WAN" and port.get("plugged") is False:
                issues.append(("warn", "WAN-DOWN", f"WAN port {port.get('name', '?')} reports no link."))
        if info.get("locating"):
            issues.append(("note", "LOCATING", "Locate mode is on (LED flashing)."))
        up = info.get("uptime")
        if isinstance(up, int) and up < 300:
            issues.append(("warn", "REBOOTED",
                           f"Uptime is only {fmt_uptime(up)}. If it keeps rebooting, check PoE budget, "
                           "cabling and firmware."))
        if not heard_ubnt and d.vendor == "Ubiquiti" and any(_in_any(ip, skipped) for ip in d.ips):
            issues.append(("note", "NOT-PROBED",
                           "Both addresses in its /30 are taken (or one is its gateway), so it wasn't probed: "
                           "getting an answer would mean borrowing one of them."))
        elif (not heard_ubnt and "sniff" in d.via and not d.alias and local_nets and d.ips
              and not any(_in_any(ip, local_nets) for ip in d.ips)):
            nets = ", ".join(sorted({str(ipaddress.IPv4Network(f"{ip}/24", strict=False)) for ip in d.ips}))
            if d.vlan and not (opts.vlans or opts.vlan_ids or opts.direct):
                advice = " It's on tagged VLAN %d: --vlans probes it through a temporary tagged interface." % d.vlan
            elif opts.alias_mode:
                advice = " It didn't answer probes from a temporary address in its subnet." if d.vendor == "Ubiquiti" else ""
            else:
                advice = " Add -a to probe it through a temporary address (--sniff -a does that automatically)."
            issues.append(("note", "OTHER-SUBNET", f"Heard on the wire, outside this computer's subnets ({nets})."
                           + advice))
        elif not heard_ubnt and not opts.listen and d.via and d.ips and d.vendor == "Ubiquiti":
            seen = "/".join(v for v in VIA_ORDER if v in d.via)
            issues.append(("warn", "NO-DISCOVERY",
                           f"Seen via {seen} but didn't answer UBNT discovery: discovery may be turned "
                           "off on the device, UDP 10001 filtered (firewall, client isolation), or the "
                           "model doesn't support it."))
        for kind, tag, standard in (("https", "HTTPS-PORT", opts.https_ports), ("ssh", "SSH-PORT", opts.ssh_ports)):
            name = "web UI" if kind == "https" else "SSH"
            said = d.said_ports(kind)
            reported = d.said_port(kind)
            if len(set(said.values())) > 1:
                issues.append(("warn", tag, f"Gives different {name} ports: " + "; ".join(
                    f"{port} from {PORT_SOURCES[source]}" for source, port in said.items()) + "."))
            if (d.key, kind) in odd_ports:
                issues.append(("warn", tag, odd_ports[(d.key, kind)]))
            if reported and standard and reported not in standard:
                issues.append(("warn", tag, f"Reports its {name} on port {reported}, not your standard "
                                            f"{', '.join(map(str, standard))}: a typo in its config?"))
            if reported and d.ports is not None:
                found = d.services.get(reported)
                elsewhere = sorted(p for p, k in d.services.items() if k == kind and p != reported)
                if found is None:
                    issues.append(("warn", tag, f"Reports its {name} on port {reported}, but nothing answers there"
                                   + (f"; {kind.upper()} answers on {', '.join(map(str, elsewhere))}." if elsewhere
                                      else ".")))
                elif kind == "https" and found == "http":
                    issues.append(("note", tag, f"The web UI on port {reported} is plain HTTP, not HTTPS."))
                elif found != kind:
                    issues.append(("warn", tag, f"Port {reported} answers, but not with {kind.upper()} ({found})."))
        if d.ports is not None and not d.ports:
            issues.append(("warn", "NO-PORTS",
                           f"No management ports open ({', '.join(map(str, CHECK_PORTS))}): firewalled, "
                           "still booting, or not reachable at layer 3."))
        if d.packets:
            bad = damage_summary(d, packet_findings(d))
            if bad:
                issues.append(("warn", "DAMAGED",
                               f"Discovery packets arrived damaged: {'; '.join(bad[:4])}"
                               + (f" and {len(bad) - 4} more" if len(bad) > 4 else "")
                               + ". On your own subnet, damage that comes and goes points to a cable or "
                                 "connector, a failing port, or a speed/duplex mismatch. See its packets "
                                 "(Packets tab, or -v --raw)."))
        answered, sent = reply_rounds(d, inv.rounds)
        if sent >= 5 and sent - answered >= 2 and (sent - answered) / sent >= 0.1:
            issues.append(("warn", "LOSS",
                           f"Answered {answered} of {sent} rounds of discovery probes while in view: "
                           f"{sent - answered} went unanswered. On your own subnet that's packet loss: "
                           "Wi-Fi interference, a bad cable or port, a busy link, or a busy device."))
        d.issues = issues


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

class Style:
    on = False
    LEVEL = {"error": "31", "warn": "33", "note": "36", "ok": "32"}

    @classmethod
    def paint(cls, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.on and code else text

    @classmethod
    def level(cls, text: str, level: str) -> str:
        return cls.paint(text, cls.LEVEL.get(level, ""))

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.paint(text, "1")


def _trunc(s: str, width: int) -> str:
    return s if len(s) <= width else s[:width - 1] + "~"


def _ip_sort_key(d: Device):
    try:
        return (0, int(ipaddress.IPv4Address(d.ip)))
    except ValueError:
        return (1, 0)


def sorted_devices(inv: Inventory) -> list:
    return sorted(inv.devices.values(), key=_ip_sort_key)


def status_cell(d: Device) -> tuple:
    """Plain text and coloured text for the STATUS column."""
    parts = [(tag, level) for level, tag, _ in d.issues]
    if d.console:
        parts.insert(0, ("console", "note"))
    if not parts:
        parts = [("ok", "ok")]
    return " ".join(t for t, _ in parts), " ".join(Style.level(t, lv) for t, lv in parts)


def render_table(devs) -> str:
    cols = [("IP", 15), ("VLAN", 4), ("VENDOR", 9), ("MAC", 17), ("MODEL", 22), ("NAME", 22), ("FIRMWARE", 16),
            ("UPTIME", 7), ("VIA", 24)]
    rows = []
    for d in devs:
        vals = [d.ip or "-", d.vlan_label or "?", d.vendor or "?", d.mac or "-", d.model or "?", d.name, d.firmware,
                fmt_uptime(d.info.get("uptime")), ",".join(v for v in VIA_ORDER if v in d.via)]
        rows.append(([_trunc(v, w) for v, (_, w) in zip(vals, cols)], status_cell(d)))
    widths = [max([len(h)] + [len(r[0][i]) for r in rows]) for i, (h, _) in enumerate(cols)]
    out = [Style.bold("  ".join(h.ljust(w) for (h, _), w in zip(cols, widths)) + "  STATUS")]
    for vals, (_, status) in rows:
        out.append("  ".join(v.ljust(w) for v, w in zip(vals, widths)) + "  " + status)
    return "\n".join(out)


def _fmt_value(key: str, value) -> str:
    if key == "uptime" and isinstance(value, int):
        return f"{fmt_uptime(value)} ({value}s)"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict):
        if key == "webui" and "port" in value:
            web = " (the web UI)" if value.get("flags", 0) & 1 else " (not marked as the web UI)"
            return f"port {value['port']}, flags 0x{value.get('flags', 0):04x}{web}"
        bits = [str(value[k]) for k in ("name", "type") if value.get(k)]
        if "plugged" in value:
            bits.append("link up" if value["plugged"] else "no link")
        bits += [str(value[k]) for k in ("mac", "ip") if k in value]
        bits += [f"{k}={v}" for k, v in value.items() if k not in ("name", "type", "plugged", "mac", "ip")]
        return "  ".join(bits)
    return str(value)


def web_url(d: Device, fallback: bool = False) -> str:
    """The device's web UI: where a deep check found HTTPS (or plain HTTP), else the port it
    says. fallback gives https://ip/ when nothing is known (to try it anyway)."""
    if not d.ip:
        return ""
    said = d.said_port("https")
    for kind in ("https", "http"):
        ports = sorted((p for p, k in d.services.items() if k == kind), key=lambda p: p != said)
        if ports:
            default = 443 if kind == "https" else 80
            return f"{kind}://{d.ip}/" if ports[0] == default else f"{kind}://{d.ip}:{ports[0]}/"
    if said and (fallback or d.ports is None):  # nothing answered a deep check: still its best guess
        return f"https://{d.ip}/" if said == 443 else f"https://{d.ip}:{said}/"
    return f"https://{d.ip}/" if fallback else ""


def render_details(d: Device) -> str:
    title = "  ".join(x for x in (d.ip, d.mac or "", d.model) if x)
    out = [Style.bold(f"== {title} " + "=" * max(4, 74 - len(title)))]

    def row(label, value):
        out.append(f"  {label:<22} {value}")

    for spec in TLV.values():
        key = spec[0]
        value = d.info.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, list):
            for n, v in enumerate(value):
                row(spec[1] if n == 0 else "", _fmt_value(key, v))
        else:
            row(spec[1], _fmt_value(key, value))
    if len(d.ips) > 1:
        row("All IPs", ", ".join(d.ips))
    if d.other_macs:
        row("Other MACs", ", ".join(sorted(d.other_macs)))
    row("Seen via", ", ".join(v for v in VIA_ORDER if v in d.via))
    if d.vlan is not None:
        how = f"tagged, on {d.vlan_parent}" if d.vlan else f"untagged on {d.vlan_parent}"
        row("VLAN", f"{d.vlan_label} ({how})")
    if d.seen_on:
        row("Answered on", ", ".join(sorted(d.seen_on)))
    if d.lldp:
        bits = [d.lldp.get(k) for k in ("system", "description") if d.lldp.get(k)]
        if d.lldp.get("mgmt_ip"):
            bits.append(f"mgmt {d.lldp['mgmt_ip']}")
        row("LLDP", "  ".join(bits) or "(announced, no identity)")
    if d.alias:
        a = d.alias
        row("Reached via alias", f"{a['alias']}/{a['prefix']} on {a['interface']}"
                                 + ("  (also answered without it)" if d.direct else ""))
    if d.protocols:
        row("UBNT protocol", ", ".join(sorted(d.protocols)) + f"  ({d.ubnt_packets} packets)")
    if d.mac:
        row("Vendor (MAC)", vendor_of(d.mac) or "not in the built-in lists")
    if d.mdns:
        if d.mdns.get("hostnames"):
            row("mDNS hostnames", ", ".join(d.mdns["hostnames"]))
        if d.mdns.get("services"):
            row("mDNS services", ", ".join(d.mdns["services"]))
        for inst, txt in list(d.mdns.get("txt", {}).items())[:6]:
            row("mDNS TXT", f"{inst}: {' '.join(txt)[:120]}")
    if d.ssdp:
        desc = " / ".join(d.ssdp[k] for k in ("friendlyName", "manufacturer", "modelName", "modelDescription")
                          if d.ssdp.get(k))
        if desc:
            row("SSDP", desc)
        if d.ssdp.get("server"):
            row("SSDP server", d.ssdp["server"])
    if d.api:
        s = d.system
        hw = s.get("hardware") if isinstance(s.get("hardware"), dict) else {}
        bits = [f"{k}={v}" for k, v in (("name", s.get("name")), ("hardware", hw.get("shortname")),
                                        ("isSetup", s.get("isSetup")), ("mac", s.get("mac"))) if v is not None]
        if bits:
            row("Console API", "  ".join(bits))
        if d.api.get("apps"):
            row("Console apps", ", ".join(d.api["apps"]))
    for kind, label in (("https", "HTTPS port"), ("ssh", "SSH port")):
        said = d.said_ports(kind)
        if said:
            row(label, "; ".join(f"{port} ({PORT_SOURCES[source]})" for source, port in said.items()))
    if d.ports is not None:
        row("Open TCP ports", ", ".join(f"{p} {d.services.get(p, '')}".strip() for p in d.ports) or "none")
    url = web_url(d)
    if url:
        row("Web UI URL", url)
    if d.unknown_tlvs:
        for n, (t, v) in enumerate(sorted(d.unknown_tlvs.items())):
            row("Unknown TLVs" if n == 0 else "", f"{t} = {v[:64]}{'...' if len(v) > 64 else ''}")
    if d.issues:
        out.append("  Diagnostics:")
        for level, tag, msg in d.issues:
            out.append(f"    {Style.level(f'[{tag}]', level)} {msg}")
    return "\n".join(out)


def _clock(at: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(at)) + f".{int(at % 1 * 1000):03d}"


def _vlan_cell(vlan) -> str:
    return "?" if vlan is None else "untagged" if vlan == 0 else str(vlan)


def _short(value, width: int = 48) -> str:
    return _trunc("(missing)" if value is None else repr(value) if isinstance(value, str) else str(value), width)


def render_packets(d: Device, inv: Inventory | None = None, counters: dict | None = None) -> str:
    """Every packet kept for a device and what the checks found, then the latest reply of
    each kind and every damaged one, field by field with its hex dump."""
    title = "  ".join(x for x in (d.ip, d.mac or "", d.model) if x)
    out = [Style.bold(f"== Packets from {title} " + "=" * max(4, 62 - len(title)))]

    def row(label, value):
        out.append(f"  {label:<16} {value}")

    packets = list(d.packets)
    garbled = [r for ip in d.ips for r in (inv.garbled.get(ip, []) if inv else [])]
    found = packet_findings(d)
    if d.ubnt_packets:
        kinds = ", ".join(f"{n} {k}" for k, n in sorted(dict(d.kind_counts).items()))
        row("Received", f"{d.ubnt_packets} UBNT discovery packet(s): {kinds}"
                        + (f"; the last {len(packets)} are listed" if len(packets) < d.ubnt_packets else ""))
        row("Damage", "; ".join(damage_summary(d, found)) or "none found")
        if found["quirks"]:
            row("Every time", "; ".join(f"{problem_name(c)} ({k})" for k, c in sorted(found["quirks"]))
                + ": how its firmware writes them, not damage")
        answered, sent = reply_rounds(d, inv.rounds) if inv else (0, 0)
        if sent:
            row("Answered", f"{answered} of {sent} rounds of our probes while in view"
                            + (f" ({sent - answered} unanswered)" if answered < sent else ""))
    if garbled:
        row("Unreadable", f"{len(garbled)} packet(s) on UDP {UBNT_PORT} from its address, too damaged to read")
    if counters:
        names = sorted({r.iface for r in packets + d.samples + garbled if r.iface} | d.seen_on
                       | ({"all adapters"} & set(counters.get("interfaces", {}))))
        for name in names:
            if name in counters.get("interfaces", {}):
                up = counters["interfaces"][name]
                if name == "all adapters":  # Windows' total drops also count protocols it just ignores
                    up = {k: n for k, n in up.items() if k != "drops"}
                row(name, f"during the scan: {counter_text(up)}" if up else "no errors or drops during the scan")
        if counters.get("system_read"):
            row("This computer", f"during the scan: {counter_text(counters['system'])}" if counters["system"]
                else "no IP or UDP errors during the scan")
    if d.ubnt_packets:
        out.append("  Checked: lengths, field sizes, text, repeated fields, changes between replies"
                   + ("; IP/UDP checksums of packets captured off the wire" if any(r.frame for r in packets) else ""))

    if packets:
        out.append("")
        out.append(f"  {'#':>5}  {'time':<12}  {'from':<21} {'via':<8} {'in on':<9} {'VLAN':<8}  {'kind':<9} "
                   f"{'bytes':>5}  check")
        for r in packets:
            check = "; ".join(problem_name(c) for c, _ in r.problems) or "ok"
            out.append(f"  {r.n:>5}  {_clock(r.at)}  {r.src:<21} {r.via:<8} {r.iface or '?':<9} "
                       f"{_vlan_cell(r.vlan):<8}  {r.kind:<9} {len(r.data):>5}  {check}")
    if found["changes"] or found["uptime"]:
        out.append("\n  Between replies of the same kind:")
        for n, kind, label, old, new, one_off in found["changes"]:
            out.append(f"    #{n} {kind}: {label} {_short(old)} -> {_short(new)}"
                       + ("  (for this packet only: damaged on the way?)" if one_off else ""))
        out += [f"    #{n} {msg}" for n, msg in found["uptime"]]

    def where(r):
        return f"{_clock(r.at)} from {r.src}" + (f" on {r.iface}" if r.iface else "") + (
            f", VLAN {_vlan_cell(r.vlan)}" if r.vlan is not None else "")

    shown = set()
    for r in [r for r in packets if any(c != "fragment" for c, _ in r.problems)][:6]:
        out.append(f"\n  Damaged packet #{r.n}, {r.kind}, {len(r.data)} bytes, {where(r)}  (@ = offset in the hex dump)")
        out += packet_lines(r.data, r.problems)
        if r.frame and any(c.startswith(("ip-", "udp-")) for c, _ in r.problems):
            out += ["   The whole frame as captured:", hexdump(r.frame)]
        shown.add(id(r))
    latest = {r.kind: r for r in packets}
    for kind, r in sorted(latest.items()):
        if id(r) not in shown:
            out.append(f"\n  Latest {kind} reply, #{r.n}, {len(r.data)} bytes, {where(r)}  (@ = offset in the hex dump)")
            out += packet_lines(r.data, r.problems)
    for r in garbled[-5:]:
        out.append(f"\n  Unreadable packet, {len(r.data)} bytes, {where(r)}")
        out += packet_lines(r.data, r.problems)
    for r in d.samples:
        what = "the whole Ethernet frame" if r.frame else f"{r.proto} payload"
        out.append(f"\n  {r.proto} packet it was found from, {where(r)}: {len(r.data)} bytes ({what})")
        out.append(hexdump(r.data))
    if not d.ubnt_packets and not d.samples and not garbled:
        how = "/".join(v for v in VIA_ORDER if v in d.via) or "nothing"
        out.append(f"  No packets to show: it was found through {how}"
                   + (", and the ARP table keeps no packets" if d.via <= {"arp", "wifi"} else "") + ".")
    return "\n".join(out)


def render_issues(devs) -> str:
    lines = []
    for d in devs:
        for level, tag, msg in d.issues:
            who = _trunc(f"{d.ip or d.mac or '-'}  {d.model or d.name or ''}".strip(), 36)
            lines.append(f"  {who:<36}  {Style.level(f'[{tag}]', level)} {msg}")
    return "\n".join(lines)


def device_to_dict(d: Device) -> dict:
    return {
        "mac": d.mac, "ip": d.ip, "ips": d.ips, "other_macs": sorted(d.other_macs),
        "model": d.model, "name": d.name, "firmware": d.firmware, "console": d.console,
        "via": [v for v in VIA_ORDER if v in d.via], "ubnt_protocols": sorted(d.protocols),
        "vendor": d.vendor or None, "ubiquiti_oui": is_ubnt_mac(d.mac), "ubnt": d.info, "unknown_tlvs": d.unknown_tlvs,
        "mdns": d.mdns, "ssdp": d.ssdp, "console_api": d.api, "open_ports": d.ports,
        "services": {str(p): k for p, k in d.services.items()} or None,
        "https_port": d.said_port("https"), "ssh_port": d.said_port("ssh"),
        "port_sources": {kind: d.said_ports(kind) for kind in ("https", "ssh") if d.said_ports(kind)} or None,
        "alias": d.alias or None, "answered_without_alias": d.direct,
        "vlan": int(d.vlan_label) if d.vlan_label.isdigit() else None,
        "vlan_tagged": bool(d.vlan), "vlan_parent": d.vlan_parent or None, "answered_on": sorted(d.seen_on), "lldp": d.lldp or None, "wifi_ap": d.wifi or None,
        "issues": [{"level": lv, "tag": t, "message": m} for lv, t, m in d.issues],
        "last_packet_hex": d.last_packet.hex() if d.last_packet else None,
        "packets_received": d.ubnt_packets,
        "packets": [packet_to_dict(r) for r in list(d.packets)[-10:]],
        "found_from": [packet_to_dict(r) for r in d.samples],
    }


def packet_to_dict(r: PacketRecord) -> dict:
    out = {"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(r.at)) + f".{int(r.at % 1 * 1000):03d}",
           "protocol": r.proto, "kind": r.kind, "from": r.src, "via": r.via, "interface": r.iface or None,
           "vlan": r.vlan, "bytes": len(r.data), "problems": [msg for _, msg in r.problems], "hex": r.data.hex()}
    if r.frame and r.frame != r.data:
        out["frame_hex"] = r.frame.hex()
    return out


def render_notes(inv: Inventory, sc: Scanner, opts) -> list:
    notes = list(sc.notes)
    controllers = {ip: ports for ip, ports in inv.requesters.items() if opts.port in ports}
    if controllers:
        who = ", ".join(sorted(controllers))
        level = "warn" if len(controllers) > 1 else "note"
        msg = (f"Other hosts are sending UBNT discovery probes from port {opts.port}: {who}. That's normally "
               "a UniFi Network application, WiFiman or another discovery tool.")
        if len(controllers) > 1:
            msg += " More than one controller on a network can adopt devices out from under each other."
        notes.append((level, msg))
    if not inv.devices and not opts.listen and not opts.direct:
        notes.append(("note", "Nothing answered. Check that you're on the same VLAN as the devices, that "
                              "Wi-Fi client isolation isn't on, and that your firewall allows inbound UDP. "
                              "Newer gear on another subnet needs -a (temporary aliases); for routed or "
                              "VPN networks, give the device subnet: opendisco.py 10.0.5.0/24"))
    return notes


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """\
examples:
  %(prog)s                     full scan: broadcast, multicast, local sweep, mDNS, SSDP, ARP
  %(prog)s -v                  ... with per-device details and diagnostics
  %(prog)s --quick             broadcast/multicast only (what the old Java tool did)
  %(prog)s 10.20.0.0/24        also unicast-probe a routed subnet (VPN, other VLAN)
  %(prog)s --deep              add TCP port checks and the UniFi OS console API
  %(prog)s --listen -t 60      send nothing; hear adoption announcements and other controllers
  %(prog)s --watch             live monitor: new devices, reboots, IP/state changes
  %(prog)s --raw               decode and hex-dump every UBNT packet as it arrives
  %(prog)s -v --raw            ... and each device's packets, checked for damage, at the end
  %(prog)s --json > scan.json  machine-readable output
  %(prog)s --interfaces        show the active interfaces it will use
  %(prog)s -a                  also probe the networks in networks.txt through temporary
                               IP aliases on every active interface (macOS/Linux, sudo)
  %(prog)s -a --hold           ... and keep the aliases that reached gear until Ctrl+C
  %(prog)s -a --dry-run        print the alias commands without running anything

  %(prog)s --vlans             on a trunk port: find its VLANs by listening, then probe each
                               one through a temporary tagged interface (macOS/Linux, sudo)
  %(prog)s --vlan 20,30        probe these VLANs on your wired ports (no listening)
  %(prog)s --sniff             listen on every port for gear on any subnet (ARP, LLDP, CDP)
  %(prog)s --sniff -a          ... and probe what it heard through temporary addresses
  %(prog)s --direct -i en7     wired straight into a radio: find its IP and VLAN from what it
                               says, live, and whether its config survived

VIA column:  ubnt = answered UBNT discovery (broadcast/unicast)   mcast = answered the
multicast probe   announce = sent an unsolicited announcement   sniff = heard in traffic on a
port (--sniff, --vlans, --direct)   wifi = the access point your Wi-Fi is joined to
mdns / ssdp = found by mDNS / UPnP   arp = known vendor's MAC in the ARP table
VLAN column: the VLAN it was found on; untagged shows the port's native VLAN (1 unless LLDP
from the switch says otherwise)
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="opendisco.py",
        description="Find and diagnose Ubiquiti devices (UniFi, airMAX, EdgeMAX, UISP, AmpliFi).",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="IP, hostname or CIDR to unicast-probe (finds devices across routers/VPNs)")
    g = p.add_argument_group("discovery")
    g.add_argument("--quick", action="store_true", help="broadcast/multicast UBNT probes only")
    g.add_argument("--listen", action="store_true", help="passive: send nothing, just listen on UDP 10001")
    g.add_argument("--no-sweep", dest="sweep", action="store_false",
                   help="don't unicast-sweep local subnets (/22 or smaller are swept by default)")
    g.add_argument("--no-mdns", dest="mdns", action="store_false", help="skip mDNS")
    g.add_argument("--no-ssdp", dest="ssdp", action="store_false", help="skip SSDP/UPnP")
    g.add_argument("--no-arp", dest="arp", action="store_false", help="skip ARP table vendor matching")
    g.add_argument("--ports", action="store_true", help=f"check TCP {', '.join(map(str, CHECK_PORTS))}")
    g.add_argument("--deep", action="store_true", help="--ports plus the UniFi OS console API")
    g.add_argument("--https-port", action="append", default=[], metavar="PORTS",
                   help="your standard web UI port(s), e.g. 8443: gear reporting another is flagged, and "
                        "--ports/--deep check them")
    g.add_argument("--ssh-port", action="append", default=[], metavar="PORTS",
                   help="your standard SSH port(s), e.g. 2222 (same as --https-port)")
    g.add_argument("-i", "--interface", action="append", metavar="NAME|IP",
                   help="only use this interface (repeatable)")
    g.add_argument("-t", "--timeout", type=float, metavar="SEC",
                   help="seconds to listen (default 6, or 30 with --listen)")
    g.add_argument("--rate", type=int, default=500, metavar="N", help="sweep rate, hosts/second (default 500)")
    g.add_argument("--oui", action="append", default=[], metavar="XXXXXX",
                   help="extra Ubiquiti OUI to recognise, e.g. 245A4C (repeatable)")
    g.add_argument("--port", type=int, default=UBNT_PORT, help=argparse.SUPPRESS)
    o = p.add_argument_group("output")
    o.add_argument("-v", "--verbose", action="store_true", help="per-device details and diagnostics")
    o.add_argument("--json", action="store_true", help="JSON output")
    o.add_argument("--export", action="append", default=[], metavar="FILE",
                   help="also save a report: .html (opens on any phone), .csv or .json (repeatable)")
    o.add_argument("--raw", action="store_true", help="decode and hex-dump UBNT packets as they arrive; with -v, each device's packets "
                        "checked for damage")
    o.add_argument("-w", "--watch", action="store_true", help="keep running and report changes")
    o.add_argument("--interval", type=float, default=5.0, metavar="SEC",
                   help="probe interval in --watch mode (default 5)")
    o.add_argument("--no-color", action="store_true", help="disable colours")
    o.add_argument("--interfaces", dest="list_interfaces", action="store_true",
                   help="list active interfaces and exit")
    o.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    o.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.add_argument_group("temporary IP aliases (macOS/Linux, uses sudo)",
                             "Newer firmware only answers discovery from its own subnet. These options "
                             "briefly give each active interface an address in your usual networks.")
    a.add_argument("-a", "--aliases", action="store_true",
                   help="probe the networks listed in the networks file")
    a.add_argument("--alias", action="append", default=[], metavar="NET",
                   help="probe this network too, e.g. 10.0.0.0/24 or 172.16.10.1-20/30 (repeatable)")
    a.add_argument("--networks", default=DEFAULT_NETWORKS_FILE, metavar="FILE",
                   help="networks file (default: networks.txt next to this script)")
    a.add_argument("--hold", action="store_true",
                   help="afterwards keep the aliases that reached gear, until Ctrl+C")
    a.add_argument("--dry-run", action="store_true", help="print the alias commands, change nothing")
    a.add_argument("--cleanup-aliases", action="store_true",
                   help="remove aliases and VLAN interfaces left behind by a run that was killed")
    v = p.add_argument_group("VLANs (macOS/Linux, uses sudo)",
                             "Plugged into a trunk port without tagging? These create temporary tagged "
                             "interfaces and probe each VLAN like -a does. Untagged results show VLAN 1, "
                             "or the native VLAN the switch reports over LLDP.")
    v.add_argument("--vlans", action="store_true",
                   help="listen on wired ports for the VLANs they carry, then probe each one")
    v.add_argument("--vlan", action="append", default=[], metavar="IDS",
                   help="probe these VLANs on wired ports, e.g. 20 or 20,30,100-105 (repeatable)")
    v.add_argument("--vlan-listen", type=float, metavar="SEC",
                   help="how long --sniff/--vlans/--direct listen (default 20, 45 for --direct; 35+ catches LLDP)")
    v.add_argument("--sniff", action="store_true",
                   help="listen passively on every active port (Wi-Fi too) for ARP, LLDP/CDP and broadcasts: "
                        "finds gear on subnets you're not on. With -a, also probes what it heard")
    v.add_argument("--pcap", metavar="PREFIX",
                   help="save what --sniff/--vlans/--direct capture as PREFIX-<interface>.pcap (for Wireshark)")
    v.add_argument("--direct", action="store_true",
                   help="plugged straight into one device (a radio, say): listen to what it says to find "
                        "its IP and VLAN, show it live, then probe it. Use -i to pick the port")
    opts = p.parse_args(argv)
    opts.vlan_ids = parse_vlan_ids(opts.vlan, p.error)
    opts.https_ports = parse_port_list(opts.https_port, p.error)
    opts.ssh_ports = parse_port_list(opts.ssh_port, p.error)
    opts.alias_mode = opts.aliases or bool(opts.alias) or opts.vlans or bool(opts.vlan_ids) or opts.direct
    # The networks file is probed unless the only thing asked for is specific --alias networks.
    opts.use_networks_file = opts.aliases or ((opts.vlans or bool(opts.vlan_ids) or opts.direct) and not opts.alias)
    if opts.sniff and opts.watch:
        p.error("--sniff can't be combined with --watch")
    if opts.vlan_listen is None:
        opts.vlan_listen = 45.0 if opts.direct else 20.0
    if (opts.hold or opts.dry_run) and not opts.alias_mode:
        p.error("--hold and --dry-run go with -a, --alias, --vlans or --vlan")
    if opts.alias_mode and (opts.watch or opts.listen):
        p.error("-a, --alias and VLAN options can't be combined with --watch or --listen")
    if opts.hold and opts.json:
        p.error("--hold prints a live list; it can't be combined with --json")
    if opts.quick:
        opts.sweep = opts.mdns = opts.ssdp = opts.arp = False
    if opts.listen:
        opts.sweep = opts.mdns = opts.ssdp = False
        if opts.targets:
            p.error("--listen sends nothing, so it can't be combined with targets")
    if opts.watch and opts.json:
        p.error("--watch prints a live event log; it can't be combined with --json")
    if opts.timeout is None:
        opts.timeout = 30.0 if opts.listen else 6.0
    opts.rate = max(10, opts.rate)
    for oui in opts.oui:
        UBNT_OUIS.add(re.sub(r"[^0-9A-Fa-f]", "", oui).upper()[:6])
    return opts


def parse_port_list(specs, error) -> list:
    ports = set()
    for part in (p.strip() for spec in specs for p in spec.split(",")):
        if part:
            if not part.isdigit() or not 1 <= int(part) <= 65535:
                error(f"{part!r} isn't a TCP port")
            ports.add(int(part))
    return sorted(ports)


def parse_vlan_ids(specs, error) -> list:
    ids = set()
    for spec in specs:
        for part in (p.strip() for p in spec.split(",")):
            if not part:
                continue
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
            if not m:
                error(f"--vlan: {part!r} isn't a VLAN id or range")
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            if not 1 <= lo <= hi <= 4094:
                error(f"--vlan: {part} is outside 1-4094")
            if hi - lo >= 256:
                error("--vlan: ranges are limited to 256 VLANs")
            ids.update(range(lo, hi + 1))
    return sorted(ids)


def expand_targets(targets, parser_error):
    hosts, nets = [], []
    for t in targets:
        try:
            net = ipaddress.IPv4Network(t, strict=False)
        except ValueError:
            try:
                net = ipaddress.IPv4Network(socket.gethostbyname(t))
            except OSError:
                parser_error(f"can't resolve target {t!r}")
        if net.num_addresses > 65536:
            parser_error(f"{t} is larger than a /16; split it up")
        nets.append(net)
        hosts.extend(str(h) for h in (net.hosts() if net.prefixlen < 31 else net))
    return hosts, nets


def _matches(wanted, *names) -> bool:
    # Windows names look like "Wireless LAN adapter Wi-Fi", so "-i Wi-Fi" matches the tail.
    return any(w in names or any(n.endswith(" " + w) for n in names if n) for w in wanted)


def select_interfaces(all_ifaces, wanted):
    if not wanted:
        return list(all_ifaces)
    return [i for i in all_ifaces if _matches(wanted, i.name, i.ip, i.label)]


def run_watch(sc: Scanner, inv: Inventory, opts) -> int:
    lost: set = set()

    def line(kind, d, extra=""):
        level = {"NEW": "ok", "BACK": "ok", "LOST": "error", "REBOOT": "warn"}.get(kind, "note")
        stamp = time.strftime("%H:%M:%S")
        who = f"{d.ip:<15}  {d.mac or '-':<17}  {_trunc(d.model or '?', 18):<18}  {_trunc(d.name, 22)}"
        print(f"{stamp}  {Style.level(f'{kind:<8}', level)}  {who}  {extra}".rstrip(), flush=True)

    def on_change(d, changes):
        if d.key in lost:
            lost.discard(d.key)
            line("BACK", d)
        for kind, extra in changes:
            if kind == "NEW":
                bits = [f"fw {d.firmware}" if d.firmware else "",
                        f"up {fmt_uptime(d.info.get('uptime'))}" if "uptime" in d.info else "",
                        "DEFAULT" if d.info.get("is_default") else ""]
                extra = "  ".join(b for b in bits if b)
            line(kind, d, extra)

    sc.on_change = on_change
    sc.probe_every = opts.interval
    # Unprobed devices only speak when they announce, so give them longer before calling them lost.
    lost_after = 90.0 if opts.listen else 3 * opts.interval + 1
    print(Style.bold(f"Watching {', '.join(str(i) for i in sc.ifaces)} - probing every {opts.interval:g}s, "
                     f"Ctrl+C to stop"), file=sys.stderr, flush=True)
    try:
        while True:
            sc.run(max(opts.interval, sc.sweep_seconds()))
            now = time.time()
            for d in list(inv.devices.values()):
                if d.ubnt_packets and d.key not in lost and now - d.last_seen > lost_after:
                    lost.add(d.key)
                    line("LOST", d, f"silent for {int(now - d.last_seen)}s")
    except KeyboardInterrupt:
        print(file=sys.stderr)
    sc.close()
    return 0


@dataclass
class ScanResult:
    """Everything one scan found, for the command line to print or a GUI to show."""
    opts: object
    devices: list
    notes: list  # (level, message)
    trunks: list
    ifaces: list
    links: list
    base_targets: list
    inv: Inventory
    mgr: "AliasManager | None"
    elapsed: float
    interrupted: bool = False
    counters: dict = field(default_factory=dict)  # error counters that went up during the scan
    diag_args: tuple = ()  # diagnose()'s other arguments, to diagnose again after a rescan

    def wire_title(self) -> str:
        if self.opts.direct:
            return "Plugged directly into"
        return "Heard on the wire" if self.opts.sniff else "VLANs heard on wired ports"

    def wire_text(self, verbose: bool = False) -> str:
        if not self.trunks:
            return ""
        return render_direct(self.trunks, self.inv) if self.opts.direct else render_trunks(self.trunks, verbose)


def result_to_dict(res: ScanResult) -> dict:
    return {
        "tool": "opendisco", "version": __version__,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "duration_s": round(res.elapsed, 2),
        "interfaces": [{"name": i.name, "label": i.label, "ip": i.ip, "prefix": i.prefix} for i in res.ifaces],
        "active_links": [{"name": l.name, "label": l.label, "ipv4": [f"{i.ip}/{i.prefix}" for i in l.addrs]}
                         for l in res.links],
        "alias_networks": [str(t.network) for t in res.base_targets],
        "trunks": [] if res.opts.direct else [trunk_to_dict(tr) for tr in res.trunks],
        "direct": [direct_to_dict(tr, res.inv) for tr in res.trunks] if res.opts.direct else [],
        "devices": [device_to_dict(d) for d in res.devices],
        "discovery_requesters": {ip: sorted(p) for ip, p in res.inv.requesters.items()},
        "unreadable_packets": {ip: [packet_to_dict(r) for r in recs] for ip, recs in res.inv.garbled.items()},
        "error_counters": res.counters or None,
        "notes": [{"level": lv, "message": m} for lv, m in res.notes],
    }


EXPORT_COLUMNS = ("IP", "VLAN", "Vendor", "MAC", "Model", "Name", "Firmware", "HTTPS", "SSH", "Uptime", "Via",
                  "Status")


def port_cell(d: Device, kind: str) -> str:
    """The HTTPS or SSH column: the port the device reports, with a deep check's verdict
    (✓ that service answers there, ✗ nothing does); otherwise whatever a deep check found."""
    reported = d.said_port(kind)
    if reported:
        if d.ports is None:
            return str(reported)
        found = d.services.get(reported)
        return f"{reported} ✓" if found == kind else f"{reported} ✗" if found is None else f"{reported} ({found})"
    return ", ".join(f"{p} ✓" for p, k in sorted(d.services.items()) if k == kind)


def device_row(d: Device) -> list:
    """The values the table, CSV and HTML exports show for a device."""
    return [d.ip or "", d.vlan_label, d.vendor, d.mac or "", d.model, d.name, d.firmware,
            port_cell(d, "https"), port_cell(d, "ssh"), fmt_uptime(d.info.get("uptime")),
            ",".join(v for v in VIA_ORDER if v in d.via), status_cell(d)[0]]


def export_csv(res: ScanResult) -> str:
    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EXPORT_COLUMNS + ("Diagnostics",))
    for d in res.devices:
        writer.writerow(device_row(d) + [" | ".join(f"[{tag}] {msg}" for _, tag, msg in d.issues)])
    return out.getvalue()


def export_html(res: ScanResult) -> str:
    """A self-contained report that opens on any phone or computer."""
    from html import escape
    colors = {"error": "#c62828", "warn": "#b26a00", "note": "#1565c0"}
    rows = []
    for d in res.devices:
        cells = "".join(f"<td>{escape(str(v))}</td>" for v in device_row(d)[:-1])
        tags = " ".join(f'<span style="color:{colors.get(lv, "#2e7d32")}">{escape(tag)}</span>'
                        for lv, tag, _ in d.issues) or '<span style="color:#2e7d32">ok</span>'
        issues = "".join(f"<li><b>{escape(tag)}</b> {escape(msg)}</li>" for _, tag, msg in d.issues)
        rows.append(f"<tr>{cells}<td>{tags}</td></tr>"
                    + (f'<tr class="issues"><td colspan="{len(EXPORT_COLUMNS)}"><ul>{issues}</ul></td></tr>'
                       if issues else ""))
    notes = "".join(f"<li>{escape(m)}</li>" for _, m in res.notes)
    wire = res.wire_text(verbose=True)
    head = "".join(f"<th>{c}</th>" for c in EXPORT_COLUMNS)
    when = time.strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>OpenDisco {when}</title>
<style>body{{font:14px -apple-system,Segoe UI,Roboto,sans-serif;margin:16px;color:#222;background:#fff}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
th{{background:#f4f4f4;position:sticky;top:0}}tr.issues td{{border-bottom:2px solid #ccc;color:#444}}ul{{margin:0;padding-left:18px}}
pre{{background:#f6f6f6;padding:10px;overflow-x:auto}}.wrap{{overflow-x:auto}}
@media (prefers-color-scheme: dark){{body{{background:#121212;color:#ddd}}th{{background:#222}}th,td{{border-color:#333}}pre{{background:#1e1e1e}}}}</style>
</head><body><h1>OpenDisco</h1><p>{when} &middot; {len(res.devices)} device(s) &middot; {res.elapsed:.0f}s</p>
<div class="wrap"><table><tr>{head}</tr>{''.join(rows)}</table></div>
{f'<h2>{escape(res.wire_title())}</h2><pre>{escape(wire)}</pre>' if wire else ''}
{f'<h2>Notes</h2><ul>{notes}</ul>' if notes else ''}</body></html>
"""


def write_export(res: ScanResult, path: str) -> None:
    """Write a report; the format follows the file extension (.json, .csv, otherwise HTML)."""
    ext = os.path.splitext(path)[1].lower()
    text = (json.dumps(result_to_dict(res), indent=2, default=str) if ext == ".json"
            else export_csv(res) if ext == ".csv" else export_html(res))
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def run_scan(opts, log, progress=None, on_inventory=None):
    """Run one scan as described by opts (from parse_args) and return a ScanResult. Shared by the
    command line and the GUI. Returns an exit code instead for the command line's --interfaces,
    --cleanup-aliases, --dry-run and --watch, which print as they go. Errors raise SystemExit
    with a message; STOP (or Ctrl+C) ends the scan early with what was found so far."""
    STOP.clear()
    all_ifaces = local_interfaces()
    links = active_links(all_ifaces)
    labels = {link.name: link.label for link in links}
    for i in all_ifaces:
        i.label = labels.get(i.name, "")
    if opts.interface:
        links = [l for l in links if _matches(opts.interface, l.name, l.label, *(i.ip for i in l.addrs))]
    if opts.list_interfaces:
        print_interfaces(links, all_ifaces)
        return 0
    if opts.cleanup_aliases:
        n = AliasManager(log).cleanup_leftovers()
        log(f"Removed {n} leftover alias(es)." if n else "No leftover aliases recorded.")
        return 0
    ifaces = select_interfaces(all_ifaces, opts.interface)
    unaddressed = [l for l in links if not l.addrs]
    wired = [l for l in links if not l.wireless]
    extra_notes, base_targets, overlap_noted = [], [], set()

    ports = wired  # where --vlans / --direct listen and tag VLANs
    if opts.direct:
        every_wired = [l for l in hardware_links(all_ifaces) if not l.wireless]
        for l in every_wired:
            l.label = labels.get(l.name, l.label)
        if opts.interface:  # may not have link yet: the user plugs in once it's listening
            ports = [l for l in every_wired if _matches(opts.interface, l.name, l.label)]
        else:  # a port with link but no real address is the one plugged into the device
            ports = [l for l in every_wired if l.active and all(i.ip.startswith("169.254.") for i in l.addrs)]
        if not ports:
            have = ", ".join(str(l) for l in every_wired if l.active) or "none has link"
            raise SystemExit("error: --direct needs the wired port that's plugged into the device; ports with "
                             f"link: {have}. Name it with -i, e.g. -i en7.")
        names = {l.name for l in ports}
        ifaces = [i for i in ifaces if i.name in names]

    def drop_overlaps(targets) -> list:
        kept = []
        for t in targets:
            clash = next((i for i in all_ifaces if i.network.overlaps(t.network)), None)
            if not clash:
                kept.append(t)
            elif t.network not in overlap_noted:
                overlap_noted.add(t.network)
                extra_notes.append(("note", f"No alias for {t.network}: {clash} is already in it, so it was "
                                            "probed directly. If gear on another port uses that subnet too, "
                                            "disconnect this network (e.g. turn Wi-Fi off) and run again."))
        return kept

    def merged(*groups) -> list:
        out = []
        for t in (t for g in groups for t in g):
            if all(t.network != o.network for o in out):
                out.append(t)
        return out

    if opts.alias_mode:
        if IS_WINDOWS and not capabilities()["aliases"]:
            raise SystemExit("error: temporary addresses need Windows 10 version 2004 or later")
        base_targets = drop_overlaps(load_alias_targets(opts.networks if opts.use_networks_file else None,
                                                        opts.alias, lambda m: sys.exit(f"error: {m}")))
        if opts.direct:  # a factory-reset radio of any brand we know sits on its default subnet
            defaults = [AliasTarget(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                        for ips in DEFAULT_ADDRESSES.values() for ip in ips]
            base_targets = merged(base_targets, drop_overlaps(defaults))
        if not links and not opts.direct:
            raise SystemExit("error: no active Ethernet or Wi-Fi interface to put aliases on (see --interfaces)")
        if (opts.vlans or opts.vlan_ids) and not ports:
            raise SystemExit("error: VLANs need an active wired port (see --interfaces)")
        if opts.dry_run:
            plans = [{"link": l, "targets": base_targets} for l in (ports if opts.direct else links)]
            plans += [{"link": Link("", f"VLAN {v}", vlan=v, parent=p.name), "targets": base_targets}
                      for p in ports for v in opts.vlan_ids]
            print_alias_plan(plans, AliasManager(log).sudo,
                             [l.name for l in ports] if opts.vlans or opts.direct else (), opts.vlan_listen)
            for _, msg in extra_notes:
                print(f"\n  * {msg}")
            return 0
    elif unaddressed:
        extra_notes += [("note", f"{l.name} ({l.label}) has link but no IPv4 address (no DHCP?). Run with -a "
                                 "to probe your usual networks on it through temporary aliases.")
                        for l in unaddressed]
    if not ifaces and not opts.alias_mode:
        names = ", ".join(str(i) for i in all_ifaces) or "none found"
        hint = f" {', '.join(l.name for l in unaddressed)} has link but no address: try -a." if unaddressed else ""
        raise SystemExit(f"error: no usable IPv4 interface (have: {names}).{hint}")

    hosts, scan_nets = expand_targets(opts.targets, lambda m: sys.exit(f"error: {m}"))
    if opts.sweep and not opts.watch:
        for i in ifaces:
            if 22 <= i.prefix <= 30 and not i.ip.startswith("169.254."):
                hosts.extend(str(h) for h in i.network.hosts())
    own = {i.ip for i in all_ifaces}
    hosts = [h for h in dict.fromkeys(hosts) if h not in own or h in opts.targets]

    inv = Inventory()
    if on_inventory:  # lets a GUI show devices while the scan is still running
        on_inventory(inv)
    sc = Scanner(opts, ifaces, all_ifaces, inv, log)
    sc.open()
    sc.set_sweep(hosts)

    if opts.watch:
        return run_watch(sc, inv, opts)

    mgr = None
    if opts.alias_mode:
        mgr = AliasManager(log)
        mgr.authorize()
        if mgr.sudo:
            ARP_SUDO[:] = ["sudo", "-n"]
        mgr.cleanup_leftovers()
        atexit.register(mgr.remove_all)

        def exit_on_signal(signum, _frame):
            raise SystemExit(128 + signum)  # unwinds through the finally that removes aliases

        if threading.current_thread() is threading.main_thread():  # a GUI scans in a worker thread
            for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):  # whichever this OS has
                if hasattr(signal, name):
                    signal.signal(getattr(signal, name), exit_on_signal)

    duration = max(opts.timeout, sc.sweep_seconds() + 2.5)
    what = []
    if opts.listen:
        what.append(f"listening on UDP {opts.port}")
    else:
        what.append("UBNT broadcast+multicast")
        if hosts:
            what.append(f"unicast sweep of {len(hosts)} hosts")
        what += [n for n, on in (("mDNS", opts.mdns), ("SSDP", opts.ssdp), ("ARP", opts.arp)) if on]
    if ifaces:
        log(f"Scanning {', '.join(str(i) for i in ifaces)}  [{', '.join(what)}]  {duration:.0f}s")

    def clear_progress():
        if progress:
            progress(None, None)

    watched = sorted({l.name for l in links} | {l.name for l in ports} | {i.name for i in ifaces})
    counters_before = interface_counters(watched)
    t0 = time.monotonic()
    alias_result, trunks, interrupted = None, [], False
    try:
        if ifaces:
            sc.run(duration, (lambda e, t: progress(e, t, inv)) if progress else None)
            clear_progress()
        listen_on = ports if opts.direct else list({l.name: l for l in (ports if opts.vlans else [])
                                                     + (links if opts.sniff else [])}.values())
        if not listen_on and (opts.vlans or opts.direct or opts.sniff):
            log("Not listening: there's no wired or Wi-Fi port to listen on (VPN, bridge and virtual "
                "adapters are left out). See --interfaces.")
        if listen_on and (opts.vlans or opts.direct or opts.sniff):
            if not capabilities()["listen"]:
                if IS_WINDOWS:
                    from opendisco import winnet
                    raise SystemExit(f"error: listening (--sniff, --vlans, --direct): {winnet.NPCAP_HELP}")
                raise SystemExit("error: listening (--sniff, --vlans, --direct) needs tcpdump")
            sudo = mgr.sudo if mgr else AliasManager(log).sudo
            if not mgr and sudo:
                authorize_sudo("Listening needs tcpdump, which needs administrator rights; sudo may ask "
                               "for your password.", log)
                ARP_SUDO[:] = ["sudo", "-n"]
            by_name = {l.name: Trunk(l, opts.vlan_listen) for l in listen_on}
            trunks = list(by_name.values())
            mine, told, started = local_macs(), set(), time.monotonic()

            def on_frames(name, frames):
                for frame in frames:
                    by_name[name].add(frame, inv, sc.local_ips, mine, opts.direct)
                if opts.direct:
                    for line in new_findings(by_name[name], told):
                        log("  " + line)

            def found_enough():  # --direct: stop a few seconds after the device used an address
                return opts.direct and any(nb.first_ip_at and time.monotonic() - nb.first_ip_at > 5
                                           for tr in trunks for nb in talkers(tr))

            if opts.direct:
                for l in ports:
                    media = link_media(l.name)
                    log(f"Listening on {l.name} ({l.label}{', ' + media if media else ''}) for up to "
                        f"{opts.vlan_listen:g}s. " + ("No link yet: plug in the device (or re-seat its cable) now."
                                                      if not l.active else
                                                      "If nothing shows up, re-seat the cable: devices talk most "
                                                      "right after link-up."))
            else:
                log(f"Listening {opts.vlan_listen:g}s on {', '.join(by_name)} for ARP, LLDP/CDP, VLAN tags and "
                    "announcements, from any subnet")
            captured = capture_frames(list(by_name), opts.vlan_listen, sudo, log, on_frames, found_enough,
                                      **({"pcap": opts.pcap} if opts.pcap else {}))
            if STOP.is_set():
                raise KeyboardInterrupt
            for tr in trunks:
                frames, tr.error = captured.get(tr.link.name, ([], "not captured"))
                for frame in frames[tr.fed:]:  # whatever wasn't analysed live
                    tr.add(frame, inv, sc.local_ips, mine, opts.direct)
                tr.finish(inv, opts.direct)
                tr.seconds = round(time.monotonic() - started, 1)
                if tr.link.wireless:
                    tr.wifi = wifi_association(tr.link.name, sudo)
                if not opts.direct:
                    gear = Counter(nb.vendor for nb in talkers(tr) if nb.vendor)
                    found = ", ".join(f"{n} {v}" for v, n in gear.most_common()) or "no known gear"
                    found += "; " + (", ".join(f"VLAN {v}" for v in tr.tagged_ids()) or "no tagged VLANs")
                    log(f"  {tr.link.name}: {'capture failed: ' + tr.error if tr.error else found}")
                elif not talkers(tr):
                    log(f"  {tr.link.name}: nothing heard" + (f" ({tr.error})" if tr.error else ""))
        if mgr:
            by_link = {tr.link.name: tr for tr in trunks}

            vendors_only = opts.sniff and not (opts.vlans or opts.direct)

            def heard_on(trunk, vid):
                """(addresses heard, ARP pairs, addresses it asked for) on one VLAN of a port."""
                if trunk is None:
                    return Counter(), (), set()
                talking = [nb for nb in trunk.neighbors.values() if nb.vendor or not vendors_only]
                wants = {ip for nb in talking for ip in nb.vlans.get(vid, {}).get("wants", ())}
                heard = trunk.heard(vid, vendors_only)
                return heard, {pair for pair in trunk.pairs.get(vid, ()) if pair[0] in heard}, wants

            plans = []
            for link in (ports if opts.direct else links):  # untagged, plus subnets heard untagged
                heard, pairs, wants = heard_on(by_link.get(link.name), 0)
                plans.append({"link": link, "busy": set(heard) | wants,  # never borrow a gateway's address
                              "targets": merged(drop_overlaps(infer_targets(heard, pairs, base_targets, opts.direct)),
                                                base_targets)})
            for link in ports:  # then every VLAN found on the port or asked for
                trunk = by_link.get(link.name)
                for vid in sorted(set(opts.vlan_ids) | set(trunk.tagged_ids() if trunk else [])):
                    existing = next((n for n, (v, p) in sc.vlan_map.items() if v == vid and p == link.name), "")
                    heard, pairs, wants = heard_on(trunk, vid)
                    targets = merged(drop_overlaps(infer_targets(heard, pairs, base_targets, opts.direct)), base_targets)
                    if not targets:
                        extra_notes.append(("note", f"VLAN {vid} on {link.name}: no subnets heard and nothing in "
                                                    "the networks file to try, so it wasn't probed."))
                    plans.append({"link": Link(existing, f"VLAN {vid}", vlan=vid, parent=link.name),
                                  "targets": targets, "busy": set(heard) | wants})
            vlans = sorted({p["link"].vlan for p in plans if p["link"].vlan and p["targets"]})
            log("Probing through temporary aliases on " + ", ".join(str(l) for l in (ports if opts.direct else links))
                + (f", and tagged VLAN {', '.join(map(str, vlans))}" if vlans else ""))
            alias_result = run_alias_rounds(sc, inv, mgr, plans, opts, log)
    except KeyboardInterrupt:
        clear_progress()
        interrupted = True
        log("\nstopped - showing what was found so far")
    finally:
        if mgr:
            mgr.remove_all()
    sc.finish_notes()
    sc.close()
    enrich(inv, sc, opts, log, alias_result)
    counters = counter_changes(counters_before, interface_counters(watched))
    natives = {tr.link.name: tr.native() for tr in trunks if tr.native()}
    assign_vlans(inv, all_ifaces, sc.vlan_map, natives)
    place_wifi_ap(inv, trunks)
    skipped = alias_result["skipped"] if alias_result else []
    diag_args = (all_ifaces, scan_nets, opts, mgr.used if mgr else (), skipped, {i.name for i in ifaces})
    diagnose(inv, *diag_args)
    elapsed = time.monotonic() - t0
    devs = sorted_devices(inv)
    notes = render_notes(inv, sc, opts) + extra_notes + counter_notes(counters)
    unread = {ip: recs for ip, recs in inv.garbled.items() if not inv.find(ip=ip)}
    if unread:
        notes.append(("warn", f"Unreadable packets arrived on UDP {opts.port} from {', '.join(sorted(unread))}: "
                              "damaged, or something other than discovery uses the port. -v --raw shows them."))
    if macs_hidden():
        if ARP_SUDO and _parse_arp(_run(ARP_SUDO + ["arp", "-an"])):
            notes.append(("note", "macOS hides MAC addresses and the ARP table from Python; this run read the "
                                  "ARP table through sudo instead."))
        else:
            notes.append(("warn", "macOS is hiding MAC addresses and the ARP table from Python, so ARP-based "
                                  "vendor detection is off. Allow Local Network access for the app you run this "
                                  "from (Terminal, iTerm, VS Code...) in System Settings > Privacy & Security > "
                                  "Local Network, then quit and reopen it. Modes that use sudo (-a, --sniff, "
                                  "--vlans, --direct) read the ARP table as root instead."))
    notes += [("note", f"{net}: no free address to borrow (both are in use, or one is what a device keeps "
                       "asking for), so it wasn't probed. If that device's uplink is down, nobody is using "
                       "the address it asks for: you can take it yourself to reach it.") for net in skipped]

    return ScanResult(opts, devs, notes, trunks, ifaces, links, base_targets, inv, mgr, elapsed, interrupted,
                      counters, diag_args)


def rescan_device(res: ScanResult, d: Device, log, seconds: float = 3.0):
    """Probe one device again: UBNT discovery sent straight to it (no broadcasts), then its
    ports, web redirect and console API. Updates it, its packets and every device's
    diagnostics in place. Returns (the device, whether it answered discovery)."""
    STOP.clear()
    opts = copy.copy(res.opts)
    opts.mdns = opts.ssdp = opts.listen = opts.raw = False
    targets = [ip for ip in d.ips if _usable_ip(ip)][:4]
    before, mac = d.ubnt_packets, d.mac
    if targets:
        all_ifaces = local_interfaces()
        sc = Scanner(opts, select_interfaces(all_ifaces, opts.interface), all_ifaces, res.inv, log)
        sc.broadcasts = False
        sc.open()
        try:
            sc.set_sweep(targets)
            sc.run(seconds)
        finally:
            sc.close()
    d = res.inv.find(mac=mac) or res.inv.find(ip=targets[0] if targets else None) or d  # it may have merged
    answered = d.ubnt_packets > before
    if d.ip:
        check_ports([d], opts, log, res.inv.devices.values())
        if d.console or (d.ports and 443 in d.ports):
            d.api = probe_console_api(d.ip) or d.api
    if res.diag_args:
        diagnose(res.inv, *res.diag_args)
    res.devices = sorted_devices(res.inv)
    return d, answered


def main(argv=None) -> int:
    opts = parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except AttributeError:
        pass
    if IS_WINDOWS:
        os.system("")  # turns on ANSI escape handling in the Windows console
    Style.on = sys.stdout.isatty() and not opts.no_color and not opts.json and "NO_COLOR" not in os.environ
    log = (lambda msg: print(msg, file=sys.stderr, flush=True))
    tty = sys.stderr.isatty() and not opts.raw

    def progress(elapsed, total, inv=None):
        if not tty:
            return
        if elapsed is None:  # done: clear the line
            sys.stderr.write("\r" + " " * 60 + "\r")
        else:
            n = sum(1 for d in inv.devices.values() if d.ubnt_packets)
            sys.stderr.write(f"\r  {elapsed:4.1f}/{total:.0f}s  {n} heard via UBNT discovery ")
        sys.stderr.flush()

    res = run_scan(opts, log, progress)
    if not isinstance(res, ScanResult):
        return res
    for path in opts.export:
        write_export(res, path)
        log(f"Saved {path}")
    devs, notes, trunks, inv = res.devices, res.notes, res.trunks, res.inv

    if opts.json:
        print(json.dumps(result_to_dict(res), indent=2, default=str))
        return 0 if devs else 1

    if devs:
        print(render_table(devs))
    heard = sum(1 for d in devs if d.ubnt_packets)
    print(f"\n{len(devs)} device(s), {heard} heard via UBNT discovery, {res.elapsed:.1f}s")
    if opts.verbose:
        for d in devs:
            print("\n" + render_details(d))
            if opts.raw:
                print("\n" + render_packets(d, inv, res.counters))
    elif any(d.issues for d in devs):
        print("\n" + Style.bold("Diagnostics") + "\n" + render_issues(devs))
    if trunks:
        print("\n" + Style.bold(res.wire_title()) + "\n" + res.wire_text(opts.verbose))
    if notes:
        print("\n" + Style.bold("Notes"))
        for level, msg in notes:
            print(f"  {Style.level('*', level)} {msg}")
    if opts.hold and res.mgr:
        hold_aliases(res.mgr, inv, log)
    return 0 if devs else 1




if __name__ == "__main__":
    sys.exit(main())
