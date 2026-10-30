# OpenDisco open-source licenses

OpenDisco (Open Discovery Tool for Ubiquiti Devices). Copyright 2026 Michael Froehlke.

Licensed under the Apache License, Version 2.0. The license text is in the LICENSE file that comes with OpenDisco, and in its repository at github.com/Nekobyte-Coding/opendisco.

OpenDisco's installers, packages and apps also include the third-party components listed below. Each is the work of its own authors and is used under its own license, whose full text is at the end of this file. Nothing in OpenDisco's Terms of Use limits any right that these licenses grant, and the Terms' disclaimers of warranty and limits of liability are also made on behalf of these components' authors and contributors.

This list covers OpenDisco 1.7.1 for macOS (the .dmg), Windows (the setup .exe), Linux (the .deb, the .rpm, the AppImage and the portable .tar.gz), Android (the .apk) and the iPhone and iPad beta. Each component says which of them include it.

Not included in OpenDisco's own files:
- The Linux .deb and .rpm use the system's Python, GTK, WebKitGTK, OpenSSH, tcpdump, ip and iw, which the distribution's package manager installs from the distribution.
- The Linux AppImage uses the system's GTK, WebKitGTK, GLib and cairo, with their introspection data, and the system's OpenSSH (where it has one), tcpdump, ip and iw. It carries Ubuntu 24.04's girepository-2.0 only for systems that don't have one.
- The portable Linux .tar.gz holds only OpenDisco's own code and xterm.js. The first time the app opens, its launcher downloads Toga, asyncssh and the packages they need from PyPI into a Python environment on the user's computer.
- On Windows, Npcap is not included. The installer downloads Npcap's own installer from npcap.com, which shows Npcap's license.
- The SSH client on macOS, Windows and Linux is the operating system's own. Where a Linux system has none, the AppImage and the portable version use asyncssh instead (the AppImage's own copy, listed below).

## Source code

Some of these licenses require the source code to be available to anyone who receives the program:
- asyncssh (Android, iPhone and iPad, Linux AppImage): OpenDisco distributes asyncssh under the Eclipse Public License 2.0, and its source code is available under that license. The exact source distribution, asyncssh-2.23.1.tar.gz, is attached to each OpenDisco release at github.com/Nekobyte-Coding/opendisco/releases, and is also at pypi.org/project/asyncssh/2.23.1.
- PyGObject and pycairo (Linux .deb, .rpm and AppImage): both are used under the GNU Lesser General Public License 2.1. Their complete source distributions, pygobject-3.58.1.tar.gz and pycairo-1.29.2.tar.gz, are attached to each OpenDisco release, and are also at pypi.org/project/PyGObject/3.58.1 and pypi.org/project/pycairo/1.29.2. They are separate files, in /usr/lib/opendisco/app_packages (the .deb), /usr/lib64/opendisco/app_packages (the .rpm) or usr/python/lib/python3.13/site-packages inside the AppImage (which its --appimage-extract option unpacks), so they can be replaced with modified versions. Modifying them for one's own use, and reverse engineering OpenDisco to debug such modifications, are permitted.
- certifi (iPhone and iPad) and Mozilla's CA certificate bundle (Android): both are under the Mozilla Public License 2.0. certifi's Source Code Form is in certifi-2026.10.23.tar.gz, attached to each OpenDisco release and also at pypi.org/project/certifi/2026.10.23. Android's bundle is Chaquopy's own copy, assets/chaquopy/cacert.pem in the APK: a text file, which is itself its Source Code Form.
- NSIS (the Windows installer): the setup .exe is built with NSIS 3.13, whose LZMA decompression module is under the Common Public License 1.0. NSIS's source code, nsis-3.13-src.tar.bz2, is attached to each OpenDisco release, and is also at nsis.sourceforge.io/Download.
- GLib's girepository-2.0 (Linux AppImage): the AppImage carries libgirepository-2.0.so.0 from Ubuntu 24.04's glib2.0 2.80.0-6ubuntu3.10, under the GNU Lesser General Public License 2.1 or later. Its complete source package, glib2.0_2.80.0-6ubuntu3.10.dsc with glib2.0_2.80.0.orig.tar.xz, glib2.0_2.80.0.orig-unicode-data.tar.xz and glib2.0_2.80.0-6ubuntu3.10.debian.tar.xz, is attached to each OpenDisco release that has an AppImage, and is also at launchpad.net/ubuntu/+source/glib2.0/2.80.0-6ubuntu3.10. The library is a separate file, usr/lib/fallback/libgirepository-2.0.so.0 inside the AppImage, used only where the system has no girepository-2.0, so it can be replaced with a modified version.
- libfuse (Linux AppImage): the AppImage starts through AppImage's type2-runtime, which is statically linked with libfuse 3.15.0, under the GNU Lesser General Public License 2.1. So that the runtime can be rebuilt and relinked with a modified libfuse, each OpenDisco release that has an AppImage attaches libfuse's source, fuse-3.15.0.tar.xz (also at github.com/libfuse/libfuse/releases/tag/fuse-3.15.0), and the runtime's complete source at the commit it was built from, type2-runtime-fedfad51acc2860b2916a1eef32ba4a500ff31ef.tar.xz (also at github.com/AppImage/type2-runtime/tree/fedfad51acc2860b2916a1eef32ba4a500ff31ef). The runtime's source includes its build scripts and the patch it applies to libfuse (patches/libfuse/mount.c.diff). The runtime's other parts, musl, squashfuse, Zstandard, zlib and mimalloc, are under permissive licenses, and its build scripts say where each comes from.
- OpenDisco's own source code is at github.com/Nekobyte-Coding/opendisco.

## Components

### Python
- Versions: 3.14.7 (macOS), 3.13.17 (Windows, python.org's embeddable build), 3.13.17 (Linux AppImage, Astral's python-build-standalone release 20261021, without its Tcl/Tk and dbm modules), 3.13.16 (Android, built by Chaquopy), 3.14.8 (iPhone and iPad, BeeWare's Python-Apple-support).
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad.
- License: Python Software Foundation License Version 2, and the licenses of the software incorporated into Python (see "Python Software Foundation License" and "Software incorporated into Python" below).
- Copyright (c) 2001 Python Software Foundation. All rights reserved.
- python-build-standalone's own build scripts, under the Mozilla Public License 2.0, are not part of the AppImage.

### OpenSSL
- Versions: 3.5.7 (macOS), 3.5.9 (Windows, Linux AppImage, Android, iPhone and iPad), 4.0.0 (Linux AppImage, in cryptography).
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad, as part of Python; the Linux AppImage's cryptography has its own, linked into its compiled module.
- License: Apache License 2.0.
- Copyright: the OpenSSL Project Authors.

### SQLite
- Versions: 3.50.4 (macOS), 3.53.1 (Linux AppImage); on Windows and Android, the version built with Python.
- In: macOS, Windows, Linux AppImage, Android, as part of Python.
- License: public domain (see "SQLite" below).

### libffi
- Versions: 3.4.7 (iPhone and iPad), 3.8.0 (Linux AppImage, as part of Python), 3.4.6 (Linux AppImage, linked into cffi's compiled module), the version built with Python 3.13.17 (Windows), 3.3 (Android, Chaquopy's chaquopy-libffi, used by cffi). macOS uses the system's own.
- In: Windows, Linux AppImage, Android, iPhone and iPad.
- License: MIT License.
- libffi - Copyright (c) 1996-2026 Anthony Green, Red Hat, Inc and others. (3.8.0)
- libffi - Copyright (c) 1996-2024 Anthony Green, Red Hat, Inc and others. (3.4.6 and 3.4.7)
- libffi - Copyright (c) 1996-2022 Anthony Green, Red Hat, Inc and others. (Windows)
- libffi - Copyright (c) 1996-2019 Anthony Green, Red Hat, Inc and others. (Android)

### bzip2
- Version: 1.0.8. macOS uses the system's own.
- In: Windows, Linux AppImage, Android, iPhone and iPad, as part of Python.
- License: the bzip2 license (see "bzip2" below).
- Copyright (C) 1996-2019 Julian R Seward.

### XZ Utils (liblzma)
- Versions: 5.6.4 (iPhone and iPad), 5.8.4 (Linux AppImage, as part of Python); on macOS, Windows and Android, the version built with Python. Pillow on Windows also contains XZ Utils 5.8.4.
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad.
- License: liblzma before version 5.6.0 is in the public domain; from 5.6.0 it is under the BSD Zero Clause License (see "XZ Utils" below).

### mpdecimal (libmpdec)
- Versions: 4.0.1 (macOS), 4.0.0 (Linux AppImage, iPhone and iPad); on Windows and Android, the version built with Python.
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad, as part of Python.
- License: BSD 2-Clause License (its text is under "libmpdec" in "Software incorporated into Python").

### Zstandard (libzstd)
- Versions: 1.5.7 (macOS, iPhone and iPad), 1.5.6 (the Linux AppImage's runtime, Alpine Linux 3.21's).
- In: macOS, iPhone and iPad, as part of Python; the Linux AppImage, in its runtime.
- License: BSD 3-Clause License. Zstandard is also offered under the GPL 2.0; OpenDisco uses it under the BSD license only.
- Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

### ncurses
- Versions: 6.5, patch 20240427 (macOS), and 6.5 (Linux AppImage).
- In: macOS and the Linux AppImage, as part of Python.
- License: the ncurses license, an MIT-style license (see "ncurses" below).

### expat
- Versions: 2.8.2 (macOS), 2.8.5 (Windows), 2.9.0 (Linux AppImage); on Android and the iPhone and iPad, the version built into Python.
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad, as part of Python.
- License: MIT License (its text is under "expat" in "Software incorporated into Python").

### zlib
- Versions: 1.3.2 (Linux AppImage, in its Python and in its runtime); on Windows, the version built with Python. macOS, Android and the iPhone and iPad use the system's own.
- In: Windows, Linux AppImage.
- License: zlib License (its text is under "zlib" in "Software incorporated into Python").
- Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler (1.3.2)

### HACL*
- What: the verified implementations of the hash functions built into Python's hashlib.
- In: macOS, Windows, Linux AppImage, Android, iPhone and iPad, as part of Python.
- License: MIT License.
- Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
- Copyright (c) 2022-2023 HACL* Contributors

### libedit
- Version: 20240808-3.1.
- In: Linux AppImage, as part of Python (its readline module).
- License: BSD 3-Clause License (see "libedit" below).
- Copyright (c) 1992, 1993 The Regents of the University of California. All rights reserved.

### libuuid
- Version: 1.0.3.
- In: Linux AppImage, as part of Python (its _uuid module).
- License: BSD 3-Clause License (see "libuuid" below).
- Copyright (C) 1996, 1997 Theodore Ts'o.

### Microsoft Visual C++ runtime
- Files: vcruntime140.dll and vcruntime140_1.dll, and Microsoft code linked into Python's .exe, .dll and .pyd files.
- In: Windows, as part of python.org's embeddable Python.
- License: Microsoft's terms for Distributable Code (see "Microsoft Distributable Code" below).
- Copyright (c) Microsoft Corporation.

### Toga
- Version: 0.5.7 (toga-core, with toga-cocoa on macOS, toga-winforms on Windows, toga-gtk on Linux, toga-android on Android and toga-iOS on the iPhone and iPad).
- In: macOS, Windows, Linux .deb, .rpm and AppImage, Android, iPhone and iPad.
- License: BSD 3-Clause License (see "Toga" below).
- Copyright (c) 2014 Russell Keith-Magee. All rights reserved.

### Travertino
- Version: 0.5.7.
- In: macOS, Windows, Linux .deb, .rpm and AppImage, Android, iPhone and iPad.
- License: BSD 3-Clause License (see "Travertino" below).
- Copyright (c) 2017 Russell Keith-Magee. All rights reserved.

### Rubicon-ObjC
- Version: 0.5.7.
- In: macOS, iPhone and iPad.
- License: BSD 3-Clause License, including code derived from objective-ctypes under the BSD 3-Clause License (see "Rubicon-ObjC" below).
- Copyright (c) 2014 Russell Keith-Magee. All rights reserved.
- Copyright (c) 2011, Phillip Nguyen. All rights reserved. (objective-ctypes)

### std-nslog
- Version: 2.0.0.
- In: macOS.
- License: BSD 3-Clause License (see "std-nslog" below).
- Copyright (c) 2022 Russell Keith-Magee. All rights reserved.

### Briefcase app templates
- What: the launcher programs and project files that Briefcase generates from its macOS app, Linux system package, Android Gradle and iOS Xcode templates.
- In: macOS (the app's launcher), Linux .deb and .rpm (the /usr/bin/opendisco launcher), Android, iPhone and iPad.
- License: MIT License.
- Copyright (c) 2014 Russell Keith-Magee. (macOS app and Linux system package templates)
- Copyright (c) 2019 Russell Keith-Magee. (Android Gradle and iOS Xcode templates)

### dotnet-webview2-winforms and the Microsoft Edge WebView2 SDK
- Version: 1.0.4258.31.
- In: Windows (Microsoft.Web.WebView2.Core.dll, Microsoft.Web.WebView2.WinForms.dll and WebView2Loader.dll, with their Python wrapper).
- License: the wrapper is under the BSD 3-Clause License, with the same text as Toga's; the WebView2 SDK is under Microsoft's BSD 3-Clause License (see "Toga" and "Microsoft Edge WebView2 SDK" below).
- Copyright (c) 2014 Russell Keith-Magee. All rights reserved. (wrapper)
- Copyright (C) Microsoft Corporation. All rights reserved. (WebView2 SDK)

### Python.NET (pythonnet)
- Version: 3.2.1.
- In: Windows.
- License: MIT License.
- Copyright (c) 2006-2021 the contributors of the Python.NET project

### clr_loader
- Version: 0.3.1.
- In: Windows.
- License: MIT License.
- Copyright (c) 2019-2026 Benedikt Reinartz

### pywinpty and winpty
- Version: pywinpty 2.0.15, which includes winpty (winpty.dll and winpty-agent.exe).
- In: Windows.
- License: MIT License, for both.
- Copyright (c) 2017 Spyder IDE (pywinpty)
- Copyright (c) 2011-2016 Ryan Prichard (winpty)

### Pillow
- Version: 13.0.0, which includes brotli 1.2.0, FreeType 2.14.3, HarfBuzz 14.5.0, Little CMS 2.19.1, libavif 1.4.2, libjpeg-turbo 3.2.0, libpng 1.6.58, libwebp 1.6.0, OpenJPEG 2.5.4, LibTIFF 4.7.2, XZ Utils 5.8.4 and zlib-ng 2.3.3.
- In: Windows.
- License: Pillow is under the MIT-CMU License. Each included library is under its own license. FreeType is used under the FreeType License (FTL), not the GPL it is also offered under. All the texts are under "Pillow" below.
- Copyright (c) 1997-2011 by Secret Labs AB; Copyright (c) 1995-2011 by Fredrik Lundh and contributors; Copyright (c) 2010 by Jeffrey 'Alex' Clark and contributors.
- Portions of this software are copyright (c) 2026 The FreeType Project (www.freetype.org). All rights reserved.
- This software is based in part on the work of the Independent JPEG Group.

### cffi
- Versions: 2.1.1 (Windows, Linux AppImage, iPhone and iPad), 1.17.1 (Android).
- In: Windows, Linux AppImage, Android, iPhone and iPad.
- License: MIT No Attribution License (2.1.1) and MIT License (1.17.1) (see "MIT No Attribution" and "MIT License" below).

### pycparser
- Version: 3.12.
- In: Windows, Linux AppImage, Android, iPhone and iPad.
- License: BSD 3-Clause License (see "pycparser" below).
- Copyright (c) 2008-2027, Eli Bendersky. All rights reserved.

### platformdirs
- Version: 4.13.5.
- In: macOS, Windows, Linux .deb, .rpm and AppImage.
- License: MIT License.
- Copyright (c) 2010-202x The platformdirs developers

### packaging
- Version: 26.3.
- In: macOS, Linux .deb, .rpm and AppImage.
- License: offered under either the Apache License 2.0 or the BSD 2-Clause License; OpenDisco uses it under the Apache License 2.0.
- Copyright (c) Donald Stufft and individual contributors.

### fontTools
- Version: 4.67.0.
- In: macOS, iPhone and iPad.
- License: MIT License, and the licenses of the parts listed in its LICENSE.external (see "fontTools" below).
- Copyright (c) 2017 Just van Rossum

### typing_extensions
- Version: 4.16.0.
- In: Linux AppImage, Android, iPhone and iPad.
- License: Python Software Foundation License Version 2 (see "Python Software Foundation License" below).
- Copyright (c) 2001-2023 Python Software Foundation. All rights reserved.

### asyncssh
- Version: 2.23.1.
- In: Linux AppImage, Android, iPhone and iPad.
- License: Eclipse Public License 2.0. asyncssh is also offered under the GNU General Public License 2.0 or later as a Secondary License; OpenDisco distributes it under the Eclipse Public License 2.0 only. See "Source code" above.
- Copyright (c) 2013-2024 by Ron Frederick and others.

### cryptography
- Versions: 47.0.0 (Linux AppImage, iPhone and iPad), 42.0.8 (Android).
- In: Linux AppImage, Android, iPhone and iPad. The AppImage's copy links OpenSSL 4.0.0 into its compiled module (see OpenSSL).
- License: offered under either the Apache License 2.0 or the BSD 3-Clause License; OpenDisco uses it under the Apache License 2.0. Its compiled Rust module includes Rust libraries under the MIT License and the Apache License 2.0, listed in cryptography's source distribution.
- In 47.0.0, those Rust libraries are:
  - pyo3 and pyo3-ffi 0.28.3, portable-atomic 1.13.1, libc 0.2.186, once_cell 1.21.4, cfg-if 1.0.4, bitflags 2.11.1, foreign-types 0.3.2, foreign-types-shared 0.1.1, base64 0.22.1 and itoa 1.0.18: each offered under either the MIT License or the Apache License 2.0; OpenDisco uses them under the Apache License 2.0.
  - self_cell 1.2.2: offered under either the Apache License 2.0 or the GNU General Public License 2.0; OpenDisco uses it under the Apache License 2.0.
  - openssl 0.10.78: the Apache License 2.0. Copyright 2011-2017 Google Inc., 2013 Jack Lloyd, 2013-2014 Steven Fackler.
  - openssl-sys 0.9.114 and pem 3.0.6: the MIT License (see "MIT License" below).
  - asn1 0.24.1 (rust-asn1): the BSD 3-Clause License (see "rust-asn1" below).
  - cryptography's own Rust libraries, under its own license.
- Copyright (c) Individual contributors.

### certifi and Mozilla's CA certificate bundle
- Version: certifi 2026.10.23 (iPhone and iPad). Android carries Chaquopy 17.1.0's own copy of Mozilla's CA bundle (cacert.pem), not certifi's file.
- In: Android, iPhone and iPad.
- License: Mozilla Public License 2.0. See "Source code" above.

### PyGObject
- Version: 3.58.1.
- In: Linux .deb, .rpm and AppImage (compiled in its build, against Ubuntu 24.04's GLib).
- License: GNU Lesser General Public License 2.1 or later. See "Source code" above.
- Copyright: the PyGObject authors, as named in its source files.

### pycairo
- Version: 1.29.2.
- In: Linux .deb, .rpm and AppImage (compiled in its build).
- License: offered under either the GNU Lesser General Public License 2.1 or the Mozilla Public License 1.1; OpenDisco uses it under the GNU Lesser General Public License 2.1. See "Source code" above.
- Copyright: the pycairo authors, as named in its source files.

### GLib's girepository-2.0
- Version: libgirepository-2.0.so.0 from Ubuntu 24.04's glib2.0 2.80.0-6ubuntu3.10 (GLib 2.80.0).
- In: Linux AppImage, used only where the system has no girepository-2.0.
- License: GNU Lesser General Public License 2.1 or later. See "Source code" above.
- Copyright: the GLib authors, as named in its source files (for girepository, Matthias Clasen, Colin Walters, Red Hat, Inc. and others).

### Chaquopy
- Version: 17.1.0.
- In: Android.
- License: MIT License.
- Copyright (c) 2017-2025 Chaquo Ltd and contributors

### AndroidX libraries
- Versions: activity 1.8.0, annotation-experimental 1.4.1, appcompat and appcompat-resources 1.7.1, cardview 1.0.0, coordinatorlayout 1.1.0, core and core-ktx 1.13.0, cursoradapter 1.0.0, customview 1.1.0, drawerlayout 1.1.1, dynamicanimation 1.1.0, emoji2 and emoji2-views-helper 1.3.0, fragment 1.5.4, graphics-shapes 1.0.1, interpolator 1.0.0, loader 1.0.0, profileinstaller 1.3.1, recyclerview 1.2.1, savedstate 1.2.1, startup-runtime 1.1.1, swiperefreshlayout 1.1.0, tracing 1.0.0, transition 1.5.0, vectordrawable and vectordrawable-animated 1.1.0, versionedparcelable 1.1.1, viewpager 1.0.0, viewpager2 1.0.0, and the arch-core and lifecycle libraries they use.
- In: Android.
- License: Apache License 2.0.
- Copyright: The Android Open Source Project.

### Material Components for Android
- Version: 1.13.0.
- In: Android.
- License: Apache License 2.0.
- Copyright: Google LLC.

### Kotlin standard library and kotlinx.coroutines
- Versions: Kotlin standard library 2.2.10; kotlinx-coroutines-core and kotlinx-coroutines-android 1.6.4.
- In: Android.
- License: Apache License 2.0.
- Copyright: JetBrains s.r.o. and Kotlin Programming Language contributors.

### Material Symbols
- What: icons drawn from Material Symbols' SVG path data, in OpenDisco's Android screens.
- In: Android.
- License: Apache License 2.0.
- Copyright: Google LLC.

### xterm.js
- Versions: @xterm/xterm 5.5.0 and @xterm/addon-fit 0.10.0.
- In: macOS, Windows, Linux .deb, .rpm, AppImage and .tar.gz, Android (included, but not used there).
- License: MIT License.
- Copyright (c) 2017-2019, The xterm.js authors (https://github.com/xtermjs/xterm.js)
- Copyright (c) 2014-2016, SourceLair Private Company (https://www.sourcelair.com)
- Copyright (c) 2012-2013, Christopher Jeffrey (https://github.com/chjj/)

### AppImage type2-runtime
- Version: the "continuous" build of 2026-10-19, from commit fedfad51acc2860b2916a1eef32ba4a500ff31ef, built on Alpine Linux 3.21 (runtime-x86_64, SHA-256 617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46).
- In: Linux AppImage, as the program at its start that mounts and runs it.
- License: MIT License. It is statically linked with libfuse, squashfuse, Zstandard, zlib, musl and mimalloc, each listed in this file.
- Copyright (c) 2004-23 probonopd

### libfuse
- Version: 3.15.0, with the runtime's patch to lib/mount.c.
- In: Linux AppImage, statically linked into its runtime.
- License: GNU Lesser General Public License 2.1, which covers libfuse's library; its other files, which the runtime doesn't use, are under the GNU General Public License 2.0. See "Source code" above.
- Copyright (C) 2001-2007 Miklos Szeredi, and the other libfuse authors named in its source files.

### squashfuse
- Version: 0.5.2.
- In: Linux AppImage, in its runtime.
- License: BSD 2-Clause License (see "squashfuse" below).
- Copyright (c) 2012 Dave Vasilevsky and Phillip Lougher. All rights reserved.

### musl
- Version: 1.2.5 (Alpine Linux 3.21's).
- In: Linux AppImage, in its runtime.
- License: MIT License, with the notes in its COPYRIGHT file (see "musl" below).
- Copyright (c) 2005-2020 Rich Felker, et al.

### mimalloc
- Version: 2.1.7 (Alpine Linux 3.21's), in the AppImage's runtime. Python 3.13 and 3.14 contain their own copy too (see "Software incorporated into Python").
- In: Linux AppImage, in its runtime.
- License: MIT License.
- Copyright (c) 2018-2021 Microsoft Corporation, Daan Leijen

### NSIS (Nullsoft Scriptable Install System)
- Version: 3.13.
- In: the Windows installer (setup.exe), as its installer program and LZMA decompression module.
- License: the zlib/libpng License, with its LZMA module under the Common Public License 1.0 (see "NSIS" below, and "Source code" above).
- Copyright (C) 1999-2026 Contributors

## License texts

Each license's full text appears once, with the components it covers.

### Apache License 2.0

Covers: OpenSSL, cryptography and the Rust libraries in it that are used under this license, packaging, the AndroidX libraries, Material Components for Android, the Kotlin standard library, kotlinx.coroutines and Material Symbols. OpenDisco itself is also under this license.

                                     Apache License
                               Version 2.0, January 2004
                            https://www.apache.org/licenses/

       TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

       1. Definitions.

          "License" shall mean the terms and conditions for use, reproduction,
          and distribution as defined by Sections 1 through 9 of this document.

          "Licensor" shall mean the copyright owner or entity authorized by
          the copyright owner that is granting the License.

          "Legal Entity" shall mean the union of the acting entity and all
          other entities that control, are controlled by, or are under common
          control with that entity. For the purposes of this definition,
          "control" means (i) the power, direct or indirect, to cause the
          direction or management of such entity, whether by contract or
          otherwise, or (ii) ownership of fifty percent (50%) or more of the
          outstanding shares, or (iii) beneficial ownership of such entity.

          "You" (or "Your") shall mean an individual or Legal Entity
          exercising permissions granted by this License.

          "Source" form shall mean the preferred form for making modifications,
          including but not limited to software source code, documentation
          source, and configuration files.

          "Object" form shall mean any form resulting from mechanical
          transformation or translation of a Source form, including but
          not limited to compiled object code, generated documentation,
          and conversions to other media types.

          "Work" shall mean the work of authorship, whether in Source or
          Object form, made available under the License, as indicated by a
          copyright notice that is included in or attached to the work
          (an example is provided in the Appendix below).

          "Derivative Works" shall mean any work, whether in Source or Object
          form, that is based on (or derived from) the Work and for which the
          editorial revisions, annotations, elaborations, or other modifications
          represent, as a whole, an original work of authorship. For the purposes
          of this License, Derivative Works shall not include works that remain
          separable from, or merely link (or bind by name) to the interfaces of,
          the Work and Derivative Works thereof.

          "Contribution" shall mean any work of authorship, including
          the original version of the Work and any modifications or additions
          to that Work or Derivative Works thereof, that is intentionally
          submitted to Licensor for inclusion in the Work by the copyright owner
          or by an individual or Legal Entity authorized to submit on behalf of
          the copyright owner. For the purposes of this definition, "submitted"
          means any form of electronic, verbal, or written communication sent
          to the Licensor or its representatives, including but not limited to
          communication on electronic mailing lists, source code control systems,
          and issue tracking systems that are managed by, or on behalf of, the
          Licensor for the purpose of discussing and improving the Work, but
          excluding communication that is conspicuously marked or otherwise
          designated in writing by the copyright owner as "Not a Contribution."

          "Contributor" shall mean Licensor and any individual or Legal Entity
          on behalf of whom a Contribution has been received by Licensor and
          subsequently incorporated within the Work.

       2. Grant of Copyright License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          copyright license to reproduce, prepare Derivative Works of,
          publicly display, publicly perform, sublicense, and distribute the
          Work and such Derivative Works in Source or Object form.

       3. Grant of Patent License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          (except as stated in this section) patent license to make, have made,
          use, offer to sell, sell, import, and otherwise transfer the Work,
          where such license applies only to those patent claims licensable
          by such Contributor that are necessarily infringed by their
          Contribution(s) alone or by combination of their Contribution(s)
          with the Work to which such Contribution(s) was submitted. If You
          institute patent litigation against any entity (including a
          cross-claim or counterclaim in a lawsuit) alleging that the Work
          or a Contribution incorporated within the Work constitutes direct
          or contributory patent infringement, then any patent licenses
          granted to You under this License for that Work shall terminate
          as of the date such litigation is filed.

       4. Redistribution. You may reproduce and distribute copies of the
          Work or Derivative Works thereof in any medium, with or without
          modifications, and in Source or Object form, provided that You
          meet the following conditions:

          (a) You must give any other recipients of the Work or
              Derivative Works a copy of this License; and

          (b) You must cause any modified files to carry prominent notices
              stating that You changed the files; and

          (c) You must retain, in the Source form of any Derivative Works
              that You distribute, all copyright, patent, trademark, and
              attribution notices from the Source form of the Work,
              excluding those notices that do not pertain to any part of
              the Derivative Works; and

          (d) If the Work includes a "NOTICE" text file as part of its
              distribution, then any Derivative Works that You distribute must
              include a readable copy of the attribution notices contained
              within such NOTICE file, excluding those notices that do not
              pertain to any part of the Derivative Works, in at least one
              of the following places: within a NOTICE text file distributed
              as part of the Derivative Works; within the Source form or
              documentation, if provided along with the Derivative Works; or,
              within a display generated by the Derivative Works, if and
              wherever such third-party notices normally appear. The contents
              of the NOTICE file are for informational purposes only and
              do not modify the License. You may add Your own attribution
              notices within Derivative Works that You distribute, alongside
              or as an addendum to the NOTICE text from the Work, provided
              that such additional attribution notices cannot be construed
              as modifying the License.

          You may add Your own copyright statement to Your modifications and
          may provide additional or different license terms and conditions
          for use, reproduction, or distribution of Your modifications, or
          for any such Derivative Works as a whole, provided Your use,
          reproduction, and distribution of the Work otherwise complies with
          the conditions stated in this License.

       5. Submission of Contributions. Unless You explicitly state otherwise,
          any Contribution intentionally submitted for inclusion in the Work
          by You to the Licensor shall be under the terms and conditions of
          this License, without any additional terms or conditions.
          Notwithstanding the above, nothing herein shall supersede or modify
          the terms of any separate license agreement you may have executed
          with Licensor regarding such Contributions.

       6. Trademarks. This License does not grant permission to use the trade
          names, trademarks, service marks, or product names of the Licensor,
          except as required for reasonable and customary use in describing the
          origin of the Work and reproducing the content of the NOTICE file.

       7. Disclaimer of Warranty. Unless required by applicable law or
          agreed to in writing, Licensor provides the Work (and each
          Contributor provides its Contributions) on an "AS IS" BASIS,
          WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
          implied, including, without limitation, any warranties or conditions
          of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
          PARTICULAR PURPOSE. You are solely responsible for determining the
          appropriateness of using or redistributing the Work and assume any
          risks associated with Your exercise of permissions under this License.

       8. Limitation of Liability. In no event and under no legal theory,
          whether in tort (including negligence), contract, or otherwise,
          unless required by applicable law (such as deliberate and grossly
          negligent acts) or agreed to in writing, shall any Contributor be
          liable to You for damages, including any direct, indirect, special,
          incidental, or consequential damages of any character arising as a
          result of this License or out of the use or inability to use the
          Work (including but not limited to damages for loss of goodwill,
          work stoppage, computer failure or malfunction, or any and all
          other commercial damages or losses), even if such Contributor
          has been advised of the possibility of such damages.

       9. Accepting Warranty or Additional Liability. While redistributing
          the Work or Derivative Works thereof, You may choose to offer,
          and charge a fee for, acceptance of support, warranty, indemnity,
          or other liability obligations and/or rights consistent with this
          License. However, in accepting such obligations, You may act only
          on Your own behalf and on Your sole responsibility, not on behalf
          of any other Contributor, and only if You agree to indemnify,
          defend, and hold each Contributor harmless for any liability
          incurred by, or claims asserted against, such Contributor by reason
          of your accepting any such warranty or additional liability.

       END OF TERMS AND CONDITIONS

       APPENDIX: How to apply the Apache License to your work.

          To apply the Apache License to your work, attach the following
          boilerplate notice, with the fields enclosed by brackets "[]"
          replaced with your own identifying information. (Don't include
          the brackets!)  The text should be enclosed in the appropriate
          comment syntax for the file format. We also recommend that a
          file or class name and description of purpose be included on the
          same "printed page" as the copyright notice for easier
          identification within third-party archives.

       Copyright [yyyy] [name of copyright owner]

       Licensed under the Apache License, Version 2.0 (the "License");
       you may not use this file except in compliance with the License.
       You may obtain a copy of the License at

           https://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing, software
       distributed under the License is distributed on an "AS IS" BASIS,
       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
       See the License for the specific language governing permissions and
       limitations under the License.

### Eclipse Public License 2.0

Covers: asyncssh.

    Eclipse Public License - v 2.0

        THE ACCOMPANYING PROGRAM IS PROVIDED UNDER THE TERMS OF THIS ECLIPSE
        PUBLIC LICENSE ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION
        OF THE PROGRAM CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT.

    1. DEFINITIONS

    "Contribution" means:

      a) in the case of the initial Contributor, the initial content
         Distributed under this Agreement, and

      b) in the case of each subsequent Contributor:
         i) changes to the Program, and
         ii) additions to the Program;
      where such changes and/or additions to the Program originate from
      and are Distributed by that particular Contributor. A Contribution
      "originates" from a Contributor if it was added to the Program by
      such Contributor itself or anyone acting on such Contributor's behalf.
      Contributions do not include changes or additions to the Program that
      are not Modified Works.

    "Contributor" means any person or entity that Distributes the Program.

    "Licensed Patents" mean patent claims licensable by a Contributor which
    are necessarily infringed by the use or sale of its Contribution alone
    or when combined with the Program.

    "Program" means the Contributions Distributed in accordance with this
    Agreement.

    "Recipient" means anyone who receives the Program under this Agreement
    or any Secondary License (as applicable), including Contributors.

    "Derivative Works" shall mean any work, whether in Source Code or other
    form, that is based on (or derived from) the Program and for which the
    editorial revisions, annotations, elaborations, or other modifications
    represent, as a whole, an original work of authorship.

    "Modified Works" shall mean any work in Source Code or other form that
    results from an addition to, deletion from, or modification of the
    contents of the Program, including, for purposes of clarity any new file
    in Source Code form that contains any contents of the Program. Modified
    Works shall not include works that contain only declarations,
    interfaces, types, classes, structures, or files of the Program solely
    in each case in order to link to, bind by name, or subclass the Program
    or Modified Works thereof.

    "Distribute" means the acts of a) distributing or b) making available
    in any manner that enables the transfer of a copy.

    "Source Code" means the form of a Program preferred for making
    modifications, including but not limited to software source code,
    documentation source, and configuration files.

    "Secondary License" means either the GNU General Public License,
    Version 2.0, or any later versions of that license, including any
    exceptions or additional permissions as identified by the initial
    Contributor.

    2. GRANT OF RIGHTS

      a) Subject to the terms of this Agreement, each Contributor hereby
      grants Recipient a non-exclusive, worldwide, royalty-free copyright
      license to reproduce, prepare Derivative Works of, publicly display,
      publicly perform, Distribute and sublicense the Contribution of such
      Contributor, if any, and such Derivative Works.

      b) Subject to the terms of this Agreement, each Contributor hereby
      grants Recipient a non-exclusive, worldwide, royalty-free patent
      license under Licensed Patents to make, use, sell, offer to sell,
      import and otherwise transfer the Contribution of such Contributor,
      if any, in Source Code or other form. This patent license shall
      apply to the combination of the Contribution and the Program if, at
      the time the Contribution is added by the Contributor, such addition
      of the Contribution causes such combination to be covered by the
      Licensed Patents. The patent license shall not apply to any other
      combinations which include the Contribution. No hardware per se is
      licensed hereunder.

      c) Recipient understands that although each Contributor grants the
      licenses to its Contributions set forth herein, no assurances are
      provided by any Contributor that the Program does not infringe the
      patent or other intellectual property rights of any other entity.
      Each Contributor disclaims any liability to Recipient for claims
      brought by any other entity based on infringement of intellectual
      property rights or otherwise. As a condition to exercising the
      rights and licenses granted hereunder, each Recipient hereby
      assumes sole responsibility to secure any other intellectual
      property rights needed, if any. For example, if a third party
      patent license is required to allow Recipient to Distribute the
      Program, it is Recipient's responsibility to acquire that license
      before distributing the Program.

      d) Each Contributor represents that to its knowledge it has
      sufficient copyright rights in its Contribution, if any, to grant
      the copyright license set forth in this Agreement.

      e) Notwithstanding the terms of any Secondary License, no
      Contributor makes additional grants to any Recipient (other than
      those set forth in this Agreement) as a result of such Recipient's
      receipt of the Program under the terms of a Secondary License
      (if permitted under the terms of Section 3).

    3. REQUIREMENTS

    3.1 If a Contributor Distributes the Program in any form, then:

      a) the Program must also be made available as Source Code, in
      accordance with section 3.2, and the Contributor must accompany
      the Program with a statement that the Source Code for the Program
      is available under this Agreement, and informs Recipients how to
      obtain it in a reasonable manner on or through a medium customarily
      used for software exchange; and

      b) the Contributor may Distribute the Program under a license
      different than this Agreement, provided that such license:
         i) effectively disclaims on behalf of all other Contributors all
         warranties and conditions, express and implied, including
         warranties or conditions of title and non-infringement, and
         implied warranties or conditions of merchantability and fitness
         for a particular purpose;

         ii) effectively excludes on behalf of all other Contributors all
         liability for damages, including direct, indirect, special,
         incidental and consequential damages, such as lost profits;

         iii) does not attempt to limit or alter the recipients' rights
         in the Source Code under section 3.2; and

         iv) requires any subsequent distribution of the Program by any
         party to be under a license that satisfies the requirements
         of this section 3.

    3.2 When the Program is Distributed as Source Code:

      a) it must be made available under this Agreement, or if the
      Program (i) is combined with other material in a separate file or
      files made available under a Secondary License, and (ii) the initial
      Contributor attached to the Source Code the notice described in
      Exhibit A of this Agreement, then the Program may be made available
      under the terms of such Secondary Licenses, and

      b) a copy of this Agreement must be included with each copy of
      the Program.

    3.3 Contributors may not remove or alter any copyright, patent,
    trademark, attribution notices, disclaimers of warranty, or limitations
    of liability ("notices") contained within the Program from any copy of
    the Program which they Distribute, provided that Contributors may add
    their own appropriate notices.

    4. COMMERCIAL DISTRIBUTION

    Commercial distributors of software may accept certain responsibilities
    with respect to end users, business partners and the like. While this
    license is intended to facilitate the commercial use of the Program,
    the Contributor who includes the Program in a commercial product
    offering should do so in a manner which does not create potential
    liability for other Contributors. Therefore, if a Contributor includes
    the Program in a commercial product offering, such Contributor
    ("Commercial Contributor") hereby agrees to defend and indemnify every
    other Contributor ("Indemnified Contributor") against any losses,
    damages and costs (collectively "Losses") arising from claims, lawsuits
    and other legal actions brought by a third party against the Indemnified
    Contributor to the extent caused by the acts or omissions of such
    Commercial Contributor in connection with its distribution of the Program
    in a commercial product offering. The obligations in this section do not
    apply to any claims or Losses relating to any actual or alleged
    intellectual property infringement. In order to qualify, an Indemnified
    Contributor must: a) promptly notify the Commercial Contributor in
    writing of such claim, and b) allow the Commercial Contributor to control,
    and cooperate with the Commercial Contributor in, the defense and any
    related settlement negotiations. The Indemnified Contributor may
    participate in any such claim at its own expense.

    For example, a Contributor might include the Program in a commercial
    product offering, Product X. That Contributor is then a Commercial
    Contributor. If that Commercial Contributor then makes performance
    claims, or offers warranties related to Product X, those performance
    claims and warranties are such Commercial Contributor's responsibility
    alone. Under this section, the Commercial Contributor would have to
    defend claims against the other Contributors related to those performance
    claims and warranties, and if a court requires any other Contributor to
    pay any damages as a result, the Commercial Contributor must pay
    those damages.

    5. NO WARRANTY

    EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, AND TO THE EXTENT
    PERMITTED BY APPLICABLE LAW, THE PROGRAM IS PROVIDED ON AN "AS IS"
    BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
    IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF
    TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR
    PURPOSE. Each Recipient is solely responsible for determining the
    appropriateness of using and distributing the Program and assumes all
    risks associated with its exercise of rights under this Agreement,
    including but not limited to the risks and costs of program errors,
    compliance with applicable laws, damage to or loss of data, programs
    or equipment, and unavailability or interruption of operations.

    6. DISCLAIMER OF LIABILITY

    EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, AND TO THE EXTENT
    PERMITTED BY APPLICABLE LAW, NEITHER RECIPIENT NOR ANY CONTRIBUTORS
    SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING WITHOUT LIMITATION LOST
    PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OR DISTRIBUTION OF THE PROGRAM OR THE
    EXERCISE OF ANY RIGHTS GRANTED HEREUNDER, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGES.

    7. GENERAL

    If any provision of this Agreement is invalid or unenforceable under
    applicable law, it shall not affect the validity or enforceability of
    the remainder of the terms of this Agreement, and without further
    action by the parties hereto, such provision shall be reformed to the
    minimum extent necessary to make such provision valid and enforceable.

    If Recipient institutes patent litigation against any entity
    (including a cross-claim or counterclaim in a lawsuit) alleging that the
    Program itself (excluding combinations of the Program with other software
    or hardware) infringes such Recipient's patent(s), then such Recipient's
    rights granted under Section 2(b) shall terminate as of the date such
    litigation is filed.

    All Recipient's rights under this Agreement shall terminate if it
    fails to comply with any of the material terms or conditions of this
    Agreement and does not cure such failure in a reasonable period of
    time after becoming aware of such noncompliance. If all Recipient's
    rights under this Agreement terminate, Recipient agrees to cease use
    and distribution of the Program as soon as reasonably practicable.
    However, Recipient's obligations under this Agreement and any licenses
    granted by Recipient relating to the Program shall continue and survive.

    Everyone is permitted to copy and distribute copies of this Agreement,
    but in order to avoid inconsistency the Agreement is copyrighted and
    may only be modified in the following manner. The Agreement Steward
    reserves the right to publish new versions (including revisions) of
    this Agreement from time to time. No one other than the Agreement
    Steward has the right to modify this Agreement. The Eclipse Foundation
    is the initial Agreement Steward. The Eclipse Foundation may assign the
    responsibility to serve as the Agreement Steward to a suitable separate
    entity. Each new version of the Agreement will be given a distinguishing
    version number. The Program (including Contributions) may always be
    Distributed subject to the version of the Agreement under which it was
    received. In addition, after a new version of the Agreement is published,
    Contributor may elect to Distribute the Program (including its
    Contributions) under the new version.

    Except as expressly stated in Sections 2(a) and 2(b) above, Recipient
    receives no rights or licenses to the intellectual property of any
    Contributor under this Agreement, whether expressly, by implication,
    estoppel or otherwise. All rights in the Program not expressly granted
    under this Agreement are reserved. Nothing in this Agreement is intended
    to be enforceable by any entity that is not a Contributor or Recipient.
    No third-party beneficiary rights are created under this Agreement.

    Exhibit A - Form of Secondary Licenses Notice

    "This Source Code may also be made available under the following
    Secondary Licenses when the conditions for such availability set forth
    in the Eclipse Public License, v. 2.0 are satisfied: {name license(s),
    version(s), and exceptions or additional permissions here}."

      Simply including a copy of this Agreement, including this Exhibit A
      is not sufficient to license the Source Code under Secondary Licenses.

      If it is not possible or desirable to put the notice in a particular
      file, then You may include the notice in a location (such as a LICENSE
      file in a relevant directory) where a recipient would be likely to
      look for such a notice.

      You may add additional accurate notices of copyright ownership.

### GNU Lesser General Public License 2.1

Covers: PyGObject (version 2.1 or later), pycairo (version 2.1), GLib's girepository-2.0 (version 2.1 or later) and libfuse (version 2.1). pycairo's own notice of its licenses is reproduced first.

    PyCairo is free software.

    Every source file in the implementation of PyCairo is available to be
    redistributed and/or modified under the terms of either the GNU Lesser
    General Public License (LGPL) version 2.1 or the Mozilla Public
    License (MPL) version 1.1.  Some files are available under more
    liberal terms, but we believe that in all cases, each file may be used
    under either the LGPL or the MPL.

    See the following files in this directory for the precise terms and
    conditions of either license:

            COPYING-LGPL-2.1
            COPYING-MPL-1.1

    Please see each file in the implementation for Copyright and licensing
    information.

    SPDX-License-Identifier: LGPL-2.1-only OR MPL-1.1


                      GNU LESSER GENERAL PUBLIC LICENSE
                           Version 2.1, February 1999

     Copyright (C) 1991, 1999 Free Software Foundation, Inc.
         51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
     Everyone is permitted to copy and distribute verbatim copies
     of this license document, but changing it is not allowed.

    [This is the first released version of the Lesser GPL.  It also counts
     as the successor of the GNU Library Public License, version 2, hence
     the version number 2.1.]

                                Preamble

      The licenses for most software are designed to take away your
    freedom to share and change it.  By contrast, the GNU General Public
    Licenses are intended to guarantee your freedom to share and change
    free software--to make sure the software is free for all its users.

      This license, the Lesser General Public License, applies to some
    specially designated software packages--typically libraries--of the
    Free Software Foundation and other authors who decide to use it.  You
    can use it too, but we suggest you first think carefully about whether
    this license or the ordinary General Public License is the better
    strategy to use in any particular case, based on the explanations below.

      When we speak of free software, we are referring to freedom of use,
    not price.  Our General Public Licenses are designed to make sure that
    you have the freedom to distribute copies of free software (and charge
    for this service if you wish); that you receive source code or can get
    it if you want it; that you can change the software and use pieces of
    it in new free programs; and that you are informed that you can do
    these things.

      To protect your rights, we need to make restrictions that forbid
    distributors to deny you these rights or to ask you to surrender these
    rights.  These restrictions translate to certain responsibilities for
    you if you distribute copies of the library or if you modify it.

      For example, if you distribute copies of the library, whether gratis
    or for a fee, you must give the recipients all the rights that we gave
    you.  You must make sure that they, too, receive or can get the source
    code.  If you link other code with the library, you must provide
    complete object files to the recipients, so that they can relink them
    with the library after making changes to the library and recompiling
    it.  And you must show them these terms so they know their rights.

      We protect your rights with a two-step method: (1) we copyright the
    library, and (2) we offer you this license, which gives you legal
    permission to copy, distribute and/or modify the library.

      To protect each distributor, we want to make it very clear that
    there is no warranty for the free library.  Also, if the library is
    modified by someone else and passed on, the recipients should know
    that what they have is not the original version, so that the original
    author's reputation will not be affected by problems that might be
    introduced by others.

      Finally, software patents pose a constant threat to the existence of
    any free program.  We wish to make sure that a company cannot
    effectively restrict the users of a free program by obtaining a
    restrictive license from a patent holder.  Therefore, we insist that
    any patent license obtained for a version of the library must be
    consistent with the full freedom of use specified in this license.

      Most GNU software, including some libraries, is covered by the
    ordinary GNU General Public License.  This license, the GNU Lesser
    General Public License, applies to certain designated libraries, and
    is quite different from the ordinary General Public License.  We use
    this license for certain libraries in order to permit linking those
    libraries into non-free programs.

      When a program is linked with a library, whether statically or using
    a shared library, the combination of the two is legally speaking a
    combined work, a derivative of the original library.  The ordinary
    General Public License therefore permits such linking only if the
    entire combination fits its criteria of freedom.  The Lesser General
    Public License permits more lax criteria for linking other code with
    the library.

      We call this license the "Lesser" General Public License because it
    does Less to protect the user's freedom than the ordinary General
    Public License.  It also provides other free software developers Less
    of an advantage over competing non-free programs.  These disadvantages
    are the reason we use the ordinary General Public License for many
    libraries.  However, the Lesser license provides advantages in certain
    special circumstances.

      For example, on rare occasions, there may be a special need to
    encourage the widest possible use of a certain library, so that it becomes
    a de-facto standard.  To achieve this, non-free programs must be
    allowed to use the library.  A more frequent case is that a free
    library does the same job as widely used non-free libraries.  In this
    case, there is little to gain by limiting the free library to free
    software only, so we use the Lesser General Public License.

      In other cases, permission to use a particular library in non-free
    programs enables a greater number of people to use a large body of
    free software.  For example, permission to use the GNU C Library in
    non-free programs enables many more people to use the whole GNU
    operating system, as well as its variant, the GNU/Linux operating
    system.

      Although the Lesser General Public License is Less protective of the
    users' freedom, it does ensure that the user of a program that is
    linked with the Library has the freedom and the wherewithal to run
    that program using a modified version of the Library.

      The precise terms and conditions for copying, distribution and
    modification follow.  Pay close attention to the difference between a
    "work based on the library" and a "work that uses the library".  The
    former contains code derived from the library, whereas the latter must
    be combined with the library in order to run.

                      GNU LESSER GENERAL PUBLIC LICENSE
       TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

      0. This License Agreement applies to any software library or other
    program which contains a notice placed by the copyright holder or
    other authorized party saying it may be distributed under the terms of
    this Lesser General Public License (also called "this License").
    Each licensee is addressed as "you".

      A "library" means a collection of software functions and/or data
    prepared so as to be conveniently linked with application programs
    (which use some of those functions and data) to form executables.

      The "Library", below, refers to any such software library or work
    which has been distributed under these terms.  A "work based on the
    Library" means either the Library or any derivative work under
    copyright law: that is to say, a work containing the Library or a
    portion of it, either verbatim or with modifications and/or translated
    straightforwardly into another language.  (Hereinafter, translation is
    included without limitation in the term "modification".)

      "Source code" for a work means the preferred form of the work for
    making modifications to it.  For a library, complete source code means
    all the source code for all modules it contains, plus any associated
    interface definition files, plus the scripts used to control compilation
    and installation of the library.

      Activities other than copying, distribution and modification are not
    covered by this License; they are outside its scope.  The act of
    running a program using the Library is not restricted, and output from
    such a program is covered only if its contents constitute a work based
    on the Library (independent of the use of the Library in a tool for
    writing it).  Whether that is true depends on what the Library does
    and what the program that uses the Library does.

      1. You may copy and distribute verbatim copies of the Library's
    complete source code as you receive it, in any medium, provided that
    you conspicuously and appropriately publish on each copy an
    appropriate copyright notice and disclaimer of warranty; keep intact
    all the notices that refer to this License and to the absence of any
    warranty; and distribute a copy of this License along with the
    Library.

      You may charge a fee for the physical act of transferring a copy,
    and you may at your option offer warranty protection in exchange for a
    fee.

      2. You may modify your copy or copies of the Library or any portion
    of it, thus forming a work based on the Library, and copy and
    distribute such modifications or work under the terms of Section 1
    above, provided that you also meet all of these conditions:

        a) The modified work must itself be a software library.

        b) You must cause the files modified to carry prominent notices
        stating that you changed the files and the date of any change.

        c) You must cause the whole of the work to be licensed at no
        charge to all third parties under the terms of this License.

        d) If a facility in the modified Library refers to a function or a
        table of data to be supplied by an application program that uses
        the facility, other than as an argument passed when the facility
        is invoked, then you must make a good faith effort to ensure that,
        in the event an application does not supply such function or
        table, the facility still operates, and performs whatever part of
        its purpose remains meaningful.

        (For example, a function in a library to compute square roots has
        a purpose that is entirely well-defined independent of the
        application.  Therefore, Subsection 2d requires that any
        application-supplied function or table used by this function must
        be optional: if the application does not supply it, the square
        root function must still compute square roots.)

    These requirements apply to the modified work as a whole.  If
    identifiable sections of that work are not derived from the Library,
    and can be reasonably considered independent and separate works in
    themselves, then this License, and its terms, do not apply to those
    sections when you distribute them as separate works.  But when you
    distribute the same sections as part of a whole which is a work based
    on the Library, the distribution of the whole must be on the terms of
    this License, whose permissions for other licensees extend to the
    entire whole, and thus to each and every part regardless of who wrote
    it.

    Thus, it is not the intent of this section to claim rights or contest
    your rights to work written entirely by you; rather, the intent is to
    exercise the right to control the distribution of derivative or
    collective works based on the Library.

    In addition, mere aggregation of another work not based on the Library
    with the Library (or with a work based on the Library) on a volume of
    a storage or distribution medium does not bring the other work under
    the scope of this License.

      3. You may opt to apply the terms of the ordinary GNU General Public
    License instead of this License to a given copy of the Library.  To do
    this, you must alter all the notices that refer to this License, so
    that they refer to the ordinary GNU General Public License, version 2,
    instead of to this License.  (If a newer version than version 2 of the
    ordinary GNU General Public License has appeared, then you can specify
    that version instead if you wish.)  Do not make any other change in
    these notices.

      Once this change is made in a given copy, it is irreversible for
    that copy, so the ordinary GNU General Public License applies to all
    subsequent copies and derivative works made from that copy.

      This option is useful when you wish to copy part of the code of
    the Library into a program that is not a library.

      4. You may copy and distribute the Library (or a portion or
    derivative of it, under Section 2) in object code or executable form
    under the terms of Sections 1 and 2 above provided that you accompany
    it with the complete corresponding machine-readable source code, which
    must be distributed under the terms of Sections 1 and 2 above on a
    medium customarily used for software interchange.

      If distribution of object code is made by offering access to copy
    from a designated place, then offering equivalent access to copy the
    source code from the same place satisfies the requirement to
    distribute the source code, even though third parties are not
    compelled to copy the source along with the object code.

      5. A program that contains no derivative of any portion of the
    Library, but is designed to work with the Library by being compiled or
    linked with it, is called a "work that uses the Library".  Such a
    work, in isolation, is not a derivative work of the Library, and
    therefore falls outside the scope of this License.

      However, linking a "work that uses the Library" with the Library
    creates an executable that is a derivative of the Library (because it
    contains portions of the Library), rather than a "work that uses the
    library".  The executable is therefore covered by this License.
    Section 6 states terms for distribution of such executables.

      When a "work that uses the Library" uses material from a header file
    that is part of the Library, the object code for the work may be a
    derivative work of the Library even though the source code is not.
    Whether this is true is especially significant if the work can be
    linked without the Library, or if the work is itself a library.  The
    threshold for this to be true is not precisely defined by law.

      If such an object file uses only numerical parameters, data
    structure layouts and accessors, and small macros and small inline
    functions (ten lines or less in length), then the use of the object
    file is unrestricted, regardless of whether it is legally a derivative
    work.  (Executables containing this object code plus portions of the
    Library will still fall under Section 6.)

      Otherwise, if the work is a derivative of the Library, you may
    distribute the object code for the work under the terms of Section 6.
    Any executables containing that work also fall under Section 6,
    whether or not they are linked directly with the Library itself.

      6. As an exception to the Sections above, you may also combine or
    link a "work that uses the Library" with the Library to produce a
    work containing portions of the Library, and distribute that work
    under terms of your choice, provided that the terms permit
    modification of the work for the customer's own use and reverse
    engineering for debugging such modifications.

      You must give prominent notice with each copy of the work that the
    Library is used in it and that the Library and its use are covered by
    this License.  You must supply a copy of this License.  If the work
    during execution displays copyright notices, you must include the
    copyright notice for the Library among them, as well as a reference
    directing the user to the copy of this License.  Also, you must do one
    of these things:

        a) Accompany the work with the complete corresponding
        machine-readable source code for the Library including whatever
        changes were used in the work (which must be distributed under
        Sections 1 and 2 above); and, if the work is an executable linked
        with the Library, with the complete machine-readable "work that
        uses the Library", as object code and/or source code, so that the
        user can modify the Library and then relink to produce a modified
        executable containing the modified Library.  (It is understood
        that the user who changes the contents of definitions files in the
        Library will not necessarily be able to recompile the application
        to use the modified definitions.)

        b) Use a suitable shared library mechanism for linking with the
        Library.  A suitable mechanism is one that (1) uses at run time a
        copy of the library already present on the user's computer system,
        rather than copying library functions into the executable, and (2)
        will operate properly with a modified version of the library, if
        the user installs one, as long as the modified version is
        interface-compatible with the version that the work was made with.

        c) Accompany the work with a written offer, valid for at
        least three years, to give the same user the materials
        specified in Subsection 6a, above, for a charge no more
        than the cost of performing this distribution.

        d) If distribution of the work is made by offering access to copy
        from a designated place, offer equivalent access to copy the above
        specified materials from the same place.

        e) Verify that the user has already received a copy of these
        materials or that you have already sent this user a copy.

      For an executable, the required form of the "work that uses the
    Library" must include any data and utility programs needed for
    reproducing the executable from it.  However, as a special exception,
    the materials to be distributed need not include anything that is
    normally distributed (in either source or binary form) with the major
    components (compiler, kernel, and so on) of the operating system on
    which the executable runs, unless that component itself accompanies
    the executable.

      It may happen that this requirement contradicts the license
    restrictions of other proprietary libraries that do not normally
    accompany the operating system.  Such a contradiction means you cannot
    use both them and the Library together in an executable that you
    distribute.

      7. You may place library facilities that are a work based on the
    Library side-by-side in a single library together with other library
    facilities not covered by this License, and distribute such a combined
    library, provided that the separate distribution of the work based on
    the Library and of the other library facilities is otherwise
    permitted, and provided that you do these two things:

        a) Accompany the combined library with a copy of the same work
        based on the Library, uncombined with any other library
        facilities.  This must be distributed under the terms of the
        Sections above.

        b) Give prominent notice with the combined library of the fact
        that part of it is a work based on the Library, and explaining
        where to find the accompanying uncombined form of the same work.

      8. You may not copy, modify, sublicense, link with, or distribute
    the Library except as expressly provided under this License.  Any
    attempt otherwise to copy, modify, sublicense, link with, or
    distribute the Library is void, and will automatically terminate your
    rights under this License.  However, parties who have received copies,
    or rights, from you under this License will not have their licenses
    terminated so long as such parties remain in full compliance.

      9. You are not required to accept this License, since you have not
    signed it.  However, nothing else grants you permission to modify or
    distribute the Library or its derivative works.  These actions are
    prohibited by law if you do not accept this License.  Therefore, by
    modifying or distributing the Library (or any work based on the
    Library), you indicate your acceptance of this License to do so, and
    all its terms and conditions for copying, distributing or modifying
    the Library or works based on it.

      10. Each time you redistribute the Library (or any work based on the
    Library), the recipient automatically receives a license from the
    original licensor to copy, distribute, link with or modify the Library
    subject to these terms and conditions.  You may not impose any further
    restrictions on the recipients' exercise of the rights granted herein.
    You are not responsible for enforcing compliance by third parties with
    this License.

      11. If, as a consequence of a court judgment or allegation of patent
    infringement or for any other reason (not limited to patent issues),
    conditions are imposed on you (whether by court order, agreement or
    otherwise) that contradict the conditions of this License, they do not
    excuse you from the conditions of this License.  If you cannot
    distribute so as to satisfy simultaneously your obligations under this
    License and any other pertinent obligations, then as a consequence you
    may not distribute the Library at all.  For example, if a patent
    license would not permit royalty-free redistribution of the Library by
    all those who receive copies directly or indirectly through you, then
    the only way you could satisfy both it and this License would be to
    refrain entirely from distribution of the Library.

    If any portion of this section is held invalid or unenforceable under any
    particular circumstance, the balance of the section is intended to apply,
    and the section as a whole is intended to apply in other circumstances.

    It is not the purpose of this section to induce you to infringe any
    patents or other property right claims or to contest validity of any
    such claims; this section has the sole purpose of protecting the
    integrity of the free software distribution system which is
    implemented by public license practices.  Many people have made
    generous contributions to the wide range of software distributed
    through that system in reliance on consistent application of that
    system; it is up to the author/donor to decide if he or she is willing
    to distribute software through any other system and a licensee cannot
    impose that choice.

    This section is intended to make thoroughly clear what is believed to
    be a consequence of the rest of this License.

      12. If the distribution and/or use of the Library is restricted in
    certain countries either by patents or by copyrighted interfaces, the
    original copyright holder who places the Library under this License may add
    an explicit geographical distribution limitation excluding those countries,
    so that distribution is permitted only in or among countries not thus
    excluded.  In such case, this License incorporates the limitation as if
    written in the body of this License.

      13. The Free Software Foundation may publish revised and/or new
    versions of the Lesser General Public License from time to time.
    Such new versions will be similar in spirit to the present version,
    but may differ in detail to address new problems or concerns.

    Each version is given a distinguishing version number.  If the Library
    specifies a version number of this License which applies to it and
    "any later version", you have the option of following the terms and
    conditions either of that version or of any later version published by
    the Free Software Foundation.  If the Library does not specify a
    license version number, you may choose any version ever published by
    the Free Software Foundation.

      14. If you wish to incorporate parts of the Library into other free
    programs whose distribution conditions are incompatible with these,
    write to the author to ask for permission.  For software which is
    copyrighted by the Free Software Foundation, write to the Free
    Software Foundation; we sometimes make exceptions for this.  Our
    decision will be guided by the two goals of preserving the free status
    of all derivatives of our free software and of promoting the sharing
    and reuse of software generally.

                                NO WARRANTY

      15. BECAUSE THE LIBRARY IS LICENSED FREE OF CHARGE, THERE IS NO
    WARRANTY FOR THE LIBRARY, TO THE EXTENT PERMITTED BY APPLICABLE LAW.
    EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR
    OTHER PARTIES PROVIDE THE LIBRARY "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE
    LIBRARY IS WITH YOU.  SHOULD THE LIBRARY PROVE DEFECTIVE, YOU ASSUME
    THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

      16. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN
    WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY
    AND/OR REDISTRIBUTE THE LIBRARY AS PERMITTED ABOVE, BE LIABLE TO YOU
    FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR
    CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE
    LIBRARY (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
    RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
    FAILURE OF THE LIBRARY TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
    SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
    DAMAGES.

                         END OF TERMS AND CONDITIONS

               How to Apply These Terms to Your New Libraries

      If you develop a new library, and you want it to be of the greatest
    possible use to the public, we recommend making it free software that
    everyone can redistribute and change.  You can do so by permitting
    redistribution under these terms (or, alternatively, under the terms of the
    ordinary General Public License).

      To apply these terms, attach the following notices to the library.  It is
    safest to attach them to the start of each source file to most effectively
    convey the exclusion of warranty; and each file should have at least the
    "copyright" line and a pointer to where the full notice is found.

        <one line to give the library's name and a brief idea of what it does.>
        Copyright (C) <year>  <name of author>

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 2.1 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library; if not, write to the Free Software
        Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Also add information on how to contact you by electronic and paper mail.

    You should also get your employer (if you work as a programmer) or your
    school, if any, to sign a "copyright disclaimer" for the library, if
    necessary.  Here is a sample; alter the names:

      Yoyodyne, Inc., hereby disclaims all copyright interest in the
      library `Frob' (a library for tweaking knobs) written by James Random Hacker.

      <signature of Ty Coon>, 1 April 1990
      Ty Coon, President of Vice

    That's all there is to it!

### Mozilla Public License 2.0

Covers: certifi, and Mozilla's CA certificate bundle in the Android app. certifi's own notice is reproduced first.

    This package contains a modified version of ca-bundle.crt:

    ca-bundle.crt -- Bundle of CA Root Certificates

    This is a bundle of X.509 certificates of public Certificate Authorities
    (CA). These were automatically extracted from Mozilla's root certificates
    file (certdata.txt).  This file can be found in the mozilla source tree:
    https://hg.mozilla.org/mozilla-central/file/tip/security/nss/lib/ckfw/builtins/certdata.txt
    It contains the certificates in PEM format and therefore
    can be directly used with curl / libcurl / php_curl, or with
    an Apache+mod_ssl webserver for SSL client authentication.
    Just configure this file as the SSLCACertificateFile.#

    ***** BEGIN LICENSE BLOCK *****
    This Source Code Form is subject to the terms of the Mozilla Public License,
    v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
    one at http://mozilla.org/MPL/2.0/.

    ***** END LICENSE BLOCK *****
    @(#) $RCSfile: certdata.txt,v $ $Revision: 1.80 $ $Date: 2011/11/03 15:11:58 $


    Mozilla Public License Version 2.0
    ==================================

    1. Definitions
    --------------

    1.1. "Contributor"
        means each individual or legal entity that creates, contributes to
        the creation of, or owns Covered Software.

    1.2. "Contributor Version"
        means the combination of the Contributions of others (if any) used
        by a Contributor and that particular Contributor's Contribution.

    1.3. "Contribution"
        means Covered Software of a particular Contributor.

    1.4. "Covered Software"
        means Source Code Form to which the initial Contributor has attached
        the notice in Exhibit A, the Executable Form of such Source Code
        Form, and Modifications of such Source Code Form, in each case
        including portions thereof.

    1.5. "Incompatible With Secondary Licenses"
        means

        (a) that the initial Contributor has attached the notice described
            in Exhibit B to the Covered Software; or

        (b) that the Covered Software was made available under the terms of
            version 1.1 or earlier of the License, but not also under the
            terms of a Secondary License.

    1.6. "Executable Form"
        means any form of the work other than Source Code Form.

    1.7. "Larger Work"
        means a work that combines Covered Software with other material, in
        a separate file or files, that is not Covered Software.

    1.8. "License"
        means this document.

    1.9. "Licensable"
        means having the right to grant, to the maximum extent possible,
        whether at the time of the initial grant or subsequently, any and
        all of the rights conveyed by this License.

    1.10. "Modifications"
        means any of the following:

        (a) any file in Source Code Form that results from an addition to,
            deletion from, or modification of the contents of Covered
            Software; or

        (b) any new file in Source Code Form that contains any Covered
            Software.

    1.11. "Patent Claims" of a Contributor
        means any patent claim(s), including without limitation, method,
        process, and apparatus claims, in any patent Licensable by such
        Contributor that would be infringed, but for the grant of the
        License, by the making, using, selling, offering for sale, having
        made, import, or transfer of either its Contributions or its
        Contributor Version.

    1.12. "Secondary License"
        means either the GNU General Public License, Version 2.0, the GNU
        Lesser General Public License, Version 2.1, the GNU Affero General
        Public License, Version 3.0, or any later versions of those
        licenses.

    1.13. "Source Code Form"
        means the form of the work preferred for making modifications.

    1.14. "You" (or "Your")
        means an individual or a legal entity exercising rights under this
        License. For legal entities, "You" includes any entity that
        controls, is controlled by, or is under common control with You. For
        purposes of this definition, "control" means (a) the power, direct
        or indirect, to cause the direction or management of such entity,
        whether by contract or otherwise, or (b) ownership of more than
        fifty percent (50%) of the outstanding shares or beneficial
        ownership of such entity.

    2. License Grants and Conditions
    --------------------------------

    2.1. Grants

    Each Contributor hereby grants You a world-wide, royalty-free,
    non-exclusive license:

    (a) under intellectual property rights (other than patent or trademark)
        Licensable by such Contributor to use, reproduce, make available,
        modify, display, perform, distribute, and otherwise exploit its
        Contributions, either on an unmodified basis, with Modifications, or
        as part of a Larger Work; and

    (b) under Patent Claims of such Contributor to make, use, sell, offer
        for sale, have made, import, and otherwise transfer either its
        Contributions or its Contributor Version.

    2.2. Effective Date

    The licenses granted in Section 2.1 with respect to any Contribution
    become effective for each Contribution on the date the Contributor first
    distributes such Contribution.

    2.3. Limitations on Grant Scope

    The licenses granted in this Section 2 are the only rights granted under
    this License. No additional rights or licenses will be implied from the
    distribution or licensing of Covered Software under this License.
    Notwithstanding Section 2.1(b) above, no patent license is granted by a
    Contributor:

    (a) for any code that a Contributor has removed from Covered Software;
        or

    (b) for infringements caused by: (i) Your and any other third party's
        modifications of Covered Software, or (ii) the combination of its
        Contributions with other software (except as part of its Contributor
        Version); or

    (c) under Patent Claims infringed by Covered Software in the absence of
        its Contributions.

    This License does not grant any rights in the trademarks, service marks,
    or logos of any Contributor (except as may be necessary to comply with
    the notice requirements in Section 3.4).

    2.4. Subsequent Licenses

    No Contributor makes additional grants as a result of Your choice to
    distribute the Covered Software under a subsequent version of this
    License (see Section 10.2) or under the terms of a Secondary License (if
    permitted under the terms of Section 3.3).

    2.5. Representation

    Each Contributor represents that the Contributor believes its
    Contributions are its original creation(s) or it has sufficient rights
    to grant the rights to its Contributions conveyed by this License.

    2.6. Fair Use

    This License is not intended to limit any rights You have under
    applicable copyright doctrines of fair use, fair dealing, or other
    equivalents.

    2.7. Conditions

    Sections 3.1, 3.2, 3.3, and 3.4 are conditions of the licenses granted
    in Section 2.1.

    3. Responsibilities
    -------------------

    3.1. Distribution of Source Form

    All distribution of Covered Software in Source Code Form, including any
    Modifications that You create or to which You contribute, must be under
    the terms of this License. You must inform recipients that the Source
    Code Form of the Covered Software is governed by the terms of this
    License, and how they can obtain a copy of this License. You may not
    attempt to alter or restrict the recipients' rights in the Source Code
    Form.

    3.2. Distribution of Executable Form

    If You distribute Covered Software in Executable Form then:

    (a) such Covered Software must also be made available in Source Code
        Form, as described in Section 3.1, and You must inform recipients of
        the Executable Form how they can obtain a copy of such Source Code
        Form by reasonable means in a timely manner, at a charge no more
        than the cost of distribution to the recipient; and

    (b) You may distribute such Executable Form under the terms of this
        License, or sublicense it under different terms, provided that the
        license for the Executable Form does not attempt to limit or alter
        the recipients' rights in the Source Code Form under this License.

    3.3. Distribution of a Larger Work

    You may create and distribute a Larger Work under terms of Your choice,
    provided that You also comply with the requirements of this License for
    the Covered Software. If the Larger Work is a combination of Covered
    Software with a work governed by one or more Secondary Licenses, and the
    Covered Software is not Incompatible With Secondary Licenses, this
    License permits You to additionally distribute such Covered Software
    under the terms of such Secondary License(s), so that the recipient of
    the Larger Work may, at their option, further distribute the Covered
    Software under the terms of either this License or such Secondary
    License(s).

    3.4. Notices

    You may not remove or alter the substance of any license notices
    (including copyright notices, patent notices, disclaimers of warranty,
    or limitations of liability) contained within the Source Code Form of
    the Covered Software, except that You may alter any license notices to
    the extent required to remedy known factual inaccuracies.

    3.5. Application of Additional Terms

    You may choose to offer, and to charge a fee for, warranty, support,
    indemnity or liability obligations to one or more recipients of Covered
    Software. However, You may do so only on Your own behalf, and not on
    behalf of any Contributor. You must make it absolutely clear that any
    such warranty, support, indemnity, or liability obligation is offered by
    You alone, and You hereby agree to indemnify every Contributor for any
    liability incurred by such Contributor as a result of warranty, support,
    indemnity or liability terms You offer. You may include additional
    disclaimers of warranty and limitations of liability specific to any
    jurisdiction.

    4. Inability to Comply Due to Statute or Regulation
    ---------------------------------------------------

    If it is impossible for You to comply with any of the terms of this
    License with respect to some or all of the Covered Software due to
    statute, judicial order, or regulation then You must: (a) comply with
    the terms of this License to the maximum extent possible; and (b)
    describe the limitations and the code they affect. Such description must
    be placed in a text file included with all distributions of the Covered
    Software under this License. Except to the extent prohibited by statute
    or regulation, such description must be sufficiently detailed for a
    recipient of ordinary skill to be able to understand it.

    5. Termination
    --------------

    5.1. The rights granted under this License will terminate automatically
    if You fail to comply with any of its terms. However, if You become
    compliant, then the rights granted under this License from a particular
    Contributor are reinstated (a) provisionally, unless and until such
    Contributor explicitly and finally terminates Your grants, and (b) on an
    ongoing basis, if such Contributor fails to notify You of the
    non-compliance by some reasonable means prior to 60 days after You have
    come back into compliance. Moreover, Your grants from a particular
    Contributor are reinstated on an ongoing basis if such Contributor
    notifies You of the non-compliance by some reasonable means, this is the
    first time You have received notice of non-compliance with this License
    from such Contributor, and You become compliant prior to 30 days after
    Your receipt of the notice.

    5.2. If You initiate litigation against any entity by asserting a patent
    infringement claim (excluding declaratory judgment actions,
    counter-claims, and cross-claims) alleging that a Contributor Version
    directly or indirectly infringes any patent, then the rights granted to
    You by any and all Contributors for the Covered Software under Section
    2.1 of this License shall terminate.

    5.3. In the event of termination under Sections 5.1 or 5.2 above, all
    end user license agreements (excluding distributors and resellers) which
    have been validly granted by You or Your distributors under this License
    prior to termination shall survive termination.

    ************************************************************************
    *                                                                      *
    *  6. Disclaimer of Warranty                                           *
    *  -------------------------                                           *
    *                                                                      *
    *  Covered Software is provided under this License on an "as is"       *
    *  basis, without warranty of any kind, either expressed, implied, or  *
    *  statutory, including, without limitation, warranties that the       *
    *  Covered Software is free of defects, merchantable, fit for a        *
    *  particular purpose or non-infringing. The entire risk as to the     *
    *  quality and performance of the Covered Software is with You.        *
    *  Should any Covered Software prove defective in any respect, You     *
    *  (not any Contributor) assume the cost of any necessary servicing,   *
    *  repair, or correction. This disclaimer of warranty constitutes an   *
    *  essential part of this License. No use of any Covered Software is   *
    *  authorized under this License except under this disclaimer.         *
    *                                                                      *
    ************************************************************************

    ************************************************************************
    *                                                                      *
    *  7. Limitation of Liability                                          *
    *  --------------------------                                          *
    *                                                                      *
    *  Under no circumstances and under no legal theory, whether tort      *
    *  (including negligence), contract, or otherwise, shall any           *
    *  Contributor, or anyone who distributes Covered Software as          *
    *  permitted above, be liable to You for any direct, indirect,         *
    *  special, incidental, or consequential damages of any character      *
    *  including, without limitation, damages for lost profits, loss of    *
    *  goodwill, work stoppage, computer failure or malfunction, or any    *
    *  and all other commercial damages or losses, even if such party      *
    *  shall have been informed of the possibility of such damages. This   *
    *  limitation of liability shall not apply to liability for death or   *
    *  personal injury resulting from such party's negligence to the       *
    *  extent applicable law prohibits such limitation. Some               *
    *  jurisdictions do not allow the exclusion or limitation of           *
    *  incidental or consequential damages, so this exclusion and          *
    *  limitation may not apply to You.                                    *
    *                                                                      *
    ************************************************************************

    8. Litigation
    -------------

    Any litigation relating to this License may be brought only in the
    courts of a jurisdiction where the defendant maintains its principal
    place of business and such litigation shall be governed by laws of that
    jurisdiction, without reference to its conflict-of-law provisions.
    Nothing in this Section shall prevent a party's ability to bring
    cross-claims or counter-claims.

    9. Miscellaneous
    ----------------

    This License represents the complete agreement concerning the subject
    matter hereof. If any provision of this License is held to be
    unenforceable, such provision shall be reformed only to the extent
    necessary to make it enforceable. Any law or regulation which provides
    that the language of a contract shall be construed against the drafter
    shall not be used to construe this License against a Contributor.

    10. Versions of the License
    ---------------------------

    10.1. New Versions

    Mozilla Foundation is the license steward. Except as provided in Section
    10.3, no one other than the license steward has the right to modify or
    publish new versions of this License. Each version will be given a
    distinguishing version number.

    10.2. Effect of New Versions

    You may distribute the Covered Software under the terms of the version
    of the License under which You originally received the Covered Software,
    or under the terms of any subsequent version published by the license
    steward.

    10.3. Modified Versions

    If you create software not governed by this License, and you want to
    create a new license for such software, you may create and use a
    modified version of this License if you rename the license and remove
    any references to the name of the license steward (except to note that
    such modified license differs from this License).

    10.4. Distributing Source Code Form that is Incompatible With Secondary
    Licenses

    If You choose to distribute Source Code Form that is Incompatible With
    Secondary Licenses under the terms of this version of the License, the
    notice described in Exhibit B of this License must be attached.

    Exhibit A - Source Code Form License Notice
    -------------------------------------------

      This Source Code Form is subject to the terms of the Mozilla Public
      License, v. 2.0. If a copy of the MPL was not distributed with this
      file, You can obtain one at https://mozilla.org/MPL/2.0/.

    If it is not possible or desirable to put the notice in a particular
    file, then You may include the notice in a location (such as a LICENSE
    file in a relevant directory) where a recipient would be likely to look
    for such a notice.

    You may add additional accurate notices of copyright ownership.

    Exhibit B - "Incompatible With Secondary Licenses" Notice
    ---------------------------------------------------------

      This Source Code Form is "Incompatible With Secondary Licenses", as
      defined by the Mozilla Public License, v. 2.0.

### Python Software Foundation License

Covers: Python, and typing_extensions (whose copy gives its copyright as "Copyright (c) 2001-2023 Python Software Foundation; All Rights Reserved"). This is Python's own LICENSE file, as shipped with Python 3.14.7.

    A. HISTORY OF THE SOFTWARE
    ==========================

    Python was created in the early 1990s by Guido van Rossum at Stichting
    Mathematisch Centrum (CWI, see https://www.cwi.nl) in the Netherlands
    as a successor of a language called ABC.  Guido remains Python's
    principal author, although it includes many contributions from others.

    In 1995, Guido continued his work on Python at the Corporation for
    National Research Initiatives (CNRI, see https://www.cnri.reston.va.us)
    in Reston, Virginia where he released several versions of the
    software.

    In May 2000, Guido and the Python core development team moved to
    BeOpen.com to form the BeOpen PythonLabs team.  In October of the same
    year, the PythonLabs team moved to Digital Creations, which became
    Zope Corporation.  In 2001, the Python Software Foundation (PSF, see
    https://www.python.org/psf/) was formed, a non-profit organization
    created specifically to own Python-related Intellectual Property.
    Zope Corporation was a sponsoring member of the PSF.

    All Python releases are Open Source (see https://opensource.org for
    the Open Source Definition).  Historically, most, but not all, Python
    releases have also been GPL-compatible; the table below summarizes
    the various releases.

        Release         Derived     Year        Owner       GPL-
                        from                                compatible? (1)

        0.9.0 thru 1.2              1991-1995   CWI         yes
        1.3 thru 1.5.2  1.2         1995-1999   CNRI        yes
        1.6             1.5.2       2000        CNRI        no
        2.0             1.6         2000        BeOpen.com  no
        1.6.1           1.6         2001        CNRI        yes (2)
        2.1             2.0+1.6.1   2001        PSF         no
        2.0.1           2.0+1.6.1   2001        PSF         yes
        2.1.1           2.1+2.0.1   2001        PSF         yes
        2.1.2           2.1.1       2002        PSF         yes
        2.1.3           2.1.2       2002        PSF         yes
        2.2 and above   2.1.1       2001-now    PSF         yes

    Footnotes:

    (1) GPL-compatible doesn't mean that we're distributing Python under
        the GPL.  All Python licenses, unlike the GPL, let you distribute
        a modified version without making your changes open source.  The
        GPL-compatible licenses make it possible to combine Python with
        other software that is released under the GPL; the others don't.

    (2) According to Richard Stallman, 1.6.1 is not GPL-compatible,
        because its license has a choice of law clause.  According to
        CNRI, however, Stallman's lawyer has told CNRI's lawyer that 1.6.1
        is "not incompatible" with the GPL.

    Thanks to the many outside volunteers who have worked under Guido's
    direction to make these releases possible.


    B. TERMS AND CONDITIONS FOR ACCESSING OR OTHERWISE USING PYTHON
    ===============================================================

    Python software and documentation are licensed under the
    Python Software Foundation License Version 2.

    Starting with Python 3.8.6, examples, recipes, and other code in
    the documentation are dual licensed under the PSF License Version 2
    and the Zero-Clause BSD license.

    Some software incorporated into Python is under different licenses.
    The licenses are listed with code falling under that license.


    PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
    --------------------------------------------

    1. This LICENSE AGREEMENT is between the Python Software Foundation
    ("PSF"), and the Individual or Organization ("Licensee") accessing and
    otherwise using this software ("Python") in source or binary form and
    its associated documentation.

    2. Subject to the terms and conditions of this License Agreement, PSF hereby
    grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
    analyze, test, perform and/or display publicly, prepare derivative works,
    distribute, and otherwise use Python alone or in any derivative version,
    provided, however, that PSF's License Agreement and PSF's notice of copyright,
    i.e., "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
    are retained in Python alone or in any derivative version prepared by Licensee.

    3. In the event Licensee prepares a derivative work that is based on
    or incorporates Python or any part thereof, and wants to make
    the derivative work available to others as provided herein, then
    Licensee hereby agrees to include in any such work a brief summary of
    the changes made to Python.

    4. PSF is making Python available to Licensee on an "AS IS"
    basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
    IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
    DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
    FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
    INFRINGE ANY THIRD PARTY RIGHTS.

    5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
    FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
    A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
    OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

    6. This License Agreement will automatically terminate upon a material
    breach of its terms and conditions.

    7. Nothing in this License Agreement shall be deemed to create any
    relationship of agency, partnership, or joint venture between PSF and
    Licensee.  This License Agreement does not grant permission to use PSF
    trademarks or trade name in a trademark sense to endorse or promote
    products or services of Licensee, or any third party.

    8. By copying, installing or otherwise using Python, Licensee
    agrees to be bound by the terms and conditions of this License
    Agreement.


    BEOPEN.COM LICENSE AGREEMENT FOR PYTHON 2.0
    -------------------------------------------

    BEOPEN PYTHON OPEN SOURCE LICENSE AGREEMENT VERSION 1

    1. This LICENSE AGREEMENT is between BeOpen.com ("BeOpen"), having an
    office at 160 Saratoga Avenue, Santa Clara, CA 95051, and the
    Individual or Organization ("Licensee") accessing and otherwise using
    this software in source or binary form and its associated
    documentation ("the Software").

    2. Subject to the terms and conditions of this BeOpen Python License
    Agreement, BeOpen hereby grants Licensee a non-exclusive,
    royalty-free, world-wide license to reproduce, analyze, test, perform
    and/or display publicly, prepare derivative works, distribute, and
    otherwise use the Software alone or in any derivative version,
    provided, however, that the BeOpen Python License is retained in the
    Software, alone or in any derivative version prepared by Licensee.

    3. BeOpen is making the Software available to Licensee on an "AS IS"
    basis.  BEOPEN MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
    IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, BEOPEN MAKES NO AND
    DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
    FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE WILL NOT
    INFRINGE ANY THIRD PARTY RIGHTS.

    4. BEOPEN SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF THE
    SOFTWARE FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS
    AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THE SOFTWARE, OR ANY
    DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

    5. This License Agreement will automatically terminate upon a material
    breach of its terms and conditions.

    6. This License Agreement shall be governed by and interpreted in all
    respects by the law of the State of California, excluding conflict of
    law provisions.  Nothing in this License Agreement shall be deemed to
    create any relationship of agency, partnership, or joint venture
    between BeOpen and Licensee.  This License Agreement does not grant
    permission to use BeOpen trademarks or trade names in a trademark
    sense to endorse or promote products or services of Licensee, or any
    third party.  As an exception, the "BeOpen Python" logos available at
    http://www.pythonlabs.com/logos.html may be used according to the
    permissions granted on that web page.

    7. By copying, installing or otherwise using the software, Licensee
    agrees to be bound by the terms and conditions of this License
    Agreement.


    CNRI LICENSE AGREEMENT FOR PYTHON 1.6.1
    ---------------------------------------

    1. This LICENSE AGREEMENT is between the Corporation for National
    Research Initiatives, having an office at 1895 Preston White Drive,
    Reston, VA 20191 ("CNRI"), and the Individual or Organization
    ("Licensee") accessing and otherwise using Python 1.6.1 software in
    source or binary form and its associated documentation.

    2. Subject to the terms and conditions of this License Agreement, CNRI
    hereby grants Licensee a nonexclusive, royalty-free, world-wide
    license to reproduce, analyze, test, perform and/or display publicly,
    prepare derivative works, distribute, and otherwise use Python 1.6.1
    alone or in any derivative version, provided, however, that CNRI's
    License Agreement and CNRI's notice of copyright, i.e., "Copyright (c)
    1995-2001 Corporation for National Research Initiatives; All Rights
    Reserved" are retained in Python 1.6.1 alone or in any derivative
    version prepared by Licensee.  Alternately, in lieu of CNRI's License
    Agreement, Licensee may substitute the following text (omitting the
    quotes): "Python 1.6.1 is made available subject to the terms and
    conditions in CNRI's License Agreement.  This Agreement together with
    Python 1.6.1 may be located on the internet using the following
    unique, persistent identifier (known as a handle): 1895.22/1013.  This
    Agreement may also be obtained from a proxy server on the internet
    using the following URL: http://hdl.handle.net/1895.22/1013".

    3. In the event Licensee prepares a derivative work that is based on
    or incorporates Python 1.6.1 or any part thereof, and wants to make
    the derivative work available to others as provided herein, then
    Licensee hereby agrees to include in any such work a brief summary of
    the changes made to Python 1.6.1.

    4. CNRI is making Python 1.6.1 available to Licensee on an "AS IS"
    basis.  CNRI MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
    IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, CNRI MAKES NO AND
    DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
    FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON 1.6.1 WILL NOT
    INFRINGE ANY THIRD PARTY RIGHTS.

    5. CNRI SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
    1.6.1 FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
    A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 1.6.1,
    OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

    6. This License Agreement will automatically terminate upon a material
    breach of its terms and conditions.

    7. This License Agreement shall be governed by the federal
    intellectual property law of the United States, including without
    limitation the federal copyright law, and, to the extent such
    U.S. federal law does not apply, by the law of the Commonwealth of
    Virginia, excluding Virginia's conflict of law provisions.
    Notwithstanding the foregoing, with regard to derivative works based
    on Python 1.6.1 that incorporate non-separable material that was
    previously distributed under the GNU General Public License (GPL), the
    law of the Commonwealth of Virginia shall govern this License
    Agreement only as to issues arising under or with respect to
    Paragraphs 4, 5, and 7 of this License Agreement.  Nothing in this
    License Agreement shall be deemed to create any relationship of
    agency, partnership, or joint venture between CNRI and Licensee.  This
    License Agreement does not grant permission to use CNRI trademarks or
    trade name in a trademark sense to endorse or promote products or
    services of Licensee, or any third party.

    8. By clicking on the "ACCEPT" button where indicated, or by copying,
    installing or otherwise using Python 1.6.1, Licensee agrees to be
    bound by the terms and conditions of this License Agreement.

            ACCEPT


    CWI LICENSE AGREEMENT FOR PYTHON 0.9.0 THROUGH 1.2
    --------------------------------------------------

    Copyright (c) 1991 - 1995, Stichting Mathematisch Centrum Amsterdam,
    The Netherlands.  All rights reserved.

    Permission to use, copy, modify, and distribute this software and its
    documentation for any purpose and without fee is hereby granted,
    provided that the above copyright notice appear in all copies and that
    both that copyright notice and this permission notice appear in
    supporting documentation, and that the name of Stichting Mathematisch
    Centrum or CWI not be used in advertising or publicity pertaining to
    distribution of the software without specific, written prior
    permission.

    STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
    THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
    FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
    FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
    OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

    ZERO-CLAUSE BSD LICENSE FOR CODE IN THE PYTHON DOCUMENTATION
    ----------------------------------------------------------------------

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.

### Software incorporated into Python

Covers: the code that Python includes from others, including expat, libffi, zlib, libmpdec (mpdecimal), mimalloc and the Unicode Character Database. This is the "Licenses and Acknowledgements for Incorporated Software" section of Python 3.14.7's documentation; Python 3.13 has the same list except for the Zstandard bindings.

    Licenses and Acknowledgements for Incorporated Software

    This section is an incomplete, but growing list of licenses and acknowledgements
    for third-party software incorporated in the Python distribution.

    Mersenne Twister

    The _random C extension underlying the random module
    includes code based on a download from
    http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html. The following are
    the verbatim comments from the original code:

       A C-program for MT19937, with initialization improved 2002/1/26.
       Coded by Takuji Nishimura and Makoto Matsumoto.

       Before using, initialize the state by using init_genrand(seed)
       or init_by_array(init_key, key_length).

       Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
       All rights reserved.

       Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:

        1. Redistributions of source code must retain the above copyright
           notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. The names of its contributors may not be used to endorse or promote
           products derived from this software without specific prior written
           permission.

       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
       A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
       CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
       EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
       PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
       PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
       LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
       NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

       Any feedback is very welcome.
       http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
       email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)

    Sockets

    The socket module uses the functions, getaddrinfo, and
    getnameinfo, which are coded in separate source files from the WIDE
    Project, https://www.wide.ad.jp/.:

       Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
       All rights reserved.

       Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:
       1. Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.
       2. Redistributions in binary form must reproduce the above copyright
          notice, this list of conditions and the following disclaimer in the
          documentation and/or other materials provided with the distribution.
       3. Neither the name of the project nor the names of its contributors
          may be used to endorse or promote products derived from this software
          without specific prior written permission.

       THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS "AS IS" AND
       ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
       ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
       FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
       OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
       HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
       LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
       OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
       SUCH DAMAGE.

    Asynchronous socket services

    The test.support.asynchat and test.support.asyncore
    modules contain the following notice:

       Copyright 1996 by Sam Rushing

                               All Rights Reserved

       Permission to use, copy, modify, and distribute this software and
       its documentation for any purpose and without fee is hereby
       granted, provided that the above copyright notice appear in all
       copies and that both that copyright notice and this permission
       notice appear in supporting documentation, and that the name of Sam
       Rushing not be used in advertising or publicity pertaining to
       distribution of the software without specific, written prior
       permission.

       SAM RUSHING DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
       INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN
       NO EVENT SHALL SAM RUSHING BE LIABLE FOR ANY SPECIAL, INDIRECT OR
       CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
       OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
       NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
       CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

    Cookie management

    The http.cookies module contains the following notice:

       Copyright 2000 by Timothy O'Malley <timo@alum.mit.edu>

                      All Rights Reserved

       Permission to use, copy, modify, and distribute this software
       and its documentation for any purpose and without fee is hereby
       granted, provided that the above copyright notice appear in all
       copies and that both that copyright notice and this permission
       notice appear in supporting documentation, and that the name of
       Timothy O'Malley  not be used in advertising or publicity
       pertaining to distribution of the software without specific, written
       prior permission.

       Timothy O'Malley DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
       SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
       AND FITNESS, IN NO EVENT SHALL Timothy O'Malley BE LIABLE FOR
       ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
       WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
       WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
       ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
       PERFORMANCE OF THIS SOFTWARE.

    Execution tracing

    The trace module contains the following notice:

       portions copyright 2001, Autonomous Zones Industries, Inc., all rights...
       err...  reserved and offered to the public under the terms of the
       Python 2.2 license.
       Author: Zooko O'Whielacronx
       http://zooko.com/
       mailto:zooko@zooko.com

       Copyright 2000, Mojam Media, Inc., all rights reserved.
       Author: Skip Montanaro

       Copyright 1999, Bioreason, Inc., all rights reserved.
       Author: Andrew Dalke

       Copyright 1995-1997, Automatrix, Inc., all rights reserved.
       Author: Skip Montanaro

       Copyright 1991-1995, Stichting Mathematisch Centrum, all rights reserved.

       Permission to use, copy, modify, and distribute this Python software and
       its associated documentation for any purpose without fee is hereby
       granted, provided that the above copyright notice appears in all copies,
       and that both that copyright notice and this permission notice appear in
       supporting documentation, and that the name of neither Automatrix,
       Bioreason or Mojam Media be used in advertising or publicity pertaining to
       distribution of the software without specific, written prior permission.

    UUencode and UUdecode functions

    The uu codec contains the following notice:

       Copyright 1994 by Lance Ellinghouse
       Cathedral City, California Republic, United States of America.
                              All Rights Reserved
       Permission to use, copy, modify, and distribute this software and its
       documentation for any purpose and without fee is hereby granted,
       provided that the above copyright notice appear in all copies and that
       both that copyright notice and this permission notice appear in
       supporting documentation, and that the name of Lance Ellinghouse
       not be used in advertising or publicity pertaining to distribution
       of the software without specific, written prior permission.
       LANCE ELLINGHOUSE DISCLAIMS ALL WARRANTIES WITH REGARD TO
       THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
       FITNESS, IN NO EVENT SHALL LANCE ELLINGHOUSE CENTRUM BE LIABLE
       FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
       WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
       ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
       OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

       Modified by Jack Jansen, CWI, July 1995:
       - Use binascii module to do the actual line-by-line conversion
         between ascii and binary. This results in a 1000-fold speedup. The C
         version is still 5 times faster, though.
       - Arguments more compliant with Python standard

    XML Remote Procedure Calls

    The xmlrpc.client module contains the following notice:

           The XML-RPC client interface is

       Copyright (c) 1999-2002 by Secret Labs AB
       Copyright (c) 1999-2002 by Fredrik Lundh

       By obtaining, using, and/or copying this software and/or its
       associated documentation, you agree that you have read, understood,
       and will comply with the following terms and conditions:

       Permission to use, copy, modify, and distribute this software and
       its associated documentation for any purpose and without fee is
       hereby granted, provided that the above copyright notice appears in
       all copies, and that both that copyright notice and this permission
       notice appear in supporting documentation, and that the name of
       Secret Labs AB or the author not be used in advertising or publicity
       pertaining to distribution of the software without specific, written
       prior permission.

       SECRET LABS AB AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD
       TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANT-
       ABILITY AND FITNESS.  IN NO EVENT SHALL SECRET LABS AB OR THE AUTHOR
       BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
       DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
       WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
       ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
       OF THIS SOFTWARE.

    test_epoll

    The test.test_epoll module contains the following notice:

      Copyright (c) 2001-2006 Twisted Matrix Laboratories.

      Permission is hereby granted, free of charge, to any person obtaining
      a copy of this software and associated documentation files (the
      "Software"), to deal in the Software without restriction, including
      without limitation the rights to use, copy, modify, merge, publish,
      distribute, sublicense, and/or sell copies of the Software, and to
      permit persons to whom the Software is furnished to do so, subject to
      the following conditions:

      The above copyright notice and this permission notice shall be
      included in all copies or substantial portions of the Software.

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
      EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
      NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
      LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
      OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
      WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Select kqueue

    The select module contains the following notice for the kqueue
    interface:

      Copyright (c) 2000 Doug White, 2006 James Knight, 2007 Christian Heimes
      All rights reserved.

      Redistribution and use in source and binary forms, with or without
      modification, are permitted provided that the following conditions
      are met:
      1. Redistributions of source code must retain the above copyright
         notice, this list of conditions and the following disclaimer.
      2. Redistributions in binary form must reproduce the above copyright
         notice, this list of conditions and the following disclaimer in the
         documentation and/or other materials provided with the distribution.

      THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
      ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
      IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
      ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
      FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
      DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
      OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
      HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
      LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
      OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
      SUCH DAMAGE.

    SipHash24

    The file Python/pyhash.c contains Marek Majkowski' implementation of
    Dan Bernstein's SipHash24 algorithm. It contains the following note:

      <MIT License>
      Copyright (c) 2013  Marek Majkowski <marek@popcount.org>

      Permission is hereby granted, free of charge, to any person obtaining a copy
      of this software and associated documentation files (the "Software"), to deal
      in the Software without restriction, including without limitation the rights
      to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
      copies of the Software, and to permit persons to whom the Software is
      furnished to do so, subject to the following conditions:

      The above copyright notice and this permission notice shall be included in
      all copies or substantial portions of the Software.
      </MIT License>

      Original location:
         https://github.com/majek/csiphash/

      Solution inspired by code from:
         Samuel Neves (supercop/crypto_auth/siphash24/little)
         djb (supercop/crypto_auth/siphash24/little2)
         Jean-Philippe Aumasson (https://131002.net/siphash/siphash24.c)

    strtod and dtoa

    The file Python/dtoa.c, which supplies C functions dtoa and
    strtod for conversion of C doubles to and from strings, is derived
    from the file of the same name by David M. Gay, currently available
    from https://web.archive.org/web/20220517033456/http://www.netlib.org/fp/dtoa.c.
    The original file, as retrieved on March 16, 2009, contains the following
    copyright and licensing notice:

       /****************************************************************
        *
        * The author of this software is David M. Gay.
        *
        * Copyright (c) 1991, 2000, 2001 by Lucent Technologies.
        *
        * Permission to use, copy, modify, and distribute this software for any
        * purpose without fee is hereby granted, provided that this entire notice
        * is included in all copies of any software which is or includes a copy
        * or modification of this software and in all copies of the supporting
        * documentation for such software.
        *
        * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
        * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR LUCENT MAKES ANY
        * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
        * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
        *
        ***************************************************************/

    OpenSSL

    The modules hashlib, posix and ssl use
    the OpenSSL library for added performance if made available by the
    operating system. Additionally, the Windows and macOS installers for
    Python may include a copy of the OpenSSL libraries, so we include a copy
    of the OpenSSL license here. For the OpenSSL 3.0 release,
    and later releases derived from that, the Apache License v2 applies. Its text is under "Apache License 2.0" in this file.

    expat

    The pyexpat extension is built using an included copy of the expat
    sources unless the build is configured --with-system-expat:

      Copyright (c) 1998, 1999, 2000 Thai Open Source Software Center Ltd
                                     and Clark Cooper

      Permission is hereby granted, free of charge, to any person obtaining
      a copy of this software and associated documentation files (the
      "Software"), to deal in the Software without restriction, including
      without limitation the rights to use, copy, modify, merge, publish,
      distribute, sublicense, and/or sell copies of the Software, and to
      permit persons to whom the Software is furnished to do so, subject to
      the following conditions:

      The above copyright notice and this permission notice shall be included
      in all copies or substantial portions of the Software.

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
      EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
      IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
      CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
      TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
      SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    libffi

    The _ctypes C extension underlying the ctypes module
    is built using an included copy of the libffi
    sources unless the build is configured --with-system-libffi:

       Copyright (c) 1996-2008  Red Hat, Inc and others.

       Permission is hereby granted, free of charge, to any person obtaining
       a copy of this software and associated documentation files (the
       "Software"), to deal in the Software without restriction, including
       without limitation the rights to use, copy, modify, merge, publish,
       distribute, sublicense, and/or sell copies of the Software, and to
       permit persons to whom the Software is furnished to do so, subject to
       the following conditions:

       The above copyright notice and this permission notice shall be included
       in all copies or substantial portions of the Software.

       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
       EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
       MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
       NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
       HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
       WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
       OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
       DEALINGS IN THE SOFTWARE.

    zlib

    The zlib extension is built using an included copy of the zlib
    sources if the zlib version found on the system is too old to be
    used for the build:

      Copyright (C) 1995-2011 Jean-loup Gailly and Mark Adler

      This software is provided 'as-is', without any express or implied
      warranty.  In no event will the authors be held liable for any damages
      arising from the use of this software.

      Permission is granted to anyone to use this software for any purpose,
      including commercial applications, and to alter it and redistribute it
      freely, subject to the following restrictions:

      1. The origin of this software must not be misrepresented; you must not
         claim that you wrote the original software. If you use this software
         in a product, an acknowledgment in the product documentation would be
         appreciated but is not required.

      2. Altered source versions must be plainly marked as such, and must not be
         misrepresented as being the original software.

      3. This notice may not be removed or altered from any source distribution.

      Jean-loup Gailly        Mark Adler
      jloup@gzip.org          madler@alumni.caltech.edu

    cfuhash

    The implementation of the hash table used by the tracemalloc is based
    on the cfuhash project:

       Copyright (c) 2005 Don Owens
       All rights reserved.

       This code is released under the BSD license:

       Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:

         * Redistributions of source code must retain the above copyright
           notice, this list of conditions and the following disclaimer.

         * Redistributions in binary form must reproduce the above
           copyright notice, this list of conditions and the following
           disclaimer in the documentation and/or other materials provided
           with the distribution.

         * Neither the name of the author nor the names of its
           contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
       FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
       COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
       INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
       HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
       STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
       ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
       OF THE POSSIBILITY OF SUCH DAMAGE.

    libmpdec

    The _decimal C extension underlying the decimal module
    is built using an included copy of the libmpdec
    library unless the build is configured --with-system-libmpdec:

       Copyright (c) 2008-2020 Stefan Krah. All rights reserved.

       Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:

       1. Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.

       2. Redistributions in binary form must reproduce the above copyright
          notice, this list of conditions and the following disclaimer in the
          documentation and/or other materials provided with the distribution.

       THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
       ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
       ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
       FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
       OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
       HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
       LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
       OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
       SUCH DAMAGE.

    W3C C14N test suite

    The C14N 2.0 test suite in the test package
    (Lib/test/xmltestdata/c14n-20/) was retrieved from the W3C website at
    https://www.w3.org/TR/xml-c14n2-testcases/ and is distributed under the
    3-clause BSD license:

       Copyright (c) 2013 W3C(R) (MIT, ERCIM, Keio, Beihang),
       All Rights Reserved.

       Redistribution and use in source and binary forms, with or without
       modification, are permitted provided that the following conditions
       are met:

       * Redistributions of works must retain the original copyright notice,
         this list of conditions and the following disclaimer.
       * Redistributions in binary form must reproduce the original copyright
         notice, this list of conditions and the following disclaimer in the
         documentation and/or other materials provided with the distribution.
       * Neither the name of the W3C nor the names of its contributors may be
         used to endorse or promote products derived from this work without
         specific prior written permission.

       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    mimalloc

    MIT License:

       Copyright (c) 2018-2021 Microsoft Corporation, Daan Leijen

       Permission is hereby granted, free of charge, to any person obtaining a copy
       of this software and associated documentation files (the "Software"), to deal
       in the Software without restriction, including without limitation the rights
       to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
       copies of the Software, and to permit persons to whom the Software is
       furnished to do so, subject to the following conditions:

       The above copyright notice and this permission notice shall be included in all
       copies or substantial portions of the Software.

       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
       IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
       FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
       AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
       LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
       OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
       SOFTWARE.

    asyncio

    Parts of the asyncio module are incorporated from
    uvloop 0.16 (https://github.com/MagicStack/uvloop/tree/v0.16.0),
    which is distributed under the MIT license:

      Copyright (c) 2015-2021 MagicStack Inc.  http://magic.io

      Permission is hereby granted, free of charge, to any person obtaining
      a copy of this software and associated documentation files (the
      "Software"), to deal in the Software without restriction, including
      without limitation the rights to use, copy, modify, merge, publish,
      distribute, sublicense, and/or sell copies of the Software, and to
      permit persons to whom the Software is furnished to do so, subject to
      the following conditions:

      The above copyright notice and this permission notice shall be
      included in all copies or substantial portions of the Software.

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
      EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
      NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
      LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
      OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
      WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Global Unbounded Sequences (GUS)

    The file Python/qsbr.c is adapted from FreeBSD's "Global Unbounded
    Sequences" safe memory reclamation scheme in
    subr_smr.c (https://github.com/freebsd/freebsd-src/blob/main/sys/kern/subr_smr.c).
    The file is distributed under the 2-Clause BSD License:

      Copyright (c) 2019,2020 Jeffrey Roberson <jeff@FreeBSD.org>

      Redistribution and use in source and binary forms, with or without
      modification, are permitted provided that the following conditions
      are met:
      1. Redistributions of source code must retain the above copyright
         notice unmodified, this list of conditions, and the following
         disclaimer.
      2. Redistributions in binary form must reproduce the above copyright
         notice, this list of conditions and the following disclaimer in the
         documentation and/or other materials provided with the distribution.

      THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
      IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
      OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
      IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
      INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
      NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
      THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Zstandard bindings

    Zstandard bindings in Modules/_zstd and Lib/compression/zstd
    are based on code from the
    pyzstd library (https://github.com/Rogdham/pyzstd/), copyright Ma Lin and
    contributors. The pyzstd code is distributed under the 3-Clause BSD License:

      Copyright (c) 2020-present, Ma Lin and contributors.
      All rights reserved.

      Redistribution and use in source and binary forms, with or without
      modification, are permitted provided that the following conditions are met:

      1. Redistributions of source code must retain the above copyright notice, this
         list of conditions and the following disclaimer.

      2. Redistributions in binary form must reproduce the above copyright notice,
         this list of conditions and the following disclaimer in the documentation
         and/or other materials provided with the distribution.

      3. Neither the name of the copyright holder nor the names of its
         contributors may be used to endorse or promote products derived from
         this software without specific prior written permission.

      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
      AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
      IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
      DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
      FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
      DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
      SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
      CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
      OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Unicode Character Database

    An extract of the Unicode Character Database (https://www.unicode.org/ucd/),
    converted to an internal format, is used by the unicodedata module and
    for the Unicode support of the str type. The original Unicode data
    files are distributed under the Unicode License (https://www.unicode.org/license.txt):

      UNICODE LICENSE V3

      COPYRIGHT AND PERMISSION NOTICE

      Copyright © 1991-2026 Unicode, Inc.

      NOTICE TO USER: Carefully read the following legal agreement. BY
      DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
      SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
      TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
      DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

      Permission is hereby granted, free of charge, to any person obtaining a
      copy of data files and any associated documentation (the "Data Files") or
      software and any associated documentation (the "Software") to deal in the
      Data Files or Software without restriction, including without limitation
      the rights to use, copy, modify, merge, publish, distribute, and/or sell
      copies of the Data Files or Software, and to permit persons to whom the
      Data Files or Software are furnished to do so, provided that either (a)
      this copyright and permission notice appear with all copies of the Data
      Files or Software, or (b) this copyright and permission notice appear in
      associated Documentation.

      THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
      KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
      THIRD PARTY RIGHTS.

      IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
      BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
      OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
      WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
      ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
      FILES OR SOFTWARE.

      Except as contained in this notice, the name of a copyright holder shall
      not be used in advertising or otherwise to promote the sale, use or other
      dealings in these Data Files or Software without prior written
      authorization of the copyright holder.

### Microsoft Distributable Code

Covers: the Microsoft Visual C++ runtime in the Windows app. These are the additional conditions in the LICENSE.txt of python.org's Windows build of Python 3.13.17.

    Additional Conditions for this Windows binary build
    ---------------------------------------------------

    This program is linked with and uses Microsoft Distributable Code,
    copyrighted by Microsoft Corporation. The Microsoft Distributable Code
    is embedded in each .exe, .dll and .pyd file as a result of running
    the code through a linker.

    If you further distribute programs that include the Microsoft
    Distributable Code, you must comply with the restrictions on
    distribution specified by Microsoft. In particular, you must require
    distributors and external end users to agree to terms that protect the
    Microsoft Distributable Code at least as much as Microsoft's own
    requirements for the Distributable Code. See Microsoft's documentation
    (included in its developer tools and on its website at microsoft.com)
    for specific details.

    Redistribution of the Windows binary build of the Python interpreter
    complies with this agreement, provided that you do not:

    - alter any copyright, trademark or patent notice in Microsoft's
    Distributable Code;

    - use Microsoft's trademarks in your programs' names or in a way that
    suggests your programs come from or are endorsed by Microsoft;

    - distribute Microsoft's Distributable Code to run on a platform other
    than Microsoft operating systems, run-time technologies or application
    platforms; or

    - include Microsoft Distributable Code in malicious, deceptive or
    unlawful programs.

    These restrictions apply only to the Microsoft Distributable Code as
    defined above, not to Python itself or any programs running on the
    Python interpreter. The redistribution of the Python interpreter and
    libraries is governed by the Python Software License included with this
    file, or by other licenses as marked.

### bzip2

Covers: bzip2. The text is as given with python.org's Windows build of Python.

    This program, "bzip2", the associated library "libbzip2", and all
    documentation, are copyright (C) 1996-2019 Julian R Seward.  All
    rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. The origin of this software must not be misrepresented; you must
       not claim that you wrote the original software.  If you use this
       software in a product, an acknowledgment in the product
       documentation would be appreciated but is not required.

    3. Altered source versions must be plainly marked as such, and must
       not be misrepresented as being the original software.

    4. The name of the author may not be used to endorse or promote
       products derived from this software without specific prior written
       permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
    OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
    GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Julian Seward, jseward@acm.org
    bzip2/libbzip2 version 1.0.8 of 13 July 2019

### Toga

Covers: Toga (toga-core and its backends) and dotnet-webview2-winforms, whose license has the same text.

    Copyright (c) 2014 Russell Keith-Magee.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of Toga nor the names of its contributors may
           be used to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Travertino

Covers: Travertino.

    Copyright (c) 2017 Russell Keith-Magee.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of Travertino nor the names of its contributors may
           be used to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Rubicon-ObjC

Covers: Rubicon-ObjC, including the code it derives from objective-ctypes.

    Copyright (c) 2014 Russell Keith-Magee.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of Rubicon nor the names of its contributors may
           be used to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    ----------------------------------------------------------------------------
    This project uses code derived from Pyglet, which, in turn, derived its code
    from objective-ctypes. The license for objective-ctypes is as follows:

    Copyright (c) 2011, Phillip Nguyen
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of objective-ctypes nor the names of its contributors may
           be used to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### std-nslog

Covers: std-nslog.

    Copyright (c) 2022 Russell Keith-Magee.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of std-nslog nor the names of its contributors may
           be used to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### pycparser

Covers: pycparser.

    pycparser -- A C parser in Python

    Copyright (c) 2008-2027, Eli Bendersky
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this
      list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of its contributors may
      be used to endorse or promote products derived from this software without
      specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
    GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
    OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### rust-asn1

Covers: asn1 0.24.1, in cryptography 47.0.0.

    Copyright (c) Alex Gaynor and individual contributors.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice,
           this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of rust-asn1 nor the names of its contributors may be used
           to endorse or promote products derived from this software without
           specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Microsoft Edge WebView2 SDK

Covers: the WebView2 SDK files in the Windows app.

    Copyright (C) Microsoft Corporation. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

       * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
       * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the
    distribution.
       * The name of Microsoft Corporation, or the names of its contributors
    may not be used to endorse or promote products derived from this
    software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Zstandard

Covers: Zstandard (libzstd) 1.5.7, and 1.5.6 in the Linux AppImage's runtime, whose license has the same text.

    BSD License

    For Zstandard software

    Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

     * Neither the name Facebook, nor Meta, nor the names of its contributors may
       be used to endorse or promote products derived from this software without
       specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### libedit

Covers: libedit, in the Linux AppImage's Python. The text is as python-build-standalone publishes it with its build.

    Copyright (c) 1992, 1993
     The Regents of the University of California.  All rights reserved.

    This code is derived from software contributed to Berkeley by
    Christos Zoulas of Cornell University.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. Neither the name of the University nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.

### libuuid

Covers: libuuid, in the Linux AppImage's Python. The text is as python-build-standalone publishes it with its build.

    Copyright (C) 1996, 1997 Theodore Ts'o.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, and the entire permission notice in its entirety,
       including the disclaimer of warranties.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. The name of the author may not be used to endorse or promote
       products derived from this software without specific prior
       written permission.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
    WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
    WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
    OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
    DAMAGE.

### squashfuse

Covers: squashfuse 0.5.2, in the Linux AppImage's runtime.

    The squashfuse distribution as a whole is copyright Dave
    Vasilevsky and is subject to the copyright notice reproduced at
    the bottom of this file.

    The file squashfs_fs.h is copyright Phillip Lougher and, with his permission,
    subject to the same license.


    Copyright (c) 2012 Dave Vasilevsky <dave@vasilevsky.ca>
                       Phillip Lougher <phillip@squashfs.org.uk>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### MIT License

Covers, with these copyright notices:
- libffi: "libffi - Copyright (c) 1996-2026 Anthony Green, Red Hat, Inc and others." (3.8.0), "libffi - Copyright (c) 1996-2024 Anthony Green, Red Hat, Inc and others." (3.4.6 and 3.4.7), "libffi - Copyright (c) 1996-2022 Anthony Green, Red Hat, Inc and others." (Windows) and "libffi - Copyright (c) 1996-2019 Anthony Green, Red Hat, Inc and others." (Android)
- Briefcase app templates: "Copyright (c) 2014 Russell Keith-Magee." (macOS app, Linux system package) and "Copyright (c) 2019 Russell Keith-Magee." (Android Gradle, iOS Xcode)
- Python.NET: "Copyright (c) 2006-2021 the contributors of the Python.NET project"
- clr_loader: "Copyright (c) 2019-2026 Benedikt Reinartz"
- pywinpty: "Copyright (c) 2017 Spyder IDE"
- winpty: "Copyright (c) 2011-2016 Ryan Prichard"
- platformdirs: "Copyright (c) 2010-202x The platformdirs developers"
- fontTools: "Copyright (c) 2017 Just van Rossum"
- openssl-sys 0.9.114, in cryptography 47.0.0: "Copyright (c) 2014 Alex Crichton"
- pem 3.0.6, in cryptography 47.0.0: "Copyright (c) 2016 Jonathan Creekmore"
- Chaquopy: "Copyright (c) 2017-2025 Chaquo Ltd and contributors"
- cffi 1.17.1, whose copyright notices are in its source files
- HACL*: "Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation" and "Copyright (c) 2022-2023 HACL* Contributors"
- AppImage type2-runtime: "Copyright (c) 2004-23 probonopd"
- mimalloc 2.1.7: "Copyright (c) 2018-2021 Microsoft Corporation, Daan Leijen"
- xterm.js: "Copyright (c) 2017-2019, The xterm.js authors (https://github.com/xtermjs/xterm.js)", "Copyright (c) 2014-2016, SourceLair Private Company (https://www.sourcelair.com)" and "Copyright (c) 2012-2013, Christopher Jeffrey (https://github.com/chjj/)"

Each of these components' license is the following text, after its copyright notices:

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

### MIT No Attribution

Covers: cffi 2.1.1.

    Except when otherwise stated (look for LICENSE files in directories or
    information at the beginning of each file) all software and
    documentation is licensed as follows:

        MIT No Attribution

        Permission is hereby granted, free of charge, to any person
        obtaining a copy of this software and associated documentation
        files (the "Software"), to deal in the Software without
        restriction, including without limitation the rights to use,
        copy, modify, merge, publish, distribute, sublicense, and/or
        sell copies of the Software, and to permit persons to whom the
        Software is furnished to do so.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
        THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
        DEALINGS IN THE SOFTWARE.

### musl

Covers: musl 1.2.5, in the Linux AppImage's runtime. This is musl's COPYRIGHT file.

    musl as a whole is licensed under the following standard MIT license:

    ----------------------------------------------------------------------
    Copyright © 2005-2020 Rich Felker, et al.

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    ----------------------------------------------------------------------

    Authors/contributors include:

    A. Wilcox
    Ada Worcester
    Alex Dowad
    Alex Suykov
    Alexander Monakov
    Andre McCurdy
    Andrew Kelley
    Anthony G. Basile
    Aric Belsito
    Arvid Picciani
    Bartosz Brachaczek
    Benjamin Peterson
    Bobby Bingham
    Boris Brezillon
    Brent Cook
    Chris Spiegel
    Clément Vasseur
    Daniel Micay
    Daniel Sabogal
    Daurnimator
    David Carlier
    David Edelsohn
    Denys Vlasenko
    Dmitry Ivanov
    Dmitry V. Levin
    Drew DeVault
    Emil Renner Berthing
    Fangrui Song
    Felix Fietkau
    Felix Janda
    Gianluca Anzolin
    Hauke Mehrtens
    He X
    Hiltjo Posthuma
    Isaac Dunham
    Jaydeep Patil
    Jens Gustedt
    Jeremy Huntwork
    Jo-Philipp Wich
    Joakim Sindholt
    John Spencer
    Julien Ramseier
    Justin Cormack
    Kaarle Ritvanen
    Khem Raj
    Kylie McClain
    Leah Neukirchen
    Luca Barbato
    Luka Perkov
    M Farkas-Dyck (Strake)
    Mahesh Bodapati
    Markus Wichmann
    Masanori Ogino
    Michael Clark
    Michael Forney
    Mikhail Kremnyov
    Natanael Copa
    Nicholas J. Kain
    orc
    Pascal Cuoq
    Patrick Oppenlander
    Petr Hosek
    Petr Skocik
    Pierre Carrier
    Reini Urban
    Rich Felker
    Richard Pennington
    Ryan Fairfax
    Samuel Holland
    Segev Finer
    Shiz
    sin
    Solar Designer
    Stefan Kristiansson
    Stefan O'Rear
    Szabolcs Nagy
    Timo Teräs
    Trutz Behn
    Valentin Ochs
    Will Dietz
    William Haddon
    William Pitcock

    Portions of this software are derived from third-party works licensed
    under terms compatible with the above MIT license:

    The TRE regular expression implementation (src/regex/reg* and
    src/regex/tre*) is Copyright © 2001-2008 Ville Laurikari and licensed
    under a 2-clause BSD license (license text in the source files). The
    included version has been heavily modified by Rich Felker in 2012, in
    the interests of size, simplicity, and namespace cleanliness.

    Much of the math library code (src/math/* and src/complex/*) is
    Copyright © 1993,2004 Sun Microsystems or
    Copyright © 2003-2011 David Schultz or
    Copyright © 2003-2009 Steven G. Kargl or
    Copyright © 2003-2009 Bruce D. Evans or
    Copyright © 2008 Stephen L. Moshier or
    Copyright © 2017-2018 Arm Limited
    and labelled as such in comments in the individual source files. All
    have been licensed under extremely permissive terms.

    The ARM memcpy code (src/string/arm/memcpy.S) is Copyright © 2008
    The Android Open Source Project and is licensed under a two-clause BSD
    license. It was taken from Bionic libc, used on Android.

    The AArch64 memcpy and memset code (src/string/aarch64/*) are
    Copyright © 1999-2019, Arm Limited.

    The implementation of DES for crypt (src/crypt/crypt_des.c) is
    Copyright © 1994 David Burren. It is licensed under a BSD license.

    The implementation of blowfish crypt (src/crypt/crypt_blowfish.c) was
    originally written by Solar Designer and placed into the public
    domain. The code also comes with a fallback permissive license for use
    in jurisdictions that may not recognize the public domain.

    The smoothsort implementation (src/stdlib/qsort.c) is Copyright © 2011
    Valentin Ochs and is licensed under an MIT-style license.

    The x86_64 port was written by Nicholas J. Kain and is licensed under
    the standard MIT terms.

    The mips and microblaze ports were originally written by Richard
    Pennington for use in the ellcc project. The original code was adapted
    by Rich Felker for build system and code conventions during upstream
    integration. It is licensed under the standard MIT terms.

    The mips64 port was contributed by Imagination Technologies and is
    licensed under the standard MIT terms.

    The powerpc port was also originally written by Richard Pennington,
    and later supplemented and integrated by John Spencer. It is licensed
    under the standard MIT terms.

    All other files which have no copyright comments are original works
    produced specifically for use as part of this library, written either
    by Rich Felker, the main author of the library, or by one or more
    contibutors listed above. Details on authorship of individual files
    can be found in the git version control history of the project. The
    omission of copyright and license comments in each file is in the
    interest of source tree size.

    In addition, permission is hereby granted for all public header files
    (include/* and arch/*/bits/*) and crt files intended to be linked into
    applications (crt/*, ldso/dlstart.c, and arch/*/crt_arch.h) to omit
    the copyright notice and permission notice otherwise required by the
    license, and to use these files without any requirement of
    attribution. These files include substantial contributions from:

    Bobby Bingham
    John Spencer
    Nicholas J. Kain
    Rich Felker
    Richard Pennington
    Stefan Kristiansson
    Szabolcs Nagy

    all of whom have explicitly granted such permission.

    This file previously contained text expressing a belief that most of
    the files covered by the above exception were sufficiently trivial not
    to be subject to copyright, resulting in confusion over whether it
    negated the permissions granted in the license. In the spirit of
    permissive licensing, and of not having licensing issues being an
    obstacle to adoption, that text has been removed.

### ncurses

Covers: ncurses 6.5, in the macOS app's Python and the Linux AppImage's Python.

    Copyright 2018-2022,2023 Thomas E. Dickey
    Copyright 1998-2017,2018 Free Software Foundation, Inc.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, distribute with modifications, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE ABOVE COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
    THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright
    holders shall not be used in advertising or otherwise to promote the
    sale, use or other dealings in this Software without prior written
    authorization.

### XZ Utils

Covers: liblzma from XZ Utils. Versions before 5.6.0 are in the public domain. Version 5.6.0 and later are under the BSD Zero Clause License:

    Permission to use, copy, modify, and/or distribute this
    software for any purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
    THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
    CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
    NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
    CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

### SQLite

Covers: SQLite, which is in the public domain. Its source files carry this notice in place of a license:

    The author disclaims copyright to this source code.  In place of
    a legal notice, here is a blessing:

       May you do good and not evil.
       May you find forgiveness for yourself and forgive others.
       May you share freely, never taking more than you give.

### fontTools

Covers: the parts of fontTools listed in its LICENSE.external, reproduced here as it ships. fontTools itself is under the MIT License above.

    FontTools includes the following font projects for testing purposes, which are
    under SIL Open Font License, Version 1.1:

    Lobster
      Copyright (c) 2010, Pablo Impallari (www.impallari.com|impallari@gmail.com),
      with Reserved Font Name Lobster.
      This Font Software is licensed under the SIL Open Font License, Version 1.1.

    Noto Fonts
      This Font Software is licensed under the SIL Open Font License, Version 1.1.

    XITS font project
      Copyright (c) 2001-2010 by the STI Pub Companies, consisting of the American
      Institute of Physics, the American Chemical Society, the American
      Mathematical Society, the American Physical Society, Elsevier, Inc., and The
      Institute of Electrical and Electronic Engineers, Inc. (www.stixfonts.org),
      with Reserved Font Name STIX Fonts, STIX Fonts (TM) is a  trademark of The
      Institute of Electrical and Electronics Engineers, Inc.

      Portions copyright (c) 1998-2003 by MicroPress, Inc.
      (www.micropress-inc.com), with Reserved Font Name TM Math. To obtain
      additional mathematical fonts, please contact MicroPress, Inc., 68-30 Harrow
      Street, Forest Hills, NY 11375, USA, Phone: (718) 575-1816.

      Portions copyright (c) 1990 by Elsevier, Inc.

      This Font Software is licensed under the SIL Open Font License, Version 1.1.

    Iosevka
      Copyright (c) 2015-2020 Belleve Invis (belleve@typeof.net).
      This Font Software is licensed under the SIL Open Font License, Version 1.1.

    This license is copied below, and is also available with a FAQ at:
    http://scripts.sil.org/OFL

    -----------------------------------------------------------
    SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
    -----------------------------------------------------------

    PREAMBLE
    The goals of the Open Font License (OFL) are to stimulate worldwide
    development of collaborative font projects, to support the font
    creation efforts of academic and linguistic communities, and to
    provide a free and open framework in which fonts may be shared and
    improved in partnership with others.

    The OFL allows the licensed fonts to be used, studied, modified and
    redistributed freely as long as they are not sold by themselves. The
    fonts, including any derivative works, can be bundled, embedded,
    redistributed and/or sold with any software provided that any reserved
    names are not used by derivative works. The fonts and derivatives,
    however, cannot be released under any other type of license. The
    requirement for fonts to remain under this license does not apply to
    any document created using the fonts or their derivatives.

    DEFINITIONS
    "Font Software" refers to the set of files released by the Copyright
    Holder(s) under this license and clearly marked as such. This may
    include source files, build scripts and documentation.

    "Reserved Font Name" refers to any names specified as such after the
    copyright statement(s).

    "Original Version" refers to the collection of Font Software
    components as distributed by the Copyright Holder(s).

    "Modified Version" refers to any derivative made by adding to,
    deleting, or substituting -- in part or in whole -- any of the
    components of the Original Version, by changing formats or by porting
    the Font Software to a new environment.

    "Author" refers to any designer, engineer, programmer, technical
    writer or other person who contributed to the Font Software.

    PERMISSION & CONDITIONS
    Permission is hereby granted, free of charge, to any person obtaining
    a copy of the Font Software, to use, study, copy, merge, embed,
    modify, redistribute, and sell modified and unmodified copies of the
    Font Software, subject to the following conditions:

    1) Neither the Font Software nor any of its individual components, in
    Original or Modified Versions, may be sold by itself.

    2) Original or Modified Versions of the Font Software may be bundled,
    redistributed and/or sold with any software, provided that each copy
    contains the above copyright notice and this license. These can be
    included either as stand-alone text files, human-readable headers or
    in the appropriate machine-readable metadata fields within text or
    binary files as long as those fields can be easily viewed by the user.

    3) No Modified Version of the Font Software may use the Reserved Font
    Name(s) unless explicit written permission is granted by the
    corresponding Copyright Holder. This restriction only applies to the
    primary font name as presented to the users.

    4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
    Software shall not be used to promote, endorse or advertise any
    Modified Version, except to acknowledge the contribution(s) of the
    Copyright Holder(s) and the Author(s) or with their explicit written
    permission.

    5) The Font Software, modified or unmodified, in part or in whole,
    must be distributed entirely under this license, and must not be
    distributed under any other license. The requirement for fonts to
    remain under this license does not apply to any document created using
    the Font Software.

    TERMINATION
    This license becomes null and void if any of the above conditions are
    not met.

    DISCLAIMER
    THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
    OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
    COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
    DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
    OTHER DEALINGS IN THE FONT SOFTWARE.

    =====

    FontTools includes Adobe AGL & AGLFN, which is under 3-clauses BSD license:

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

    Neither the name of Adobe Systems Incorporated nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    =====

    FontTools includes cu2qu, which is Copyright 2016 Google Inc. All Rights Reserved.
    Licensed under the Apache License, Version 2.0, a copy of which is reproduced below:

                                     Apache License
                               Version 2.0, January 2004
                            http://www.apache.org/licenses/

       TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

       1. Definitions.

          "License" shall mean the terms and conditions for use, reproduction,
          and distribution as defined by Sections 1 through 9 of this document.

          "Licensor" shall mean the copyright owner or entity authorized by
          the copyright owner that is granting the License.

          "Legal Entity" shall mean the union of the acting entity and all
          other entities that control, are controlled by, or are under common
          control with that entity. For the purposes of this definition,
          "control" means (i) the power, direct or indirect, to cause the
          direction or management of such entity, whether by contract or
          otherwise, or (ii) ownership of fifty percent (50%) or more of the
          outstanding shares, or (iii) beneficial ownership of such entity.

          "You" (or "Your") shall mean an individual or Legal Entity
          exercising permissions granted by this License.

          "Source" form shall mean the preferred form for making modifications,
          including but not limited to software source code, documentation
          source, and configuration files.

          "Object" form shall mean any form resulting from mechanical
          transformation or translation of a Source form, including but
          not limited to compiled object code, generated documentation,
          and conversions to other media types.

          "Work" shall mean the work of authorship, whether in Source or
          Object form, made available under the License, as indicated by a
          copyright notice that is included in or attached to the work
          (an example is provided in the Appendix below).

          "Derivative Works" shall mean any work, whether in Source or Object
          form, that is based on (or derived from) the Work and for which the
          editorial revisions, annotations, elaborations, or other modifications
          represent, as a whole, an original work of authorship. For the purposes
          of this License, Derivative Works shall not include works that remain
          separable from, or merely link (or bind by name) to the interfaces of,
          the Work and Derivative Works thereof.

          "Contribution" shall mean any work of authorship, including
          the original version of the Work and any modifications or additions
          to that Work or Derivative Works thereof, that is intentionally
          submitted to Licensor for inclusion in the Work by the copyright owner
          or by an individual or Legal Entity authorized to submit on behalf of
          the copyright owner. For the purposes of this definition, "submitted"
          means any form of electronic, verbal, or written communication sent
          to the Licensor or its representatives, including but not limited to
          communication on electronic mailing lists, source code control systems,
          and issue tracking systems that are managed by, or on behalf of, the
          Licensor for the purpose of discussing and improving the Work, but
          excluding communication that is conspicuously marked or otherwise
          designated in writing by the copyright owner as "Not a Contribution."

          "Contributor" shall mean Licensor and any individual or Legal Entity
          on behalf of whom a Contribution has been received by Licensor and
          subsequently incorporated within the Work.

       2. Grant of Copyright License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          copyright license to reproduce, prepare Derivative Works of,
          publicly display, publicly perform, sublicense, and distribute the
          Work and such Derivative Works in Source or Object form.

       3. Grant of Patent License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          (except as stated in this section) patent license to make, have made,
          use, offer to sell, sell, import, and otherwise transfer the Work,
          where such license applies only to those patent claims licensable
          by such Contributor that are necessarily infringed by their
          Contribution(s) alone or by combination of their Contribution(s)
          with the Work to which such Contribution(s) was submitted. If You
          institute patent litigation against any entity (including a
          cross-claim or counterclaim in a lawsuit) alleging that the Work
          or a Contribution incorporated within the Work constitutes direct
          or contributory patent infringement, then any patent licenses
          granted to You under this License for that Work shall terminate
          as of the date such litigation is filed.

       4. Redistribution. You may reproduce and distribute copies of the
          Work or Derivative Works thereof in any medium, with or without
          modifications, and in Source or Object form, provided that You
          meet the following conditions:

          (a) You must give any other recipients of the Work or
              Derivative Works a copy of this License; and

          (b) You must cause any modified files to carry prominent notices
              stating that You changed the files; and

          (c) You must retain, in the Source form of any Derivative Works
              that You distribute, all copyright, patent, trademark, and
              attribution notices from the Source form of the Work,
              excluding those notices that do not pertain to any part of
              the Derivative Works; and

          (d) If the Work includes a "NOTICE" text file as part of its
              distribution, then any Derivative Works that You distribute must
              include a readable copy of the attribution notices contained
              within such NOTICE file, excluding those notices that do not
              pertain to any part of the Derivative Works, in at least one
              of the following places: within a NOTICE text file distributed
              as part of the Derivative Works; within the Source form or
              documentation, if provided along with the Derivative Works; or,
              within a display generated by the Derivative Works, if and
              wherever such third-party notices normally appear. The contents
              of the NOTICE file are for informational purposes only and
              do not modify the License. You may add Your own attribution
              notices within Derivative Works that You distribute, alongside
              or as an addendum to the NOTICE text from the Work, provided
              that such additional attribution notices cannot be construed
              as modifying the License.

          You may add Your own copyright statement to Your modifications and
          may provide additional or different license terms and conditions
          for use, reproduction, or distribution of Your modifications, or
          for any such Derivative Works as a whole, provided Your use,
          reproduction, and distribution of the Work otherwise complies with
          the conditions stated in this License.

       5. Submission of Contributions. Unless You explicitly state otherwise,
          any Contribution intentionally submitted for inclusion in the Work
          by You to the Licensor shall be under the terms and conditions of
          this License, without any additional terms or conditions.
          Notwithstanding the above, nothing herein shall supersede or modify
          the terms of any separate license agreement you may have executed
          with Licensor regarding such Contributions.

       6. Trademarks. This License does not grant permission to use the trade
          names, trademarks, service marks, or product names of the Licensor,
          except as required for reasonable and customary use in describing the
          origin of the Work and reproducing the content of the NOTICE file.

       7. Disclaimer of Warranty. Unless required by applicable law or
          agreed to in writing, Licensor provides the Work (and each
          Contributor provides its Contributions) on an "AS IS" BASIS,
          WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
          implied, including, without limitation, any warranties or conditions
          of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
          PARTICULAR PURPOSE. You are solely responsible for determining the
          appropriateness of using or redistributing the Work and assume any
          risks associated with Your exercise of permissions under this License.

       8. Limitation of Liability. In no event and under no legal theory,
          whether in tort (including negligence), contract, or otherwise,
          unless required by applicable law (such as deliberate and grossly
          negligent acts) or agreed to in writing, shall any Contributor be
          liable to You for damages, including any direct, indirect, special,
          incidental, or consequential damages of any character arising as a
          result of this License or out of the use or inability to use the
          Work (including but not limited to damages for loss of goodwill,
          work stoppage, computer failure or malfunction, or any and all
          other commercial damages or losses), even if such Contributor
          has been advised of the possibility of such damages.

       9. Accepting Warranty or Additional Liability. While redistributing
          the Work or Derivative Works thereof, You may choose to offer,
          and charge a fee for, acceptance of support, warranty, indemnity,
          or other liability obligations and/or rights consistent with this
          License. However, in accepting such obligations, You may act only
          on Your own behalf and on Your sole responsibility, not on behalf
          of any other Contributor, and only if You agree to indemnify,
          defend, and hold each Contributor harmless for any liability
          incurred by, or claims asserted against, such Contributor by reason
          of your accepting any such warranty or additional liability.

       END OF TERMS AND CONDITIONS

       APPENDIX: How to apply the Apache License to your work.

          To apply the Apache License to your work, attach the following
          boilerplate notice, with the fields enclosed by brackets "[]"
          replaced with your own identifying information. (Don't include
          the brackets!)  The text should be enclosed in the appropriate
          comment syntax for the file format. We also recommend that a
          file or class name and description of purpose be included on the
          same "printed page" as the copyright notice for easier
          identification within third-party archives.

       Copyright [yyyy] [name of copyright owner]

       Licensed under the Apache License, Version 2.0 (the "License");
       you may not use this file except in compliance with the License.
       You may obtain a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing, software
       distributed under the License is distributed on an "AS IS" BASIS,
       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
       See the License for the specific language governing permissions and
       limitations under the License.

    =====

    FontTools includes code in `fontTools.misc.filesystem` which is derived from:

    PyFilesystem2 (i.e. the `fs` package) by Will McGugan
    Licensed under the MIT License
    https://github.com/PyFilesystem/pyfilesystem2

    Copyright (c) 2017-2021 The PyFilesystem2 contributors
    Copyright (c) 2016-2019 Will McGugan

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

### Pillow

Covers: Pillow and the libraries built into it, in the Windows app. This is Pillow 13.0.0's license file as it ships. FreeType is used under the FreeType License (FTL) it contains, not the GPL also reproduced there.

    The Python Imaging Library (PIL) is

        Copyright © 1997-2011 by Secret Labs AB
        Copyright © 1995-2011 by Fredrik Lundh and contributors

    Pillow is the friendly PIL fork. It is

        Copyright © 2010 by Jeffrey 'Alex' Clark and contributors

    Like PIL, Pillow is licensed under the open source MIT-CMU License:

    By obtaining, using, and/or copying this software and/or its associated
    documentation, you agree that you have read, understood, and will comply
    with the following terms and conditions:

    Permission to use, copy, modify and distribute this software and its
    documentation for any purpose and without fee is hereby granted,
    provided that the above copyright notice appears in all copies, and that
    both that copyright notice and this permission notice appear in supporting
    documentation, and that the name of Secret Labs AB or the author not be
    used in advertising or publicity pertaining to distribution of the software
    without specific, written prior permission.

    SECRET LABS AB AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
    SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
    IN NO EVENT SHALL SECRET LABS AB OR THE AUTHOR BE LIABLE FOR ANY SPECIAL,
    INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
    OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.

    ===== brotli-1.2.0 =====

    Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    ===== freetype-2.14.3 =====

    FREETYPE LICENSES
    -----------------

    The FreeType  2 font  engine is  copyrighted work  and cannot  be used
    legally without  a software  license.  In order  to make  this project
    usable to  a vast majority of  developers, we distribute it  under two
    mutually exclusive open-source licenses.

    This means that *you* must choose  *one* of the two licenses described
    below, then obey all its terms and conditions when using FreeType 2 in
    any of your projects or products.

      - The FreeType License,  found in the file  `docs/FTL.TXT`, which is
        similar to the  original BSD license *with*  an advertising clause
        that forces  you to explicitly  cite the FreeType project  in your
        product's  documentation.  All  details are  in the  license file.
        This license is suited to products which don't use the GNU General
        Public License.

        Note that  this license  is compatible to  the GNU  General Public
        License version 3, but not version 2.

      - The   GNU   General   Public   License   version   2,   found   in
        `docs/GPLv2.TXT`  (any  later  version  can  be  used  also),  for
        programs  which  already  use  the  GPL.  Note  that  the  FTL  is
        incompatible with GPLv2 due to its advertisement clause.

    The contributed  BDF and PCF  drivers come  with a license  similar to
    that  of the  X Window  System.   It is  compatible to  the above  two
    licenses (see files `src/bdf/README`  and `src/pcf/README`).  The same
    holds   for   the   source    code   files   `src/base/fthash.c`   and
    `include/freetype/internal/fthash.h`; they were part of the BDF driver
    in earlier FreeType versions.

    The gzip  module uses the  zlib license (see  `src/gzip/zlib.h`) which
    too is compatible to the above two licenses.

    The   files   `src/autofit/ft-hb-ft.c`,   `src/autofit/ft-hb-decls.h`,
    `src/autofit/ft-hb-types.h`,     and    `src/autofit/hb-script-list.h`
    contain code taken (almost) verbatim  from the HarfBuzz library, which
    uses the 'Old MIT' license compatible to the above two licenses.

    The  MD5 checksum  support  (only used  for  debugging in  development
    builds) is in the public domain.


    --- end of LICENSE.TXT ---
                        The FreeType Project LICENSE
                        ----------------------------

                                2006-Jan-27

                        Copyright 1996-2002, 2006 by
              David Turner, Robert Wilhelm, and Werner Lemberg



    Introduction
    ============

      The FreeType  Project is distributed in  several archive packages;
      some of them may contain, in addition to the FreeType font engine,
      various tools and  contributions which rely on, or  relate to, the
      FreeType Project.

      This  license applies  to all  files found  in such  packages, and
      which do not  fall under their own explicit  license.  The license
      affects  thus  the  FreeType   font  engine,  the  test  programs,
      documentation and makefiles, at the very least.

      This  license   was  inspired  by  the  BSD,   Artistic,  and  IJG
      (Independent JPEG  Group) licenses, which  all encourage inclusion
      and  use of  free  software in  commercial  and freeware  products
      alike.  As a consequence, its main points are that:

        o We don't promise that this software works. However, we will be
          interested in any kind of bug reports. (`as is' distribution)

        o You can  use this software for whatever you  want, in parts or
          full form, without having to pay us. (`royalty-free' usage)

        o You may not pretend that  you wrote this software.  If you use
          it, or  only parts of it,  in a program,  you must acknowledge
          somewhere  in  your  documentation  that  you  have  used  the
          FreeType code. (`credits')

      We  specifically  permit  and  encourage  the  inclusion  of  this
      software, with  or without modifications,  in commercial products.
      We  disclaim  all warranties  covering  The  FreeType Project  and
      assume no liability related to The FreeType Project.


      Finally,  many  people  asked  us  for  a  preferred  form  for  a
      credit/disclaimer to use in compliance with this license.  We thus
      encourage you to use the following text:

       """
        Portions of this software are copyright © <year> The FreeType
        Project (https://freetype.org).  All rights reserved.
       """

      Please replace <year> with the value from the FreeType version you
      actually use.


    Legal Terms
    ===========

    0. Definitions
    --------------

      Throughout this license,  the terms `package', `FreeType Project',
      and  `FreeType  archive' refer  to  the  set  of files  originally
      distributed  by the  authors  (David Turner,  Robert Wilhelm,  and
      Werner Lemberg) as the `FreeType Project', be they named as alpha,
      beta or final release.

      `You' refers to  the licensee, or person using  the project, where
      `using' is a generic term including compiling the project's source
      code as  well as linking it  to form a  `program' or `executable'.
      This  program is  referred to  as  `a program  using the  FreeType
      engine'.

      This  license applies  to all  files distributed  in  the original
      FreeType  Project,   including  all  source   code,  binaries  and
      documentation,  unless  otherwise  stated   in  the  file  in  its
      original, unmodified form as  distributed in the original archive.
      If you are  unsure whether or not a particular  file is covered by
      this license, you must contact us to verify this.

      The FreeType  Project is copyright (C) 1996-2000  by David Turner,
      Robert Wilhelm, and Werner Lemberg.  All rights reserved except as
      specified below.

    1. No Warranty
    --------------

      THE FREETYPE PROJECT  IS PROVIDED `AS IS' WITHOUT  WARRANTY OF ANY
      KIND, EITHER  EXPRESS OR IMPLIED,  INCLUDING, BUT NOT  LIMITED TO,
      WARRANTIES  OF  MERCHANTABILITY   AND  FITNESS  FOR  A  PARTICULAR
      PURPOSE.  IN NO EVENT WILL ANY OF THE AUTHORS OR COPYRIGHT HOLDERS
      BE LIABLE  FOR ANY DAMAGES CAUSED  BY THE USE OR  THE INABILITY TO
      USE, OF THE FREETYPE PROJECT.

    2. Redistribution
    -----------------

      This  license  grants  a  worldwide, royalty-free,  perpetual  and
      irrevocable right  and license to use,  execute, perform, compile,
      display,  copy,   create  derivative  works   of,  distribute  and
      sublicense the  FreeType Project (in  both source and  object code
      forms)  and  derivative works  thereof  for  any  purpose; and  to
      authorize others  to exercise  some or all  of the  rights granted
      herein, subject to the following conditions:

        o Redistribution of  source code  must retain this  license file
          (`FTL.TXT') unaltered; any  additions, deletions or changes to
          the original  files must be clearly  indicated in accompanying
          documentation.   The  copyright   notices  of  the  unaltered,
          original  files must  be  preserved in  all  copies of  source
          files.

        o Redistribution in binary form must provide a  disclaimer  that
          states  that  the software is based in part of the work of the
          FreeType Team,  in  the  distribution  documentation.  We also
          encourage you to put an URL to the FreeType web page  in  your
          documentation, though this isn't mandatory.

      These conditions  apply to any  software derived from or  based on
      the FreeType Project,  not just the unmodified files.   If you use
      our work, you  must acknowledge us.  However, no  fee need be paid
      to us.

    3. Advertising
    --------------

      Neither the  FreeType authors and  contributors nor you  shall use
      the name of the  other for commercial, advertising, or promotional
      purposes without specific prior written permission.

      We suggest,  but do not require, that  you use one or  more of the
      following phrases to refer  to this software in your documentation
      or advertising  materials: `FreeType Project',  `FreeType Engine',
      `FreeType library', or `FreeType Distribution'.

      As  you have  not signed  this license,  you are  not  required to
      accept  it.   However,  as  the FreeType  Project  is  copyrighted
      material, only  this license, or  another one contracted  with the
      authors, grants you  the right to use, distribute,  and modify it.
      Therefore,  by  using,  distributing,  or modifying  the  FreeType
      Project, you indicate that you understand and accept all the terms
      of this license.

    4. Contacts
    -----------

      There are two mailing lists related to FreeType:

        o freetype@nongnu.org

          Discusses general use and applications of FreeType, as well as
          future and  wanted additions to the  library and distribution.
          If  you are looking  for support,  start in  this list  if you
          haven't found anything to help you in the documentation.

        o freetype-devel@nongnu.org

          Discusses bugs,  as well  as engine internals,  design issues,
          specific licenses, porting, etc.

      Our home page can be found at

        https://freetype.org


    --- end of FTL.TXT ---
                        GNU GENERAL PUBLIC LICENSE
                           Version 2, June 1991

     Copyright (C) 1989, 1991 Free Software Foundation, Inc.
         51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
     Everyone is permitted to copy and distribute verbatim copies
     of this license document, but changing it is not allowed.

                                Preamble

      The licenses for most software are designed to take away your
    freedom to share and change it.  By contrast, the GNU General Public
    License is intended to guarantee your freedom to share and change free
    software--to make sure the software is free for all its users.  This
    General Public License applies to most of the Free Software
    Foundation's software and to any other program whose authors commit to
    using it.  (Some other Free Software Foundation software is covered by
    the GNU Library General Public License instead.)  You can apply it to
    your programs, too.

      When we speak of free software, we are referring to freedom, not
    price.  Our General Public Licenses are designed to make sure that you
    have the freedom to distribute copies of free software (and charge for
    this service if you wish), that you receive source code or can get it
    if you want it, that you can change the software or use pieces of it
    in new free programs; and that you know you can do these things.

      To protect your rights, we need to make restrictions that forbid
    anyone to deny you these rights or to ask you to surrender the rights.
    These restrictions translate to certain responsibilities for you if you
    distribute copies of the software, or if you modify it.

      For example, if you distribute copies of such a program, whether
    gratis or for a fee, you must give the recipients all the rights that
    you have.  You must make sure that they, too, receive or can get the
    source code.  And you must show them these terms so they know their
    rights.

      We protect your rights with two steps: (1) copyright the software, and
    (2) offer you this license which gives you legal permission to copy,
    distribute and/or modify the software.

      Also, for each author's protection and ours, we want to make certain
    that everyone understands that there is no warranty for this free
    software.  If the software is modified by someone else and passed on, we
    want its recipients to know that what they have is not the original, so
    that any problems introduced by others will not reflect on the original
    authors' reputations.

      Finally, any free program is threatened constantly by software
    patents.  We wish to avoid the danger that redistributors of a free
    program will individually obtain patent licenses, in effect making the
    program proprietary.  To prevent this, we have made it clear that any
    patent must be licensed for everyone's free use or not licensed at all.

      The precise terms and conditions for copying, distribution and
    modification follow.


                        GNU GENERAL PUBLIC LICENSE
       TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

      0. This License applies to any program or other work which contains
    a notice placed by the copyright holder saying it may be distributed
    under the terms of this General Public License.  The "Program", below,
    refers to any such program or work, and a "work based on the Program"
    means either the Program or any derivative work under copyright law:
    that is to say, a work containing the Program or a portion of it,
    either verbatim or with modifications and/or translated into another
    language.  (Hereinafter, translation is included without limitation in
    the term "modification".)  Each licensee is addressed as "you".

    Activities other than copying, distribution and modification are not
    covered by this License; they are outside its scope.  The act of
    running the Program is not restricted, and the output from the Program
    is covered only if its contents constitute a work based on the
    Program (independent of having been made by running the Program).
    Whether that is true depends on what the Program does.

      1. You may copy and distribute verbatim copies of the Program's
    source code as you receive it, in any medium, provided that you
    conspicuously and appropriately publish on each copy an appropriate
    copyright notice and disclaimer of warranty; keep intact all the
    notices that refer to this License and to the absence of any warranty;
    and give any other recipients of the Program a copy of this License
    along with the Program.

    You may charge a fee for the physical act of transferring a copy, and
    you may at your option offer warranty protection in exchange for a fee.

      2. You may modify your copy or copies of the Program or any portion
    of it, thus forming a work based on the Program, and copy and
    distribute such modifications or work under the terms of Section 1
    above, provided that you also meet all of these conditions:

        a) You must cause the modified files to carry prominent notices
        stating that you changed the files and the date of any change.

        b) You must cause any work that you distribute or publish, that in
        whole or in part contains or is derived from the Program or any
        part thereof, to be licensed as a whole at no charge to all third
        parties under the terms of this License.

        c) If the modified program normally reads commands interactively
        when run, you must cause it, when started running for such
        interactive use in the most ordinary way, to print or display an
        announcement including an appropriate copyright notice and a
        notice that there is no warranty (or else, saying that you provide
        a warranty) and that users may redistribute the program under
        these conditions, and telling the user how to view a copy of this
        License.  (Exception: if the Program itself is interactive but
        does not normally print such an announcement, your work based on
        the Program is not required to print an announcement.)


    These requirements apply to the modified work as a whole.  If
    identifiable sections of that work are not derived from the Program,
    and can be reasonably considered independent and separate works in
    themselves, then this License, and its terms, do not apply to those
    sections when you distribute them as separate works.  But when you
    distribute the same sections as part of a whole which is a work based
    on the Program, the distribution of the whole must be on the terms of
    this License, whose permissions for other licensees extend to the
    entire whole, and thus to each and every part regardless of who wrote it.

    Thus, it is not the intent of this section to claim rights or contest
    your rights to work written entirely by you; rather, the intent is to
    exercise the right to control the distribution of derivative or
    collective works based on the Program.

    In addition, mere aggregation of another work not based on the Program
    with the Program (or with a work based on the Program) on a volume of
    a storage or distribution medium does not bring the other work under
    the scope of this License.

      3. You may copy and distribute the Program (or a work based on it,
    under Section 2) in object code or executable form under the terms of
    Sections 1 and 2 above provided that you also do one of the following:

        a) Accompany it with the complete corresponding machine-readable
        source code, which must be distributed under the terms of Sections
        1 and 2 above on a medium customarily used for software interchange; or,

        b) Accompany it with a written offer, valid for at least three
        years, to give any third party, for a charge no more than your
        cost of physically performing source distribution, a complete
        machine-readable copy of the corresponding source code, to be
        distributed under the terms of Sections 1 and 2 above on a medium
        customarily used for software interchange; or,

        c) Accompany it with the information you received as to the offer
        to distribute corresponding source code.  (This alternative is
        allowed only for noncommercial distribution and only if you
        received the program in object code or executable form with such
        an offer, in accord with Subsection b above.)

    The source code for a work means the preferred form of the work for
    making modifications to it.  For an executable work, complete source
    code means all the source code for all modules it contains, plus any
    associated interface definition files, plus the scripts used to
    control compilation and installation of the executable.  However, as a
    special exception, the source code distributed need not include
    anything that is normally distributed (in either source or binary
    form) with the major components (compiler, kernel, and so on) of the
    operating system on which the executable runs, unless that component
    itself accompanies the executable.

    If distribution of executable or object code is made by offering
    access to copy from a designated place, then offering equivalent
    access to copy the source code from the same place counts as
    distribution of the source code, even though third parties are not
    compelled to copy the source along with the object code.


      4. You may not copy, modify, sublicense, or distribute the Program
    except as expressly provided under this License.  Any attempt
    otherwise to copy, modify, sublicense or distribute the Program is
    void, and will automatically terminate your rights under this License.
    However, parties who have received copies, or rights, from you under
    this License will not have their licenses terminated so long as such
    parties remain in full compliance.

      5. You are not required to accept this License, since you have not
    signed it.  However, nothing else grants you permission to modify or
    distribute the Program or its derivative works.  These actions are
    prohibited by law if you do not accept this License.  Therefore, by
    modifying or distributing the Program (or any work based on the
    Program), you indicate your acceptance of this License to do so, and
    all its terms and conditions for copying, distributing or modifying
    the Program or works based on it.

      6. Each time you redistribute the Program (or any work based on the
    Program), the recipient automatically receives a license from the
    original licensor to copy, distribute or modify the Program subject to
    these terms and conditions.  You may not impose any further
    restrictions on the recipients' exercise of the rights granted herein.
    You are not responsible for enforcing compliance by third parties to
    this License.

      7. If, as a consequence of a court judgment or allegation of patent
    infringement or for any other reason (not limited to patent issues),
    conditions are imposed on you (whether by court order, agreement or
    otherwise) that contradict the conditions of this License, they do not
    excuse you from the conditions of this License.  If you cannot
    distribute so as to satisfy simultaneously your obligations under this
    License and any other pertinent obligations, then as a consequence you
    may not distribute the Program at all.  For example, if a patent
    license would not permit royalty-free redistribution of the Program by
    all those who receive copies directly or indirectly through you, then
    the only way you could satisfy both it and this License would be to
    refrain entirely from distribution of the Program.

    If any portion of this section is held invalid or unenforceable under
    any particular circumstance, the balance of the section is intended to
    apply and the section as a whole is intended to apply in other
    circumstances.

    It is not the purpose of this section to induce you to infringe any
    patents or other property right claims or to contest validity of any
    such claims; this section has the sole purpose of protecting the
    integrity of the free software distribution system, which is
    implemented by public license practices.  Many people have made
    generous contributions to the wide range of software distributed
    through that system in reliance on consistent application of that
    system; it is up to the author/donor to decide if he or she is willing
    to distribute software through any other system and a licensee cannot
    impose that choice.

    This section is intended to make thoroughly clear what is believed to
    be a consequence of the rest of this License.


      8. If the distribution and/or use of the Program is restricted in
    certain countries either by patents or by copyrighted interfaces, the
    original copyright holder who places the Program under this License
    may add an explicit geographical distribution limitation excluding
    those countries, so that distribution is permitted only in or among
    countries not thus excluded.  In such case, this License incorporates
    the limitation as if written in the body of this License.

      9. The Free Software Foundation may publish revised and/or new versions
    of the General Public License from time to time.  Such new versions will
    be similar in spirit to the present version, but may differ in detail to
    address new problems or concerns.

    Each version is given a distinguishing version number.  If the Program
    specifies a version number of this License which applies to it and "any
    later version", you have the option of following the terms and conditions
    either of that version or of any later version published by the Free
    Software Foundation.  If the Program does not specify a version number of
    this License, you may choose any version ever published by the Free Software
    Foundation.

      10. If you wish to incorporate parts of the Program into other free
    programs whose distribution conditions are different, write to the author
    to ask for permission.  For software which is copyrighted by the Free
    Software Foundation, write to the Free Software Foundation; we sometimes
    make exceptions for this.  Our decision will be guided by the two goals
    of preserving the free status of all derivatives of our free software and
    of promoting the sharing and reuse of software generally.

                                NO WARRANTY

      11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
    FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
    OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
    PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
    TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
    PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
    REPAIR OR CORRECTION.

      12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
    WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
    REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
    INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
    OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
    TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
    YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
    PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGES.

                         END OF TERMS AND CONDITIONS


                How to Apply These Terms to Your New Programs

      If you develop a new program, and you want it to be of the greatest
    possible use to the public, the best way to achieve this is to make it
    free software which everyone can redistribute and change under these terms.

      To do so, attach the following notices to the program.  It is safest
    to attach them to the start of each source file to most effectively
    convey the exclusion of warranty; and each file should have at least
    the "copyright" line and a pointer to where the full notice is found.

        <one line to give the program's name and a brief idea of what it does.>
        Copyright (C) <year>  <name of author>

        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


    Also add information on how to contact you by electronic and paper mail.

    If the program is interactive, make it output a short notice like this
    when it starts in an interactive mode:

        Gnomovision version 69, Copyright (C) year  name of author
        Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
        This is free software, and you are welcome to redistribute it
        under certain conditions; type `show c' for details.

    The hypothetical commands `show w' and `show c' should show the appropriate
    parts of the General Public License.  Of course, the commands you use may
    be called something other than `show w' and `show c'; they could even be
    mouse-clicks or menu items--whatever suits your program.

    You should also get your employer (if you work as a programmer) or your
    school, if any, to sign a "copyright disclaimer" for the program, if
    necessary.  Here is a sample; alter the names:

      Yoyodyne, Inc., hereby disclaims all copyright interest in the program
      `Gnomovision' (which makes passes at compilers) written by James Hacker.

      <signature of Ty Coon>, 1 April 1989
      Ty Coon, President of Vice

    This General Public License does not permit incorporating your program into
    proprietary programs.  If your program is a subroutine library, you may
    consider it more useful to permit linking proprietary applications with the
    library.  If this is what you want to do, use the GNU Library General
    Public License instead of this License.

    ===== harfbuzz-14.5.0 =====

    HarfBuzz is licensed under the so-called "Old MIT" license.  Details follow.
    For parts of HarfBuzz that are licensed under different licenses see individual
    files names COPYING in subdirectories where applicable.

    Copyright © 2010-2022  Google, Inc.
    Copyright © 2015-2020  Ebrahim Byagowi
    Copyright © 2019,2020  Facebook, Inc.
    Copyright © 2012,2015  Mozilla Foundation
    Copyright © 2011  Codethink Limited
    Copyright © 2008,2010  Nokia Corporation and/or its subsidiary(-ies)
    Copyright © 2009  Keith Stribley
    Copyright © 2011  Martin Hosken and SIL International
    Copyright © 2007  Chris Wilson
    Copyright © 2005,2006,2020,2021,2022,2023  Behdad Esfahbod
    Copyright © 2004,2007,2008,2009,2010,2013,2021,2022,2023  Red Hat, Inc.
    Copyright © 1998-2005  David Turner and Werner Lemberg
    Copyright © 2016  Igalia S.L.
    Copyright © 2022  Matthias Clasen
    Copyright © 2018,2021  Khaled Hosny
    Copyright © 2018,2019,2020  Adobe, Inc
    Copyright © 2013-2015  Alexei Podtelezhnikov

    For full copyright notices consult the individual files in the package.


    Permission is hereby granted, without written agreement and without
    license or royalty fees, to use, copy, modify, and distribute this
    software and its documentation for any purpose, provided that the
    above copyright notice and the following two paragraphs appear in
    all copies of this software.

    IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE TO ANY PARTY FOR
    DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
    ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN
    IF THE COPYRIGHT HOLDER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
    DAMAGE.

    THE COPYRIGHT HOLDER SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING,
    BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
    FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
    ON AN "AS IS" BASIS, AND THE COPYRIGHT HOLDER HAS NO OBLIGATION TO
    PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

    ===== lcms2-2.19.1 =====

    MIT License

    Copyright (c) 2023 Marti Maria Saguer

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject
    to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    ===== libavif-1.4.2 =====

    Copyright 2019 Joe Drago. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    ------------------------------------------------------------------------------

    Files: src/obu.c

    Copyright © 2018-2019, VideoLAN and dav1d authors
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    ------------------------------------------------------------------------------

    Files: third_party/iccjpeg/*

    In plain English:

    1. We don't promise that this software works.  (But if you find any bugs,
       please let us know!)
    2. You can use this software for whatever you want.  You don't have to pay us.
    3. You may not pretend that you wrote this software.  If you use it in a
       program, you must acknowledge somewhere in your documentation that
       you've used the IJG code.

    In legalese:

    The authors make NO WARRANTY or representation, either express or implied,
    with respect to this software, its quality, accuracy, merchantability, or
    fitness for a particular purpose.  This software is provided "AS IS", and you,
    its user, assume the entire risk as to its quality and accuracy.

    This software is copyright (C) 1991-2013, Thomas G. Lane, Guido Vollbeding.
    All Rights Reserved except as specified below.

    Permission is hereby granted to use, copy, modify, and distribute this
    software (or portions thereof) for any purpose, without fee, subject to these
    conditions:
    (1) If any part of the source code for this software is distributed, then this
    README file must be included, with this copyright and no-warranty notice
    unaltered; and any additions, deletions, or changes to the original files
    must be clearly indicated in accompanying documentation.
    (2) If only executable code is distributed, then the accompanying
    documentation must state that "this software is based in part on the work of
    the Independent JPEG Group".
    (3) Permission for use of this software is granted only if the user accepts
    full responsibility for any undesirable consequences; the authors accept
    NO LIABILITY for damages of any kind.

    These conditions apply to any software derived from or based on the IJG code,
    not just to the unmodified library.  If you use our work, you ought to
    acknowledge us.

    Permission is NOT granted for the use of any IJG author's name or company name
    in advertising or publicity relating to this software or products derived from
    it.  This software may be referred to only as "the Independent JPEG Group's
    software".

    We specifically permit and encourage the use of this software as the basis of
    commercial products, provided that all warranty or liability claims are
    assumed by the product vendor.


    The Unix configuration script "configure" was produced with GNU Autoconf.
    It is copyright by the Free Software Foundation but is freely distributable.
    The same holds for its supporting scripts (config.guess, config.sub,
    ltmain.sh).  Another support script, install-sh, is copyright by X Consortium
    but is also freely distributable.

    The IJG distribution formerly included code to read and write GIF files.
    To avoid entanglement with the Unisys LZW patent, GIF reading support has
    been removed altogether, and the GIF writer has been simplified to produce
    "uncompressed GIFs".  This technique does not use the LZW algorithm; the
    resulting GIF files are larger than usual, but are readable by all standard
    GIF decoders.

    We are required to state that
        "The Graphics Interchange Format(c) is the Copyright property of
        CompuServe Incorporated.  GIF(sm) is a Service Mark property of
        CompuServe Incorporated."

    ------------------------------------------------------------------------------

    Files: contrib/gdk-pixbuf/*

    Copyright 2020 Emmanuel Gil Peyrot. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    ------------------------------------------------------------------------------

    Files: android_jni/gradlew*


                                     Apache License
                               Version 2.0, January 2004
                            http://www.apache.org/licenses/

       TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

       1. Definitions.

          "License" shall mean the terms and conditions for use, reproduction,
          and distribution as defined by Sections 1 through 9 of this document.

          "Licensor" shall mean the copyright owner or entity authorized by
          the copyright owner that is granting the License.

          "Legal Entity" shall mean the union of the acting entity and all
          other entities that control, are controlled by, or are under common
          control with that entity. For the purposes of this definition,
          "control" means (i) the power, direct or indirect, to cause the
          direction or management of such entity, whether by contract or
          otherwise, or (ii) ownership of fifty percent (50%) or more of the
          outstanding shares, or (iii) beneficial ownership of such entity.

          "You" (or "Your") shall mean an individual or Legal Entity
          exercising permissions granted by this License.

          "Source" form shall mean the preferred form for making modifications,
          including but not limited to software source code, documentation
          source, and configuration files.

          "Object" form shall mean any form resulting from mechanical
          transformation or translation of a Source form, including but
          not limited to compiled object code, generated documentation,
          and conversions to other media types.

          "Work" shall mean the work of authorship, whether in Source or
          Object form, made available under the License, as indicated by a
          copyright notice that is included in or attached to the work
          (an example is provided in the Appendix below).

          "Derivative Works" shall mean any work, whether in Source or Object
          form, that is based on (or derived from) the Work and for which the
          editorial revisions, annotations, elaborations, or other modifications
          represent, as a whole, an original work of authorship. For the purposes
          of this License, Derivative Works shall not include works that remain
          separable from, or merely link (or bind by name) to the interfaces of,
          the Work and Derivative Works thereof.

          "Contribution" shall mean any work of authorship, including
          the original version of the Work and any modifications or additions
          to that Work or Derivative Works thereof, that is intentionally
          submitted to Licensor for inclusion in the Work by the copyright owner
          or by an individual or Legal Entity authorized to submit on behalf of
          the copyright owner. For the purposes of this definition, "submitted"
          means any form of electronic, verbal, or written communication sent
          to the Licensor or its representatives, including but not limited to
          communication on electronic mailing lists, source code control systems,
          and issue tracking systems that are managed by, or on behalf of, the
          Licensor for the purpose of discussing and improving the Work, but
          excluding communication that is conspicuously marked or otherwise
          designated in writing by the copyright owner as "Not a Contribution."

          "Contributor" shall mean Licensor and any individual or Legal Entity
          on behalf of whom a Contribution has been received by Licensor and
          subsequently incorporated within the Work.

       2. Grant of Copyright License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          copyright license to reproduce, prepare Derivative Works of,
          publicly display, publicly perform, sublicense, and distribute the
          Work and such Derivative Works in Source or Object form.

       3. Grant of Patent License. Subject to the terms and conditions of
          this License, each Contributor hereby grants to You a perpetual,
          worldwide, non-exclusive, no-charge, royalty-free, irrevocable
          (except as stated in this section) patent license to make, have made,
          use, offer to sell, sell, import, and otherwise transfer the Work,
          where such license applies only to those patent claims licensable
          by such Contributor that are necessarily infringed by their
          Contribution(s) alone or by combination of their Contribution(s)
          with the Work to which such Contribution(s) was submitted. If You
          institute patent litigation against any entity (including a
          cross-claim or counterclaim in a lawsuit) alleging that the Work
          or a Contribution incorporated within the Work constitutes direct
          or contributory patent infringement, then any patent licenses
          granted to You under this License for that Work shall terminate
          as of the date such litigation is filed.

       4. Redistribution. You may reproduce and distribute copies of the
          Work or Derivative Works thereof in any medium, with or without
          modifications, and in Source or Object form, provided that You
          meet the following conditions:

          (a) You must give any other recipients of the Work or
              Derivative Works a copy of this License; and

          (b) You must cause any modified files to carry prominent notices
              stating that You changed the files; and

          (c) You must retain, in the Source form of any Derivative Works
              that You distribute, all copyright, patent, trademark, and
              attribution notices from the Source form of the Work,
              excluding those notices that do not pertain to any part of
              the Derivative Works; and

          (d) If the Work includes a "NOTICE" text file as part of its
              distribution, then any Derivative Works that You distribute must
              include a readable copy of the attribution notices contained
              within such NOTICE file, excluding those notices that do not
              pertain to any part of the Derivative Works, in at least one
              of the following places: within a NOTICE text file distributed
              as part of the Derivative Works; within the Source form or
              documentation, if provided along with the Derivative Works; or,
              within a display generated by the Derivative Works, if and
              wherever such third-party notices normally appear. The contents
              of the NOTICE file are for informational purposes only and
              do not modify the License. You may add Your own attribution
              notices within Derivative Works that You distribute, alongside
              or as an addendum to the NOTICE text from the Work, provided
              that such additional attribution notices cannot be construed
              as modifying the License.

          You may add Your own copyright statement to Your modifications and
          may provide additional or different license terms and conditions
          for use, reproduction, or distribution of Your modifications, or
          for any such Derivative Works as a whole, provided Your use,
          reproduction, and distribution of the Work otherwise complies with
          the conditions stated in this License.

       5. Submission of Contributions. Unless You explicitly state otherwise,
          any Contribution intentionally submitted for inclusion in the Work
          by You to the Licensor shall be under the terms and conditions of
          this License, without any additional terms or conditions.
          Notwithstanding the above, nothing herein shall supersede or modify
          the terms of any separate license agreement you may have executed
          with Licensor regarding such Contributions.

       6. Trademarks. This License does not grant permission to use the trade
          names, trademarks, service marks, or product names of the Licensor,
          except as required for reasonable and customary use in describing the
          origin of the Work and reproducing the content of the NOTICE file.

       7. Disclaimer of Warranty. Unless required by applicable law or
          agreed to in writing, Licensor provides the Work (and each
          Contributor provides its Contributions) on an "AS IS" BASIS,
          WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
          implied, including, without limitation, any warranties or conditions
          of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
          PARTICULAR PURPOSE. You are solely responsible for determining the
          appropriateness of using or redistributing the Work and assume any
          risks associated with Your exercise of permissions under this License.

       8. Limitation of Liability. In no event and under no legal theory,
          whether in tort (including negligence), contract, or otherwise,
          unless required by applicable law (such as deliberate and grossly
          negligent acts) or agreed to in writing, shall any Contributor be
          liable to You for damages, including any direct, indirect, special,
          incidental, or consequential damages of any character arising as a
          result of this License or out of the use or inability to use the
          Work (including but not limited to damages for loss of goodwill,
          work stoppage, computer failure or malfunction, or any and all
          other commercial damages or losses), even if such Contributor
          has been advised of the possibility of such damages.

       9. Accepting Warranty or Additional Liability. While redistributing
          the Work or Derivative Works thereof, You may choose to offer,
          and charge a fee for, acceptance of support, warranty, indemnity,
          or other liability obligations and/or rights consistent with this
          License. However, in accepting such obligations, You may act only
          on Your own behalf and on Your sole responsibility, not on behalf
          of any other Contributor, and only if You agree to indemnify,
          defend, and hold each Contributor harmless for any liability
          incurred by, or claims asserted against, such Contributor by reason
          of your accepting any such warranty or additional liability.

       END OF TERMS AND CONDITIONS

       APPENDIX: How to apply the Apache License to your work.

          To apply the Apache License to your work, attach the following
          boilerplate notice, with the fields enclosed by brackets "[]"
          replaced with your own identifying information. (Don't include
          the brackets!)  The text should be enclosed in the appropriate
          comment syntax for the file format. We also recommend that a
          file or class name and description of purpose be included on the
          same "printed page" as the copyright notice for easier
          identification within third-party archives.

       Copyright [yyyy] [name of copyright owner]

       Licensed under the Apache License, Version 2.0 (the "License");
       you may not use this file except in compliance with the License.
       You may obtain a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing, software
       distributed under the License is distributed on an "AS IS" BASIS,
       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
       See the License for the specific language governing permissions and
       limitations under the License.

    ------------------------------------------------------------------------------

    Files: third_party/libyuv/*

    Copyright 2011 The LibYuv Project Authors. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in
        the documentation and/or other materials provided with the
        distribution.

      * Neither the name of Google nor the names of its contributors may
        be used to endorse or promote products derived from this software
        without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    ===== libjpeg-turbo-3.2.0 =====

    LEGAL ISSUES
    ============

    In plain English:

    1. We don't promise that this software works.  (But if you find any bugs,
       please let us know!)
    2. You can use this software for whatever you want.  You don't have to pay us.
    3. You may not pretend that you wrote this software.  If you use it in a
       program, you must acknowledge somewhere in your documentation that
       you've used the IJG code.

    In legalese:

    The authors make NO WARRANTY or representation, either express or implied,
    with respect to this software, its quality, accuracy, merchantability, or
    fitness for a particular purpose.  This software is provided "AS IS", and you,
    its user, assume the entire risk as to its quality and accuracy.

    This software is copyright (C) 1991-2020, Thomas G. Lane, Guido Vollbeding.
    All Rights Reserved except as specified below.

    Permission is hereby granted to use, copy, modify, and distribute this
    software (or portions thereof) for any purpose, without fee, subject to these
    conditions:
    (1) If any part of the source code for this software is distributed, then this
    README file must be included, with this copyright and no-warranty notice
    unaltered; and any additions, deletions, or changes to the original files
    must be clearly indicated in accompanying documentation.
    (2) If only executable code is distributed, then the accompanying
    documentation must state that "this software is based in part on the work of
    the Independent JPEG Group".
    (3) Permission for use of this software is granted only if the user accepts
    full responsibility for any undesirable consequences; the authors accept
    NO LIABILITY for damages of any kind.

    These conditions apply to any software derived from or based on the IJG code,
    not just to the unmodified library.  If you use our work, you ought to
    acknowledge us.

    Permission is NOT granted for the use of any IJG author's name or company name
    in advertising or publicity relating to this software or products derived from
    it.  This software may be referred to only as "the Independent JPEG Group's
    software".

    We specifically permit and encourage the use of this software as the basis of
    commercial products, provided that all warranty or liability claims are
    assumed by the product vendor.

    libjpeg-turbo Licenses
    ======================

    libjpeg-turbo is covered by two compatible BSD-style open source licenses:

    - The IJG (Independent JPEG Group) License, which is listed in
      [README.ijg](README.ijg)

      This license applies to the libjpeg API library and associated programs,
      including any code inherited from libjpeg and any modifications to that
      code.

    - The Modified (3-clause) BSD License, which is listed below

      This license applies to the TurboJPEG API library and associated programs,
      [libspng](https://libspng.org) (which is used by cjpeg and djpeg), and the
      build/test system.

      * The TurboJPEG API library wraps the libjpeg API library, so in the context
        of the overall TurboJPEG API library, both the terms of the IJG License and
        the terms of the Modified (3-clause) BSD License apply.
      * cjpeg and djpeg use libspng, so in the context of those programs, both the
        terms of the IJG License and the terms of the Modified (3-clause) BSD
        License apply.


    Component Licenses
    ==================

    Some of libjpeg-turbo's modules and internal dependencies are covered by less
    restrictive licenses, but in the context of libjpeg-turbo as a whole, the terms
    of the less restrictive licenses are subsumed by either the IJG License or the
    Modified BSD License.  (In other words, the terms of the less restrictive
    licenses are satisfied if the terms of the IJG and Modified BSD Licenses are
    satisfied.)

    - The libjpeg-turbo SIMD source code and zlib are covered by the
      [zlib License](https://spdx.org/licenses/Zlib.html), which is subsumed by the
      IJG License in the context of the cjpeg and djpeg programs and the libjpeg
      API library.

    - Some of the libspng source code is covered by the
      [PNG Reference Library License v2](https://spdx.org/licenses/libpng-2.0.html),
      which is subsumed by the IJG License in the context of the cjpeg and djpeg
      programs and the TurboJPEG API library.

    - Most of the libspng source code is covered by the
      [Simplified (2-clause) BSD License](https://spdx.org/licenses/BSD-2-Clause.html),
      which is subsumed by the Modified BSD License in the context of the cjpeg and
      djpeg programs and the TurboJPEG API library.


    Complying with the libjpeg-turbo Licenses
    =========================================

    This section provides a roll-up of the libjpeg-turbo licensing terms, to the
    best of our understanding.  This is not a license in and of itself.  It is
    intended solely for clarification.

    1.  If you are distributing a modified version of the libjpeg-turbo source,
        then:

        1.  You cannot alter or remove any existing copyright or license notices
            from the source.

            **Origin**
            - Clause 1 of the IJG License
            - Clause 1 of the Modified BSD License

        2.  You must add your own copyright notice to the header of each source
            file you modified, so others can tell that you modified that file.  (If
            there is not an existing copyright header in that file, then you can
            simply add a notice stating that you modified the file.)

            **Origin**
            - Clause 1 of the IJG License

        3.  You must include the IJG README file, and you must not alter any of the
            copyright or license text in that file.

            **Origin**
            - Clause 1 of the IJG License

    2.  If you are distributing only libjpeg-turbo binaries without the source, or
        if you are distributing an application that statically links with
        libjpeg-turbo, then:

        1.  Your product documentation must include a message stating:

            This software is based in part on the work of the Independent JPEG
            Group.

            **Origin**
            - Clause 2 of the IJG license

        2.  If your binary distribution includes or uses the TurboJPEG API or
            associated programs, cjpeg, or djpeg, then your product documentation
            must include the text of the Modified BSD License (see below.)

            **Origin**
            - Clause 2 of the Modified BSD License

    3.  You cannot use the name of the IJG or The libjpeg-turbo Project or the
        contributors thereof in advertising, publicity, etc.

        **Origin**
        - IJG License
        - Clause 3 of the Modified BSD License

    4.  The authors and distributors do not warrant libjpeg-turbo to be free of
        defects, nor do we accept any liability for undesirable consequences
        resulting from your use of the software.

        **Origin**
        - IJG License
        - Modified BSD License


    The Modified (3-clause) BSD License
    ===================================

    Copyright (C) 2009-2026 D. R. Commander<br>
    Copyright (C) 2018-2023 Randy <randy408@protonmail.com>

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    - Neither the name of the libjpeg-turbo Project nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS",
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    ===== libpng-1.6.58 =====

    COPYRIGHT NOTICE, DISCLAIMER, and LICENSE
    =========================================

    PNG Reference Library License version 2
    ---------------------------------------

     * Copyright (c) 1995-2026 The PNG Reference Library Authors.
     * Copyright (c) 2018-2026 Cosmin Truta.
     * Copyright (c) 2000-2002, 2004, 2006-2018 Glenn Randers-Pehrson.
     * Copyright (c) 1996-1997 Andreas Dilger.
     * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.

    The software is supplied "as is", without warranty of any kind,
    express or implied, including, without limitation, the warranties
    of merchantability, fitness for a particular purpose, title, and
    non-infringement.  In no event shall the Copyright owners, or
    anyone distributing the software, be liable for any damages or
    other liability, whether in contract, tort or otherwise, arising
    from, out of, or in connection with the software, or the use or
    other dealings in the software, even if advised of the possibility
    of such damage.

    Permission is hereby granted to use, copy, modify, and distribute
    this software, or portions hereof, for any purpose, without fee,
    subject to the following restrictions:

     1. The origin of this software must not be misrepresented; you
        must not claim that you wrote the original software.  If you
        use this software in a product, an acknowledgment in the product
        documentation would be appreciated, but is not required.

     2. Altered source versions must be plainly marked as such, and must
        not be misrepresented as being the original software.

     3. This Copyright notice may not be removed or altered from any
        source or altered source distribution.


    PNG Reference Library License version 1 (for libpng 0.5 through 1.6.35)
    -----------------------------------------------------------------------

    libpng versions 1.0.7, July 1, 2000, through 1.6.35, July 15, 2018 are
    Copyright (c) 2000-2002, 2004, 2006-2018 Glenn Randers-Pehrson, are
    derived from libpng-1.0.6, and are distributed according to the same
    disclaimer and license as libpng-1.0.6 with the following individuals
    added to the list of Contributing Authors:

        Simon-Pierre Cadieux
        Eric S. Raymond
        Mans Rullgard
        Cosmin Truta
        Gilles Vollant
        James Yu
        Mandar Sahastrabuddhe
        Google Inc.
        Vadim Barkov

    and with the following additions to the disclaimer:

        There is no warranty against interference with your enjoyment of
        the library or against infringement.  There is no warranty that our
        efforts or the library will fulfill any of your particular purposes
        or needs.  This library is provided with all faults, and the entire
        risk of satisfactory quality, performance, accuracy, and effort is
        with the user.

    Some files in the "contrib" directory and some configure-generated
    files that are distributed with libpng have other copyright owners, and
    are released under other open source licenses.

    libpng versions 0.97, January 1998, through 1.0.6, March 20, 2000, are
    Copyright (c) 1998-2000 Glenn Randers-Pehrson, are derived from
    libpng-0.96, and are distributed according to the same disclaimer and
    license as libpng-0.96, with the following individuals added to the
    list of Contributing Authors:

        Tom Lane
        Glenn Randers-Pehrson
        Willem van Schaik

    libpng versions 0.89, June 1996, through 0.96, May 1997, are
    Copyright (c) 1996-1997 Andreas Dilger, are derived from libpng-0.88,
    and are distributed according to the same disclaimer and license as
    libpng-0.88, with the following individuals added to the list of
    Contributing Authors:

        John Bowler
        Kevin Bracey
        Sam Bushell
        Magnus Holmgren
        Greg Roelofs
        Tom Tanner

    Some files in the "scripts" directory have other copyright owners,
    but are released under this license.

    libpng versions 0.5, May 1995, through 0.88, January 1996, are
    Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.

    For the purposes of this copyright and license, "Contributing Authors"
    is defined as the following set of individuals:

        Andreas Dilger
        Dave Martindale
        Guy Eric Schalnat
        Paul Schmidt
        Tim Wegner

    The PNG Reference Library is supplied "AS IS".  The Contributing
    Authors and Group 42, Inc. disclaim all warranties, expressed or
    implied, including, without limitation, the warranties of
    merchantability and of fitness for any purpose.  The Contributing
    Authors and Group 42, Inc. assume no liability for direct, indirect,
    incidental, special, exemplary, or consequential damages, which may
    result from the use of the PNG Reference Library, even if advised of
    the possibility of such damage.

    Permission is hereby granted to use, copy, modify, and distribute this
    source code, or portions hereof, for any purpose, without fee, subject
    to the following restrictions:

     1. The origin of this source code must not be misrepresented.

     2. Altered versions must be plainly marked as such and must not
        be misrepresented as being the original source.

     3. This Copyright notice may not be removed or altered from any
        source or altered source distribution.

    The Contributing Authors and Group 42, Inc. specifically permit,
    without fee, and encourage the use of this source code as a component
    to supporting the PNG file format in commercial products.  If you use
    this source code in a product, acknowledgment is not required but would
    be appreciated.

    ===== libwebp-1.6.0 =====

    Copyright (c) 2010, Google Inc. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in
        the documentation and/or other materials provided with the
        distribution.

      * Neither the name of Google nor the names of its contributors may
        be used to endorse or promote products derived from this software
        without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


    ===== openjpeg-2.5.4 =====

    /*
     * The copyright in this software is being made available under the 2-clauses
     * BSD License, included below. This software may be subject to other third
     * party and contributor rights, including patent rights, and no such rights
     * are granted under this license.
     *
     * Copyright (c) 2002-2014, Universite catholique de Louvain (UCL), Belgium
     * Copyright (c) 2002-2014, Professor Benoit Macq
     * Copyright (c) 2003-2014, Antonin Descampe
     * Copyright (c) 2003-2009, Francois-Olivier Devaux
     * Copyright (c) 2005, Herve Drolon, FreeImage Team
     * Copyright (c) 2002-2003, Yannick Verschueren
     * Copyright (c) 2001-2003, David Janssens
     * Copyright (c) 2011-2012, Centre National d'Etudes Spatiales (CNES), France
     * Copyright (c) 2012, CS Systemes d'Information, France
     *
     * All rights reserved.
     *
     * Redistribution and use in source and binary forms, with or without
     * modification, are permitted provided that the following conditions
     * are met:
     * 1. Redistributions of source code must retain the above copyright
     *    notice, this list of conditions and the following disclaimer.
     * 2. Redistributions in binary form must reproduce the above copyright
     *    notice, this list of conditions and the following disclaimer in the
     *    documentation and/or other materials provided with the distribution.
     *
     * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS `AS IS'
     * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
     * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
     * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
     * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
     * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
     * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
     * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
     * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
     * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
     * POSSIBILITY OF SUCH DAMAGE.
     */

    ===== tiff-4.7.2 =====

    # LibTIFF license

    Copyright © 1988-1997 Sam Leffler\
    Copyright © 1991-1997 Silicon Graphics, Inc.

    Permission to use, copy, modify, distribute, and sell this software and
    its documentation for any purpose is hereby granted without fee, provided
    that (i) the above copyright notices and this permission notice appear in
    all copies of the software and related documentation, and (ii) the names of
    Sam Leffler and Silicon Graphics may not be used in any advertising or
    publicity relating to the software without the specific, prior written
    permission of Sam Leffler and Silicon Graphics.

    THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
    EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
    WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

    IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
    ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
    OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF
    LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
    OF THIS SOFTWARE.

    # Lempel-Ziv & Welch Compression (tif_lzw.c) license
    The code of tif_lzw.c is derived from the compress program whose code is
    derived from software contributed to Berkeley by James A. Woods,
    derived from original work by Spencer Thomas and Joseph Orost.

    The original Berkeley copyright notice appears below in its entirety:

    Copyright (c) 1985, 1986 The Regents of the University of California.
    All rights reserved.

    This code is derived from software contributed to Berkeley by
    James A. Woods, derived from original work by Spencer Thomas
    and Joseph Orost.

    Redistribution and use in source and binary forms are permitted
    provided that the above copyright notice and this paragraph are
    duplicated in all such forms and that any documentation,
    advertising materials, and other materials related to such
    distribution and use acknowledge that the software was developed
    by the University of California, Berkeley.  The name of the
    University may not be used to endorse or promote products derived
    from this software without specific prior written permission.
    THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
    WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

    ===== xz-5.8.4 =====


    XZ Utils Licensing
    ==================

        Different licenses apply to different files in this package. Here
        is a summary of which licenses apply to which parts of this package:

          - liblzma is under the BSD Zero Clause License (0BSD).

          - The command line tools xz, xzdec, lzmadec, and lzmainfo are
            under 0BSD except that, on systems that don't have a usable
            getopt_long, GNU getopt_long is compiled and linked in from the
            'lib' directory. The getopt_long code is under GNU LGPLv2.1+.

          - The scripts to grep, diff, and view compressed files have been
            adapted from GNU gzip. These scripts (xzgrep, xzdiff, xzless,
            and xzmore) are under GNU GPLv2+. The man pages of the scripts
            are under 0BSD; they aren't based on the man pages of GNU gzip.

          - Most of the XZ Utils specific documentation that is in
            plain text files (like README, INSTALL, PACKAGERS, NEWS,
            and ChangeLog) are under 0BSD unless stated otherwise in
            the file itself. The files xz-file-format.txt and
            lzma-file-format.xt are in the public domain but may
            be distributed under the terms of 0BSD too.

          - Translated messages and man pages are under 0BSD except that
            some old translations are in the public domain.

          - Test files and test code in the 'tests' directory, and
            debugging utilities in the 'debug' directory are under
            the BSD Zero Clause License (0BSD).

          - The GNU Autotools based build system contains files that are
            under GNU GPLv2+, GNU GPLv3+, and a few permissive licenses.
            These files don't affect the licensing of the binaries being
            built.

          - The 'extra' directory contains files that are under various
            free software licenses. These aren't built or installed as
            part of XZ Utils.

        The following command may be helpful in finding per-file license
        information. It works on xz.git and on a clean file tree extracted
        from a release tarball.

            sh build-aux/license-check.sh -v

        For the files under the BSD Zero Clause License (0BSD), if
        a copyright notice is needed, the following is sufficient:

            Copyright (C) The XZ Utils authors and contributors

        If you copy significant amounts of 0BSD-licensed code from XZ Utils
        into your project, acknowledging this somewhere in your software is
        polite (especially if it is proprietary, non-free software), but
        it is not legally required by the license terms. Here is an example
        of a good notice to put into "about box" or into documentation:

            This software includes code from XZ Utils <https://tukaani.org/xz/>.

        The following license texts are included in the following files:
          - COPYING.0BSD: BSD Zero Clause License
          - COPYING.LGPLv2.1: GNU Lesser General Public License version 2.1
          - COPYING.GPLv2: GNU General Public License version 2
          - COPYING.GPLv3: GNU General Public License version 3

        If you have questions, don't hesitate to ask for more information.
        The contact information is in the README file.


    ===== zlib-ng-2.3.3 =====

    (C) 1995-2024 Jean-loup Gailly and Mark Adler

    This software is provided 'as-is', without any express or implied
    warranty. In no event will the authors be held liable for any damages
    arising from the use of this software.

    Permission is granted to anyone to use this software for any purpose,
    including commercial applications, and to alter it and redistribute it
    freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
       misrepresented as being the original software.

    3. This notice may not be removed or altered from any source distribution.

### NSIS

Covers: NSIS 3.13, the Windows installer program, with its LZMA module under the Common Public License 1.0 and its special exception. This is NSIS's COPYING file as it ships.

    COPYRIGHT
    ---------

    Copyright (C) 1999-2026 Contributors

    More detailed copyright information can be found in the individual source code files.

    APPLICABLE LICENSES
    -------------------

    * All NSIS source code, plug-ins, documentation, examples, header files and graphics, with the exception of the compression modules and where otherwise noted, are licensed under the zlib/libpng license.

    * The zlib compression module for NSIS is licensed under the zlib/libpng license.

    * The bzip2 compression module for NSIS is licensed under the bzip2 license.

    * The LZMA compression module for NSIS is licensed under the Common Public License version 1.0.

    ZLIB/LIBPNG LICENSE
    -------------------

    This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

    Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:

          1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.

          2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.

          3. This notice may not be removed or altered from any source distribution.

    BZIP2 LICENSE
    -------------

    This program, "bzip2" and associated library "libbzip2", are copyright (C) 1996-2000 Julian R Seward. All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

          1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

          2. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.

          3. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.

          4. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Julian Seward, Cambridge, UK.

    jseward@acm.org

    COMMON PUBLIC LICENSE VERSION 1.0
    ---------------------------------

    THE ACCOMPANYING PROGRAM IS PROVIDED UNDER THE TERMS OF THIS COMMON PUBLIC LICENSE ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THE PROGRAM CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT.

    1. DEFINITIONS

    "Contribution" means:

          a) in the case of the initial Contributor, the initial code and documentation distributed under this Agreement, and
          b) in the case of each subsequent Contributor:

          i) changes to the Program, and

          ii) additions to the Program;

          where such changes and/or additions to the Program originate from and are distributed by that particular Contributor. A Contribution 'originates' from a Contributor if it was added to the Program by such Contributor itself or anyone acting on such Contributor's behalf. Contributions do not include additions to the Program which: (i) are separate modules of software distributed in conjunction with the Program under their own license agreement, and (ii) are not derivative works of the Program.

    "Contributor" means any person or entity that distributes the Program.

    "Licensed Patents " mean patent claims licensable by a Contributor which are necessarily infringed by the use or sale of its Contribution alone or when combined with the Program.

    "Program" means the Contributions distributed in accordance with this Agreement.

    "Recipient" means anyone who receives the Program under this Agreement, including all Contributors.

    2. GRANT OF RIGHTS

          a) Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, distribute and sublicense the Contribution of such Contributor, if any, and such derivative works, in source code and object code form.

          b) Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free patent license under Licensed Patents to make, use, sell, offer to sell, import and otherwise transfer the Contribution of such Contributor, if any, in source code and object code form. This patent license shall apply to the combination of the Contribution and the Program if, at the time the Contribution is added by the Contributor, such addition of the Contribution causes such combination to be covered by the Licensed Patents. The patent license shall not apply to any other combinations which include the Contribution. No hardware per se is licensed hereunder.

          c) Recipient understands that although each Contributor grants the licenses to its Contributions set forth herein, no assurances are provided by any Contributor that the Program does not infringe the patent or other intellectual property rights of any other entity. Each Contributor disclaims any liability to Recipient for claims brought by any other entity based on infringement of intellectual property rights or otherwise. As a condition to exercising the rights and licenses granted hereunder, each Recipient hereby assumes sole responsibility to secure any other intellectual property rights needed, if any. For example, if a third party patent license is required to allow Recipient to distribute the Program, it is Recipient's responsibility to acquire that license before distributing the Program.

          d) Each Contributor represents that to its knowledge it has sufficient copyright rights in its Contribution, if any, to grant the copyright license set forth in this Agreement.

    3. REQUIREMENTS

    A Contributor may choose to distribute the Program in object code form under its own license agreement, provided that:

          a) it complies with the terms and conditions of this Agreement; and

          b) its license agreement:

          i) effectively disclaims on behalf of all Contributors all warranties and conditions, express and implied, including warranties or conditions of title and non-infringement, and implied warranties or conditions of merchantability and fitness for a particular purpose;

          ii) effectively excludes on behalf of all Contributors all liability for damages, including direct, indirect, special, incidental and consequential damages, such as lost profits;

          iii) states that any provisions which differ from this Agreement are offered by that Contributor alone and not by any other party; and

          iv) states that source code for the Program is available from such Contributor, and informs licensees how to obtain it in a reasonable manner on or through a medium customarily used for software exchange.

    When the Program is made available in source code form:

          a) it must be made available under this Agreement; and

          b) a copy of this Agreement must be included with each copy of the Program.

    Contributors may not remove or alter any copyright notices contained within the Program.

    Each Contributor must identify itself as the originator of its Contribution, if any, in a manner that reasonably allows subsequent Recipients to identify the originator of the Contribution.

    4. COMMERCIAL DISTRIBUTION

    Commercial distributors of software may accept certain responsibilities with respect to end users, business partners and the like. While this license is intended to facilitate the commercial use of the Program, the Contributor who includes the Program in a commercial product offering should do so in a manner which does not create potential liability for other Contributors. Therefore, if a Contributor includes the Program in a commercial product offering, such Contributor ("Commercial Contributor") hereby agrees to defend and indemnify every other Contributor ("Indemnified Contributor") against any losses, damages and costs (collectively "Losses") arising from claims, lawsuits and other legal actions brought by a third party against the Indemnified Contributor to the extent caused by the acts or omissions of such Commercial Contributor in connection with its distribution of the Program in a commercial product offering. The obligations in this section do not apply to any claims or Losses relating to any actual or alleged intellectual property infringement. In order to qualify, an Indemnified Contributor must: a) promptly notify the Commercial Contributor in writing of such claim, and b) allow the Commercial Contributor to control, and cooperate with the Commercial Contributor in, the defense and any related settlement negotiations. The Indemnified Contributor may participate in any such claim at its own expense.

    For example, a Contributor might include the Program in a commercial product offering, Product X. That Contributor is then a Commercial Contributor. If that Commercial Contributor then makes performance claims, or offers warranties related to Product X, those performance claims and warranties are such Commercial Contributor's responsibility alone. Under this section, the Commercial Contributor would have to defend claims against the other Contributors related to those performance claims and warranties, and if a court requires any other Contributor to pay any damages as a result, the Commercial Contributor must pay those damages.

    5. NO WARRANTY

    EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is solely responsible for determining the appropriateness of using and distributing the Program and assumes all risks associated with its exercise of rights under this Agreement, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and unavailability or interruption of operations.

    6. DISCLAIMER OF LIABILITY

    EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

    7. GENERAL

    If any provision of this Agreement is invalid or unenforceable under applicable law, it shall not affect the validity or enforceability of the remainder of the terms of this Agreement, and without further action by the parties hereto, such provision shall be reformed to the minimum extent necessary to make such provision valid and enforceable.

    If Recipient institutes patent litigation against a Contributor with respect to a patent applicable to software (including a cross-claim or counterclaim in a lawsuit), then any patent licenses granted by that Contributor to such Recipient under this Agreement shall terminate as of the date such litigation is filed. In addition, if Recipient institutes patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Program itself (excluding combinations of the Program with other software or hardware) infringes such Recipient's patent(s), then such Recipient's rights granted under Section 2(b) shall terminate as of the date such litigation is filed.

    All Recipient's rights under this Agreement shall terminate if it fails to comply with any of the material terms or conditions of this Agreement and does not cure such failure in a reasonable period of time after becoming aware of such noncompliance. If all Recipient's rights under this Agreement terminate, Recipient agrees to cease use and distribution of the Program as soon as reasonably practicable. However, Recipient's obligations under this Agreement and any licenses granted by Recipient relating to the Program shall continue and survive.

    Everyone is permitted to copy and distribute copies of this Agreement, but in order to avoid inconsistency the Agreement is copyrighted and may only be modified in the following manner. The Agreement Steward reserves the right to publish new versions (including revisions) of this Agreement from time to time. No one other than the Agreement Steward has the right to modify this Agreement. IBM is the initial Agreement Steward. IBM may assign the responsibility to serve as the Agreement Steward to a suitable separate entity. Each new version of the Agreement will be given a distinguishing version number. The Program (including Contributions) may always be distributed subject to the version of the Agreement under which it was received. In addition, after a new version of the Agreement is published, Contributor may elect to distribute the Program (including its Contributions) under the new version. Except as expressly stated in Sections 2(a) and 2(b) above, Recipient receives no rights or licenses to the intellectual property of any Contributor under this Agreement, whether expressly, by implication, estoppel or otherwise. All rights in the Program not expressly granted under this Agreement are reserved.

    This Agreement is governed by the laws of the State of New York and the intellectual property laws of the United States of America. No party to this Agreement will bring a legal action under this Agreement more than one year after the cause of action arose. Each party waives its rights to a jury trial in any resulting litigation.

    SPECIAL EXCEPTION FOR LZMA COMPRESSION MODULE
    ---------------------------------------------

    Igor Pavlov and Amir Szekely, the authors of the LZMA compression module for NSIS, expressly permit you to statically or dynamically link your code (or bind by name) to the files from the LZMA compression module for NSIS without subjecting your linked code to the terms of the Common Public license version 1.0. Any modifications or additions to files from the LZMA compression module for NSIS, however, are subject to the terms of the Common Public License version 1.0.
