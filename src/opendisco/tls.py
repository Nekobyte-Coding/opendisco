"""Certificate-checked HTTPS for what OpenDisco fetches from the internet (the NVD's CVE data).

Python finds the system's root certificates by itself on Windows (its certificate store), on
Linux (OpenSSL's folders) and on Android (Chaquopy loads a bundle it brings). The Python inside
the macOS app doesn't: its OpenSSL looks where python.org's installer puts certificates, a folder
that only exists after that installer's "Install Certificates" step, so every certificate check
fails. Where Python finds none, context() loads the system's own: macOS's /etc/ssl/cert.pem, or
the bundle or folder a Linux distribution or Android keeps them in. iOS keeps its root
certificates where no app can read them, so the iOS app brings certifi's list (Mozilla's).

Standard library only, plus certifi in the iOS app.
"""
from __future__ import annotations

import os
import ssl
import threading
import urllib.request

# The system's root certificates: bundles (macOS and most Linux distributions), then folders of
# single certificates (Android, newest first; Linux)
CA_FILES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/ca-bundle.pem")
CA_DIRS = ("/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts", "/etc/ssl/certs")

_context = None
_lock = threading.Lock()


def _python_finds_them(ctx: ssl.SSLContext) -> bool:
    if ctx.cert_store_stats()["x509_ca"]:
        return True  # loaded: Windows' store, Chaquopy's bundle, or OpenSSL's own file
    folder = ssl.get_default_verify_paths().capath  # read only as certificates are needed
    try:
        return bool(folder and any(name.endswith(".0") for name in os.listdir(folder)))
    except OSError:
        return False


def _read_folder(folder: str) -> str:
    """Every certificate file in a folder, as one text. Android names its files by OpenSSL's old
    subject hash, so OpenSSL can't look them up there itself."""
    texts = []
    try:
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                with open(path, encoding="ascii", errors="ignore") as f:
                    texts.append(f.read())
    except OSError:
        pass
    return "\n".join(texts)


def _load_system_roots(ctx: ssl.SSLContext) -> str | None:
    """Load the first of CA_FILES or CA_DIRS that has certificates; where they came from."""
    for path in CA_FILES:
        try:
            ctx.load_verify_locations(cafile=path)
        except (OSError, ssl.SSLError):
            continue
        if ctx.cert_store_stats()["x509_ca"]:
            return path
    for folder in CA_DIRS:
        pem = _read_folder(folder)
        if "-----BEGIN CERTIFICATE-----" in pem:
            try:
                ctx.load_verify_locations(cadata=pem)
            except (ssl.SSLError, ValueError):
                continue
            if ctx.cert_store_stats()["x509_ca"]:
                return folder
    return None


def _load_bundled_roots(ctx: ssl.SSLContext) -> str | None:
    """certifi's root certificates, where the app brings them (iOS); where they came from."""
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError, ssl.SSLError):
        return None
    return certifi.where() if ctx.cert_store_stats()["x509_ca"] else None


def context() -> ssl.SSLContext:
    """A default, certificate-checking SSL context that trusts the system's root certificates."""
    global _context
    with _lock:
        if _context is None:
            ctx = ssl.create_default_context()
            if not _python_finds_them(ctx):
                _load_system_roots(ctx) or _load_bundled_roots(ctx)
            _context = ctx
        return _context


def urlopen(request, timeout: float):
    """urllib.request.urlopen with context()."""
    return urllib.request.urlopen(request, timeout=timeout, context=context())
