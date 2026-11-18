"""The self-update: the release list and downloads from the update server, the X-Update-Key header,
the signed SHA256SUMS, the update key's store and rotation, URL checks and redirects.

    python3 -m unittest discover -s tests -v

A local HTTP server stands in for the update server (update.ALLOW_HTTP, for tests only). Signing
the test releases needs the cryptography package; the Ed25519 test vectors don't.
"""
import base64
import hashlib
import http.server
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from opendisco import __version__, signing, update, updatekey  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

KEY = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode()  # the install's key
OLD_KEY = base64.urlsafe_b64encode(b"o" * 32).rstrip(b"=").decode()
NEW_KEY = base64.urlsafe_b64encode(b"n" * 33).rstrip(b"=").decode()  # what the release carries
NEXT = "99.0.0"
TAG = f"v{NEXT}"
INSTALLER = f"OpenDisco-{NEXT}-linux.tar.gz"

# RFC 8032 section 7.1, tests 1, 2 and 3: (public key, message, signature)
VECTORS = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class Ed25519Vectors(unittest.TestCase):
    def test_rfc8032(self):
        for pub, msg, sig in VECTORS:
            pub, msg, sig = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
            self.assertTrue(signing.verify_pure(pub, msg, sig))
            self.assertTrue(signing.verify(pub, msg, sig))
            bad = bytearray(sig)
            bad[5] ^= 1
            self.assertFalse(signing.verify_pure(pub, msg, bytes(bad)))
            self.assertFalse(signing.verify_pure(pub, msg + b"x", sig))

    def test_rejects_bad_shapes(self):
        pub, msg, sig = (bytes.fromhex(v) for v in VECTORS[0])
        self.assertFalse(signing.verify_pure(pub[:31], msg, sig))
        self.assertFalse(signing.verify_pure(pub, msg, sig[:63]))
        s = int.from_bytes(sig[32:], "little") + signing._L  # a non-canonical S
        self.assertFalse(signing.verify_pure(pub, msg, sig[:32] + s.to_bytes(32, "little")))

    @unittest.skipIf(Ed25519PrivateKey is None, "needs cryptography")
    def test_agrees_with_cryptography(self):
        for n in range(5):
            key = Ed25519PrivateKey.generate()
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            msg = os.urandom(n * 37)
            sig = key.sign(msg)
            self.assertTrue(signing.verify_pure(pub, msg, sig))
            self.assertFalse(signing.verify_pure(pub, msg + b"!", sig))

    def test_committed_public_key(self):
        pub = signing.public_key()
        self.assertEqual(len(pub), 32)
        pem = (Path(__file__).resolve().parents[1] / "keys" / "opendisco-release-signing.pub.pem").read_text()
        der = base64.b64decode("".join(pem.strip().splitlines()[1:-1]))
        self.assertEqual(der[-32:], pub)  # the same key in both files


class Server:
    """The update server: answers only requests with an accepted X-Update-Key, records each request."""

    def __init__(self, files: dict, keys=(KEY,)):
        self.files, self.keys, self.seen = files, set(keys), []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                server.seen.append((self.path, self.headers.get("X-Update-Key"), self.headers.get("User-Agent")))
                if self.headers.get("X-Update-Key") not in server.keys:
                    self.send_error(404)
                    return
                if self.path.startswith("/redirect-same/"):
                    self.send_response(302)
                    self.send_header("Location", "/updates/opendisco/" + self.path.split("/", 2)[2])
                    self.end_headers()
                    return
                if self.path.startswith("/redirect-other/"):
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{self.server.server_port}/updates/opendisco/"
                                     + self.path.split("/", 2)[2])
                    self.end_headers()
                    return
                prefix = "/updates/opendisco/"
                data = server.files.get(self.path[len(prefix):]) if self.path.startswith(prefix) else None
                if data is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/updates/opendisco"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def release_files(signer, installer=b"new version" * 1000, extra=None, sign_with=None):
    files = {INSTALLER: installer, updatekey.NAME: (NEW_KEY + "\n").encode()}
    files.update(extra or {})
    sums = "".join(f"{hashlib.sha256(v).hexdigest()}  {k}\n" for k, v in sorted(files.items())).encode()
    out = {f"{TAG}/{k}": v for k, v in files.items()}
    out[f"{TAG}/SHA256SUMS"] = sums
    out[f"{TAG}/SHA256SUMS.sig"] = base64.b64encode((sign_with or signer).sign(sums)) + b"\n"
    listing = [{"tag": "v100.0.0-rc.1", "version": "100.0.0-rc.1", "prerelease": True, "assets": []},
               {"tag": TAG, "version": NEXT, "prerelease": False, "published_at": "2026-11-10T00:00:00Z",
                "html_url": "https://git.nekohosting.moe/nekobyte-coding/opendisco/releases/tag/" + TAG,
                "notes": "## New\n- things", "assets": [{"name": k, "size": len(v)} for k, v in files.items()]},
               {"tag": "v1.0.0", "version": "1.0.0", "prerelease": False, "assets": []}]
    out["releases.json"] = json.dumps(listing).encode()
    return out


@unittest.skipIf(Ed25519PrivateKey is None, "needs cryptography to sign test releases")
class Feed(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        public = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        patches = [mock.patch.object(update, "ALLOW_HTTP", True),
                   mock.patch.object(signing, "public_key", lambda *a: public)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.tmp = Path(tempfile.mkdtemp())
        self.key = updatekey.UpdateKey(KEY, "built-in")

    def serve(self, files, keys=(KEY,)):
        server = Server(files, keys)
        self.addCleanup(server.close)
        return server

    def fetch(self, server, key=None):
        key = key or self.key
        release = update.latest(key, server.url)
        asset = release.assets[INSTALLER]
        new_key = update.prepare(release, asset, key)
        path = update.download(asset, self.tmp, key)
        return release, path, new_key

    def test_list_and_download(self):
        server = self.serve(release_files(self.signer))
        release, path, new_key = self.fetch(server)
        self.assertEqual((release.version, release.tag, release.prerelease), (NEXT, TAG, False))
        self.assertTrue(release.newer)
        self.assertEqual(path.read_bytes(), b"new version" * 1000)
        self.assertEqual(new_key, NEW_KEY)
        self.assertFalse(list(self.tmp.glob("*.part")))

    def test_prereleases_only_when_asked(self):
        server = self.serve(release_files(self.signer))
        self.assertEqual(update.latest(self.key, server.url, prereleases=True).version, "100.0.0-rc.1")

    def test_key_header_on_every_request(self):
        server = self.serve(release_files(self.signer))
        self.fetch(server)
        self.assertGreaterEqual(len(server.seen), 5)  # list, sums, signature, update-key, installer
        for path, key, agent in server.seen:
            self.assertEqual(key, KEY, path)
            self.assertEqual(agent, f"OpenDisco/{__version__}")

    def test_wrong_key(self):
        server = self.serve(release_files(self.signer))
        with self.assertRaises(update.KeyRefused) as e:
            update.latest(updatekey.UpdateKey(OLD_KEY, "built-in"), server.url)
        self.assertIn("isn't accepted", str(e.exception))
        self.assertIn("by hand", str(e.exception))

    def test_no_key(self):
        server = self.serve(release_files(self.signer))
        with self.assertRaises(update.KeyRefused) as e:
            update.latest(None, server.url)
        self.assertIn("no update key", str(e.exception))
        self.assertEqual(server.seen, [])  # nothing asked without a key

    def test_unreachable(self):
        server = self.serve({})
        url = server.url
        server.close()
        with self.assertRaises(update.UpdateError) as e:
            update.latest(self.key, url, timeout=2)
        self.assertIn("couldn't reach the OpenDisco update server", str(e.exception))

    def test_bad_signature(self):
        other = Ed25519PrivateKey.generate()
        server = self.serve(release_files(self.signer, sign_with=other))
        with self.assertRaises(update.UpdateError) as e:
            self.fetch(server)
        self.assertIn("isn't signed", str(e.exception))
        self.assertFalse(any(self.tmp.iterdir()))

    def test_tampered_sums(self):
        files = release_files(self.signer)
        files[f"{TAG}/SHA256SUMS"] = files[f"{TAG}/SHA256SUMS"].replace(b"0", b"1", 1)
        server = self.serve(files)
        with self.assertRaises(update.UpdateError):
            self.fetch(server)

    def test_tampered_file(self):
        files = release_files(self.signer)
        files[f"{TAG}/{INSTALLER}"] = b"evil" * 2750
        server = self.serve(files)
        with self.assertRaises(update.UpdateError) as e:
            self.fetch(server)
        self.assertIn("doesn't match", str(e.exception))
        self.assertFalse(any(self.tmp.iterdir()))  # the partial download is gone

    def test_oversized_file(self):
        files = release_files(self.signer)
        files[f"{TAG}/{INSTALLER}"] += b"more"
        server = self.serve(files)
        with self.assertRaises(update.UpdateError) as e:
            self.fetch(server)
        self.assertIn("larger", str(e.exception))

    def test_tampered_update_key(self):
        files = release_files(self.signer)
        files[f"{TAG}/{updatekey.NAME}"] = (OLD_KEY + "\n").encode()
        server = self.serve(files)
        with self.assertRaises(update.UpdateError) as e:
            self.fetch(server)
        self.assertIn(updatekey.NAME, str(e.exception))

    def test_file_not_in_sums(self):
        files = release_files(self.signer)
        listing = json.loads(files["releases.json"])
        listing[1]["assets"].append({"name": f"OpenDisco-{NEXT}-linux-x86_64.AppImage", "size": 4})
        files["releases.json"] = json.dumps(listing).encode()
        files[f"{TAG}/OpenDisco-{NEXT}-linux-x86_64.AppImage"] = b"\x7fELF"
        server = self.serve(files)
        release = update.latest(self.key, server.url)
        asset = release.assets[f"OpenDisco-{NEXT}-linux-x86_64.AppImage"]
        with self.assertRaises(update.UpdateError) as e:
            update.prepare(release, asset, self.key)
        self.assertIn("isn't in the release's signed SHA256SUMS", str(e.exception))
        with self.assertRaises(update.UpdateError):
            update.download(asset, self.tmp, self.key)  # never without a checked hash

    def test_unsafe_names_dropped(self):
        files = release_files(self.signer)
        listing = json.loads(files["releases.json"])
        listing[1]["assets"] += [{"name": "../evil", "size": 1}, {"name": "a/b", "size": 1}]
        files["releases.json"] = json.dumps(listing).encode()
        release = update.latest(self.key, self.serve(files).url)
        self.assertEqual(set(release.assets), {INSTALLER, updatekey.NAME})
        with self.assertRaises(update.UpdateError):
            update.parse_sums(b"0" * 64 + b"  ../evil\n")

    def test_redirect_same_host(self):
        server = self.serve(release_files(self.signer))
        url = server.url.replace("/updates/opendisco", "/redirect-same")
        self.assertEqual(update.latest(self.key, url).version, NEXT)
        self.assertTrue(all(key == KEY for _, key, _ in server.seen))

    def test_redirect_other_host_refused(self):
        server = self.serve(release_files(self.signer))
        url = server.url.replace("/updates/opendisco", "/redirect-other")
        with self.assertRaises(update.UpdateError) as e:
            update.latest(self.key, url)
        self.assertIn("another address", str(e.exception))
        self.assertEqual(len(server.seen), 1)  # localhost was never asked

    def test_rotation_after_update(self):
        """The release's key waits until the new version opens, then replaces the stored one (0600)."""
        data = self.tmp / "data"
        updatekey._write(data / updatekey.NAME, KEY, "1.0.0")
        server = self.serve(release_files(self.signer))
        release, _, new_key = self.fetch(server)
        updatekey.stage(data, new_key, release.version)
        self.assertEqual(updatekey._read(data / updatekey.NAME)[0], KEY)  # not before it opens
        self.assertFalse(updatekey.promote(data, "98.0.0"))  # another version opened: dropped
        updatekey.stage(data, new_key, release.version)
        self.assertTrue(updatekey.promote(data, NEXT))
        self.assertEqual(updatekey._read(data / updatekey.NAME), (NEW_KEY, NEXT))
        self.assertFalse((data / updatekey.PENDING).exists())
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE((data / updatekey.NAME).stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(data.stat().st_mode), 0o700)
        with mock.patch.object(updatekey, "__version__", NEXT), mock.patch.object(updatekey, "RESOURCE",
                                                                                  self.tmp / "none"):
            self.assertEqual(updatekey.load(data).value, NEW_KEY)

    def find(self, server, key, github, github_signed=True, current=__version__):
        """update.find() with server as the default source and github standing in for GitHub
        (a Release, or an UpdateError it raises). A GitHub release's signature check passes
        when github_signed; the server's is checked for real. current: the running version."""
        real = update.verify_sums

        def verify(release, sent, timeout=30):
            if release.origin != "github":
                return real(release, sent, timeout)
            self.assertIsNone(sent)  # never the key
            if not github_signed:
                raise update.UpdateError("the release's SHA256SUMS isn't signed")
            return {}

        ask = mock.Mock(side_effect=github) if isinstance(github, Exception) else mock.Mock(return_value=github)
        with mock.patch.object(update, "DEFAULT_SOURCE", server.url), \
                mock.patch.dict(os.environ, {"OPENDISCO_UPDATE_URL": ""}), \
                mock.patch.object(update, "latest_github", ask), \
                mock.patch.object(update, "verify_sums", verify), \
                mock.patch.object(update, "__version__", current):
            release = update.find(key)
        ask.assert_called_once()  # GitHub is asked every time
        return release

    @staticmethod
    def github(version):
        return update.Release(version, version, "", "", {}, f"v{version}", origin="github")

    def test_both_newer_higher_wins(self):
        files = release_files(self.signer)
        release = self.find(self.serve(files), self.key, self.github("99.1.0"))
        self.assertEqual((release.version, release.origin), ("99.1.0", "github"))
        release = self.find(self.serve(files), self.key, self.github("98.0.0"))
        self.assertEqual((release.version, release.origin), (NEXT, ""))
        self.assertIn(INSTALLER, release.sums)  # a newer release's signature is checked already

    def test_tie_goes_to_the_server(self):
        release = self.find(self.serve(release_files(self.signer)), self.key, self.github(NEXT))
        self.assertEqual((release.version, release.origin), (NEXT, ""))

    def test_github_newer_but_unsigned(self):
        release = self.find(self.serve(release_files(self.signer)), self.key, self.github("99.1.0"),
                            github_signed=False)
        self.assertEqual((release.version, release.origin), (NEXT, ""))

    def test_server_up_to_date_github_newer(self):
        release = self.find(self.serve(release_files(self.signer)), self.key, self.github("99.1.0"), current=NEXT)
        self.assertEqual((release.version, release.origin), ("99.1.0", "github"))
        release = self.find(self.serve(release_files(self.signer)), self.key, self.github(NEXT), current=NEXT)
        self.assertFalse(release.newer)  # neither has anything newer: no update

    def test_server_fails_github_used(self):
        down = self.serve({})
        down.close()
        theirs = self.github("99.1.0")
        for files, key in ((release_files(self.signer), updatekey.UpdateKey(OLD_KEY, "built-in")),  # refused
                           (release_files(self.signer), None),  # no key built in
                           (release_files(self.signer, sign_with=Ed25519PrivateKey.generate()), self.key)):
            with self.subTest(key=key):
                self.assertIs(self.find(self.serve(files), key, theirs), theirs)
        self.assertIs(self.find(down, self.key, theirs), theirs)  # unreachable

    def test_github_fails_server_used(self):
        release = self.find(self.serve(release_files(self.signer)), self.key, update.UpdateError("GitHub's error"))
        self.assertEqual((release.version, release.origin), (NEXT, ""))

    def test_both_fail_gives_the_servers_error(self):
        with self.assertRaises(update.KeyRefused):
            self.find(self.serve(release_files(self.signer)), updatekey.UpdateKey(OLD_KEY, "built-in"),
                      update.UpdateError("GitHub's error"))

    def test_another_source_alone(self):
        server = self.serve(release_files(self.signer))
        with mock.patch.object(update, "latest_github", mock.Mock(side_effect=AssertionError("GitHub asked"))), \
                self.assertRaises(update.KeyRefused):
            update.find(updatekey.UpdateKey(OLD_KEY, "built-in"), server.url)


class GitHub(unittest.TestCase):
    def test_release_list_without_key(self):
        listing = {"tag_name": TAG, "name": f"OpenDisco {NEXT}", "body": "notes", "draft": False,
                   "prerelease": False, "html_url": f"https://github.com/{update.GITHUB_REPO}/releases/tag/{TAG}",
                   "assets": [{"name": INSTALLER, "size": 11000}, {"name": "../evil", "size": 1}]}
        calls = []

        def small(url, key, timeout, what, limit=update.MAX_SMALL, github=False):
            calls.append((url, key, github))
            return json.dumps(listing).encode()

        with mock.patch.object(update, "_small", small):
            release = update.latest_github()
        self.assertEqual(calls, [(f"{update.GITHUB_API}/latest", None, True)])
        self.assertEqual((release.version, release.origin), (NEXT, "github"))
        self.assertEqual(set(release.assets), {INSTALLER})
        asset = release.assets[INSTALLER]
        self.assertEqual(asset.url, f"https://github.com/{update.GITHUB_REPO}/releases/download/{TAG}/{INSTALLER}")
        self.assertEqual(asset.origin, "github")

    def test_no_key_header(self):
        seen = []

        class Opener:
            def open(self, request, timeout):
                seen.append(dict(request.header_items()))

        with mock.patch.object(update.urllib.request, "build_opener", lambda *handlers: Opener()):
            update._get(f"{update.GITHUB_API}/latest", updatekey.UpdateKey(KEY, "built-in"), 5, github=True)
        self.assertNotIn("X-update-key", seen[0])
        self.assertNotIn(KEY, json.dumps(seen[0]))

    def test_redirect_hosts(self):
        request = update.urllib.request.Request(f"https://github.com/{update.GITHUB_REPO}/releases/download/x/y")
        github, plain = update._SameHost(update.GITHUB_REDIRECTS), update._SameHost()
        for host in update.GITHUB_REDIRECTS:
            self.assertIsNotNone(github.redirect_request(request, None, 302, "Found", {}, f"https://{host}/a"))
            with self.assertRaises(update.UpdateError):
                plain.redirect_request(request, None, 302, "Found", {}, f"https://{host}/a")
            with self.assertRaises(update.UpdateError):
                github.redirect_request(request, None, 302, "Found", {}, f"http://{host}/a")
        with self.assertRaises(update.UpdateError):
            github.redirect_request(request, None, 302, "Found", {}, "https://evil.example/a")


class Keys(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.resource = self.tmp / "resource"
        patch = mock.patch.object(updatekey, "RESOURCE", self.resource)
        patch.start()
        self.addCleanup(patch.stop)

    def test_valid(self):
        self.assertTrue(updatekey.valid(KEY))
        self.assertTrue(updatekey.valid(KEY + "="))
        self.assertFalse(updatekey.valid(base64.urlsafe_b64encode(b"x" * 31).decode()))
        self.assertFalse(updatekey.valid(KEY + "+"))
        self.assertFalse(updatekey.valid(""))

    def test_never_shown(self):
        key = updatekey.UpdateKey(KEY, "built-in")
        for text in (str(key), repr(key), f"{key}", key.hint(), str([key])):
            self.assertNotIn(KEY, text)
            self.assertNotIn(KEY[:-4], text)
        self.assertEqual(key.hint(), "…" + KEY[-4:])

    def test_bundled_copied_on_first_run(self):
        self.resource.write_text(KEY + "\n")
        data = self.tmp / "data"
        self.assertEqual(updatekey.load(data).value, KEY)
        self.assertEqual(updatekey._read(data / updatekey.NAME), (KEY, __version__))
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE((data / updatekey.NAME).stat().st_mode), 0o600)

    def test_stored_kept_for_same_version(self):
        self.resource.write_text(KEY + "\n")
        data = self.tmp / "data"
        updatekey._write(data / updatekey.NAME, NEW_KEY, __version__)  # came with this version's update
        self.assertEqual(updatekey.load(data).value, NEW_KEY)

    def test_bundled_wins_after_install_by_hand(self):
        self.resource.write_text(NEW_KEY + "\n")
        data = self.tmp / "data"
        updatekey._write(data / updatekey.NAME, OLD_KEY, "1.0.0")
        self.assertEqual(updatekey.load(data).value, NEW_KEY)

    def test_none(self):
        self.assertIsNone(updatekey.load(self.tmp / "data"))

    def test_garbage_ignored(self):
        data = self.tmp / "data"
        data.mkdir()
        (data / updatekey.NAME).write_text("not a key\n")
        self.assertIsNone(updatekey.load(data))


class Sources(unittest.TestCase):
    def test_default(self):
        with mock.patch.dict(os.environ, {"OPENDISCO_UPDATE_URL": ""}):
            self.assertEqual(update.source(), "https://git.nekohosting.moe/updates/opendisco")

    def test_normalised(self):
        self.assertEqual(update.source("https://Git.Nekohosting.moe/updates/opendisco/"),
                         "https://git.nekohosting.moe/updates/opendisco")
        self.assertEqual(update.source("https://example.org:8443/u"), "https://example.org:8443/u")

    def test_refused(self):
        for url in ("http://git.nekohosting.moe/updates/opendisco", "ftp://x/y", "https://user:pw@example.org/u",
                    "https://user@example.org/u", "https://example.org/u?x=1", "https://example.org/u#f",
                    "https:///u", "https://exa mple.org/u", "https://example.org:99999/u", "file:///etc/passwd",
                    "https://example.org\\@evil/u", "https://example.org/a b"):
            with self.subTest(url=url), self.assertRaises(update.UpdateError) as e:
                update.source(url)
            self.assertNotIn("pw", str(e.exception))

    def test_env(self):
        with mock.patch.dict(os.environ, {"OPENDISCO_UPDATE_URL": "https://mirror.example/od"}):
            self.assertEqual(update.source(), "https://mirror.example/od")


class Versions(unittest.TestCase):
    def test_order(self):
        order = ["1.7.2", "1.8.0-alpha", "1.8.0-alpha.1", "1.8.0-alpha.beta", "1.8.0-beta.2", "1.8.0-beta.11",
                 "1.8.0-rc.1", "1.8.0", "v1.8.1", "1.10.0"]
        keys = [update.version_key(v) for v in order]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(update.version_key("1.8"), ())
        self.assertEqual(update.version_key("x1.8.0"), ())


if __name__ == "__main__":
    unittest.main()
