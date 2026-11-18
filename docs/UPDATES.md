# How OpenDisco updates itself

OpenDisco checks for new versions and installs them from its own update server on the Git Box,
`https://git.nekohosting.moe/updates/opendisco`, first. This is a private download point, not
Forgejo's releases page, which sits behind a login. It works from any network. The server only
answers requests that carry OpenDisco's update key, and every release is signed with OpenDisco's
release key, which the app checks before it installs anything.

From 1.8.1, the app also checks the public GitHub releases of `Nekobyte-Coding/opendisco`, every
time, and installs the newest verified release of the two (see [GitHub](#github)). Both sources
are signature-checked the same way.

## What the app does

1. It reads `releases.json`, the server's list of releases (newest first: `tag`, `version`,
   `prerelease`, `published_at`, `html_url`, `notes`, `assets: [{name, size}]`). It picks the
   newest version, skipping pre-releases unless `"update_prereleases": true` is in settings.json.
   Versions are `X.Y.Z`, and a pre-release such as `1.8.0-rc.1` sorts before `1.8.0`.
2. When you choose Update, it downloads `<tag>/SHA256SUMS` and `<tag>/SHA256SUMS.sig` and checks
   the signature with the release public key built into the app
   (`src/opendisco/resources/release-signing.pub`). It refuses the release if the signature doesn't
   match.
3. It downloads this platform's installer (the same files as before: `.dmg`, `setup.exe`, `.deb`,
   `.rpm`, `.tar.gz`, `.AppImage` or `.apk`) and checks its SHA-256 against the signed
   `SHA256SUMS`. A file that is missing from that list, doesn't match it, or is larger than the
   release says is refused and deleted.
4. It downloads the release's `update-key`, checks it against `SHA256SUMS` too, and keeps it
   until the new version opens. The new version then makes it the install's key (see
   [Key rotation](#key-rotation)).
5. It installs the update the way this copy was installed, then reopens, just as before.

Every request sends the header `X-Update-Key: <key>` and a `User-Agent` of `OpenDisco/<version>`.
The app follows a redirect only when it stays on the same scheme, host and port (at most 3 times),
and never follows one to another host. The release list is limited to 1 MB, and `SHA256SUMS` and
the other small files to 64 KB.

### GitHub

Each check asks both the Git Box and GitHub
(`https://api.github.com/repos/Nekobyte-Coding/opendisco/releases/latest`, or the release list when
pre-releases are on), each with its own timeout. The app offers the higher version of the two; on
the same version, the Git Box's. A source is left out when it fails: no key built in (Git Box
only: a dev or test build), a refused key, no answer or a timeout, any other error status, an
unreadable release list, or a newer release whose `SHA256SUMS` isn't signed with the release key
(the check already looks at the signature when a release is newer). So when the newer of the two
fails its signature, the other one's release is offered if it is newer than this copy. There's
"no update" only when neither has anything newer. When both fail, the Git Box's error is shown.
The Log says what each source had.

- GitHub is **never sent the update key**: only `User-Agent` (and `Accept` on the API).
- A GitHub release is checked exactly like a Git Box one: `SHA256SUMS` and `SHA256SUMS.sig` are
  downloaded from the release's files, the signature is checked against the bundled release key,
  and the installer against `SHA256SUMS`. Nothing unverified is installed.
- Downloads come from `https://github.com/Nekobyte-Coding/opendisco/releases/download/<tag>/<file>`.
  Redirects are followed to `objects.githubusercontent.com` and
  `release-assets.githubusercontent.com` only, over https; any other host is refused, as before.
- With a custom update source (`update_source`, `OPENDISCO_UPDATE_URL`), only that source is asked.

**Each GitHub release must have `SHA256SUMS` and `SHA256SUMS.sig` attached**, the same files the
Release workflow made for the Forgejo release, next to the same installers. Without them, the
app passes over the GitHub release. Don't attach
`update-key` to the public release: the app does without it there (the install keeps its key, and
picks up a new one the next time it updates from the Git Box).

### What you see

- **Settings** shows `Updates: built-in key (…ABCD)` (at most the key's last 4 characters) or
  `Updates: no key`, with the update source below it.
- **A key the server refuses** (it answers 404, 401 or 403): *This install's update key isn't
  accepted. Install the latest release once by hand.*
- **No key at all** (a copy built without one): *This install has no update key. Install the latest
  release once by hand.* Nothing is sent to the server in that case.
- **No network:** *Couldn't reach the OpenDisco update server (…).*
- These messages appear only when GitHub fails too; when GitHub has the release, the update is
  offered as usual and the Log notes that the Git Box failed.

The key never goes into the Log, settings.json, an export, an error message or any screen, apart
from its last 4 characters in Settings. `UpdateKey`'s `str()` and `repr()` show only those 4.

### The update source

The default is `https://git.nekohosting.moe/updates/opendisco`. You can change it with the
`OPENDISCO_UPDATE_URL` environment variable or with `"update_source"` in settings.json. The address
must be `https://`, must name a host, and can't hold a user name, password (`user:pass@`), query or
fragment. A trailing `/` is removed.

## Where the key is kept

- **In the build:** `src/opendisco/resources/update-key` is written only while a release build runs
  and is removed after it (see `packaging/update_key.py`). It is in `.gitignore` and is never committed.
- **In the release:** a file named `update-key`, listed in `SHA256SUMS` and so covered by the signature.
- **In each install:** a file named `update-key` in the app's data folder, holding the key and, on a
  second line, the version it came with. The file is 0600, in a folder that is 0700 on macOS and
  Linux. On Windows the data folder belongs to that user; on Android it is in the app's private
  storage. On first run the app copies the key bundled in the build into that file. It also does so
  when you install a different version by hand, so a release installed by hand brings its own key.

### The honest limit

Anyone who has the app can pull the key out of it, so the key is not a secret for each customer.
What it does: it keeps scanners and anyone without OpenDisco off the update server, and it keeps
OpenDisco installs out of RFHeat's files (each product has its own key and folder). If a key
leaks, rotation cuts it off.

## Releasing a version (Michael)

1. **Build by hand**, with the update key available to the build scripts. On a Mac, keep it in the
   login keychain once:
   `security add-generic-password -a opendisco -s "OpenDisco Update Key" -w`
   (it asks for the value, so the key never appears on a command line). Anywhere else, set
   `OPENDISCO_UPDATE_KEY` in that shell. `build_dmg.py`, `build_installer.py`, `build_packages.py`
   and `build_apk.py` stop if they can't find a key, unless you pass `--no-update-key` for a test
   build, which can't update itself. The iOS build carries no key, because iOS has no self-update.
2. **Create a draft release** on Forgejo (nekobyte-coding/opendisco → Releases → New release, and
   tick "draft") with the tag, the notes and every installer from `dist/`.
3. **Run the Release workflow** (Actions → Release → Run workflow, tag `vX.Y.Z`). It downloads the
   draft's files (with the `OPENDISCO_RELEASE_READ_TOKEN` secret), adds `update-key` from the
   `OPENDISCO_UPDATE_KEY` secret, writes and signs `SHA256SUMS` with the `OPENDISCO_RELEASE_SIGNING_KEY` secret, checks the signature with the
   committed public key (and with openssl), and uploads `update-key`, `SHA256SUMS` and
   `SHA256SUMS.sig` to the draft. It refuses a release that is already published.
4. **Publish the release.** Within 5 minutes, the Git Box's sync checks the signature and puts the
   release on the update server.
5. **GitHub:** publish the same tag on `Nekobyte-Coding/opendisco` with the same
   installers plus `SHA256SUMS` and `SHA256SUMS.sig` from the signed Forgejo release (not
   `update-key`). Without both files, the app passes over the GitHub release.

A signed release holds the installers, plus:

| File | What it is |
| --- | --- |
| `update-key` | The update key that installs switch to after updating (one line, base64url) |
| `SHA256SUMS` | `<sha256 hex>  <file name>`, one line per file (sha256sum's format), sorted, covering every file except itself and `.sig` |
| `SHA256SUMS.sig` | The Ed25519 signature of `SHA256SUMS`'s exact bytes, as base64 on one line |

### The repository secrets

You add these secrets yourself, at nekobyte-coding/opendisco → Settings → Actions → Secrets:

- `OPENDISCO_UPDATE_KEY`: random, 32 bytes or more, base64url, for example
  `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` run on a box, never pasted in a chat.
  The same value goes into the Git Box's nginx map.
- `OPENDISCO_RELEASE_SIGNING_KEY`: the Ed25519 private key as a PKCS#8 PEM, the whole
  `-----BEGIN PRIVATE KEY-----` ... `-----END PRIVATE KEY-----` block, as `openssl genpkey -algorithm
  ed25519` writes it. Only the release workflow uses it. Michael keeps the
  private key and its backup; it is never in the repository.
- `OPENDISCO_RELEASE_READ_TOKEN`: an access token with the `read:repository` scope, from an account
  that can write this repository's releases. Forgejo serves a draft release's files only to such an
  account, and the job's own token isn't one on those download links (the API, where it is, lists a
  release's files but can't send them). The workflow uses it only to download the draft's files.

## The release key

- Public key, raw: `src/opendisco/resources/release-signing.pub` (32 bytes, base64, one line;
  this file ships in the app).
- Public key, PEM: `keys/opendisco-release-signing.pub.pem` (SubjectPublicKeyInfo, for openssl and
  the Git Box).
- Fingerprint: `9fa4b9b71ed68330` (the first 16 hex digits of the raw key's SHA-256).

This key is for OpenDisco only and is never shared with RFHeat. To check a release by hand, or in
the Git Box's sync:

```sh
openssl pkeyutl -verify -pubin -inkey keys/opendisco-release-signing.pub.pem -rawin \
    -in SHA256SUMS -sigfile <(base64 -d SHA256SUMS.sig)
sha256sum -c --strict SHA256SUMS
```

or `python3 packaging/sign_release.py --verify <folder>`.

## Key rotation

The Git Box's map (`/etc/nginx/update-keys/opendisco.map`) holds two keys: the current one and the
previous one.

1. Make a new key and add it to the map beside the current one, which becomes the previous one.
   Drop the key that was previous before.
2. Set `OPENDISCO_UPDATE_KEY` (and your keychain item) to the new key, then build and release as
   usual. Each install updates with its old key, picks up the new one from the release's
   `update-key`, and uses it from then on.
3. After about 30 days, take the old key out of the map. Installs that haven't updated by then get
   "This install's update key isn't accepted" and need one release installed by hand.

## Existing installs (1.7.2 and earlier)

Up to 1.7.2, OpenDisco checked GitHub only, without the key or a signature check, and couldn't
update while the GitHub account was suspended. **Install 1.8.0 or later once by hand**, the same
way as a fresh install, to move a copy onto signed updates. From then on, it updates itself (from
1.8.1, from the Git Box or GitHub, whichever has the newer verified release).

## What the Git Box needs

- The map entry `/etc/nginx/update-keys/opendisco.map` with the value of `OPENDISCO_UPDATE_KEY`.
- The OpenDisco sync entry: Forgejo `nekobyte-coding/opendisco` → `/srv/updates/opendisco/`.
- The release public key `keys/opendisco-release-signing.pub.pem` (fingerprint `9fa4b9b71ed68330`),
  for the sync's signature check (the command above).

## Tests

`python3 -m unittest discover -s tests -v` (`tests/test_update.py`) covers:

- the release list and downloads from a local stand-in server
- the key header on every request
- a wrong or missing key
- a bad signature, a tampered `SHA256SUMS`, file or `update-key`, a file missing from `SHA256SUMS`, and an oversized file
- unsafe file names
- key rotation after an update
- URL checks
- redirects on the same host (followed) and to another host (refused)
- both sources: the higher verified version wins, the Git Box on a tie, an unsigned newer release
  is passed over, one source down uses the other, both down gives the Git Box's error; GitHub is
  never sent the key; its release list and its redirect hosts
- the RFC 8032 test vectors, and agreement with `cryptography`
