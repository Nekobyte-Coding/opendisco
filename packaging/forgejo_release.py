#!/usr/bin/env python3
"""The release workflow's side of a Forgejo draft release (.forgejo/workflows/release.yml).

    python3 packaging/forgejo_release.py download TAG FOLDER   # the draft's files into FOLDER
    python3 packaging/forgejo_release.py upload TAG FOLDER      # update-key, SHA256SUMS(.sig) onto it

Both refuse a release that's published already: signing happens on the draft, before anyone
can download it. Uploading replaces those three files if an earlier run left them.

FORGEJO_TOKEN (the job's token), FORGEJO_SERVER (https://git.nekohosting.moe) and FORGEJO_REPO
(nekobyte-coding/opendisco) say where. The tokens are only ever sent to that server.

Downloading a draft's files needs OPENDISCO_RELEASE_READ_TOKEN as well: Forgejo serves a draft's
files only to an account that can write releases, and the job's token doesn't count on those
download links (it does on the API, which lists the files but can't send them). That token is
used for those downloads only; finding the draft, uploading and deleting use the job's token.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

SIGNED = ("update-key", "SHA256SUMS", "SHA256SUMS.sig")


def api(method: str, path: str, data: bytes = None, content_type: str = "application/json"):
    server = os.environ["FORGEJO_SERVER"].rstrip("/")
    if not server.startswith("https://"):
        sys.exit("error: FORGEJO_SERVER must be https")
    request = urllib.request.Request(f"{server}/api/v1/repos/{os.environ['FORGEJO_REPO']}{path}", data=data,
                                     method=method, headers={"Authorization": f"token {os.environ['FORGEJO_TOKEN']}",
                                                             "Accept": "application/json",
                                                             **({"Content-Type": content_type} if data else {})})
    with urllib.request.urlopen(request, timeout=120) as r:
        body = r.read()
    return json.loads(body) if body else None


def draft(tag: str) -> dict:
    page = 1
    while True:
        releases = api("GET", f"/releases?draft=true&limit=50&page={page}")
        if not releases:
            break
        for release in releases:
            if release.get("tag_name") == tag:
                if not release.get("draft"):
                    sys.exit(f"error: {tag} is published already: sign it as a draft, before publishing")
                return release
        page += 1
    sys.exit(f"error: no draft release for {tag}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"refusing to follow a redirect ({code})", headers, fp)


def download(tag: str, folder: Path) -> None:
    read_token = os.environ.get("OPENDISCO_RELEASE_READ_TOKEN", "").strip()
    if not read_token:
        sys.exit("error: the repository secret OPENDISCO_RELEASE_READ_TOKEN isn't set: Forgejo serves a draft's "
                 "files only to an account that can write releases (see docs/UPDATES.md)")
    opener = urllib.request.build_opener(_NoRedirect)  # the token never follows a redirect elsewhere
    release = draft(tag)
    folder.mkdir(parents=True, exist_ok=True)
    server = urllib.parse.urlsplit(os.environ["FORGEJO_SERVER"]).hostname
    names = []
    for asset in release.get("assets") or []:
        name = asset["name"]
        if name in SIGNED:
            continue  # an earlier run's: written afresh
        if "/" in name or "\\" in name or name.startswith("."):
            sys.exit(f"error: the release has a file named {name!r}")
        url = asset["browser_download_url"]
        if urllib.parse.urlsplit(url).hostname != server:
            sys.exit(f"error: {name} isn't on {server}")
        request = urllib.request.Request(url, headers={"Authorization": f"token {read_token}"})
        try:
            r = opener.open(request, timeout=600)
        except urllib.error.HTTPError as e:
            sys.exit(f"error: downloading {name} failed: HTTP {e.code}"
                     + (": does OPENDISCO_RELEASE_READ_TOKEN belong to an account that can write releases, "
                        "with read:repository?" if e.code in (401, 403, 404) else ""))
        with r, open(folder / name, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        if (folder / name).stat().st_size != asset.get("size", -1):
            sys.exit(f"error: {name} came down at the wrong size")
        names.append(name)
    if not names:
        sys.exit(f"error: the draft for {tag} has no files: upload the installers first")
    print(f"{tag}: {len(names)} files")
    for name in sorted(names):
        print(f"  {name}")


def upload(tag: str, folder: Path) -> None:
    release = draft(tag)
    for asset in release.get("assets") or []:
        if asset["name"] in SIGNED:
            api("DELETE", f"/releases/{release['id']}/assets/{asset['id']}")
    for name in SIGNED:
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + (folder / name).read_bytes() \
            + f"\r\n--{boundary}--\r\n".encode()
        api("POST", f"/releases/{release['id']}/assets?name={urllib.parse.quote(name)}", body,
            f"multipart/form-data; boundary={boundary}")
        print(f"Uploaded {name}")


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in ("download", "upload"):
        sys.exit(__doc__)
    tag, folder = sys.argv[2], Path(sys.argv[3])
    (download if sys.argv[1] == "download" else upload)(tag, folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
