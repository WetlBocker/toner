"""Finding, downloading and installing new versions of Toner from its GitHub releases.

How it works
    A release is a GitHub release (tag v1.2.0) with the installer attached as Toner-Setup-1.2.0.exe. GitHub records a
    SHA-256 checksum for every uploaded file; a sidecar file named Toner-Setup-1.2.0.exe.sha256 also works.
    The installer is downloaded over HTTPS from GitHub only, its checksum is compared with the published one, and only
    then is it run (silently, per-user installs stay per-user). A download with no published checksum is never run.
    The checksum comes from the same release, so it protects against a corrupted or swapped download, not against
    someone who controls the repository.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests

from core import db, paths, proxy, trust
from core.version import REPO, VERSION

API = "https://api.github.com/repos/{repo}/releases/latest"
API_TAG = "https://api.github.com/repos/{repo}/releases/tags/{tag}"
KEEP = 3                                                        # installers kept in the updates folder, for going back
MANIFEST = "installers.json"                                    # their checksums, recorded when each was downloaded
ALLOWED_HOSTS = ("github.com", "githubusercontent.com")        # the installer may only come from these (and subdomains)
ALLOW_HTTP = False                                              # tests only
SETUP = re.compile(r"^Toner-Setup-(\d+(?:\.\d+){1,3})\.exe$", re.I)
CHUNK = 65536


class UpdateError(Exception):
    pass


@dataclass
class Release:
    version: str
    tag: str
    name: str = ""
    notes: str = ""
    page_url: str = ""
    published: str = ""
    asset_name: str = ""
    asset_url: str = ""
    asset_size: int = 0
    sha256: str = ""
    checksum_url: str = ""


# ---------------------------------------------------------------- versions
def parse(text):
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text or "")
    return tuple(int(p) for p in m.group(1).split(".")) if m else ()


def is_newer(latest, current=VERSION):
    a, b = parse(latest), parse(current)
    n = max(len(a), len(b))
    return bool(a) and a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


# ---------------------------------------------------------------- what is running
def frozen():
    return paths.frozen()


def app_dir():
    return paths.app_dir()


def installed_kind():
    """'installed' (set up with the installer), 'portable' (the installer's portable option: a copy that keeps its data
    beside it), 'unpacked' (files copied from somewhere, which cannot update itself) or 'source' (running from the code)."""
    if not frozen():
        return "source"
    if paths.is_portable():
        return "portable"
    return "installed" if any(f.lower().startswith("unins") and f.lower().endswith(".exe") for f in os.listdir(app_dir())) else "unpacked"


def can_self_update():
    """Installed and portable copies update themselves through the installer; the installer then keeps the same type."""
    return installed_kind() in ("installed", "portable")


def updates_dir():
    d = db.base_path().parent / "updates"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- finding a release
def _pick_hex(text, name=""):
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{64})\b(.*)$", line)
        if m and (not name or not m.group(2).strip() or name.lower() in m.group(2).lower()):
            return m.group(1).lower()
    return ""


def _proxies(url):
    """Settings > Proxy, unless About > Connect directly for updates is ticked."""
    return proxy.web_kwargs(urlparse(url).hostname, bool(db.get_setting("update_direct")))


def _ssl_reason(e):
    """The useful part of an SSLError, such as 'certificate verify failed: self-signed certificate in certificate chain'."""
    m = re.search(r"certificate verify failed: ([^()\]]+)", str(e))
    return ("the certificate was not trusted (" + m.group(1).strip() + ")") if m else str(e)[:120]


def fetch_latest(repo=REPO, timeout=10):
    """The newest published release, or None when the repository has none (or is private). Raises UpdateError."""
    return _fetch_release(API.format(repo=repo), timeout)


def fetch_version(version, repo=REPO, timeout=10):
    """The release of one version (tag v1.2.0), or None when there is no such release. Raises UpdateError."""
    return _fetch_release(API_TAG.format(repo=repo, tag="v" + version), timeout)


def _fetch_release(url, timeout):
    try:
        r = requests.get(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Toner"}, timeout=timeout,
                         **_proxies(url))
    except requests.exceptions.SSLError as e:
        raise UpdateError(f"Could not reach GitHub securely: {_ssl_reason(e)}. {trust.SSL_HINT}") from None
    except requests.RequestException as e:
        raise UpdateError(f"Could not reach GitHub: {type(e).__name__}: {str(e)[:120]}") from None
    if r.status_code == 404:
        return None
    if r.status_code in (403, 429):
        raise UpdateError("GitHub is limiting requests from this network. Try again in a while.")
    if r.status_code != 200:
        raise UpdateError(f"GitHub answered with an error (HTTP {r.status_code}).")
    try:
        j = r.json()
    except ValueError:
        raise UpdateError("GitHub sent an answer that could not be read.") from None
    tag = str(j.get("tag_name") or "")
    if not parse(tag):
        raise UpdateError(f"The latest release has a tag that is not a version number ({tag[:30]!r}).")
    rel = Release(version=".".join(map(str, parse(tag))), tag=tag, name=j.get("name") or tag, notes=j.get("body") or "",
                  page_url=j.get("html_url") or "", published=(j.get("published_at") or "")[:10])
    assets = j.get("assets") or []
    for a in assets:
        if SETUP.match(a.get("name") or ""):
            rel.asset_name, rel.asset_url, rel.asset_size = a["name"], a.get("browser_download_url") or "", int(a.get("size") or 0)
            digest = str(a.get("digest") or "")
            rel.sha256 = digest.split(":", 1)[1].lower() if digest.lower().startswith("sha256:") else ""
            break
    if rel.asset_name and not rel.sha256:
        for a in assets:
            if (a.get("name") or "").lower() in (rel.asset_name.lower() + ".sha256", "sha256sums.txt", "sha256sums"):
                rel.checksum_url = a.get("browser_download_url") or ""
                break
    return rel


def check(current=VERSION, repo=REPO, timeout=10):
    """('available', release) | ('current', release) | ('none', None)."""
    rel = fetch_latest(repo, timeout)
    if rel is None:
        return "none", None
    return ("available" if is_newer(rel.version, current) else "current"), rel


# ---------------------------------------------------------------- downloading
def _check_url(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if p.scheme != "https" and not (ALLOW_HTTP and p.scheme == "http"):
        raise UpdateError("The download address is not HTTPS, so it was not used.")
    if not any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS):
        raise UpdateError(f"The download comes from {host}, which is not GitHub. It was not used.")


def expected_hash(rel, timeout=15):
    if rel.sha256:
        return rel.sha256
    if rel.checksum_url:
        _check_url(rel.checksum_url)
        try:
            r = requests.get(rel.checksum_url, timeout=timeout, headers={"User-Agent": "Toner"},
                             **_proxies(rel.checksum_url))
            r.raise_for_status()
        except requests.RequestException as e:
            raise UpdateError(f"Could not fetch the checksum: {type(e).__name__}") from None
        got = _pick_hex(r.text, rel.asset_name)
        if got:
            return got
    raise UpdateError("This release does not publish a checksum for the installer, so it cannot be verified and "
                      "will not be installed automatically. Download it from the release page if you trust it.")


def download(rel, dest_dir=None, progress=None, cancel=None, timeout=30):
    """Download and verify the installer. Returns (path, sha256). Raises UpdateError."""
    if not rel.asset_url:
        raise UpdateError("This release has no installer attached.")
    _check_url(rel.asset_url)
    want = expected_hash(rel)
    dest_dir = str(dest_dir or updates_dir())
    os.makedirs(dest_dir, exist_ok=True)
    final = os.path.join(dest_dir, re.sub(r"[^\w.\-]", "_", rel.asset_name))
    part, h, got = final + ".part", hashlib.sha256(), 0
    try:
        with requests.get(rel.asset_url, stream=True, timeout=timeout, headers={"User-Agent": "Toner"},
                          **_proxies(rel.asset_url)) as r:
            r.raise_for_status()
            _check_url(r.url)                                   # after redirects, still GitHub
            total = int(r.headers.get("Content-Length") or rel.asset_size or 0)
            with open(part, "wb") as out:
                for block in r.iter_content(CHUNK):
                    if cancel is not None and cancel.is_set():
                        raise UpdateError("cancelled")
                    out.write(block)
                    h.update(block)
                    got += len(block)
                    if progress:
                        progress(got, total)
        if rel.asset_size and got != rel.asset_size:
            raise UpdateError(f"The download is {got} bytes but the release says {rel.asset_size}. It was discarded.")
        if h.hexdigest() != want:
            raise UpdateError("The download does not match its published checksum. It was discarded and not installed.")
        os.replace(part, final)
        _remember(dest_dir, rel.version, final, want)
    except requests.exceptions.SSLError as e:
        host = urlparse(getattr(getattr(e, "request", None), "url", "") or rel.asset_url).hostname or "GitHub"
        raise UpdateError(f"The download from {host} failed its security check: {_ssl_reason(e)}. {trust.SSL_HINT} "
                          f"Or download the installer from the release page.") from None
    except requests.RequestException as e:
        raise UpdateError(f"The download failed: {type(e).__name__}: {str(e)[:100]}") from None
    finally:
        if os.path.exists(part):
            try:
                os.remove(part)
            except OSError:
                pass
    return final, want


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------- installers kept for going back to an earlier version
def _read_manifest(folder=None):
    try:
        with open(os.path.join(str(folder or updates_dir()), MANIFEST), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_manifest(data, folder=None):
    try:
        with open(os.path.join(str(folder or updates_dir()), MANIFEST), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
    except OSError:
        pass


def _remember(folder, version, path, sha):
    """Record a verified download's checksum, so it can be checked again before it is ever run to go back."""
    data = _read_manifest(folder)
    data[version] = {"file": os.path.basename(path), "sha256": sha, "at": datetime.now().strftime("%Y-%m-%d")}
    _write_manifest(data, folder)


def installers():
    """The installers in the updates folder, newest version first: [{'version', 'path', 'sha256' ('' when it was downloaded
    before checksums were recorded), 'at' (the day it was downloaded)}]."""
    folder, data, out = updates_dir(), _read_manifest(), []
    for name in os.listdir(folder):
        m = SETUP.match(name)
        if not m:
            continue
        path = str(folder / name)
        rec = data.get(m.group(1)) or {}
        if rec.get("file") != name:
            rec = {}
        try:
            at = rec.get("at") or datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d")
        except OSError:
            continue
        out.append({"version": m.group(1), "path": path, "sha256": rec.get("sha256", ""), "at": at})
    return sorted(out, key=lambda i: parse(i["version"]), reverse=True)


def earlier(current=VERSION):
    """The kept installers of versions older than this one: what Toner can go back to."""
    return [i for i in installers() if is_newer(current, i["version"])]


def prune(keep=KEEP, spare=()):
    """Keep the installers of the `keep` newest versions and delete the rest. A downloaded update waiting to be installed
    does not count and is kept, as is any path in `spare`. Returns the versions removed."""
    pend = (db.get_setting("update_pending") or {}).get("path") or ""
    skip = {os.path.normcase(os.path.abspath(p)) for p in (pend, *spare) if p}
    counted = [i for i in installers() if os.path.normcase(os.path.abspath(i["path"])) not in skip]
    gone = []
    for i in counted[keep:]:
        try:
            os.remove(i["path"])
            gone.append(i["version"])
        except OSError:
            pass
    if gone:
        data = _read_manifest()
        for v in gone:
            data.pop(v, None)
        _write_manifest(data)
    return gone


def verify_installer(item, timeout=10):
    """Check a kept installer before it is run: against the checksum recorded when it was downloaded or, for one downloaded
    before checksums were recorded, against the one its GitHub release publishes. Raises UpdateError when it cannot be
    checked or does not match."""
    want = item.get("sha256") or ""
    if not want:
        try:
            rel = fetch_version(item["version"], timeout=timeout)
            want = expected_hash(rel) if rel else ""
        except UpdateError:
            want = ""
    try:
        ok = bool(want) and file_hash(item["path"]) == want
    except OSError:
        ok = False
    if not ok:
        raise UpdateError(f"The installer for {item['version']} could not be checked against its published checksum, so it was "
                          "not run. Connect to the internet and try again, or download it from the release page.")


def revert(item, current=VERSION):
    """Go back to a kept earlier version: check its installer, then run it over this copy. The version being left is skipped,
    so automatic updating does not install it again straight away (newer ones are still offered). Raises UpdateError."""
    verify_installer(item)
    db.set_setting("update_skip", current)
    db.set_setting("update_pending", {})                        # a downloaded newer update must not install on the next exit
    launch_installer(item["path"], relaunch=True)


# ---------------------------------------------------------------- a downloaded update waiting to be installed
def set_pending(rel, path, sha):
    db.set_setting("update_pending", {"version": rel.version, "path": path, "sha256": sha})


def clear_pending(delete=True):
    p = db.get_setting("update_pending") or {}
    db.set_setting("update_pending", {})
    if delete and p.get("path") and os.path.dirname(os.path.abspath(p["path"])) == str(updates_dir()):
        try:
            os.remove(p["path"])
        except OSError:
            pass


def pending(current=VERSION):
    """The downloaded, still-valid update, or None. A file that has gone, changed, or is not newer is forgotten."""
    p = db.get_setting("update_pending") or {}
    if not p.get("path"):
        return None
    try:
        if os.path.isfile(p["path"]) and file_hash(p["path"]) == p["sha256"] \
                and os.path.dirname(os.path.abspath(p["path"])) == str(updates_dir()):
            if is_newer(p["version"], current):
                return p
            clear_pending(delete=False)                         # installed by now: its installer is kept for going back
            return None
    except (OSError, KeyError):
        pass
    clear_pending()
    return None


def launch_installer(path, relaunch=True):
    """Start the installer detached, so it keeps running after Toner closes. It verifies nothing itself: call this only
    with a file whose checksum was checked (pending() re-checks it). Installers beyond the newest few are cleared first."""
    try:
        prune(spare=(path,))
    except OSError:
        pass
    args = [path, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/relaunch={1 if relaunch else 0}",
            f"/LOG={updates_dir() / 'install.log'}"]
    if installed_kind() == "portable":                          # update this folder in place, as a portable copy again
        args += ["/MODE=portable", f"/DIR={app_dir()}"]
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(args, close_fds=True, creationflags=flags, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def due(hours=24, now=None):
    """Has it been long enough since the last check?"""
    last = db.get_setting("update_last_check")
    try:
        return (now or datetime.now()) - datetime.strptime(last, "%Y-%m-%d %H:%M:%S") >= timedelta(hours=hours)
    except (ValueError, TypeError):
        return True


def mark_checked(now=None):
    db.set_setting("update_last_check", (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S"))
