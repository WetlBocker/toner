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

from core import db, paths, proxy
from core.version import REPO, VERSION

API = "https://api.github.com/repos/{repo}/releases/latest"
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
    d = db.db_path().parent / "updates"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- finding a release
def _pick_hex(text, name=""):
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{64})\b(.*)$", line)
        if m and (not name or not m.group(2).strip() or name.lower() in m.group(2).lower()):
            return m.group(1).lower()
    return ""


def fetch_latest(repo=REPO, timeout=10):
    """The newest published release, or None when the repository has none (or is private). Raises UpdateError."""
    url = API.format(repo=repo)
    try:
        r = requests.get(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Toner"}, timeout=timeout,
                         **proxy.requests_kwargs(None, urlparse(url).hostname))
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
                             **proxy.requests_kwargs(None, urlparse(rel.checksum_url).hostname))
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
                          **proxy.requests_kwargs(None, urlparse(rel.asset_url).hostname)) as r:
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
        if is_newer(p["version"], current) and os.path.isfile(p["path"]) and file_hash(p["path"]) == p["sha256"] \
                and os.path.dirname(os.path.abspath(p["path"])) == str(updates_dir()):
            return p
    except (OSError, KeyError):
        pass
    clear_pending()
    return None


def launch_installer(path, relaunch=True):
    """Start the installer detached, so it keeps running after Toner closes. It verifies nothing itself: call this only
    with a file whose checksum was checked (pending() re-checks it)."""
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
