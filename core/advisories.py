"""Known vulnerabilities for the software a device runs (the Scanning section). The version the health checks read is looked up
at Cisco PSIRT openVuln (Cisco platforms, with the account's client id and secret from Settings > Scanning) or at NIST's NVD
(Fortinet, Juniper, Palo Alto, MikroTik, Arista, HPE), every CVE found is checked against CISA's known-exploited list and
FIRST's EPSS scores, and the answer becomes one row per check, like a health run. Lookups are cached for a day in the Global
file: many organizations run the same handful of versions, and Cisco rate-limits."""
import json
import re
import threading
from datetime import datetime, timedelta

import keyring
import requests

from core import db, proxy, quiet
from drivers.base import ERROR, FAIL, NA, OK, WARN, Driver, Result

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_URL = "https://apix.cisco.com/security/advisories/v2/OSType/{os}?version={version}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 30
CACHE_HOURS = 24

CISCO_OS = {"cisco_ios": "ios", "cisco_xe": "iosxe", "cisco_nxos": "nxos", "cisco_asa": "asa"}
CISCO_NAMES = {"ios": "IOS", "iosxe": "IOS XE", "nxos": "NX-OS", "asa": "ASA"}
NVD_CPE = {"fortinet": "fortinet:fortios", "juniper": "juniper:junos", "paloalto": "paloaltonetworks:pan-os",
           "mikrotik": "mikrotik:routeros", "arista": "arista:eos", "hpe": "arubanetworks:arubaos"}
SECRETS = {"psirt_id": "service:psirt-id", "psirt_secret": "service:psirt-secret", "nvd_key": "service:nvd-key"}
SOFTWARE, ADVISORIES, KEV = "software version", "advisories", "known exploited (CISA)"
NO_VERSION = "No version on record. Run the health checks first; they read it."
NO_SOURCE = "No advisory source for this vendor yet."
OFF = "Vulnerability lookups are off under Settings > Scanning."
NONE_FOUND = "No known advisories for this version"
NONE_KEV = "None of the advisories are on CISA's known exploited list"
CHECK_SETTINGS = "Check Settings > Scanning."
APP_TYPE = "The app at apiconsole.cisco.com must be of type Service with the Client Credentials grant; check the id and secret under Settings > Scanning."


def _said(r):
    """What an OAuth or Okta error answer says, in a few words: 'invalid_client: Invalid value for client_id'."""
    try:
        body = r.json()
    except ValueError:
        return f"HTTP {r.status_code}"
    code = body.get("error") or body.get("errorCode") or f"HTTP {r.status_code}"
    text = body.get("error_description") or body.get("errorSummary") or ""
    return f"{code}: {text}".rstrip(": ")


class LookupError_(Exception):
    """A source could not be asked, or refused: the message is shown as the row's reason."""


# ---------------------------------------------------------------- the account
def get_secret(kind):
    try:
        return keyring.get_password(db.SERVICE, SECRETS[kind]) or ""
    except Exception:
        quiet.ignored()
        return ""


def set_secret(kind, value):
    if value:
        db.set_secret(SECRETS[kind], value)
    else:
        db.delete_secret(SECRETS[kind])


def enabled():
    return bool(db.get_setting("scan_enabled"))


# ---------------------------------------------------------------- the version, as each source wants it
def cisco_os(dev):
    """Which PSIRT OS a Cisco device is asked about: its platform; without one, IOS XE for a 16.x or 17.x version, else IOS."""
    os_ = CISCO_OS.get(dev.get("platform") or "")
    if os_:
        return os_, False
    major = (db.software_of(dev)["version"].split(".", 1) + [""])[0]
    return ("iosxe" if major in ("16", "17") else "ios"), True


def cisco_version(version):
    """'17.09.04a' (as a Catalyst's show version table prints it) -> '17.9.4a', the form PSIRT answers to."""
    return re.sub(r"(?<![\d])0+(?=\d)", "", version.strip())


def cpe_version(vendor, version):
    """The version and update parts of a CPE match string. Juniper's '22.4R3-S2.1' is 22.4 with update r3-s2 (the build after the
    last dot is dropped); the rest lose a leading 'v' and are lowercased. shortcut: NVD's own CPE spellings vary per vendor, widen
    this when a vendor's lookups come back empty for versions that do have advisories."""
    v = version.strip().lower().lstrip("v").split(" ")[0].split(",")[0]
    if vendor == "juniper":
        m = re.match(r"^(\d+\.\d+)(r.*)?$", v)
        if m:
            upd = re.sub(r"\.\d+$", "", m.group(2) or "")
            return m.group(1), upd or "*"
    return v, "*"


# ---------------------------------------------------------------- the cache (Global file, one row per lookup, a day each)
def _cached(key, fetch):
    now = datetime.now()
    with db.within(db.GLOBAL):
        with db.connect() as c:
            row = c.execute("SELECT fetched_at, body FROM advisory_cache WHERE key=?", (key,)).fetchone()
    if row and datetime.strptime(row["fetched_at"], "%Y-%m-%d %H:%M:%S") > now - timedelta(hours=CACHE_HOURS):
        return json.loads(row["body"])
    got = fetch()
    with db.within(db.GLOBAL):
        with db.connect() as c:
            c.execute("INSERT OR REPLACE INTO advisory_cache(key, fetched_at, body) VALUES(?,?,?)",
                      (key, now.strftime("%Y-%m-%d %H:%M:%S"), json.dumps(got)))
    return got


def forget_cache():
    with db.within(db.GLOBAL):
        with db.connect() as c:
            c.execute("DELETE FROM advisory_cache")


# ---------------------------------------------------------------- the sources
def _get(url, host, **kw):
    try:
        return requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Toner", **kw.pop("headers", {})}, **proxy.web_kwargs(host), **kw)
    except requests.RequestException as e:
        raise LookupError_(f"{host}: {Driver.explain(e)}") from None


_token = {}                                                 # (id, secret) -> (expires_at, token); Cisco's tokens live an hour
_token_lock = threading.Lock()


def cisco_token(cid, secret):
    with _token_lock:
        got = _token.get((cid, secret))
        if got and got[0] > datetime.now():
            return got[1]
    try:
        r = requests.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret},
                          timeout=TIMEOUT, headers={"User-Agent": "Toner"}, **proxy.web_kwargs("id.cisco.com"))
    except requests.RequestException as e:
        raise LookupError_(f"Cisco PSIRT: {type(e).__name__} reaching id.cisco.com") from None
    if r.status_code in (400, 401, 403):
        raise LookupError_(f"Cisco PSIRT: sign-in rejected ({_said(r)}). {APP_TYPE}")
    if r.status_code != 200:
        raise LookupError_(f"Cisco PSIRT: HTTP {r.status_code} from id.cisco.com")
    tok = r.json().get("access_token") or ""
    if not tok:
        raise LookupError_(f"Cisco PSIRT: no token in the answer. {CHECK_SETTINGS}")
    with _token_lock:
        _token[(cid, secret)] = (datetime.now() + timedelta(minutes=50), tok)
    return tok


def psirt(os_, version, cid=None, secret=None):
    """[{id, title, cves, cvss, fixed, url}] from Cisco PSIRT openVuln for one OS and version."""
    cid, secret = cid if cid is not None else get_secret("psirt_id"), secret if secret is not None else get_secret("psirt_secret")
    if not cid or not secret:
        raise LookupError_(f"Cisco PSIRT: no client id and secret. {CHECK_SETTINGS}")

    def fetch():
        tok = cisco_token(cid, secret)
        r = _get(PSIRT_URL.format(os=os_, version=requests.utils.quote(version, safe="")), "apix.cisco.com",
                 headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"})
        if r.status_code in (404, 406):                     # Cisco's 'No data found' for a version with nothing published
            return []
        if r.status_code == 401:
            raise LookupError_(f"Cisco PSIRT: the token was refused. {CHECK_SETTINGS}")
        if r.status_code != 200:
            raise LookupError_(f"Cisco PSIRT: HTTP {r.status_code}")
        out = []
        for a in r.json().get("advisories") or []:
            try:
                score = float(a.get("cvssBaseScore") or 0)
            except ValueError:
                score = 0.0
            fixed = [f for f in (a.get("firstFixed") or []) if f and f != "NA"]
            out.append({"id": a.get("advisoryId") or "", "title": a.get("advisoryTitle") or "", "cves": [c for c in (a.get("cves") or []) if c.startswith("CVE-")],
                        "cvss": score, "sir": a.get("sir") or "", "fixed": fixed, "url": a.get("publicationUrl") or ""})
        return out
    return _cached(f"psirt:{os_}:{version}", fetch)


def nvd(vendor, version, key=None):
    """[{id, title, cves, cvss, fixed, url}] from NIST's NVD for one vendor's product and version: one entry per CVE."""
    product = NVD_CPE[vendor]
    ver, upd = cpe_version(vendor, version)
    key = key if key is not None else get_secret("nvd_key")

    def fetch():
        out, start = [], 0
        while True:
            r = _get(NVD_URL, "services.nvd.nist.gov", params={"virtualMatchString": f"cpe:2.3:o:{product}:{ver}:{upd}", "startIndex": start},
                     headers={"apiKey": key} if key else {})
            if r.status_code == 404:
                return []
            if r.status_code == 403:
                raise LookupError_("NVD: rate limit reached, try again in a minute (an API key under Settings > Scanning raises it)")
            if r.status_code != 200:
                raise LookupError_(f"NVD: HTTP {r.status_code}")
            body = r.json()
            for item in body.get("vulnerabilities") or []:
                cve = item.get("cve") or {}
                metrics = cve.get("metrics") or {}
                score = 0.0
                for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(k):
                        score = float(metrics[k][0].get("cvssData", {}).get("baseScore") or 0)
                        break
                title = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
                out.append({"id": cve.get("id") or "", "title": title.split(". ")[0][:160], "cves": [cve.get("id") or ""], "cvss": score, "sir": "",
                            "fixed": [], "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id') or ''}"})
            start += body.get("resultsPerPage") or len(out) or 1
            if start >= (body.get("totalResults") or 0) or not body.get("vulnerabilities"):
                return out
    return _cached(f"nvd:{product}:{ver}:{upd}", fetch)


def kev():
    """The CVE ids on CISA's known exploited vulnerabilities list (a set)."""
    def fetch():
        r = _get(KEV_URL, "www.cisa.gov")
        if r.status_code != 200:
            raise LookupError_(f"CISA KEV: HTTP {r.status_code}")
        return sorted(v.get("cveID") for v in r.json().get("vulnerabilities") or [] if v.get("cveID"))
    return set(_cached("kev", fetch))


def epss(cves):
    """{cve: probability 0..1} from FIRST's EPSS for these CVEs, in batches of 100. A failure leaves the scores out, never the scan."""
    out = {}
    cves = sorted(set(c for c in cves if c))
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            got = _cached("epss:" + ",".join(batch), lambda: _epss_fetch(batch))
        except LookupError_:
            quiet.ignored()
            continue
        out.update(got)
    return out


def _epss_fetch(batch):
    r = _get(EPSS_URL, "api.first.org", params={"cve": ",".join(batch)})
    if r.status_code != 200:
        raise LookupError_(f"EPSS: HTTP {r.status_code}")
    return {d["cve"]: float(d.get("epss") or 0) for d in r.json().get("data") or [] if d.get("cve")}


# ---------------------------------------------------------------- one device
def status_of(a, exploited):
    """FAIL when a CVE of the advisory is on CISA's list or CVSS is 9 or more, WARN from 7, OK below."""
    if a["cvss"] >= 9 or any(c in exploited for c in a["cves"]):
        return FAIL
    return WARN if a["cvss"] >= 7 else OK


def lookup(dev, creds=None):
    """(what was looked up, [advisories]) for a device, by its vendor and version; raises LookupError_ when a source refused.
    `creds` overrides the stored account: {'psirt_id', 'psirt_secret', 'nvd_key'} (the Settings page's Test)."""
    creds = creds or {}
    vendor, version = dev.get("vendor") or "", db.software_of(dev)["version"]
    if vendor == "cisco":
        os_, guessed = cisco_os(dev)
        v = cisco_version(version)
        what = f"{CISCO_NAMES[os_]} {v}" + (" (platform assumed from the version)" if guessed else "")
        return what, psirt(os_, v, creds.get("psirt_id"), creds.get("psirt_secret"))
    ver, upd = cpe_version(vendor, version)
    what = f"{NVD_CPE[vendor].split(':')[1]} {ver}" + (f" {upd}" if upd != "*" else "")
    return what, nvd(vendor, version, creds.get("nvd_key"))


# where a stored configuration backup states the software version, for a device whose checks have not recorded one
BACKUP_VERSION = {"fortinet": [r"^#config-version=\S+?-(\d+\.\d+\.\d+)-FW-build"],
                  "paloalto": [r'<config\b[^>]*\bdetail-version="([^"]+)"', r'<config\b[^>]*\bversion="([^"]+)"'],
                  "juniper": [r"^version (\S+);"]}


def version_from_backup(dev):
    """(version, when the backup was taken) read from the device's newest configuration backup, or ('', '')."""
    from core import backup
    patterns = BACKUP_VERSION.get(dev.get("vendor") or "")
    latest = backup.latest(dev.get("key") or dev["name"]) if patterns else None
    if not latest:
        return "", ""
    text = backup.get_text(latest["id"], latest.get("org")) or ""
    for rx in patterns:
        m = re.search(rx, text, re.M)
        if m:
            return m.group(1), latest.get("taken_at") or ""
    return "", ""


def scan(dev):
    """The Scanning rows of one device: the version lookups (versions) and the configuration hardening rules (core/hardening)."""
    from core import hardening
    return versions(dev) + hardening.scan(dev)


def versions(dev):
    """The version rows of one device: its software version (and whether it could be looked up), one row per advisory found,
    an 'advisories' row when none was, and the CISA known-exploited row."""
    name, org = dev["name"], dev.get("org")
    row = lambda check, status, value="", message="": Result(name, check, status, value, message, org=org)
    version, read_at = db.software_of(dev)["version"], db.software_of(dev)["read_at"]
    source = f", read {read_at[:10]}" if read_at else ""
    if not version:                                    # the checks have not read one: the newest backup may state it
        version, taken = version_from_backup(dev)
        if version:
            dev = {**dev, "sw_version": version}
            source = f", from the configuration backup of {taken[:10]}"
    vendor = dev.get("vendor") or ""
    if not enabled():
        return [row(SOFTWARE, NA, version, OFF)]
    if vendor != "cisco" and vendor not in NVD_CPE:
        return [row(SOFTWARE, NA, version, NO_SOURCE)]
    if not version:
        return [row(SOFTWARE, NA, "", NO_VERSION)]
    try:
        what, found = lookup(dev)
        exploited = kev() if found else set()
    except LookupError_ as e:
        return [row(SOFTWARE, ERROR, version, f"{version}: {e}")]
    scores = epss([c for a in found for c in a["cves"]])
    rows = [row(SOFTWARE, OK, version, what + source)]
    if not found:
        rows.append(row(ADVISORIES, OK, "", NONE_FOUND))
    for a in sorted(found, key=lambda a: (-a["cvss"], a["id"])):
        best = max((scores.get(c, 0) for c in a["cves"]), default=0)
        value = f"CVSS {a['cvss']:g}" + (f" · EPSS {best:.0%}" if best else "")
        message = a["title"] + (f" Fixed in {', '.join(a['fixed'][:3])}." if a["fixed"] else "")
        rows.append(row(a["id"], status_of(a, exploited), value, message.strip()))
    hot = sorted({c for a in found for c in a["cves"] if c in exploited})
    rows.append(row(KEV, FAIL if hot else OK, "", f"{', '.join(hot)} on CISA's known exploited list" if hot else NONE_KEV) if found else row(KEV, OK, "", NONE_KEV))
    return rows


def scan_all(devices, on_rows=None, workers=4):
    """scan() each device, a few at a time (the sources rate-limit); on_rows(rows) per device as they finish. Returns every row."""
    from concurrent.futures import ThreadPoolExecutor
    out = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for rows in ex.map(_safe_scan, devices):
            out.extend(rows)
            if on_rows:
                on_rows(rows)
    return out


def _safe_scan(dev):
    try:
        return scan(dev)
    except Exception as e:                                   # one device's surprise never ends the scan
        quiet.ignored()
        return [Result(dev["name"], SOFTWARE, ERROR, db.software_of(dev)["version"], f"Scan failed: {e}", org=dev.get("org"))]


def test(cid, secret, nvd_key=""):
    """Settings > Scanning's Test: ask PSIRT about one well-known version with these credentials. Returns the line to show."""
    try:
        forget_cache_for("psirt:iosxe:17.9.4a")
        found = psirt("iosxe", "17.9.4a", cid, secret)
    except LookupError_ as e:
        return str(e)
    line = f"Cisco PSIRT answered: {len(found)} advisor{'y' if len(found) == 1 else 'ies'} for IOS XE 17.9.4a."
    if nvd_key:
        try:
            forget_cache_for("nvd:fortinet:fortios:7.2.5:*")
            got = nvd("fortinet", "7.2.5", nvd_key)
            line += f" NVD answered: {len(got)} CVE{'s' if len(got) != 1 else ''} for FortiOS 7.2.5."
        except LookupError_ as e:
            line += f" {e}"
    return line


def forget_cache_for(key):
    with db.within(db.GLOBAL):
        with db.connect() as c:
            c.execute("DELETE FROM advisory_cache WHERE key=?", (key,))
