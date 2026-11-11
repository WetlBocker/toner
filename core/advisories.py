"""Known vulnerabilities for the software a device runs (the Scanning section). The version the health checks read is looked up
at Cisco PSIRT openVuln (Cisco platforms, with the account's client id and secret from Settings > Scanning) or at NIST's NVD
(Fortinet, Juniper, Palo Alto, MikroTik, Arista, HPE) and, for a Windows computer's exact build, at NVD's microsoft: products.
A FortiGate whose version NVD has nothing for is also looked up in Fortinet's advisory feed (core/fortifeed: CSAF files, one
a second; a partial read is kept in memory for an hour, not in the day cache). Every CVE found is checked against CISA's
known-exploited list and FIRST's EPSS scores, and the answer becomes one row per check, like a health run, followed by the
hardening rules (core/hardening). Lookups are cached for a day in the Global file: many organizations run the same handful of
versions, and Cisco rate-limits. An NVD answer of nothing is "could not confirm" (N/A), except for a Windows build, where it is clean."""
import json
import re
import threading
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta

import keyring
import requests

from core import db, fortifeed, proxy, quiet
from drivers.base import ERROR, FAIL, NA, OK, WARN, Driver, Result

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_URL = "https://apix.cisco.com/security/advisories/v2/OSType/{os}?version={version}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 30
CACHE_HOURS = 24

CISCO_OS = {"cisco_ios": "ios", "cisco_xe": "iosxe", "cisco_nxos": "nxos", "cisco_asa": "asa"}
CISCO_NVD = {"ios": "cisco:ios", "iosxe": "cisco:ios_xe", "nxos": "cisco:nx-os"}
CISCO_NAMES = {"ios": "IOS", "iosxe": "IOS XE", "nxos": "NX-OS", "asa": "ASA"}
NVD_CPE = {"fortinet": "fortinet:fortios", "juniper": "juniper:junos", "paloalto": "paloaltonetworks:pan-os",
           "mikrotik": "mikrotik:routeros", "arista": "arista:eos", "hpe": "arubanetworks:arubaos"}
OS_NAMES = {"fortinet": "FortiOS", "juniper": "Junos", "paloalto": "PAN-OS", "mikrotik": "RouterOS", "arista": "EOS", "hpe": "ArubaOS"}
# (is a server, build number) -> NVD's name under microsoft:, each tried live
WINDOWS_NVD = {**{(True, b): n for b, n in {"14393": "windows_server_2016", "17763": "windows_server_2019", "20348": "windows_server_2022",
                                            "25398": "windows_server_2022_23h2", "26100": "windows_server_2025"}.items()},
               **{(False, b): n for b, n in {"14393": "windows_10_1607", "17763": "windows_10_1809", "19044": "windows_10_21h2", "19045": "windows_10_22h2",
                                             "22621": "windows_11_22h2", "22631": "windows_11_23h2", "26100": "windows_11_24h2", "26200": "windows_11_25h2"}.items()}}
WINDOWS_BUILD = re.compile(r"\(build (\d+)(?:\.(\d+))?\)")
PAN_CSAF = "https://security.paloaltonetworks.com/csaf/{cve}"          # Palo Alto's advisory per CVE, with its title (NIST has none)
CISCO_ADVISORY = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{id}"
PAN_ADVISORY = "https://security.paloaltonetworks.com/{cve}"
FORTI_RSS = "https://www.fortiguard.com/rss/ir.xml"
FEED_HOST, FEED_SCHEMES, FEED_MAX = "filestore.fortinet.com", ("https",), 2_000_000      # where CSAF files may come from (tests point these at a fake server), and their size cap
FEED_DELAY = 1                                                           # seconds between Fortinet's CSAF files; tests set 0
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{cve}"
TITLE_MAX = 120                                                          # a NIST description's first sentence, cut to this


def advisory_url(check, vendor=""):
    """The page of an advisory row's id: Cisco's advisory, Palo Alto's own page for a CVE, else NIST's. '' for other rows."""
    if check.startswith("cisco-sa-"):
        return CISCO_ADVISORY.format(id=check)
    if re.match(r"^CVE-\d{4}-\d+$", check):
        return (PAN_ADVISORY if vendor == "paloalto" else NVD_PAGE).format(cve=check)
    if re.match(r"^FG-IR-\d+-\d+$", check):
        return fortifeed.PAGE.format(id=check)
    return ""


def pan_title(cve):
    """The advisory's title from Palo Alto's CSAF document for the CVE ('PAN-OS: Authentication Bypass in the Management Web
    Interface'), or '' when there is none or it cannot be read."""
    try:
        r = _get(PAN_CSAF.format(cve=cve), "security.paloaltonetworks.com")
        if r.status_code != 200:
            return ""
        notes = (r.json().get("document") or {}).get("notes") or []
        title = next((n.get("title") for n in notes if n.get("category") == "summary" and n.get("title")), "") or (notes[0].get("title") if notes else "")
        return (title or "").strip().rstrip(".")
    except (LookupError_, ValueError):
        return ""


SECRETS = {"psirt_id": "service:psirt-id", "psirt_secret": "service:psirt-secret", "nvd_key": "service:nvd-key"}
SOFTWARE, ADVISORIES, KEV = "Software version", "Advisories", "Known exploited (CISA)"
SEVERITY_BANDS = (("Low", 0, 4), ("Medium", 4, 7), ("High", 7, 9), ("Critical", 9, 10.01))     # CVSS: from <= score < to


UNSCORED = "CVSS not given"


def is_unscored(value):
    return (value or "").startswith(UNSCORED)


def cvss_of(value):
    """The CVSS score an advisory row's value states ('CVSS 7.5, EPSS 12%' -> 7.5), or None (fixed rows, hardening rules)."""
    m = re.search(r"CVSS\s+(\d+(?:\.\d+)?)", value or "")
    return float(m.group(1)) if m else None


NO_VERSION = "No version on record. Run the health checks first; they read it."
NO_SOURCE = "No advisory source for this vendor yet."
OFF = "Vulnerability lookups are off under Settings > Scanning."
NONE_FOUND = "No known advisories for this version"
COULD_NOT_CONFIRM = "NVD has no data for this version, so Toner could not confirm it is clean."
NO_PATCH = "The full Windows build is not known yet. Run the health checks; an older agent needs updating."
FROM_NVD = "from NVD (Cisco PSIRT was not available)"
FROM_FEED = "from Fortinet's advisory feed (its 50 newest advisories)"
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
    _partial.clear()
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
                score = float(a.get("cvssBaseScore"))
            except (TypeError, ValueError):
                score = None
            fixed = [f for f in (a.get("firstFixed") or []) if f and f != "NA"]
            out.append({"id": a.get("advisoryId") or "", "title": a.get("advisoryTitle") or "", "cves": [c for c in (a.get("cves") or []) if c.startswith("CVE-")],
                        "cvss": score, "sir": a.get("sir") or "", "fixed": fixed, "url": a.get("publicationUrl") or ""})
        return out
    return _cached(f"psirt:{os_}:{version}", fetch)


def _vtuple(v):
    """'11.1.4-h3' -> (11, 1, 4, 3), '11.1.4' -> (11, 1, 4, 0); None when it is not that shape (Junos '22.4R3-S2.1')."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)(?:-h(\d+))?$", v or "")
    return tuple(int(x) for x in m.group(1).split(".")) + (int(m.group(2) or 0),) if m else None


def fixed_from(cve, product, version):
    """The versions an NVD record says fix `version`: the versionEndExcluding of each range of the product that holds it, unless that
    very version is still listed as vulnerable. [] when the version cannot be compared. shortcut: one hotfix number, no letters."""
    have = _vtuple(version)
    if not have:
        return []
    ranges, listed = [], set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = (m.get("criteria") or "").split(":")
                if not m.get("vulnerable") or len(parts) < 6 or f"{parts[3]}:{parts[4]}" != product:
                    continue
                if parts[5] != "*":
                    listed.add(parts[5])
                elif m.get("versionEndExcluding"):
                    ranges.append(m)
    out = set()
    for m in ranges:
        end, lo, lo_x = _vtuple(m["versionEndExcluding"]), _vtuple(m.get("versionStartIncluding")), _vtuple(m.get("versionStartExcluding"))
        if end and have < end and not (lo and have < lo) and not (lo_x and have <= lo_x) and m["versionEndExcluding"] not in listed:
            out.add(m["versionEndExcluding"])
    return sorted(out, key=_vtuple)


_feed_lock = threading.Lock()
PARTIAL_SECONDS = 3600
_partial = {}                                               # 'fortifeed' -> (when, digests): a partial read, kept in memory for an hour so each FortiGate does not refetch 50 files

class _Partial(Exception):
    """Some CSAF files failed: carries what was read, which is used for this scan but not cached."""
    def __init__(self, got):
        self.got = got


def _csaf(url):
    """The JSON of one CSAF file, or None (429 when rate limited): only FEED_SCHEMES and FEED_HOST, no redirects, at most FEED_MAX bytes."""
    u = urlparse(url)
    if u.scheme not in FEED_SCHEMES or u.hostname != FEED_HOST:
        return None
    r = _get(url, FEED_HOST, allow_redirects=False, stream=True)
    try:
        if r.status_code == 429:
            return 429
        if r.status_code != 200:
            return None
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > FEED_MAX:
                return None
        return json.loads(body)
    except (requests.RequestException, ValueError):
        return None
    finally:
        r.close()


def fortinet_feed(version):
    """The advisories of Fortinet's feed (its newest 50) that list this FortiOS version. The digests are cached a day; the lock makes
    four scan threads fetch once. A CSAF file that cannot be read is skipped, and then the digests are not cached (a rate limit would
    hide advisories for a day); LookupError_ when the RSS itself cannot be read."""
    def fetch():
        r = _get(FORTI_RSS, "www.fortiguard.com")
        if r.status_code != 200:
            raise LookupError_(f"Fortinet: HTTP {r.status_code}")
        try:
            urls = fortifeed.csaf_urls(r.content)
        except ValueError as e:
            raise LookupError_(f"Fortinet: the feed could not be read ({e})") from None
        if not urls:
            raise LookupError_("Fortinet: the feed lists no advisories")
        out, failed, failed_429 = [], False, False
        for i, url in enumerate(urls):
            if failed_429:
                failed = True
                break
            if i:
                time.sleep(FEED_DELAY)                          # at most one file a second
            try:
                doc = _csaf(url)
            except LookupError_:
                doc = None
            if doc == 429:                                  # rate limited: the rest would be refused too
                failed_429, failed = True, True
                continue
            d = fortifeed.digest(doc, url) if isinstance(doc, dict) else None
            if d:
                out.append(d)
            elif not (isinstance(doc, dict) and not doc.get("vulnerabilities")):      # a readable file without vulnerabilities is no failure
                failed = True
        if failed:
            raise _Partial(out)
        return out
    with _feed_lock:
        held = _partial.get("fortifeed")
        if held and time.monotonic() - held[0] < PARTIAL_SECONDS:
            digests = held[1]
        else:
            try:
                digests = _cached("fortifeed", fetch)
            except _Partial as p:
                digests = p.got
                _partial["fortifeed"] = (time.monotonic(), digests)
    return [m for m in (fortifeed.match(d, version) for d in digests) if m]


def nvd(vendor, version, key=None):
    """[{id, title, cves, cvss, fixed, url}] from NIST's NVD for one vendor's product and version: one entry per CVE."""
    ver, upd = cpe_version(vendor, version)
    return nvd_cve(NVD_CPE[vendor], ver, upd, vendor, key)


def nvd_cve(product, ver, upd, vendor="", key=None, build=False):
    """The fetch behind nvd(): `product` is the CPE vendor:product, `ver` and `upd` its version parts; build=True writes the fixes as
    'build X' (Windows). cvss is None for a CVE NVD has not scored."""
    key = key if key is not None else get_secret("nvd_key")

    def fetch():
        out, start = [], 0
        while True:
            r = _get(NVD_URL, "services.nvd.nist.gov", params={"virtualMatchString": f"cpe:2.3:o:{product}:{ver}:{upd}", "startIndex": start},
                     headers={"apiKey": key} if key else {})
            if r.status_code == 404 and start == 0 and not build:     # a 404 elsewhere is not 'nothing': Windows answers by exact build, and a later page must not drop the rows read
                return []
            _nvd_status(r)
            body = r.json()
            out += [_nvd_entry(item.get("cve") or {}, product, ver, upd, vendor, build) for item in body.get("vulnerabilities") or []]
            start += body.get("resultsPerPage") or len(out) or 1
            if start >= (body.get("totalResults") or 0) or not body.get("vulnerabilities"):
                return out
    return _cached(f"nvd:{product}:{ver}:{upd}", fetch)


def _nvd_status(r):
    """Raise for an NVD answer that is not a page of results."""
    if r.status_code == 403:
        raise LookupError_("NVD: rate limit reached, try again in a minute (an API key under Settings > Scanning raises it)")
    if r.status_code != 200:
        raise LookupError_(f"NVD: HTTP {r.status_code}")


def _nvd_entry(cve, product, ver, upd, vendor="", build=False):
    """One advisory dict (see nvd()) from an NVD CVE record, its fixes worked out for `product` at `ver` `upd`."""
    metrics = cve.get("metrics") or {}
    score = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            base = metrics[k][0].get("cvssData", {}).get("baseScore")
            score = float(base) if base is not None else None
            break
    fixed = fixed_from(cve, product, ver if upd == "*" else ver + upd)
    desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "").split(". ")[0]
    summary = desc if len(desc) <= TITLE_MAX else desc[:TITLE_MAX - 1].rstrip() + "…"
    return {"id": cve.get("id") or "", "title": pan_title(cve.get("id") or "") if vendor == "paloalto" else "", "summary": summary,
            "cves": [cve.get("id") or ""], "cvss": score, "sir": "", "fixed": [f"build {x}" for x in fixed] if build else fixed, "url": NVD_PAGE.format(cve=cve.get("id") or "")}


def kev():
    """{CVE id: CISA's name for it} for CISA's known exploited vulnerabilities list."""
    def fetch():
        r = _get(KEV_URL, "www.cisa.gov")
        if r.status_code != 200:
            raise LookupError_(f"CISA KEV: HTTP {r.status_code}")
        return {v["cveID"]: v.get("vulnerabilityName") or "" for v in r.json().get("vulnerabilities") or [] if v.get("cveID")}
    got = _cached("kev", fetch)
    return got if isinstance(got, dict) else {c: "" for c in got}          # a list: cached by 1.11.1 to 1.11.3


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
    """FAIL when a CVE of the advisory is on CISA's list or CVSS is 9 or more, WARN from 7, OK below. No score: FAIL if on the list, else WARN."""
    if any(c in exploited for c in a["cves"]) or (a["cvss"] or 0) >= 9:
        return FAIL
    return WARN if a["cvss"] is None or a["cvss"] >= 7 else OK


def cisco_cpe(os_, version):
    """(NVD product, version) for a Cisco OS and version: parentheses are escaped for IOS and NX-OS, ASA's become dots, all lowercase."""
    v = cisco_version(version).lower()
    if os_ == "asa":
        return "cisco:adaptive_security_appliance_software", v.replace("(", ".").replace(")", ".").strip(".")
    return CISCO_NVD[os_], v.replace("(", r"\(").replace(")", r"\)")


def windows_cpe(software):
    """(NVD product, version) for a stored Windows software string such as 'Microsoft Windows Server 2022 Standard (build 20348.5760)', or
    None when it has no patch level or its build is not in WINDOWS_NVD. A server is told from a client by its name: builds are shared."""
    m = WINDOWS_BUILD.search(software or "")
    name = m and m.group(2) and WINDOWS_NVD.get(("server" in software[:m.start()].lower(), m.group(1)))
    return (f"microsoft:{name}", f"10.0.{m.group(1)}.{m.group(2)}") if name else None


def lookup(dev, creds=None):
    """(what was looked up, [advisories], confirmed) for a device, by its vendor and version; raises LookupError_ when no source could be
    asked. confirmed is False when the answer is NVD's nothing, which is not proof the version is clean. Cisco asks PSIRT first and NVD
    when PSIRT cannot answer. `creds` overrides the stored account: {'psirt_id', 'psirt_secret', 'nvd_key'} (the Settings page's Test)."""
    creds = creds or {}
    vendor, version = dev.get("vendor") or "", db.software_of(dev)["version"]
    if vendor == "cisco":
        os_, guessed = cisco_os(dev)
        v = cisco_version(version)
        what = f"{CISCO_NAMES[os_]} {v}" + (" (platform assumed from the version)" if guessed else "")
        try:
            return what, psirt(os_, v, creds.get("psirt_id"), creds.get("psirt_secret")), True
        except LookupError_ as e:
            try:
                product, ver = cisco_cpe(os_, v)
                found = nvd_cve(product, ver, "*", "cisco", creds.get("nvd_key"))
            except LookupError_:
                raise e from None
            return f"{what} {FROM_NVD}", found, bool(found)
    if vendor == "windows":                    # an exact patched build answers, so nothing found is a clean version
        product, ver = windows_cpe(version)
        return f"{product.split(':')[1].replace('_', ' ').title()} {ver}", nvd_cve(product, ver, "*", "windows", creds.get("nvd_key"), build=True), True
    ver, upd = cpe_version(vendor, version)
    what = f"{OS_NAMES[vendor]} {ver}" + (f" {upd}" if upd != "*" else "")
    try:
        found = nvd(vendor, version, creds.get("nvd_key"))
    except LookupError_ as e:
        if vendor != "fortinet":
            raise
        found, err = [], e
    else:
        err = None
    if found or vendor != "fortinet":
        return what, found, bool(found)
    try:
        feed = fortinet_feed(version)
    except LookupError_:
        feed = []
        if err:
            raise err from None
    if feed:
        return f"{what} {FROM_FEED}", feed, True
    if err:
        raise err
    return what, [], False


# where a stored configuration backup states the software version, for a device whose checks have not recorded one
BACKUP_VERSION = {"fortinet": [r"^#config-version=\S+?-(\d+\.\d+\.\d+)-FW-build"],
                  "paloalto": [r'<config\b[^>]*\bdetail-version="([^"]+)"', r'<config\b[^>]*\bversion="([^"]+)"'],
                  "juniper": [r"^version (\S+);"]}


def version_in(vendor, text):
    """The software version a configuration backup's text states, or ''."""
    for rx in BACKUP_VERSION.get(vendor or "", []):
        m = re.search(rx, text or "", re.M)
        if m:
            return m.group(1)
    return ""


def version_from_backup(dev):
    """(version, when the backup was taken) read from the device's newest configuration backup, or ('', '')."""
    from core import backup
    latest = backup.latest(dev.get("key") or dev["name"]) if dev.get("vendor") in BACKUP_VERSION else None
    if not latest:
        return "", ""
    version = version_in(dev.get("vendor"), backup.get_text(latest["id"], latest.get("org")))
    return (version, latest.get("taken_at") or "") if version else ("", "")


def scan(dev):
    """The Scanning rows of one device: the version lookups (versions) and the configuration hardening rules (core/hardening)."""
    from core import hardening
    return versions(dev) + hardening.scan(dev)


def _prepared(dev):
    """(dev, version, where it was read, None) for a device that can be looked up, or (dev, version, where, why not) when it cannot.
    A device whose checks have not read a version takes the one its newest configuration backup states (dev then carries it)."""
    version, read_at = db.software_of(dev)["version"], db.software_of(dev)["read_at"]
    source = f", read {read_at[:10]}" if read_at else ""
    if not version:                                    # the checks have not read one: the newest backup may state it
        version, taken = version_from_backup(dev)
        if version:
            dev = {**dev, "sw_version": version}
            source = f", from the configuration backup of {taken[:10]}"
    vendor = dev.get("vendor") or ""
    if not enabled():
        return dev, version, source, OFF
    if vendor != "cisco" and vendor != "windows" and vendor not in NVD_CPE:
        return dev, version, source, NO_SOURCE
    if not version:
        return dev, "", source, NO_VERSION
    if vendor == "windows":                    # Linux and macOS agents report as windows too: their OS text has no 'windows'
        if "windows" not in version.lower():
            return dev, version, source, NO_SOURCE
        m = WINDOWS_BUILD.search(version)
        if not m or not m.group(2):
            return dev, version, source, NO_PATCH
        if not windows_cpe(version):
            return dev, version, source, COULD_NOT_CONFIRM
    return dev, version, source, None


def versions(dev):
    """The version rows of one device: its software version (and whether it could be looked up), one row per advisory found,
    an 'advisories' row when none was, and the CISA known-exploited row."""
    name, org = dev["name"], dev.get("org")
    row = lambda check, status, value="", message="": Result(name, check, status, value, message, org=org)
    dev, version, source, why = _prepared(dev)
    if why:
        return [row(SOFTWARE, NA, version, why)]
    try:
        what, found, confirmed = lookup(dev)
        exploited = kev() if found else {}
    except LookupError_ as e:
        return [row(SOFTWARE, ERROR, version, f"{version}: {e}")]
    if not found and not confirmed:
        return [row(SOFTWARE, NA, version, COULD_NOT_CONFIRM)]
    scores = epss([c for a in found for c in a["cves"]])
    found = sorted(found, key=lambda a: (a["cvss"] is None, -(a["cvss"] or 0), a["id"]))
    statuses = [status_of(a, exploited) for a in found]
    worst = FAIL if FAIL in statuses else WARN if WARN in statuses else OK            # the version is as bad as its worst advisory
    bad = ", ".join(f"{statuses.count(s)} {s}" for s in (FAIL, WARN) if s in statuses)
    tail = (f", {len(found)} advisor{'y' if len(found) == 1 else 'ies'}" + (f": {bad}" if bad else "")) if found else ""
    rows = [row(SOFTWARE, worst, version, what + source + tail)]
    if not found:
        rows.append(row(ADVISORIES, OK, "", NONE_FOUND))
    for a, status in zip(found, statuses):
        best = max((scores.get(c, 0) for c in a["cves"]), default=0)
        value = (UNSCORED if a["cvss"] is None else f"CVSS {a['cvss']:g}") + (f", EPSS {best:.0%}" if best else "")
        # the vendor's title (Cisco, Palo Alto), else CISA's name when exploited, else the first sentence NIST gives
        title = a.get("title") or next((exploited[c] for c in a["cves"] if exploited.get(c)), "") or a.get("summary", "")
        message = title + (f" Fixed in {', '.join(a['fixed'][:3])}." if a["fixed"] else "")
        rows.append(row(a["id"], status, value, message.strip()))
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


# ---------------------------------------------------------------- Check CVEs: are the devices shown affected by these CVEs?
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
AFFECTED = "Affected: {what}. {score}, {fix}."
OUTSIDE = "Not affected: {what} is outside the affected versions."
NOT_LISTED = "Not affected: {cve} does not list {product}."
NOT_ANALYSED = "Cannot tell: NVD has not analysed {cve} yet."
NO_RECORD = "NVD has no record of {cve}."


def cve_ids(text):
    """Each CVE ID in `text` once, upper-cased, in the order given."""
    return list(dict.fromkeys(m.upper() for m in CVE_ID.findall(text or "")))


def nvd_record(cve, key=None):
    """What NVD says of one CVE: None when it has no record, {'parts': None} when it has not analysed it, else {'parts': {vendor:product:
    CPE part}} for the products its configurations name. Not cached: a check is asked for now, and NVD analyses CVEs every day."""
    key = key if key is not None else get_secret("nvd_key")
    r = _get(NVD_URL, "services.nvd.nist.gov", params={"cveId": cve}, headers={"apiKey": key} if key else {})
    _nvd_status(r)
    items = r.json().get("vulnerabilities") or []
    if not items:
        return None
    parts = {}
    for cfg in (items[0].get("cve") or {}).get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                f = (m.get("criteria") or "").split(":")
                if len(f) > 4:
                    parts.setdefault(f"{f[3]}:{f[4]}", f[2])
    return {"parts": parts or None}


def nvd_affects(cve, part, product, ver, upd, vendor="", key=None, build=False):
    """The advisory dict when NVD lists `cve` for this exact product and version, else None."""
    key = key if key is not None else get_secret("nvd_key")
    r = _get(NVD_URL, "services.nvd.nist.gov", params={"cveId": cve, "virtualMatchString": f"cpe:2.3:{part}:{product}:{ver}:{upd}"},
             headers={"apiKey": key} if key else {})
    _nvd_status(r)
    items = r.json().get("vulnerabilities") or []
    return _nvd_entry(items[0].get("cve") or {}, product, ver, upd, vendor, build) if items else None


def _affected(what, a, exploited):
    fix = f"fixed in {', '.join(a['fixed'][:3])}" if a["fixed"] else "no fix stated"
    status = status_of(a, exploited)
    details = AFFECTED.format(what=what, score=UNSCORED if a["cvss"] is None else f"CVSS {a['cvss']:g}", fix=fix)
    return (WARN if status == OK else status), details, a.get("url") or ""        # affected is never a green OK, however low the score


def check_cve(dev, version, cve, record, exploited):
    """(status, details, link) for whether `cve` affects this prepared device (see _prepared). `record(cve)` is nvd_record, asked once
    per CVE by the caller; `exploited()` is CISA's list. Cisco asks PSIRT first, Fortinet the feed when NVD cannot tell, as Scan does."""
    vendor, page = dev.get("vendor") or "", NVD_PAGE.format(cve=cve)
    if vendor == "cisco":
        os_, _guessed = cisco_os(dev)
        v = cisco_version(version)
        what, name = f"{CISCO_NAMES[os_]} {v}", CISCO_NAMES[os_]
        product, ver = cisco_cpe(os_, v)
        upd, build = "*", False
        try:
            hit = next((a for a in psirt(os_, v) if cve in a["cves"]), None)
        except LookupError_:
            hit = False                                  # PSIRT cannot answer: NVD below
        if hit:
            return _affected(what, hit, exploited())
        if hit is None:                                  # PSIRT answered for this version without it
            try:
                rec = record(cve)
            except LookupError_:
                rec = None
            listed = rec and rec["parts"]
            return OK, (NOT_LISTED.format(cve=cve, product=name) if listed and product not in listed else OUTSIDE.format(what=what)), page
    elif vendor == "windows":
        product, ver = windows_cpe(version)
        upd, build = "*", True
        name = product.split(":")[1].replace("_", " ").title()
        what = f"{name} {ver}"
    else:
        product, (ver, upd), build = NVD_CPE[vendor], cpe_version(vendor, version), False
        name = OS_NAMES[vendor]
        what = f"{name} {ver}" + (f" {upd}" if upd != "*" else "")
    rec = record(cve)
    if rec and rec["parts"]:
        if product not in rec["parts"]:
            return OK, NOT_LISTED.format(cve=cve, product=name), page
        hit = nvd_affects(cve, rec["parts"][product], product, ver, upd, vendor, build=build)
        return _affected(what, hit, exploited()) if hit else (OK, OUTSIDE.format(what=what), page)
    if vendor == "fortinet":                             # NVD cannot tell yet: Fortinet's own feed may
        try:
            hit = next((a for a in fortinet_feed(version) if cve in a["cves"]), None)
        except LookupError_:
            hit = None
        if hit:
            return _affected(what, hit, exploited())
    return NA, (NOT_ANALYSED if rec else NO_RECORD).format(cve=cve), page


def check_all(devices, cves, on_rows=None):
    """Check CVEs: [{device, cve, status, details, link}] for every device and CVE, one device at a time (NVD rate-limits);
    on_rows(rows) per device as it finishes. NVD is asked about each CVE once, whatever the number of devices."""
    records, kev_list = {}, []

    def record(cve):
        if cve not in records:
            try:
                records[cve] = nvd_record(cve)
            except LookupError_ as e:
                records[cve] = e
        if isinstance(records[cve], LookupError_):
            raise records[cve]
        return records[cve]

    def exploited():
        if not kev_list:
            try:
                kev_list.append(kev())
            except Exception:                            # the list is a bonus: without it, a score alone decides
                quiet.ignored()
                kev_list.append({})
        return kev_list[0]

    out = []
    for dev in devices:
        rows = []
        try:
            prepared, version, _source, why = _prepared(dev)
        except Exception as e:                           # one device's surprise never ends the check
            quiet.ignored()
            prepared, version, why = dev, "", f"Scan failed: {e}"
        for cve in cves:
            if why:
                status, details, link = NA, why, ""
            else:
                try:
                    status, details, link = check_cve(prepared, version, cve, record, exploited)
                except LookupError_ as e:
                    status, details, link = ERROR, f"{version}: {e}", NVD_PAGE.format(cve=cve)
                except Exception as e:
                    quiet.ignored()
                    status, details, link = ERROR, f"Scan failed: {e}", NVD_PAGE.format(cve=cve)
            rows.append({"device": dev["name"], "cve": cve, "status": status, "details": details, "link": link})
        out += rows
        if on_rows:
            on_rows(rows)
    return out


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
