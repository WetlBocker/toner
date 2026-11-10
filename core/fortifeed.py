"""Fortinet's PSIRT advisory feed, read without the network: the RSS item links to each CSAF file, a CSAF file boiled down to what
matching a FortiOS version needs, and the match itself. core/advisories.py fetches and caches."""
import re
import xml.etree.ElementTree as ET

PAGE = "https://fortiguard.fortinet.com/psirt/{id}"
_ID = re.compile(r"fg-ir-\d+-\d+", re.I)


def csaf_urls(rss: bytes) -> list:
    """The csaf_ link of each RSS item, in order (an item also links its page and its CVRF file). ValueError on a DOCTYPE or bad XML."""
    if re.search(rb"<!(DOCTYPE|ENTITY)", rss, re.I):          # no entity expansion from a feed
        raise ValueError("the feed has a DOCTYPE")
    try:
        root = ET.fromstring(rss)
    except ET.ParseError as e:
        raise ValueError(str(e)) from None
    return [(e.text or "").strip() for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "link" and "csaf_" in (e.text or "")]


def _forms(statuses):
    """The affected FortiOS forms of a product_status list: ['branch', 'X.Y'], ['range', lo|None, hi], ['exact', 'X.Y.Z']. Other products
    (FortiOS-6K7K, FortiOS-upcoming) and forms not understood give nothing."""
    out = []
    for s in statuses or []:
        m = re.match(r"^FortiOS[/ ]\s*(.+)$", s.strip())
        if not m:
            continue
        t = m.group(1).strip()
        for pat, make in ((r"^(\d+\.\d+) all versions$", lambda g: ["branch", g[0]]), (r"^>=(\d+(?:\.\d+)*)\|<=(\d+(?:\.\d+)*)$", lambda g: ["range", g[0], g[1]]),
                          (r"^<=(\d+(?:\.\d+)*)$", lambda g: ["range", None, g[0]]), (r"^(\d+\.\d+\.\d+)$", lambda g: ["exact", g[0]])):
            f = re.match(pat, t)
            if f:
                out.append(make(f.groups()))
                break
    return out


def digest(doc: dict, url: str):
    """{id, title, cves, cvss, affected, remediation} from a CSAF document, or None when it has no vulnerabilities or its url no id."""
    try:
        return _digest(doc, url)
    except (AttributeError, TypeError, KeyError, ValueError):       # a document of an unexpected shape is no digest
        return None


def _digest(doc, url):
    vulns = doc.get("vulnerabilities") or []
    m = _ID.search(url)
    if not vulns or not m:
        return None
    scores = [s["baseScore"] for v in vulns for sc in v.get("scores") or [] for s in sc.values() if isinstance(s, dict) and s.get("baseScore") is not None]
    return {"id": m.group(0).upper(), "title": (doc.get("document") or {}).get("title") or "", "cves": [v["cve"] for v in vulns if v.get("cve")],
            "cvss": float(max(scores)) if scores else None,
            "affected": [f for v in vulns for f in _forms((v.get("product_status") or {}).get("known_affected"))],
            "remediation": "\n".join(r.get("details") or "" for v in vulns for r in v.get("remediations") or [] if r.get("category") == "vendor_fix")}


def _tuple(v):
    return tuple(int(x) for x in v.split("."))


def match(d, version: str):
    """The advisory dict for FortiOS `version` when the digest lists it as affected, else None. `fixed` is the release the digest names for
    the version's branch, [] when it only says to migrate."""
    v = (version or "").strip().lstrip("v")
    if not d or not re.match(r"^\d+\.\d+(\.\d+)*$", v):
        return None
    have, branch = _tuple(v), ".".join(v.split(".")[:2])
    for f in d["affected"]:
        if f[0] == "branch" and f[1] == branch or f[0] == "exact" and f[1] == v \
                or f[0] == "range" and (f[1] is None or _tuple(f[1]) <= have) and have <= _tuple(f[2]):
            break
    else:
        return None
    line = next((x for x in d["remediation"].splitlines() if re.match(rf"^FortiOS {re.escape(branch)}:", x.strip())), "")
    fixed = re.findall(r"\d+\.\d+\.\d+", line) if "upgrade" in line.lower() else []
    return {"id": d["id"], "title": d["title"], "summary": "", "cves": d["cves"], "cvss": d["cvss"], "sir": "", "fixed": fixed[:1],
            "url": PAGE.format(id=d["id"])}
