# Run directly (python tests/test_fortifeed.py). Fortinet's advisory feed: RSS links, a CSAF document's digest, and the version match.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
from core import fortifeed as F

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

DOC = {"document": {"title": "Double free in signal handler"}, "product_tree": {},
       "vulnerabilities": [{"cve": "CVE-2026-106175",
         "product_status": {"known_affected": ["FortiOS >=7.6.0|<=7.6.8", "FortiOS 7.4 all versions", "FortiOS 7.2 all versions"],
                            "known_not_affected": ["FortiOS/ 8.0 all versions", "FortiOS-upcoming  7.6.9"]},
         "remediations": [{"details": "FortiOS 8.0: Not Applicable\nFortiOS 7.6: Upgrade to upcoming  7.6.9 or above\nFortiOS 7.4: Migrate to a fixed release", "category": "vendor_fix"}],
         "scores": [{"cvss_v3": {"baseScore": 2.1}}]}]}
U = "https://filestore.fortinet.com/fortiguard/psirt/csaf_double-free-in-signal-handler_fg-ir-26-182.json"
d = F.digest(DOC, U)
check("7.6.5 is inside the range, and the fix is its branch's", F.match(d, "v7.6.5")["fixed"] == ["7.6.9"] and F.match(d, "7.6.5")["id"] == "FG-IR-26-182" and F.match(d, "7.6.5")["cvss"] == 2.1)
check("a branch told to migrate has no version to name", F.match(d, "7.4.2")["fixed"] == [])
check("8.0.0 is listed not affected", F.match(d, "8.0.0") is None)
check("7.6.9 is past the range", F.match(d, "7.6.9") is None)
check("the advisory page is FortiGuard's", F.match(d, "7.6.5")["url"] == "https://fortiguard.fortinet.com/psirt/FG-IR-26-182")
check("no vulnerabilities key: no digest", F.digest({"document": {"title": "x"}, "product_tree": {}}, U) is None)
check("an unreadable form is not a match", F.match(F.digest({**DOC, "vulnerabilities": [{**DOC["vulnerabilities"][0], "product_status": {"known_affected": ["FortiOS something odd"]}}]}, U), "7.6.5") is None)
check("another product is not FortiOS", F.match(F.digest({**DOC, "vulnerabilities": [{**DOC["vulnerabilities"][0], "product_status": {"known_affected": ["FortiOS-6K7K 7.6 all versions"]}}]}, U), "7.6.5") is None)
check("no score: None, so it reads WARN", F.digest({**DOC, "vulnerabilities": [{**DOC["vulnerabilities"][0], "scores": []}]}, U)["cvss"] is None)
try: F.csaf_urls(b"<!DOCTYPE x><rss/>"); check("a DOCTYPE is refused", False)
except ValueError: check("a DOCTYPE is refused", True)
try: F.csaf_urls(b"<rss><channel>"); check("bad XML is refused", False)
except ValueError: check("bad XML is refused", True)
RSS = b"""<?xml version="1.0"?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>
<item><title>a</title><link>https://www.fortiguard.com/psirt/FG-IR-26-182</link><link>https://filestore.fortinet.com/csaf_a_fg-ir-26-182.json</link><link>https://filestore.fortinet.com/cvrf_a.xml</link></item>
<item><title>b</title><link>https://www.fortiguard.com/psirt/FG-IR-26-181</link><link>https://filestore.fortinet.com/csaf_b_fg-ir-26-181.json</link></item></channel></rss>"""
check("only the csaf_ links, in order", F.csaf_urls(RSS) == ["https://filestore.fortinet.com/csaf_a_fg-ir-26-182.json", "https://filestore.fortinet.com/csaf_b_fg-ir-26-181.json"], F.csaf_urls(RSS))

bad_doc = lambda **kw: F.digest({**DOC, "vulnerabilities": [{**DOC["vulnerabilities"][0], **kw}]}, U)
check("a non-dict vulnerability is no digest", F.digest({**DOC, "vulnerabilities": ["x"]}, U) is None and F.digest({**DOC, "vulnerabilities": 5}, U) is None)
check("odd scores, statuses and remediations are no digest", bad_doc(scores=["x"]) is None and bad_doc(scores=[{"cvss_v3": {"baseScore": "high"}}]) is None
      and bad_doc(product_status=["x"]) is None and bad_doc(remediations=[5]) is None and F.digest([], U) is None)
check("an unreadable range is not a match, and does not raise", F.match(bad_doc(product_status={"known_affected": ["FortiOS >=7.6.|<=7.6.8", "FortiOS <=7..8"]}), "7.6.5") is None)

print(f"\n{ok} passed, {bad} failed")
_sys.exit(1 if bad else 0)
