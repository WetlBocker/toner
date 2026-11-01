"""Who an IP address belongs to, from the registries' own RDAP service (the successor to whois): rdap.org sends the question on to
the right registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC). No key, no sign-up. The WHOIS Lookup window shows this first, and the
ipstack location under it when a key is saved (core/iplookup.py)."""
import ipaddress
import json
import urllib.error
import urllib.request

URL = "https://rdap.org/ip/{ip}"


def lookup(ip, timeout=10, opener=None):
    """The RDAP record for an address, as the dict the registry returns. ValueError for a bad address, LookupError when the
    registry has nothing or refuses, and the usual network errors when it cannot be reached."""
    ip = str(ipaddress.ip_address(str(ip).strip()))
    req = urllib.request.Request(URL.format(ip=ip), headers={"User-Agent": "Toner", "Accept": "application/rdap+json, application/json"})
    try:
        f = (opener or urllib.request.urlopen)(req, timeout=timeout)
        body = f.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise LookupError("no registry has a record for this address (a private or reserved one, most likely)") from None
        raise LookupError(f"the registry answered HTTP {e.code}") from None
    try:
        return json.loads(body)
    except ValueError:
        raise LookupError("the registry gave an answer Toner could not read") from None


def _entities(data, depth=0):
    """Every entity in a record, the nested ones too (an abuse contact is often inside the registrant)."""
    for ent in data.get("entities") or []:
        if isinstance(ent, dict):
            yield ent
            if depth < 3:
                yield from _entities(ent, depth + 1)


def _entity_names(data, role):
    """The names of the entities with a role ('registrant', 'abuse', 'administrative'), from their vCards."""
    out = []
    for ent in _entities(data):
        if role not in (ent.get("roles") or []):
            continue
        name = _vcard(ent, "fn") or ent.get("handle") or ""
        email = _vcard(ent, "email")
        if name or email:
            out.append(f"{name} <{email}>" if name and email else name or email)
    return list(dict.fromkeys(out))


def _vcard(ent, key):
    card = ent.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2:
        return ""
    for field in card[1]:
        if isinstance(field, list) and field and field[0] == key and len(field) >= 4:
            return str(field[3])
    return ""


def summary(data):
    """[(label, value)] of what matters: the network's name and range, who holds it, the country, the abuse contact, the registry."""
    if not isinstance(data, dict):
        return []
    rows = []
    name = data.get("name") or data.get("handle") or ""
    if name:
        rows.append(("Network", str(name)))
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        rows.append(("Range", f"{start} - {end}"))
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs:
        rows.append(("Prefix", ", ".join(f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in cidrs if c.get("length") is not None)))
    kind = data.get("type")
    if kind:
        rows.append(("Type", str(kind)))
    holders = _entity_names(data, "registrant")
    if holders:
        rows.append(("Holder", "; ".join(holders)))
    if data.get("country"):
        rows.append(("Country", str(data["country"])))
    abuse = _entity_names(data, "abuse")
    if abuse:
        rows.append(("Abuse contact", "; ".join(abuse)))
    port43 = data.get("port43")
    if port43:
        rows.append(("Registry", str(port43)))
    for ev in data.get("events") or []:
        if ev.get("eventAction") == "last changed" and ev.get("eventDate"):
            rows.append(("Last changed", str(ev["eventDate"])[:10]))
            break
    remarks = [" ".join(" ".join(r.get("description") or []).split()) for r in (data.get("remarks") or []) if r.get("description")]
    if remarks:
        rows.append(("Remarks", remarks[0][:200]))
    return rows
