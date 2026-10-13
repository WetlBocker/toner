"""Palo Alto PAN-OS: ask the firewall for an API key with an administrator's user name and password.
The password is sent once, over HTTPS, in the body of the request (not in the address), and Toner keeps only the key it gets back."""
import xml.etree.ElementTree as ET

import requests
import urllib3

from core import proxy


def keygen(dev, username, password, timeout=20):
    """The API key for this administrator, from the firewall at dev['host']. Raises ValueError with a reason a person can act on."""
    username, password = (username or "").strip(), password or ""
    if not username or not password:
        raise ValueError("Enter the administrator's user name and password.")
    host, port = dev["host"], dev.get("port") or 443
    verify = bool(dev.get("verify_ssl"))
    if not verify:
        urllib3.disable_warnings()
    try:
        r = requests.post(f"https://{host}:{port}/api/", data={"type": "keygen", "user": username, "password": password},
                          verify=verify, timeout=timeout, **proxy.requests_kwargs(dev))
    except requests.exceptions.SSLError:
        raise ValueError("The firewall's certificate is not trusted. Untick 'Verify SSL certificate' on this tab to accept it, then try again.") from None
    except requests.exceptions.Timeout:
        raise ValueError(f"The firewall at {host}:{port} did not answer in {timeout} seconds.") from None
    except requests.exceptions.ConnectionError:
        raise ValueError(f"Could not reach the firewall at {host}:{port}. Check the address and port, and that its management interface allows HTTPS from this computer.") from None
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        root = None
    said = ((root.findtext(".//msg") or root.findtext(".//line") or "") if root is not None else "").strip()
    if root is not None and root.get("status") == "success" and (root.findtext(".//key") or "").strip():
        return root.findtext(".//key").strip()
    if r.status_code in (401, 403) or "credential" in said.lower() or "invalid" in said.lower():
        raise ValueError("The firewall refused that user name or password" + (f" ({said})" if said else f" (HTTP {r.status_code})") +
                         ". The administrator must be allowed to use the XML API (Device > Admin Roles).")
    if said:
        raise ValueError(f"The firewall answered: {said}")
    raise ValueError(f"The firewall did not give a key (HTTP {r.status_code}). Is this the management address of a Palo Alto firewall?")
