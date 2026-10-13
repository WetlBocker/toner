"""Proxmox VE: make an API token with an administrator's user name and password.
Toner signs in once (the password goes in the body of an HTTPS request and is not kept), creates a token called "toner", and gives that token
the read-only PVEAuditor role on / so it can read what Toner checks and nothing else. Only the token is returned."""
import time
from urllib.parse import quote

import requests
import urllib3

from core import proxy

DEFAULT_PORT = 8006
ROLE = "PVEAuditor"


def _fail(r, what):
    """A readable reason from a Proxmox answer that was not a success."""
    said = ""
    try:
        body = r.json()
        errs = body.get("errors")
        said = (", ".join(f"{k}: {v}" for k, v in errs.items()) if isinstance(errs, dict) and errs else "") or str(body.get("message") or "")
    except Exception:
        pass
    if r.status_code in (401, 403) and what == "sign-in":
        return ValueError("Proxmox refused that user name or password. Enter the user with its realm, e.g. root@pam or admin@pve.")
    return ValueError(f"Proxmox could not {what} (HTTP {r.status_code})" + (f": {said}" if said else "."))


def create_token(dev, username, password, timeout=20):
    """(token as 'user@realm!name=secret', a note or ''). Raises ValueError with a reason a person can act on."""
    username, password = (username or "").strip(), password or ""
    if not username or not password:
        raise ValueError("Enter the administrator's user name and password.")
    if "@" not in username:
        raise ValueError("Enter the user with its realm, e.g. root@pam or admin@pve.")
    host, port = dev["host"], dev.get("port") or DEFAULT_PORT
    verify = bool(dev.get("verify_ssl"))
    if not verify:
        urllib3.disable_warnings()
    base = f"https://{host}:{port}/api2/json"
    common = dict(verify=verify, timeout=timeout, **proxy.requests_kwargs(dev))
    try:
        r = requests.post(f"{base}/access/ticket", data={"username": username, "password": password}, **common)
        if r.status_code != 200:
            raise _fail(r, "sign-in")
        data = (r.json() or {}).get("data") or {}
        ticket, csrf = data.get("ticket"), data.get("CSRFPreventionToken")
        if data.get("NeedTFA") or not ticket or not csrf:
            raise ValueError("This account needs a second sign-in step (two-factor), which Toner cannot do. Make the token in the Proxmox web "
                             "interface (Datacenter > Permissions > API Tokens), or use an account without two-factor.")
        cookies, headers = {"PVEAuthCookie": ticket}, {"CSRFPreventionToken": csrf}
        who = quote(username, safe="")
        token = None
        for name in ("toner", f"toner-{time.strftime('%Y%m%d-%H%M%S')}"):         # a second one if "toner" already exists
            r = requests.post(f"{base}/access/users/{who}/token/{name}", data={"privsep": 1, "comment": "made by Toner for read-only checks"},
                              cookies=cookies, headers=headers, **common)
            if r.status_code == 200:
                got = (r.json() or {}).get("data") or {}
                full = got.get("full-tokenid") or (got.get("info") or {}).get("full-tokenid") or f"{username}!{name}"
                secret = got.get("value")
                if not secret:
                    raise ValueError("Proxmox made the token but did not show its secret.")
                token = f"{full}={secret}"
                break
            if "exist" not in r.text.lower():
                raise _fail(r, "make a token")
        if token is None:
            raise ValueError("Proxmox already has tokens called 'toner' for this user, and could not make another.")
        note = ""
        r = requests.put(f"{base}/access/acl", data={"path": "/", "roles": ROLE, "tokens": token.split("=", 1)[0], "propagate": 1},
                         cookies=cookies, headers=headers, **common)
        if r.status_code != 200:
            note = (f"The token was made, but it could not be given the read-only role ({ROLE}). In Proxmox, Datacenter > Permissions > Add > "
                    f"API Token Permission: path /, token {token.split('=', 1)[0]}, role {ROLE}.")
        return token, note
    except requests.exceptions.SSLError:
        raise ValueError("The Proxmox certificate is not trusted. Untick 'Verify SSL certificate' on this tab to accept it, then try again.") from None
    except requests.exceptions.Timeout:
        raise ValueError(f"Proxmox at {host}:{port} did not answer in {timeout} seconds.") from None
    except requests.exceptions.ConnectionError:
        raise ValueError(f"Could not reach Proxmox at {host}:{port}. Check the address and port (8006 by default).") from None
