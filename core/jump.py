"""Reach a device over SSH through another inventory device (a jump host / bastion)."""
import json

import paramiko

from core import db, nettools, profiles, proxy
from core import quiet


def spec(dev):
    """{'device': name} when the device is set to go through a jump host, else None."""
    raw = dev.get("jump") or ""
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("device") else None


def jump_device(dev):
    s = spec(dev)
    if not s:
        return None
    with db.within(dev.get("org")):                       # a jump host from the device's own organization (or a Shared one)
        devs = db.list_devices()
    for d in devs:
        if d["name"] == s["device"] and d["name"] != dev.get("name"):
            return profiles.resolve(d)
    raise ValueError(f"The jump host '{s['device']}' is no longer in the inventory.")


def open_channel(dev, timeout=15):
    """(socket-like object to reach the device, [objects to close afterwards]): a channel through its jump host, or a
    tunnel through its proxy. (None, []) when the device is reached directly."""
    jd = jump_device(dev)
    if jd is None:
        cfg = proxy.for_device(dev)
        if cfg is None:
            return None, []
        sock = proxy.connect(cfg, dev["host"], int(dev.get("port") or 22), timeout)
        return sock, [sock]
    client = paramiko.SSHClient()
    nettools.configure_hostkeys(client, db.get_setting("hostkey_mode"))
    via, extra = None, []
    try:
        cfg = proxy.for_device(jd)                       # the jump host itself may be behind a proxy
        if cfg is not None:
            via = proxy.connect(cfg, jd["host"], int(jd.get("port") or 22), timeout)
            extra.append(via)
        client.connect(jd["host"], port=jd.get("port") or 22, username=jd.get("username") or "",
                       password=profiles.secret(jd) or "", timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, allow_agent=False, look_for_keys=False, sock=via)
        chan = client.get_transport().open_channel(
            "direct-tcpip", (dev["host"], int(dev.get("port") or 22)), ("127.0.0.1", 0), timeout=timeout)
    except Exception as e:
        client.close()
        for s in extra:
            s.close()
        raise ConnectionError(f"via jump host {jd['name']}: {type(e).__name__}: {e}") from None
    return chan, [chan, client] + extra


class Managed:
    """Wraps a netmiko connection so the jump-host session is closed when the connection is."""

    def __init__(self, handler, closers):
        self.handler, self.closers = handler, closers

    def __enter__(self):
        return self.handler.__enter__()

    def __exit__(self, *a):
        try:
            return self.handler.__exit__(*a)
        finally:
            for c in self.closers:
                try:
                    c.close()
                except Exception:
                    quiet.ignored()
