"""The interfaces a device has, asked live, so a person can choose which ones Toner checks (Edit device > Checks)."""
from core import db, profiles

STATE_TEXT = {"up": "Up", "down": "Down", "off": "Switched off", "errdisabled": "Err-disabled"}


def available(vendor):
    """True for the kinds of device that have an interfaces check (and so a list to choose from)."""
    from core import checks
    return any(k == "interfaces" for k, _label in checks.CATALOG.get(vendor, []))


def listing(dev, opts=None):
    """[(name, state text)] for every interface on the device, in the order the device gives them. Raises with a readable reason."""
    from drivers import DRIVERS
    dev = profiles.resolve(dev)
    vendor = dev["vendor"]
    if vendor not in DRIVERS or not available(vendor):
        raise ValueError("this kind of device has no list of interfaces to choose from")
    drv = DRIVERS[vendor](dev, db.get_thresholds(), opts or db.runtime_options())
    rows = drv.list_interfaces()
    return [(str(n), STATE_TEXT.get(s, s)) for n, s in rows]
