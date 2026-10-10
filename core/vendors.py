"""Everything the app knows about each supported vendor, in one place.

kind      "ssh" (netmiko login) or "api" (web API)
secret    what the stored secret is called in the device dialog
username  whether the device needs a username
site      label for the Site field, or "" if the vendor has none
ha        whether the "HA pair expected" box applies
platforms [(netmiko device_type, shown name)]; the first is the default
paging    command that switches off paging in an interactive SSH session ("" = none needed)
login     False when the device needs no password, token or SNMP (a public status page, this computer's Wi-Fi)
"""

VENDORS = {
    "cisco": dict(name="Cisco", kind="ssh", secret="Password", username=True, site="", ha=False,
                  platforms=[("cisco_ios", "IOS"), ("cisco_xe", "IOS XE"), ("cisco_nxos", "NX-OS"),
                             ("cisco_asa", "ASA")],
                  paging="terminal length 0"),
    "fortinet": dict(name="Fortinet", kind="api", secret="API token", username=False, site="", ha=True,
                     platforms=[], paging=""),
    "unifi": dict(name="UniFi", kind="api", secret="Password", username=True, site="Site", ha=False,
                  platforms=[], paging=""),
    "juniper": dict(name="Juniper", kind="ssh", secret="Password", username=True, site="", ha=False,
                    platforms=[("juniper_junos", "Junos")], paging="set cli screen-length 0"),
    "arista": dict(name="Arista", kind="ssh", secret="Password", username=True, site="", ha=False,
                   platforms=[("arista_eos", "EOS")], paging="terminal length 0"),
    "hpe": dict(name="HPE Aruba", kind="ssh", secret="Password", username=True, site="", ha=False,
                platforms=[("aruba_aoscx", "AOS-CX"), ("aruba_osswitch", "AOS-S / ProCurve")],
                paging="no page"),
    "mikrotik": dict(name="MikroTik", kind="ssh", secret="Password", username=True, site="", ha=False,
                     platforms=[("mikrotik_routeros", "RouterOS")], paging=""),
    "paloalto": dict(name="Palo Alto", kind="api", secret="API key", username=False, site="", ha=True,
                     platforms=[], paging=""),
    "snmp": dict(name="Generic SNMP", kind="snmp", secret="SNMP community", username=False, site="", ha=False,
                 platforms=[], paging=""),
    "meraki": dict(name="Meraki", kind="api", secret="API key", username=False, site="Organization", ha=False,
                   platforms=[], paging=""),
    "cloud": dict(name="Cloud status page", kind="status", secret="", username=False, site="", ha=False,
                  platforms=[], paging="", login=False),
    "wifi": dict(name="This PC's Wi-Fi", kind="local", secret="", username=False, site="", ha=False,
                 platforms=[], paging="", login=False),
}

DEFAULT_PAGING = "terminal length 0"      # the Settings > Terminal default


def get(vendor):
    return VENDORS.get(vendor, {})


def paging_command(vendor, configured):
    """The command to send for a vendor: the vendor's own, unless the user changed the setting."""
    if configured and configured != DEFAULT_PAGING:
        return configured
    return get(vendor).get("paging", "")


def has_login(vendor):
    return get(vendor).get("login", True)


def is_snmp(vendor):
    return get(vendor).get("kind") == "snmp"


def uses_ssh_login(vendor):
    return get(vendor).get("kind") == "ssh" or vendor == "unifi"     # UniFi stores a password that SSH can reuse


def platform_keys(vendor):
    return [k for k, _ in get(vendor).get("platforms", [])]


def default_platform(vendor):
    keys = platform_keys(vendor)
    return keys[0] if keys else ""
