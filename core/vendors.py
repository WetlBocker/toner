"""Everything the app knows about each supported vendor, in one place.

kind      "ssh" (netmiko login), "api" (web API), "windows" (agent, WinRM or this computer), ...
secret    what the stored secret is called in the device dialog
username  whether the device needs a username
site      label for the Site field, or "" if the vendor has none
ha        whether the "HA pair expected" box applies
platforms [(netmiko device_type, shown name)]; the first is the default
paging    command that switches off paging in an interactive SSH session ("" = none needed)
login     False when the device needs no password, token or SNMP (a public status page, this computer's Wi-Fi)
"""
import sys


VENDORS = {
    "cisco": dict(name="Cisco", kind="ssh", secret="Password", username=True, site="", ha=False,
                  platforms=[("cisco_ios", "IOS"), ("cisco_xe", "IOS XE"), ("cisco_nxos", "NX-OS"),
                             ("cisco_asa", "ASA")],
                  paging="terminal length 0"),
    "fortinet": dict(name="Fortinet", kind="api", secret="API token", username=False, site="", ha=True,
                     platforms=[], paging=""),
    "unifi": dict(name="UniFi", kind="api", secret="Password", username=True, site="Site", ha=False,
                  platforms=[], paging=""),
    "unifi_network": dict(name="UniFi Network (API key)", kind="api", secret="API key", username=False, site="Site", ha=False,
                          platforms=[], paging=""),
    "unifi_protect": dict(name="UniFi Protect (API key)", kind="api", secret="API key", username=False, site="", ha=False,
                          platforms=[], paging=""),
    "unifi_cloud": dict(name="UniFi Site Manager (cloud)", kind="api", secret="API key", username=False, site="Console or site", ha=False,
                        platforms=[], paging=""),
    "proxmox": dict(name="Proxmox VE", kind="api", secret="API token (user@realm!name=secret)", username=False, site="", ha=False, platforms=[], paging=""),
    "truenas": dict(name="TrueNAS", kind="api", secret="API key", username=False, site="", ha=False, platforms=[], paging=""),
    "opnsense": dict(name="OPNsense", kind="api", secret="API key:secret", username=False, site="", ha=False, platforms=[], paging=""),
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
    "windows": dict(name="Windows", kind="windows", secret="Password", username=True, site="", ha=False,
                    platforms=[("agent", "Agent (reports to Toner)"), ("winrm", "WinRM (Toner connects)")]
                    + ([("local", "This computer")] if sys.platform == "win32" else []), paging=""),   # (Toner reading Windows itself)
    "wifi": dict(name="This PC's Wi-Fi", kind="local", secret="", username=False, site="", ha=False,
                 platforms=[], paging="", login=False),
    # added 2026-11: controllers and managers over their APIs, more switches over SSH, two firewalls over SNMP
    "ciscoise": dict(name="Cisco ISE", kind="api", secret="Password", username=True, site="", ha=False, platforms=[], paging=""),
    "ciscosdwan": dict(name="Cisco SD-WAN Manager", kind="api", secret="Password", username=True, site="", ha=False, platforms=[], paging=""),
    "ciscofmc": dict(name="Cisco FMC", kind="api", secret="Password", username=True, site="", ha=False, platforms=[], paging=""),
    "vmware": dict(name="VMware vCenter", kind="api", secret="Password", username=True, site="", ha=False, platforms=[], paging=""),
    "esxi": dict(name="VMware ESXi (SNMP)", kind="snmp", secret="SNMP community", username=False, site="", ha=False, platforms=[], paging=""),
    "dell": dict(name="Dell PowerSwitch", kind="ssh", secret="Password", username=True, site="", ha=False,
                 platforms=[("dell_os10", "SmartFabric OS10"), ("dell_force10", "OS9 (S and Z series)"), ("dell_os6", "OS6 (N series)")],
                 paging="terminal length 0"),
    "sophos": dict(name="Sophos Firewall (SNMP)", kind="snmp", secret="SNMP community", username=False, site="", ha=False, platforms=[], paging=""),
    "sonicwall": dict(name="SonicWall", kind="api", secret="Password", username=True, site="", ha=False, platforms=[], paging=""),
    "extreme": dict(name="Extreme Networks", kind="ssh", secret="Password", username=True, site="", ha=False,
                    platforms=[("extreme_exos", "Switch Engine / EXOS"), ("extreme_vsp", "Fabric Engine / VOSS")], paging="disable clipaging"),
    "mist": dict(name="Juniper Mist", kind="api", secret="API token", username=False, site="Organization ID", ha=False, platforms=[], paging=""),
}

# One entry in the Vendor box can stand for several kinds of monitoring: UniFi is one vendor, and "how to monitor" picks the console login
# or one of the API-key applications. Each kind is still its own type underneath (its own driver, checks and limits).
FAMILY = {"unifi": "unifi", "unifi_network": "unifi", "unifi_protect": "unifi", "unifi_cloud": "unifi",
          "ciscoise": "cisco", "ciscofmc": "cisco", "ciscosdwan": "cisco"}
MODES = {"unifi": [("unifi", "Console login (user name and password)"), ("unifi_network", "Network API (API key)"),
                   ("unifi_protect", "Protect API (API key)"), ("unifi_cloud", "Site Manager in the cloud (API key)")],
         "cisco": [("cisco", "Switch, router or ASA by SSH"), ("ciscoise", "ISE (Open API)"), ("ciscofmc", "FMC (REST API)"),
                   ("ciscosdwan", "SD-WAN Manager (REST API)")]}
SHORT = {"unifi": "login", "unifi_network": "network", "unifi_protect": "protect", "unifi_cloud": "cloud",
         "ciscoise": "ise", "ciscofmc": "fmc", "ciscosdwan": "sdwan"}     # the platform column in import and export files


def family(vendor):
    """The vendor as people think of it: all UniFi types are 'unifi'."""
    return FAMILY.get(vendor, vendor)


def modes(vendor):
    """[(type, shown name)] a vendor can be monitored by, or [] when it has just one way."""
    return MODES.get(family(vendor), [])


def mode_label(vendor):
    """The way of monitoring a vendor with several ways ('Network API (API key)'); '' for one with a platform list of its own (a Cisco
    switch says IOS or NX-OS instead) and for a vendor with one way."""
    if sub_platforms(vendor):
        return ""
    return dict(modes(vendor)).get(vendor, "")


def listed():
    """The vendors offered in the Vendor box."""
    return [v for v in VENDORS if family(v) == v]


def from_file(vendor, platform):
    """('unifi', 'network') from an import file -> ('unifi_network', ''); ('cisco', 'ise') -> ('ciscoise', ''). Anything else, a Cisco
    switch with its platform (cisco, cisco_ios) included, is returned as it came."""
    vendor, platform = (vendor or "").lower(), (platform or "").strip().lower()
    if vendor in MODES and platform:
        for key, _label in MODES[vendor]:
            short = SHORT.get(key, "")
            if platform in (short, key, key.split("_")[-1], key[len(vendor):] if key.startswith(vendor) and key != vendor else "") and platform:
                return key, ""
    return vendor, platform


def sub_platforms(vendor):
    """The platforms of one way of monitoring a vendor with several ways (Cisco by SSH has IOS, IOS XE, NX-OS, ASA); [] otherwise."""
    return list(get(vendor).get("platforms", [])) if modes(vendor) else []


DEFAULT_PAGING = "terminal length 0"      # the Settings > Terminal default


# A device imported before anyone said what it is (a MobaXterm session whose vendor wasn't detected): it is kept and
# edited like any other, with a user name and password, and only the checks that need no sign-in run until a vendor is chosen.
NO_VENDOR = dict(name="", kind="", secret="Password", username=True, site="", ha=False, platforms=[], paging="")


def get(vendor):
    return VENDORS.get(vendor) or (NO_VENDOR if not vendor else {})


def paging_command(vendor, configured):
    """The command to send for a vendor: the vendor's own, unless the user changed the setting."""
    if configured and configured != DEFAULT_PAGING:
        return configured
    return get(vendor).get("paging", "")


def has_login(vendor):
    return get(vendor).get("login", True)


def is_snmp(vendor):
    return get(vendor).get("kind") == "snmp"


# devices Toner checks through their API whose command line can also be reached over SSH (the Command Runner, SSH sessions): netmiko's
# device type. The firewalls keep a separate SSH login beside the API key; the Cisco managers sign in to both with one account.
CLI_TYPES = {"fortinet": "fortinet", "paloalto": "paloalto_panos", "ciscoise": "cisco_ios", "ciscofmc": "cisco_ftd", "ciscosdwan": "cisco_viptela"}
SHARED_LOGIN = {"ciscoise", "ciscofmc", "ciscosdwan"}         # the API user name and password serve SSH too (an SSH password of its own is optional)
SNMP_EXTRAS = {"ciscoise", "ciscofmc", "ciscosdwan", "vmware", "sonicwall"}   # API-checked managers that also answer SNMP once it is set up on the device


def shared_login(vendor):
    return vendor in SHARED_LOGIN


def uses_ssh_login(vendor):
    return get(vendor).get("kind") == "ssh" or vendor == "unifi"     # UniFi stores a password that SSH can reuse


def ssh_reachable(vendor):
    """Whether an SSH session can be opened to this kind of device with the login it stores: switches and routers, UniFi, and the
    Cisco managers whose one account serves SSH too. (A FortiGate or Palo Alto keeps an SSH login only for the Command Runner.)"""
    return uses_ssh_login(vendor) or shared_login(vendor)


def platform_keys(vendor):
    return [k for k, _ in get(vendor).get("platforms", [])]


def default_platform(vendor):
    keys = platform_keys(vendor)
    return keys[0] if keys else ""
