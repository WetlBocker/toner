from .arista import AristaDriver
from .cisco import CiscoDriver
from .ciscofmc import CiscoFmcDriver
from .ciscoise import CiscoIseDriver
from .ciscosdwan import CiscoSdwanDriver
from .cloud import CloudDriver
from .dell import DellDriver
from .esxi import EsxiDriver
from .extreme import ExtremeDriver
from .fortinet import FortinetDriver
from .mist import MistDriver
from .sonicwall import SonicwallDriver
from .sophos import SophosDriver
from .vmware import VmwareDriver
from .hpe import HpeDriver
from .juniper import JuniperDriver
from .meraki import MerakiDriver
from .mikrotik import MikrotikDriver
from .paloalto import PaloAltoDriver
from .snmpdev import SnmpDriver
from .opnsense import OpnsenseDriver
from .proxmox import ProxmoxDriver
from .truenas import TruenasDriver
from .unifi import UnifiDriver
from .unifi_cloud import UnifiCloudDriver
from .unifi_network import UnifiNetworkDriver
from .unifi_protect import UnifiProtectDriver
from .wifi import WifiDriver
from .windows import WindowsDriver

DRIVERS = {"cisco": CiscoDriver, "fortinet": FortinetDriver, "proxmox": ProxmoxDriver, "truenas": TruenasDriver, "opnsense": OpnsenseDriver, "unifi": UnifiDriver, "unifi_network": UnifiNetworkDriver, "unifi_protect": UnifiProtectDriver, "unifi_cloud": UnifiCloudDriver, "juniper": JuniperDriver,
           "arista": AristaDriver, "hpe": HpeDriver, "mikrotik": MikrotikDriver, "paloalto": PaloAltoDriver,
           "meraki": MerakiDriver, "snmp": SnmpDriver, "cloud": CloudDriver, "wifi": WifiDriver, "windows": WindowsDriver,
           "ciscoise": CiscoIseDriver, "ciscosdwan": CiscoSdwanDriver, "ciscofmc": CiscoFmcDriver, "vmware": VmwareDriver, "esxi": EsxiDriver,
           "dell": DellDriver, "sophos": SophosDriver, "sonicwall": SonicwallDriver, "extreme": ExtremeDriver, "mist": MistDriver}
