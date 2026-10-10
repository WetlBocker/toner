from .arista import AristaDriver
from .cisco import CiscoDriver
from .cloud import CloudDriver
from .fortinet import FortinetDriver
from .hpe import HpeDriver
from .juniper import JuniperDriver
from .meraki import MerakiDriver
from .mikrotik import MikrotikDriver
from .paloalto import PaloAltoDriver
from .snmpdev import SnmpDriver
from .unifi import UnifiDriver
from .wifi import WifiDriver

DRIVERS = {"cisco": CiscoDriver, "fortinet": FortinetDriver, "unifi": UnifiDriver, "juniper": JuniperDriver,
           "arista": AristaDriver, "hpe": HpeDriver, "mikrotik": MikrotikDriver, "paloalto": PaloAltoDriver,
           "meraki": MerakiDriver, "snmp": SnmpDriver, "cloud": CloudDriver, "wifi": WifiDriver}
