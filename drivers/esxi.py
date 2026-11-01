"""A standalone VMware ESXi host by SNMP (the host's own agent: `esxcli system snmp set --communities public --enable true`, or v3).
Without vCenter a host has no REST API, so the standard MIBs give CPU, memory, storage, uptime and interfaces, and VMware's own MIBs
the product version and the virtual machines with their power state (VMWARE-SYSTEM-MIB, VMWARE-VMINFO-MIB)."""
from core.snmp import text_of
from .base import OK
from .snmpdev import SnmpDriver

VMW_PROD_NAME = "1.3.6.1.4.1.6876.1.1.0"
VMW_PROD_VERSION = "1.3.6.1.4.1.6876.1.2.0"
VMW_PROD_BUILD = "1.3.6.1.4.1.6876.1.4.0"
VMW_VM_NAME = "1.3.6.1.4.1.6876.2.1.1.2"
VMW_VM_POWER = "1.3.6.1.4.1.6876.2.1.1.6"


class EsxiDriver(SnmpDriver):
    def check_list(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("storage", self.storage), ("uptime", self.uptime),
                ("interfaces", self.interfaces), ("interface errors", self.errors), ("bandwidth", self.bandwidth),
                ("version", self.version), ("vms", self.vms)]

    def version(self):
        got = self.c.try_get(VMW_PROD_NAME, VMW_PROD_VERSION, VMW_PROD_BUILD)
        if not got:
            return []
        version = text_of(got.get(VMW_PROD_VERSION, ""))
        build = text_of(got.get(VMW_PROD_BUILD, ""))
        self.found_software(version, build)
        return self.result("version", OK, version or "unknown", f"{text_of(got.get(VMW_PROD_NAME, ''))} build {build}".strip())

    def vms(self):
        names = self.c.try_column(VMW_VM_NAME)
        if not names:
            return []
        power = self.c.try_column(VMW_VM_POWER)
        on = [text_of(n) for i, n in names.items() if "on" in text_of(power.get(i, "")).lower().replace("poweredoff", "")]
        return self.result("vms", OK, f"{len(on)} of {len(names)} powered on", ", ".join(on[:8]), numeric=float(len(on)))
