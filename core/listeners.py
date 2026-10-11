"""Receive syslog messages (UDP) and SNMP traps (v1/v2c), and tag each with the inventory device it came from."""
import asyncio
import re
import socket
import threading
import time
from datetime import datetime

from core import db
from core import quiet

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
              "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
              "local7"]
SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]


def parse_syslog(data, addr):
    """One UDP datagram -> {'time','source','facility','severity','severity_no','text'}."""
    text = data.decode("utf-8", "replace").strip("\x00\r\n ")
    pri, facility, severity = None, "user", 5
    m = re.match(r"^<(\d{1,3})>(.*)$", text, re.S)
    if m:
        pri = int(m.group(1))
        facility = FACILITIES[min(pri >> 3, 23)]
        severity = pri & 7
        text = m.group(2)
    text = re.sub(r"^\d\s+", "", text, count=1) if re.match(r"^\d\s+\d{4}-", text) else text      # RFC 5424 version
    return {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": addr[0], "facility": facility,
            "severity": SEVERITIES[severity], "severity_no": severity, "text": " ".join(text.split())[:2000]}


def device_for(ip, cache={}):
    """Inventory name for a source address, or ''. Resolved names are remembered for a minute."""
    now = time.time()
    if not cache or now - cache.get("_t", 0) > 60:
        cache.clear()
        cache["_t"] = now
        for d in db.list_devices():
            try:
                cache[socket.gethostbyname(d["host"])] = d["name"]
            except OSError:
                pass
    return cache.get(ip, "")


class SyslogListener:
    def __init__(self, port=514, on_message=None, bind="0.0.0.0"):
        self.port, self.bind, self.on_message = int(port), bind, on_message
        self.sock = None
        self.thread = None
        self.stop_event = threading.Event()
        self.count = 0

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, self.port))                     # raises OSError if the port is taken
        s.settimeout(0.5)
        self.sock = s
        self.stop_event.clear()

        def loop():
            while not self.stop_event.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                msg = parse_syslog(data, addr)
                msg["device"] = device_for(addr[0])
                self.count += 1
                if self.on_message:
                    self.on_message(msg)
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.port = s.getsockname()[1]

    def stop(self):
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(2)


class TrapListener:
    """SNMP v1/v2c trap receiver on a UDP port (162 by default). Needs the community strings to accept."""

    def __init__(self, port=162, communities=("public",), on_trap=None, bind="0.0.0.0"):
        self.port, self.bind, self.on_trap = int(port), bind, on_trap
        self.communities = [c for c in communities if c] or ["public"]
        self.thread = None
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.error = ""
        self.count = 0

    def start(self, wait=5):
        self.stop_event.clear()
        self.ready.clear()
        self.error = ""
        self.thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self.thread.start()
        self.ready.wait(wait)
        if self.error:
            raise OSError(self.error)

    async def _main(self):
        from pysnmp.entity import config, engine
        from pysnmp.entity.rfc3413 import ntfrcv
        from pysnmp.carrier.asyncio.dgram import udp
        from core import snmp
        try:
            eng = engine.SnmpEngine()
            config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((self.bind, self.port)))
            for i, com in enumerate(self.communities):
                config.add_v1_system(eng, f"trap{i}", com)

            def cb(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
                try:
                    _, addr = snmpEngine.message_dispatcher.get_transport_info(stateReference)
                    src = addr[0]
                except Exception:
                    src = "?"
                rows = []
                trap_oid = ""
                for oid, val in varBinds:
                    o = str(oid)
                    typ, text = snmp.format_value(val)
                    if o == snmp.NAMES["snmpTrapOID"] + ".0":
                        trap_oid = text
                    rows.append((o, snmp.name_of(o), text))
                self.count += 1
                if self.on_trap:
                    self.on_trap({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": src,
                                  "device": device_for(src), "trap": snmp.name_of(trap_oid) if trap_oid else "",
                                  "varbinds": rows,
                                  "text": "; ".join(f"{n} = {t}" for _, n, t in rows)[:2000]})
            ntfrcv.NotificationReceiver(eng, cb)
            eng.transport_dispatcher.job_started(1)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
            self.ready.set()
            return
        self.ready.set()
        while not self.stop_event.is_set():
            await asyncio.sleep(0.2)
        try:
            eng.close_dispatcher()
        except Exception:
            quiet.ignored()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(3)
