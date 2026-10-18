"""This computer's own Wi-Fi: is it connected, how strong is the signal, how fast is the link. Handy on a laptop that
walks around a site; add it as a device with the host 'localhost'."""
from core import wifi
from .base import Driver, OK, FAIL, grade_low


class WifiDriver(Driver):
    def run(self):
        adapters, err = wifi.interfaces()
        if err:
            raise RuntimeError(err)
        a = wifi.current(adapters)
        if a is None:
            from core.platforms import WINDOWS
            return [self.result("connection", FAIL, "no Wi-Fi adapter", "this computer has no wireless adapter, or " +
                                ("the WLAN AutoConfig service is not running" if WINDOWS else "NetworkManager is not running"))]
        out = []
        if not a["connected"]:
            return [self.result("connection", FAIL, "not connected", f"adapter {a.get('name', '')}: {a.get('state', '')}")]
        details = ", ".join(x for x in (a.get("bssid", ""), a.get("band_text", ""),
                                        f"channel {a['channel_no']}" if a.get("channel_no") else "",
                                        a.get("radio type", "")) if x)
        if self.enabled("connection"):
            out.append(self.result("connection", OK, a.get("ssid", "connected"), details))
        if a["signal_pct"] is not None and self.enabled("signal"):
            t = self.th["wifi_signal"]
            out.append(self.result("signal", grade_low(a["signal_pct"], t["warn"], t["fail"]), f"{a['signal_pct']}%",
                                   numeric=float(a["signal_pct"])))
        if a["rx"] and self.enabled("link speed"):
            out.append(self.result("link speed", OK, f"{a['rx']} Mbps", f"receive {a['rx']} / transmit {a['tx'] or '?'} Mbps",
                                   numeric=float(a["rx"])))
        return out
