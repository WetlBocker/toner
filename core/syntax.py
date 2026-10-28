"""Colours for live command output in the terminal (SSH, Telnet and Serial tabs): comments, keywords, addresses, numbers,
interface names, permit and deny, up and down, by vendor. marks() says what kind each character of a line is; the terminal
widget turns the kinds into colours that fit its scheme, and only for text the device sent in the default colour."""
import re

KINDS = ("comment", "keyword", "no", "number", "address", "interface", "good", "bad")

_FAMILY = {"cisco": "cisco", "arista": "cisco", "hpe": "cisco", "meraki": "cisco",
           "juniper": "juniper", "paloalto": "juniper", "mikrotik": "mikrotik", "fortinet": "fortinet"}


def family_of(vendor):
    """Which rule set a vendor's output follows. Cisco-style for anything else, and for a session with no inventory device."""
    return _FAMILY.get((vendor or "").lower(), "cisco")


def _words(*words):
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(w) for w in words) + r")(?![\w-])", re.I)


_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"
_IPV6 = r"(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{0,4}(?:/\d{1,3})?|(?:[0-9a-f]{1,4}:)*:(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}(?:/\d{1,3})?|::"
_MAC = r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
ADDRESS = re.compile(r"(?<![\w.:/-])(?:" + _IPV4 + "|" + _MAC + "|" + _IPV6 + r")(?![\w.:/-])", re.I)
NUMBER = re.compile(r"(?<![\w.:/-])\d+(?:\.\d+)?(?![\w.:/-])")
ERROR = re.compile(r"^\s*%.*$")                           # a device's own error line: '% Invalid input detected'
# a prompt stays plain, whatever words the host name holds: 'router#', 'Switch(config-if)#', 'user@host>', '[admin@MikroTik] /ip>', 'FGT (port1) #'
PROMPT = re.compile(r"^(?:\[[^\]]+\]\s*(?:/[\w /-]*)?|[\w.@-]+(?:\s?\([\w./-]+\))?\s?)[#>$](?:\s|$)")

_CISCO_IFACE = (r"(?:(?:Hundred|Forty|TwentyFive|Ten)?Gig(?:abit)?Ethernet|FastEthernet|Ethernet|Port-?channel|Vlan|Loopback|"
                r"Tunnel|Serial|Management|Mgmt|BVI|Dialer|Cellular|Async|Null|Bundle-Ether|Virtual-Template|"
                r"Gi|Fa|Te|Twe|Fo|Hu|Eth|Et|Po|Lo|Tu|Vl|Se|Ma|Mg)\s?\d+(?:/\d+)*(?:\.\d+)?")

CISCO_WORDS = ("interface", "ip", "ipv6", "address", "access-list", "access-group", "extended", "standard", "host", "any",
               "route", "nat", "inside", "outside", "description", "switchport", "mode", "access", "trunk", "vlan", "name",
               "hostname", "username", "password", "secret", "enable", "service", "logging", "ntp", "server", "snmp-server",
               "community", "line", "vty", "con", "console", "login", "local", "transport", "input", "output", "exec-timeout",
               "spanning-tree", "portfast", "router", "ospf", "bgp", "eigrp", "rip", "neighbor", "remote-as", "network", "area",
               "crypto", "isakmp", "ikev2", "ipsec", "policy", "map", "key", "pre-share", "encryption", "authentication",
               "group", "lifetime", "hash", "transform-set", "match", "set", "peer", "dhcp", "pool", "excluded-address",
               "default-router", "dns-server", "domain-name", "default-gateway", "default", "static", "mask", "helper-address",
               "directed-broadcast", "redirects", "proxy-arp", "speed", "duplex", "mtu", "channel-group", "encapsulation",
               "dot1q", "native", "allowed", "add", "remove", "aaa", "new-model", "radius", "tacacs", "banner", "motd", "boot",
               "system", "version", "show", "running-config", "startup-config", "configure", "terminal", "write", "memory",
               "copy", "interfaces", "brief", "status", "summary", "detail", "ping", "traceroute", "clock", "timezone",
               "object", "object-group", "subnet", "range", "eq", "gt", "lt", "tcp", "udp", "icmp", "esp", "gre", "log",
               "class-map", "policy-map", "service-policy", "class", "priority", "bandwidth", "queue", "shape", "police",
               "vrf", "forwarding", "member", "redistribute", "metric", "distance", "passive-interface", "hsrp", "vrrp",
               "standby", "track", "monitor", "session", "source", "destination", "exit", "end")

JUNIPER_WORDS = ("set", "delete", "deactivate", "activate", "edit", "show", "configure", "commit", "rollback", "run", "top", "up",
                 "interfaces", "unit", "family", "inet", "inet6", "address", "description", "mtu", "vlan-id", "vlan-tagging",
                 "routing-options", "static", "route", "next-hop", "protocols", "ospf", "bgp", "lldp", "area", "neighbor",
                 "security", "policies", "zones", "security-zone", "from-zone", "to-zone", "policy", "match", "then",
                 "source-address", "destination-address", "application", "system", "host-name", "root-authentication",
                 "login", "user", "class", "services", "ssh", "ntp", "syslog", "vlans", "firewall", "filter", "term", "from",
                 "protocol", "port", "count", "nat", "pool", "rule-set", "rule", "apply-groups", "groups", "chassis",
                 "ethernet-switching", "interface-mode", "members", "access", "trunk", "ike", "ipsec", "proposal", "gateway",
                 "pre-shared-key", "ascii-text", "address-book", "group", "name", "exit", "quit")
_JUNIPER_IFACE = r"(?:ge|xe|et|ae|irb|lo|fxp|em|reth|st|gr|vlan|me)-?\d+(?:/\d+)*(?:\.\d+)?"

MIKROTIK_WORDS = ("add", "set", "remove", "print", "enable", "disable", "export", "find", "move", "interface", "ip", "ipv6",
                  "address", "route", "firewall", "filter", "nat", "mangle", "raw", "chain", "action", "dst-address",
                  "src-address", "dst-port", "src-port", "protocol", "in-interface", "out-interface", "in-interface-list",
                  "out-interface-list", "list", "comment", "name", "disabled", "gateway", "network", "dhcp-server",
                  "dhcp-client", "pool", "ranges", "bridge", "port", "vlan", "vlan-ids", "pvid", "system", "identity", "user",
                  "routing", "ospf", "bgp", "service", "dns", "servers", "static", "ntp", "client", "wireless", "ssid",
                  "security-profile", "mode", "band", "frequency", "connection-state", "masquerade", "to-addresses", "to-ports",
                  "log", "log-prefix", "place-before", "copy-from", "quit")
_MIKROTIK_IFACE = r"(?:ether|sfp-sfpplus|sfp|wlan|wifi|bridge|vlan|pppoe-out|lte|combo)\d*"

FORTINET_WORDS = ("config", "edit", "set", "unset", "next", "end", "show", "get", "diagnose", "execute", "system", "interface",
                  "firewall", "policy", "address", "addrgrp", "service", "custom", "group", "router", "static", "vdom", "global",
                  "srcintf", "dstintf", "srcaddr", "dstaddr", "schedule", "action", "nat", "status", "ip", "allowaccess",
                  "alias", "type", "mode", "gateway", "device", "distance", "subnet", "dst", "vpn", "ipsec", "phase1-interface",
                  "phase2-interface", "psksecret", "proposal", "remote-gw", "dhcprelay", "dns", "primary", "secondary",
                  "admin", "password", "hostname", "timezone", "logtraffic", "comments", "utm-status", "ssl-ssh-profile",
                  "av-profile", "webfilter-profile", "ips-sensor", "application-list", "inspection-mode", "full-mode",
                  "snmp", "ntp", "ntpsync", "sdwan", "members", "zone", "vlanid", "role", "lan", "wan", "dmz", "always")
_FORTINET_IFACE = r"(?:port|wan|internal|lan|dmz|mgmt|ha|x|fortilink|ssl\.root|npu\d_vlink)\d*"

GOOD = ("permit", "accept", "allow", "up", "connected", "enabled", "enable", "active", "established", "full", "ok", "yes", "running")
BAD = ("deny", "reject", "drop", "down", "shutdown", "err-disabled", "errdisabled", "disabled", "disable", "notconnect",
       "failed", "fail", "invalid", "error", "blocked", "unreachable", "administratively")

# per family: [(regex, kind)] in order of priority; the first rule to claim a character wins
RULES = {
    "cisco": [(re.compile(r"^\s*!.*$"), "comment"), (ERROR, "bad"), (PROMPT, "plain"),
              (re.compile(r"(?<![\w/.-])" + _CISCO_IFACE + r"(?![\w/.-])", re.I), "interface"),
              (ADDRESS, "address"), (_words(*BAD), "bad"), (_words(*GOOD), "good"), (_words("no"), "no"),
              (_words(*CISCO_WORDS), "keyword"), (NUMBER, "number")],
    "juniper": [(re.compile(r"^\s*(?:#.*|##.*)$"), "comment"), (re.compile(r"[{};]"), "comment"), (ERROR, "bad"), (PROMPT, "plain"),
                (re.compile(r"(?<![\w/.-])" + _JUNIPER_IFACE + r"(?![\w/.-])", re.I), "interface"),
                (ADDRESS, "address"), (_words(*BAD), "bad"), (_words(*GOOD), "good"), (_words("no"), "no"),
                (_words(*JUNIPER_WORDS), "keyword"), (NUMBER, "number")],
    "mikrotik": [(re.compile(r"^\s*#.*$"), "comment"), (ERROR, "bad"), (PROMPT, "plain"),
                 (re.compile(r"(?<![\w/.-])" + _MIKROTIK_IFACE + r"(?![\w/.-])", re.I), "interface"),
                 (ADDRESS, "address"), (_words(*BAD), "bad"), (_words(*GOOD), "good"), (_words("no"), "bad"),
                 (re.compile(r"(?<![\w-])[\w-]+(?==)"), "keyword"), (re.compile(r"(?<![\w/])/[\w/ -]*?(?=\s(?:add|set|remove|print|enable|disable|export)\b|$)", re.I), "keyword"),
                 (_words(*MIKROTIK_WORDS), "keyword"), (NUMBER, "number")],
    "fortinet": [(re.compile(r"^\s*#.*$"), "comment"), (ERROR, "bad"), (PROMPT, "plain"),
                 (re.compile(r"(?<![\w/.-])" + _FORTINET_IFACE + r"(?![\w/.-])", re.I), "interface"),
                 (ADDRESS, "address"), (_words(*BAD), "bad"), (_words(*GOOD), "good"),
                 (_words(*FORTINET_WORDS), "keyword"), (NUMBER, "number")],
}


def marks(family, text):
    """The kind of each character of one line of output (None = plain; 'plain' = claimed by a prompt, drawn plain), by the family's rules."""
    out = [None] * len(text)
    if not text.strip():
        return out
    for rx, kind in RULES.get(family) or RULES["cisco"]:
        for m in rx.finditer(text):
            a, b = m.span()
            if a == b:
                continue
            if out[a] is None and out[b - 1] is None:
                for i in range(a, b):
                    if out[i] is None:
                        out[i] = kind
    return out


def spans(family, text):
    """[(start, end, kind)] for tests and tools."""
    out, ms = [], marks(family, text)
    i = 0
    while i < len(ms):
        if ms[i] is None:
            i += 1
            continue
        j = i
        while j < len(ms) and ms[j] == ms[i]:
            j += 1
        out.append((i, j, ms[i]))
        i = j
    return out
