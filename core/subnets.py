"""The Subnet Calculator's arithmetic (IPv4 and IPv6), with no window in it: what an address and prefix mean, how a network splits
into smaller ones, and whether an address is a public one (which the calculator can then look up: core/iplookup.py)."""
import ipaddress

MAX_CHILDREN = 1024                 # a split that would make more subnets than this is refused: the tree would be unreadable


def parse(text):
    """'192.168.1.10/24', '10.0.0.0/255.255.255.0', '2001:db8::1/64' or a bare address -> an ip_interface. ValueError when it is none."""
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter an address with a prefix, e.g. 192.168.1.10/24 or 2001:db8::/64")
    return ipaddress.ip_interface(t)


def version(text):
    """4 or 6 for what was typed, or None when it is not an address yet."""
    try:
        return parse(text).version
    except ValueError:
        return None


def hosts_in(net):
    """How many hosts a network holds: IPv4 keeps the network and broadcast addresses back (except /31 and /32); IPv6 counts every address."""
    if net.version == 4:
        return net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    return net.num_addresses


def host_range(net):
    """(first, last) usable address, or None when the network has none."""
    if net.version == 4 and net.prefixlen < 31:
        if net.num_addresses <= 2:
            return None
        return net.network_address + 1, net.broadcast_address - 1
    return net.network_address, net.broadcast_address if net.version == 4 else net[-1]


def facts(iface):
    """[(label, value)] for the calculator's table."""
    net = iface.network
    rows = [("Address", str(iface.ip)), ("Network", f"{net.network_address}/{net.prefixlen}"), ("Netmask", str(net.netmask))]
    if net.version == 4:
        rows += [("Wildcard", str(net.hostmask)), ("Broadcast", str(net.broadcast_address))]
        rng = host_range(net)
        if rng:
            rows.append(("Host range", f"{rng[0]} - {rng[1]}"))
        rows += [("Usable hosts", f"{max(hosts_in(net), 0):,}"), ("Private", "yes" if net.is_private else "no")]
    else:
        rows += [("Addresses", f"{net.num_addresses:,}"), ("Range", f"{net[0]} - {net[-1]}"),
                 ("Kind", kind6(iface.ip))]
    rows.append(("Public", "yes" if is_public(iface.ip) else "no"))
    return rows


def kind6(ip):
    """What sort of IPv6 address this is, in plain words."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (fe80::/10)"
    if ip.is_private:
        return "unique local (fc00::/7)" if str(ip).lower().startswith(("fc", "fd")) else "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_global:
        return "global unicast"
    return "reserved"


def is_public(ip):
    """A public (globally routed) address: the one kind worth looking up."""
    return bool(ip.is_global) and not ip.is_multicast


def children(net, new_prefix):
    """The subnets `net` splits into at `new_prefix`. ValueError when the prefix is not longer, too long, or would make too many."""
    top = 32 if net.version == 4 else 128
    if new_prefix <= net.prefixlen:
        raise ValueError(f"Pick a prefix longer than /{net.prefixlen}.")
    if new_prefix > top:
        raise ValueError(f"A prefix cannot be longer than /{top}.")
    count = 2 ** (new_prefix - net.prefixlen)
    if count > MAX_CHILDREN:
        raise ValueError(f"That would make {count:,} subnets. Split in steps instead (up to {MAX_CHILDREN:,} at a time).")
    return list(net.subnets(new_prefix=new_prefix))


def row(net):
    """(network, first, last, hosts, broadcast, subnet mask, wildcard mask) as the Split tree shows them; the last three are IPv4 only, as in facts()."""
    rng = host_range(net)
    first, last = (str(rng[0]), str(rng[1])) if rng else ("", "")
    v4 = net.version == 4
    return (f"{net.network_address}/{net.prefixlen}", first, last, f"{max(hosts_in(net), 0):,}",
            str(net.broadcast_address) if v4 else "", str(net.netmask) if v4 else "", str(net.hostmask) if v4 else "")


def join(networks):
    """The one network these exactly fill (no gap, no overlap), or None."""
    nets = list(networks)
    if len(nets) < 2:
        return None
    merged = list(ipaddress.collapse_addresses(nets))
    if len(merged) != 1 or merged[0].num_addresses != sum(n.num_addresses for n in nets):
        return None
    return merged[0]
