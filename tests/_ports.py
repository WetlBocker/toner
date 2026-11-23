# Passive port ranges for the FTP tests. A fixed range will not do: Windows (Hyper-V, WSL) reserves blocks of ports that
# change with each restart, and a server whose whole range is reserved answers "425 No passive port is free."
import socket


def free_range(count=11):
    """(low, high): `count` neighbouring ports that could all be bound on 127.0.0.1 a moment ago."""
    for _ in range(50):
        socks = []
        try:
            for i in range(count):
                s = socket.socket(); socks.append(s)
                s.bind(("127.0.0.1", socks[0].getsockname()[1] + i if i else 0))      # the first is the system's choice
            low = socks[0].getsockname()[1]
            return low, low + count - 1
        except (OSError, OverflowError):                    # a neighbour is taken or reserved, or past 65535: another place
            pass
        finally:
            for s in socks:
                s.close()
    raise RuntimeError(f"No {count} neighbouring ports are free on 127.0.0.1.")
