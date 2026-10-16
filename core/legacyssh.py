"""Older SSH algorithms for older network devices (Settings > Security > Older SSH algorithms).

paramiko 5 dropped everything that uses SHA-1: the ssh-rsa host key signature and the diffie-hellman-group1-sha1,
group14-sha1 and group-exchange-sha1 key exchanges. Many Cisco ASAs, older IOS switches and other network gear offer
nothing newer, so the connection fails with "Incompatible ssh peer (no acceptable host key)" or "(no acceptable kex
algorithm)". This puts them back, at the end of each list: a device that offers anything newer still agrees on the newer
one, and only a device that offers nothing else uses SHA-1. It is what OpenSSH's -oHostKeyAlgorithms=+ssh-rsa and
-oKexAlgorithms=+diffie-hellman-group14-sha1 do. paramiko still has the CBC ciphers and hmac-sha1 these devices use.
"""
from hashlib import sha1

import paramiko
from cryptography.hazmat.primitives import hashes
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256

from core import db


class KexGroup14SHA1(KexGroup14SHA256):
    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class KexGroup1SHA1(KexGroup14SHA256):
    # RFC 2409 section 6.2, the 1024-bit Oakley group 2
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa
    G = 2
    name = "diffie-hellman-group1-sha1"
    hash_algo = sha1


class KexGexSHA1(KexGexSHA256):
    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1


KEX = [KexGroup14SHA1, KexGexSHA1, KexGroup1SHA1]           # in this order, after every newer one
HOST_KEYS = ["ssh-rsa"]


def enabled():
    T = paramiko.Transport
    return "ssh-rsa" in T._preferred_keys and all(k.name in T._preferred_kex for k in KEX)


def enable(on=True):
    """Add (or remove) the older algorithms for every SSH connection Toner makes from now on."""
    T = paramiko.Transport
    names = [k.name for k in KEX]
    T._preferred_kex = tuple(k for k in T._preferred_kex if k not in names) + (tuple(names) if on else ())
    T._preferred_keys = tuple(k for k in T._preferred_keys if k not in HOST_KEYS) + (tuple(HOST_KEYS) if on else ())
    for k in KEX:
        if on:
            T._kex_info[k.name] = k
        else:
            T._kex_info.pop(k.name, None)
    if on:
        T._key_info["ssh-rsa"] = paramiko.RSAKey
        paramiko.RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
    else:
        T._key_info.pop("ssh-rsa", None)
        paramiko.RSAKey.HASHES.pop("ssh-rsa", None)


def apply():
    """Follow the setting (on unless turned off in Settings > Security)."""
    try:
        on = bool(db.get_setting("ssh_legacy_algorithms"))
    except Exception:
        on = True
    enable(on)
    return on


enable(True)                                  # on from the start; apply() turns it off if the setting says so
