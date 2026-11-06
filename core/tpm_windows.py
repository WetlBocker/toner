"""The security chip on Windows: RSA-2048 keys in the Microsoft Platform Crypto Provider (the TPM), each protected by a PIN that
Toner passes in code (NCRYPT_PIN_PROPERTY, every call silent, so Windows never shows a prompt). Wrong PINs are counted by
Windows: after 4 in 8 hours (its defaults for a standard user, before the TPM's own 32), it refuses every try, even a right one
and even making a new key, until the oldest is 8 hours old. That is LockedOut.

Elsewhere, and on a computer without the key, decrypt and delete raise FileNotFoundError; a wrong PIN raises PermissionError."""
import ctypes
import functools
import os
import sys

PROVIDER = "Microsoft Platform Crypto Provider"
SILENT, OVERWRITE, OAEP, ALLOW_DECRYPT = 0x40, 0x80, 0x4, 0x1
BAD_KEYSET = 0x80090016                                          # NTE_BAD_KEYSET: no key by that name here
WRONG_PIN = {0x80090010, 0x80290408}                             # NTE_PERM, TPM_E_PCP_AUTHENTICATION_FAILED
LOCKED = {0x80090031, 0x80290409, 0x80280921}                    # NTE_AUTHENTICATION_IGNORED, its PCP twin, TPM_20_E_LOCKOUT
DEFAULT_WAIT = 480 * 60                                          # Windows' default "Standard User Lockout Duration"


class LockedOut(Exception):
    def __init__(self, seconds):
        self.seconds = int(seconds)
        super().__init__(f"the security chip refuses PINs for up to {self.seconds} seconds")


@functools.cache
def _nc():
    from ctypes import wintypes as W
    nc = ctypes.WinDLL("ncrypt.dll")
    H, P = ctypes.c_size_t, ctypes.c_void_p
    for fn, args in {
        "NCryptOpenStorageProvider": [ctypes.POINTER(H), W.LPCWSTR, W.DWORD],
        "NCryptCreatePersistedKey": [H, ctypes.POINTER(H), W.LPCWSTR, W.LPCWSTR, W.DWORD, W.DWORD],
        "NCryptOpenKey": [H, ctypes.POINTER(H), W.LPCWSTR, W.DWORD, W.DWORD],
        "NCryptSetProperty": [H, W.LPCWSTR, P, W.DWORD, W.DWORD],
        "NCryptFinalizeKey": [H, W.DWORD],
        "NCryptExportKey": [H, H, W.LPCWSTR, P, P, W.DWORD, ctypes.POINTER(W.DWORD), W.DWORD],
        "NCryptDecrypt": [H, P, W.DWORD, P, P, W.DWORD, ctypes.POINTER(W.DWORD), W.DWORD],
        "NCryptDeleteKey": [H, W.DWORD],
        "NCryptFreeObject": [H],
    }.items():
        f = getattr(nc, fn)
        f.argtypes, f.restype = args, ctypes.c_long
    return nc


def _check(r, what):
    r &= 0xFFFFFFFF
    if r == 0:
        return
    if r in LOCKED:
        raise LockedOut(_lockout_wait())
    if r in WRONG_PIN:
        raise PermissionError("wrong PIN")
    if r == BAD_KEYSET:
        raise FileNotFoundError("no such key on this computer")
    raise OSError(f"{what} failed (0x{r:08X})")


def _lockout_wait():
    """The longest Windows' lockout can last: a standard user's TPM failures count for the "Standard User Lockout Duration"
    policy (480 minutes unless set). The time left can't be read without admin rights."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Tpm") as k:
            minutes = int(winreg.QueryValueEx(k, "StandardUserAuthorizationFailureDuration")[0])
        return minutes * 60 if minutes > 0 else DEFAULT_WAIT
    except (OSError, ValueError):
        return DEFAULT_WAIT


def _provider():
    if sys.platform != "win32":
        raise FileNotFoundError("no security chip here")
    h = ctypes.c_size_t()
    r = _nc().NCryptOpenStorageProvider(ctypes.byref(h), PROVIDER, 0)
    if r:
        raise FileNotFoundError(f"the security chip's provider didn't open (0x{r & 0xFFFFFFFF:08X})")
    return h


def _open(prov, name):
    k = ctypes.c_size_t()
    _check(_nc().NCryptOpenKey(prov, ctypes.byref(k), name, 0, SILENT), "open key")
    return k


def _set_pin(k, pin):
    buf = ctypes.create_unicode_buffer(pin)
    try:
        _check(_nc().NCryptSetProperty(k, "SmartCardPin", buf, ctypes.sizeof(buf), 0), "set PIN")    # NCRYPT_PIN_PROPERTY
    finally:
        ctypes.memset(buf, 0, ctypes.sizeof(buf))


def available():
    """True when the provider opens and a test key can be made and deleted, or the chip is there but locked out (Windows then
    refuses even a key with no PIN)."""
    try:
        name = "Toner-probe-" + os.urandom(8).hex()
        create(name, None)
        delete(name)
        return True
    except LockedOut:
        return True
    except OSError:
        return False


def create(name, pin):
    """A persisted RSA-2048 decryption key (replacing one of that name); returns its public key, DER SubjectPublicKeyInfo."""
    from ctypes import wintypes as W
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    nc, prov = _nc(), _provider()
    k = ctypes.c_size_t()
    try:
        _check(nc.NCryptCreatePersistedKey(prov, ctypes.byref(k), "RSA", name, 0, OVERWRITE), "create key")
        try:
            _check(nc.NCryptSetProperty(k, "Length", ctypes.byref(W.DWORD(2048)), 4, 0), "set length")
            _check(nc.NCryptSetProperty(k, "Key Usage", ctypes.byref(W.DWORD(ALLOW_DECRYPT)), 4, 0), "set usage")
            if pin is not None:
                _set_pin(k, pin)
            _check(nc.NCryptFinalizeKey(k, SILENT), "finalize key")
            n = W.DWORD()
            _check(nc.NCryptExportKey(k, 0, "RSAPUBLICBLOB", None, None, 0, ctypes.byref(n), 0), "export key")
            blob = ctypes.create_string_buffer(n.value)
            _check(nc.NCryptExportKey(k, 0, "RSAPUBLICBLOB", None, blob, n.value, ctypes.byref(n), 0), "export key")
        finally:
            nc.NCryptFreeObject(k)
    finally:
        nc.NCryptFreeObject(prov)
    raw = blob.raw[:n.value]               # BCRYPT_RSAKEY_BLOB: six ULONGs, then the exponent and the modulus, big-endian
    cbe, cbm = int.from_bytes(raw[8:12], "little"), int.from_bytes(raw[12:16], "little")
    pub = rsa.RSAPublicNumbers(int.from_bytes(raw[24:24 + cbe], "big"), int.from_bytes(raw[24 + cbe:24 + cbe + cbm], "big"))
    return pub.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def decrypt(name, pin, data):
    """RSA-OAEP-SHA256 decryption with the key's PIN."""
    from ctypes import wintypes as W

    class OaepInfo(ctypes.Structure):
        _fields_ = [("pszAlgId", W.LPCWSTR), ("pbLabel", ctypes.c_void_p), ("cbLabel", W.ULONG)]
    nc, prov = _nc(), _provider()
    try:
        k = _open(prov, name)
        try:
            _set_pin(k, pin)
            out, n = ctypes.create_string_buffer(512), W.DWORD()
            _check(nc.NCryptDecrypt(k, data, len(data), ctypes.byref(OaepInfo("SHA256", None, 0)), out, 512, ctypes.byref(n),
                                    OAEP | SILENT), "decrypt")
            try:
                return out.raw[:n.value]
            finally:
                ctypes.memset(out, 0, 512)
        finally:
            nc.NCryptFreeObject(k)
    finally:
        nc.NCryptFreeObject(prov)


def delete(name):
    """Deletes the key; nothing happens when it isn't here."""
    nc = _nc() if sys.platform == "win32" else None
    try:
        prov = _provider()
    except FileNotFoundError:
        return
    try:
        try:
            k = _open(prov, name)
        except FileNotFoundError:
            return
        r = nc.NCryptDeleteKey(k, 0)              # (NCRYPT_SILENT_FLAG is refused here: NTE_BAD_FLAGS); success frees k
        if r:
            nc.NCryptFreeObject(k)
            _check(r, "delete key")
    finally:
        nc.NCryptFreeObject(prov)
