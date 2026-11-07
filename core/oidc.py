"""OpenID Connect for SSO sign-in: provider discovery and ID-token checks. No Qt and no database, so a system helper can import it.
Errors carry the provider's host only, never a token, a secret or a URL query."""
import hmac
import threading
import time
import urllib.parse

import jwt
import requests

_TEST_ALLOW_HTTP = False        # only tests set this
ALGS = ("RS256", "PS256", "ES256")      # never "none", never HMAC
LEEWAY = 60                             # seconds of clock difference we forgive
CACHE_SECONDS = 3600
_DIRECT = {"proxies": {"http": "", "https": ""}}   # like every web connection in Toner: direct, whatever proxy the system has


class OidcError(Exception):
    pass


class Unreachable(OidcError):
    pass


class Refused(OidcError):
    pass


class NotFresh(OidcError):
    pass


class BadAnswer(OidcError):
    pass


class Cancelled(OidcError):
    pass


_lock = threading.Lock()
_meta_cache = {}        # issuer -> (fetched_at, document)
_keys_cache = {}        # jwks_uri -> (fetched_at, {kid: PyJWK})


def host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or "the provider"
    except ValueError:
        return "the provider"


def _https(url):
    try:
        scheme = urllib.parse.urlsplit(url).scheme
    except ValueError:
        return False
    return scheme == "https" or (_TEST_ALLOW_HTTP and scheme == "http")


def _get_json(url, timeout):
    host = host_of(url)
    if not _https(url):
        raise BadAnswer(f"{host} is not reached over https")
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "Toner"}, **_DIRECT)
    except requests.RequestException:
        raise Unreachable(f"{host} can't be reached") from None
    try:
        if r.status_code != 200:
            raise ValueError
        out = r.json()
        if not isinstance(out, dict):
            raise ValueError
    except ValueError:
        raise BadAnswer(f"{host} gave an answer that can't be read") from None
    return out


def discover(issuer, timeout=10):
    """The provider's discovery document, cached for an hour. Its `issuer` must be the one asked for and every endpoint https."""
    now = time.monotonic()
    with _lock:
        hit = _meta_cache.get(issuer)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    host = host_of(issuer)
    meta = _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout)
    if meta.get("issuer") != issuer:
        raise BadAnswer(f"{host} named a different issuer")
    if not isinstance(meta.get("jwks_uri"), str):
        raise BadAnswer(f"{host} gave no signing keys")
    for k, v in meta.items():
        if (k.endswith("_endpoint") or k == "jwks_uri") and not (isinstance(v, str) and _https(v)):
            raise BadAnswer(f"{host} gave an endpoint that is not https")
    with _lock:
        _meta_cache[issuer] = (now, meta)
    return meta


def _fetch_keys(meta, timeout):
    uri = meta["jwks_uri"]
    doc = _get_json(uri, timeout)
    out = {}
    for jwk in doc["keys"] if isinstance(doc.get("keys"), list) else []:
        try:
            if isinstance(jwk, dict) and isinstance(jwk.get("kid"), str):
                out[jwk["kid"]] = jwt.PyJWK(jwk)
        except jwt.PyJWTError:
            continue            # a key type we don't use (or a broken one) is skipped, not fatal
    with _lock:
        _keys_cache[uri] = (time.monotonic(), out)
    return out


def keys(meta, kid, timeout=10):
    """The provider's signing key `kid`. Cached; an unknown kid refetches once (key rotation), then is refused."""
    with _lock:
        hit = _keys_cache.get(meta["jwks_uri"])
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS and kid in hit[1]:
        return hit[1][kid]
    found = _fetch_keys(meta, timeout).get(kid)
    if found is None:
        raise BadAnswer(f"{host_of(meta['jwks_uri'])} has no signing key for this sign-in")
    return found


def _num(claims, name):
    v = claims.get(name)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise BadAnswer("the sign-in answer has a bad time")
    return v


def verify_id_token(cfg, token, nonce, max_age=300, now=None):
    """The claims of an ID token meant for this app, from this issuer, signed by its key, and (with max_age) from a fresh sign-in."""
    host = host_of(cfg["issuer"])
    now = time.time() if now is None else now
    meta = discover(cfg["issuer"])
    try:
        head = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise BadAnswer(f"{host}'s answer couldn't be read") from None
    alg, kid = head.get("alg"), head.get("kid")
    if alg not in ALGS or not isinstance(kid, str):
        raise BadAnswer(f"{host}'s answer is signed in a way Toner doesn't accept")
    key = keys(meta, kid)
    try:
        # exp/iat/nbf are checked below instead, so `now` can be given
        claims = jwt.decode(token, key, algorithms=[alg], audience=cfg["client_id"], issuer=meta["issuer"], leeway=LEEWAY,
                            options={"require": ["exp", "iat", "iss", "aud"], "verify_exp": False, "verify_iat": False, "verify_nbf": False})
    except jwt.PyJWTError:
        raise BadAnswer(f"{host}'s answer failed its checks") from None
    if _num(claims, "exp") + LEEWAY < now or _num(claims, "iat") - LEEWAY > now or ("nbf" in claims and _num(claims, "nbf") - LEEWAY > now):
        raise BadAnswer(f"{host}'s answer is not valid at this time")
    if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and claims.get("azp") != cfg["client_id"]:
        raise BadAnswer(f"{host}'s answer was meant for other apps")
    if nonce is not None and not (isinstance(claims.get("nonce"), str) and hmac.compare_digest(claims["nonce"].encode(), nonce.encode())):
        raise BadAnswer(f"{host}'s answer doesn't match this sign-in")
    if max_age is not None:
        if "auth_time" not in claims:
            raise NotFresh(f"{host} gave no sign-in time")
        t = _num(claims, "auth_time")
        if t - LEEWAY > now:
            raise BadAnswer(f"{host}'s answer is not valid at this time")
        if now - t > max_age + LEEWAY:
            raise NotFresh(f"{host} did not confirm a fresh sign-in")
    return claims
