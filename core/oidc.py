"""OpenID Connect for SSO sign-in: provider discovery, ID-token checks, the browser sign-in, refresh and Entra groups. No Qt and no database,
so a system helper can import it. Errors carry the provider's host only, never a token, a secret or a URL query."""
import base64
import hashlib
import hmac
import http.server
import math
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass

import jwt
import requests

from core import directory, osstore

_TEST_ALLOW_HTTP = False        # only tests set this
ALGS = ("RS256", "PS256", "ES256")      # never "none", never HMAC
LEEWAY = 60                             # seconds of clock difference we forgive
CACHE_SECONDS = 3600
_DIRECT = {"proxies": {"http": "", "https": ""}}   # like every web connection in Toner: direct, whatever proxy the system has
GRAPH = "https://graph.microsoft.com/v1.0"
SSO_DONE_PAGE = "You're signed in. You can close this tab and go back to Toner."


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


def _send(method, url, timeout, **kw):
    """The response of a direct https request. No connection, or a 5xx/429 (the provider is down or busy): Unreachable."""
    host = host_of(url)
    if not _https(url):
        raise BadAnswer(f"{host} is not reached over https")
    kw["headers"] = {"User-Agent": "Toner", **kw.get("headers", {})}
    try:
        r = requests.request(method, url, timeout=timeout, allow_redirects=False, **kw, **_DIRECT)
    except requests.RequestException:
        raise Unreachable(f"{host} can't be reached") from None
    if r.status_code >= 500 or r.status_code == 429:
        raise Unreachable(f"{host} can't be reached")
    return r


def _json(r, url):
    try:
        out = r.json()
        if r.status_code != 200 or not isinstance(out, dict):
            raise ValueError
    except ValueError:
        raise BadAnswer(f"{host_of(url)} gave an answer that can't be read") from None
    return out


def _get_json(url, timeout):
    return _json(_send("GET", url, timeout), url)


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
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
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
        # PS256 verifies only when the provider's key says "alg": "PS256" (PyJWK takes the algorithm from the key; a bare RSA key is RS256)
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


@dataclass
class Tokens:
    id_token: str
    access_token: str
    refresh_token: str | None
    claims: dict


def _token_call(cfg, form):
    """POST to the token endpoint; (id_token, access_token, refresh_token) from the answer. invalid_grant is Refused."""
    url = discover(cfg["issuer"])["token_endpoint"]
    form = {**form, "client_id": cfg["client_id"]}
    secret = osstore.get(f"oidc:{cfg['id']}")
    if secret:
        form["client_secret"] = secret.decode()
    r = _send("POST", url, 10, data=form)
    try:
        err = r.json().get("error")
    except (ValueError, AttributeError):
        err = None
    if err == "invalid_grant":
        raise Refused(f"{host_of(url)} no longer allows this sign-in")
    out = _json(r, url)
    got = [out.get(k) for k in ("id_token", "access_token", "refresh_token")]
    if not isinstance(got[1], str) or not all(v is None or isinstance(v, str) for v in (got[0], got[2])):
        raise BadAnswer(f"{host_of(url)}'s answer couldn't be read")
    return got


class _LoopbackServer(http.server.ThreadingHTTPServer):
    daemon_threads = True       # an idle pre-connection from the browser must not hold anything up
    owner = None


class _Redirect(http.server.BaseHTTPRequestHandler):
    timeout = 5

    def log_message(self, *a):
        pass

    def _reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        owner, url = self.server.owner, urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        if url.path != "/" or not ({"code", "state", "error"} & q.keys()):
            return self._reply(404)         # a stray request (favicon, a probe) is not the redirect
        with owner._lock:
            first = owner._result is None
            if first:
                owner._result = q
        if not first:
            return self._reply(404)
        owner._got.set()
        good = "error" not in q and q.get("state") == owner._state
        self._reply(200 if good else 400, f"<!doctype html><meta charset=utf-8><title>Toner</title><p>{SSO_DONE_PAGE}</p>".encode() if good else b"")


class BrowserSignIn:
    """One sign-in in the person's browser: authorization code with PKCE on a loopback port, forced fresh (prompt=login, max_age=0).
    The port is bound here (so .url has it); run() or close() frees it."""

    def __init__(self, cfg, nonce=None, open_url=webbrowser.open, login_hint=None, scopes="openid profile email offline_access"):
        self.cfg, self.open_url = cfg, open_url
        self.nonce = nonce or secrets.token_urlsafe(32)
        self._state = secrets.token_urlsafe(32)
        self._verifier = secrets.token_urlsafe(64)
        endpoint = discover(cfg["issuer"])["authorization_endpoint"]
        self._result = None             # the redirect's query, once there is one
        self._got = threading.Event()
        self._lock = threading.Lock()
        self._server = _LoopbackServer(("127.0.0.1", 0), _Redirect)
        self._server.owner = self
        self.redirect_uri = f"http://localhost:{self._server.server_address[1]}/"     # the name providers register; the listener is 127.0.0.1 only
        q = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": self.redirect_uri, "scope": scopes, "state": self._state,
             "nonce": self.nonce, "prompt": "login", "max_age": "0", "code_challenge_method": "S256",
             "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(self._verifier.encode()).digest()).rstrip(b"=").decode()}
        if login_hint:
            q["login_hint"] = login_hint
        self.url = endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(q)

    def open(self):
        self.open_url(self.url)

    def close(self):
        if self._server:
            self._server.server_close()
            self._server = None

    def run(self, cancel, timeout=300):
        srv = self._server
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
        end = time.monotonic() + timeout
        try:
            while not self._got.wait(0.1):
                if cancel.is_set() or time.monotonic() > end:
                    raise Cancelled("the sign-in was not finished")
        finally:
            srv.shutdown()
            self.close()
        got, host = self._result, host_of(self.cfg["issuer"])
        if "error" in got:
            raise Refused(f"{host} refused the sign-in")
        if not hmac.compare_digest(got.get("state", "").encode(), self._state.encode()) or not got.get("code"):
            raise BadAnswer(f"{host}'s answer doesn't match this sign-in")
        id_token, access, refresh_token = _token_call(self.cfg, {"grant_type": "authorization_code", "code": got["code"],
                                                                 "redirect_uri": self.redirect_uri, "code_verifier": self._verifier})
        if not id_token:
            raise BadAnswer(f"{host} gave no ID token")
        return Tokens(id_token, access, refresh_token, verify_id_token(self.cfg, id_token, self.nonce, max_age=300))


def refresh(cfg, refresh_token):
    """New tokens from a refresh token. A revoked one is Refused, no connection is Unreachable."""
    id_token, access, new = _token_call(cfg, {"grant_type": "refresh_token", "refresh_token": refresh_token})
    claims = verify_id_token(cfg, id_token, None, max_age=None) if id_token else {}
    return Tokens(id_token or "", access, new, claims)


def _graph(method, path, token, **kw):
    r = _send(method, GRAPH + path, 10, **{**kw, "headers": {"Authorization": f"Bearer {token}", **kw.get("headers", {})}})
    return _json(r, GRAPH)


def groups(cfg, claims, access_token):
    """The person's groups: the groups claim, or (Entra, over about 200 groups) the list fetched from Graph for this same person."""
    name = cfg.get("groups_claim")
    if not name:
        return ()
    pointer = claims.get("_claim_names")
    if isinstance(pointer, dict) and name in pointer:
        if _graph("GET", "/me", access_token).get("id") != claims.get("oid"):
            raise BadAnswer(f"{host_of(GRAPH)} answered for someone else")
        found = _graph("POST", "/me/getMemberObjects", access_token, json={"securityEnabledOnly": False}).get("value")
    else:
        found = claims.get(name)
    if isinstance(found, str):
        found = [found]
    return tuple(g for g in found if isinstance(g, str)) if isinstance(found, list) else ()


def domain_ok(cfg, claims):
    """True when the account the token names is in one of the connection's email domains (any case). Google: its hd claim (no
    hd: refused). Others: the email's domain (refused when email_verified is there and not true), else preferred_username's."""
    if cfg.get("provider") == "google":
        dom = claims.get("hd")
    else:
        email = claims.get("email")
        if isinstance(email, str) and email:
            if "email_verified" in claims and claims["email_verified"] is not True:
                return False
            who = email
        else:
            who = claims.get("preferred_username")
        dom = who.rsplit("@", 1)[1] if isinstance(who, str) and "@" in who else None
    return isinstance(dom, str) and bool(dom) and dom.casefold() in {str(s).casefold() for s in cfg.get("suffixes") or []}


def user_from(cfg, claims, groups):
    """The person the token names, once their domain is one of the connection's (BadAnswer otherwise)."""
    if not domain_ok(cfg, claims):
        raise BadAnswer(f"{host_of(cfg['issuer'])}'s answer is for an account outside the connection's email domains")
    name =(claims.get("preferred_username") or claims.get("email") or claims["sub"]).lower()
    return directory.User(guid=claims[cfg.get("id_claim", "sub")], name=name, display=claims.get("name") or name, groups=tuple(groups), enabled=True)


def search_groups(access_token, text, cap=200):
    """Entra groups matching `text` (the first page when empty) as (id, name). One page only: Graph's page size is 999, so cap is at most that."""
    params = {"$select": "id,displayName", "$top": str(min(cap, 999))}
    headers = {}
    if text:
        params["$search"] = '"displayName:' + text.replace('"', "") + '"'
        headers["ConsistencyLevel"] = "eventual"
    rows = _graph("GET", "/groups", access_token, params=params, headers=headers).get("value")
    rows = rows if isinstance(rows, list) else []
    return [(g["id"], g["displayName"]) for g in rows if isinstance(g, dict) and isinstance(g.get("id"), str) and isinstance(g.get("displayName"), str)][:cap]
