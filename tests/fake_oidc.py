"""A fake OpenID Connect provider on 127.0.0.1 for tests (tests/ is on sys.path when run as a script:  from fake_oidc import FakeProvider).

    p = FakeProvider(); issuer = p.start()          # "http://127.0.0.1:<port>"; set oidc._TEST_ALLOW_HTTP = True first
    p.token(sub="x", nonce="n")                      # an RS256 ID token; defaults below, a claim given as None is left out
    p.token_es256(...)                               # the same, signed with the ES256 key
    p.token(_kid="other")                            # _kid sets the header's kid (the signature is still the real key's)
    p.rotate()                                       # new keys with new kids; only the new ones are served
    p.public_pem()                                   # PEM of the RS256 public key (for the HS256-with-the-public-key attack)
    p.jwks_hits                                      # how many times the key set was fetched
    p.issuer_claim / p.meta_extra                    # change the discovery document: a different `issuer`, extra fields
    p.routes["/x"] = fn(provider, handler)           # add endpoints here (GET and POST)
    /authorize redirects to the redirect_uri with a code (p.mode = "denied" / "bad_state" for the other answers) and records its query in
    p.authorize_seen; /token swaps a code (checking the PKCE verifier: p.pkce_ok) or refresh token "rt-1" (p.revoked) for tokens, records the
    forms in p.token_requests; p.id_claims adds claims to those ID tokens; p.token_ps256(...) is signed with the PS256 key;
    p.force = 503 makes every endpoint answer with that status; a fake Microsoft Graph lives under "/graph" (oidc.GRAPH = issuer + "/graph"):
    /me (p.graph_me_id), /me/getMemberObjects (p.graph_member_ids), /groups (p.graph_groups); p.graph_seen records (path, query, headers).
    p.stop()
Defaults: iss=issuer, aud="toner-app", exp=now+600, iat=now, auth_time=now, sub, oid, preferred_username, groups."""
import base64
import hashlib
import http.server
import json
import re
import threading
import time
import urllib.parse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


def leaks(texts, tokens):
    """The texts that hold one of the tokens as a whole value. The stand-ins ("at-1", "rt-1") are four characters, and a random state,
    nonce or challenge in a logged URL holds those by chance about once in several thousand runs."""
    found = [re.compile(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])") for t in tokens]
    return [x for x in texts if any(f.search(x) for f in found)]


assert leaks(["access_token=at-1&x=1", "Bearer at-1", "'at-1'", "state=Qm9at-1xYz"], ["at-1"]) == ["access_token=at-1&x=1", "Bearer at-1", "'at-1'"]


class FakeProvider:
    CLIENT_ID = "toner-app"

    def __init__(self):
        self.issuer = None
        self.issuer_claim = None
        self.meta_extra = {}
        self.routes = {}
        self.jwks_hits = 0
        self.generation = 0
        self._server = None
        self.force = None
        self.mode = "ok"
        self.codes = {}
        self.authorize_seen = []
        self.token_requests = []
        self.pkce_ok = None
        self.revoked = set()
        self.id_claims = {}
        self.graph_me_id = "oid-1"
        self.graph_member_ids = ["g-1", "g-2"]
        self.graph_groups = [("id-a", "Alpha"), ("id-b", "Beta")]
        self.graph_seen = []
        self.routes.update({"/authorize": _authorize, "/token": _token, "/graph/me": _graph_me,
                            "/graph/me/getMemberObjects": _graph_members, "/graph/groups": _graph_groups})
        self._new_keys()

    def _new_keys(self):
        self.rsa_kid, self.ec_kid, self.ps_kid = f"rsa-{self.generation}", f"ec-{self.generation}", f"ps-{self.generation}"
        self.rsa_key = rsa.generate_private_key(65537, 2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())

    def rotate(self):
        self.generation += 1
        self._new_keys()

    def public_pem(self):
        return self.rsa_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def jwks(self):
        return {"keys": [
            {**json.loads(RSAAlgorithm.to_jwk(self.rsa_key.public_key())), "kid": self.rsa_kid, "use": "sig", "alg": "RS256"},
            {**json.loads(ECAlgorithm.to_jwk(self.ec_key.public_key())), "kid": self.ec_kid, "use": "sig", "alg": "ES256"},
            {**json.loads(RSAAlgorithm.to_jwk(self.rsa_key.public_key())), "kid": self.ps_kid, "use": "sig", "alg": "PS256"}]}

    def meta(self):
        u = self.issuer
        return {"issuer": self.issuer_claim or u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
                "jwks_uri": u + "/jwks", **self.meta_extra}

    def _claims(self, claims):
        now = int(time.time())
        out = {"iss": self.issuer, "aud": self.CLIENT_ID, "exp": now + 600, "iat": now, "auth_time": now, "sub": "sub-1",
               "oid": "oid-1", "preferred_username": "ann@example.com", "groups": ["g1"]}
        out.update(claims)
        return {k: v for k, v in out.items() if v is not None}

    def token(self, _kid=None, **claims):
        return jwt.encode(self._claims(claims), self.rsa_key, algorithm="RS256", headers={"kid": _kid or self.rsa_kid})

    def token_es256(self, _kid=None, **claims):
        return jwt.encode(self._claims(claims), self.ec_key, algorithm="ES256", headers={"kid": _kid or self.ec_kid})

    def token_ps256(self, _kid=None, **claims):
        return jwt.encode(self._claims(claims), self.rsa_key, algorithm="PS256", headers={"kid": _kid or self.ps_kid})

    def start(self):
        prov = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send_json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def handle_any(self):
                path = self.path.split("?")[0]
                if prov.force:
                    self.body()                 # read first: answering over an unread POST body resets the connection on Windows
                    self.send_json({}, prov.force)
                elif path == "/.well-known/openid-configuration":
                    self.send_json(prov.meta())
                elif path == "/jwks":
                    prov.jwks_hits += 1
                    self.send_json(prov.jwks())
                elif path in prov.routes:
                    prov.routes[path](prov, self)
                else:
                    self.send_json({}, 404)

            do_GET = do_POST = handle_any

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.issuer = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self.issuer

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def _query(handler):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(handler.path).query, keep_blank_values=True).items()}


def _authorize(prov, h):
    q = _query(h)
    prov.authorize_seen.append(q)
    sep = "&" if "?" in q["redirect_uri"] else "?"
    if prov.mode == "denied":
        back = {"error": "access_denied", "state": q["state"]}
    else:
        code = f"code-{len(prov.codes)}"
        prov.codes[code] = (q["code_challenge"], q.get("nonce"))
        back = {"code": code, "state": "wrong" if prov.mode == "bad_state" else q["state"]}
    h.send_response(302)
    h.send_header("Location", q["redirect_uri"] + sep + urllib.parse.urlencode(back))
    h.send_header("Content-Length", "0")
    h.end_headers()


def _token(prov, h):
    f = {k: v[0] for k, v in urllib.parse.parse_qs(h.body().decode()).items()}
    prov.token_requests.append(f)
    if f.get("grant_type") == "refresh_token":
        if f.get("refresh_token") != "rt-1" or "rt-1" in prov.revoked:
            return h.send_json({"error": "invalid_grant"}, 400)
        return h.send_json({"id_token": prov.token(**prov.id_claims), "access_token": "at-2", "refresh_token": "rt-2"})
    challenge, nonce = prov.codes.pop(f.get("code"), (None, None))
    verifier = f.get("code_verifier", "")
    prov.pkce_ok = challenge is not None and challenge == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not prov.pkce_ok:
        return h.send_json({"error": "invalid_grant"}, 400)
    h.send_json({"id_token": prov.token(nonce=nonce, **prov.id_claims), "access_token": "at-1", "refresh_token": "rt-1"})


def _graph(prov, h, answer):
    prov.graph_seen.append((h.path.split("?")[0], _query(h), dict(h.headers)))
    if h.headers.get("Authorization") != "Bearer at-1":
        return h.send_json({}, 401)
    h.send_json(answer)


def _graph_me(prov, h):
    _graph(prov, h, {"id": prov.graph_me_id})


def _graph_members(prov, h):
    _graph(prov, h, {"value": prov.graph_member_ids})


def _graph_groups(prov, h):
    _graph(prov, h, {"value": [{"id": i, "displayName": n} for i, n in prov.graph_groups]})
