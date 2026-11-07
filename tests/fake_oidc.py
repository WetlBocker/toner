"""A fake OpenID Connect provider on 127.0.0.1 for tests (tests/ is on sys.path when run as a script:  from fake_oidc import FakeProvider).

    p = FakeProvider(); issuer = p.start()          # "http://127.0.0.1:<port>"; set oidc._TEST_ALLOW_HTTP = True first
    p.token(sub="x", nonce="n")                      # an RS256 ID token; defaults below, a claim given as None is left out
    p.token_es256(...)                               # the same, signed with the ES256 key
    p.token(_kid="other")                            # _kid sets the header's kid (the signature is still the real key's)
    p.rotate()                                       # new keys with new kids; only the new ones are served
    p.public_pem()                                   # PEM of the RS256 public key (for the HS256-with-the-public-key attack)
    p.jwks_hits                                      # how many times the key set was fetched
    p.issuer_claim / p.meta_extra                    # change the discovery document: a different `issuer`, extra fields
    p.routes["/authorize"] = fn(provider, handler)   # later tasks add endpoints here (GET and POST); the document already names /authorize and /token
    p.stop()
Defaults: iss=issuer, aud="toner-app", exp=now+600, iat=now, auth_time=now, sub, oid, preferred_username, groups."""
import http.server
import json
import threading
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


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
        self._new_keys()

    def _new_keys(self):
        self.rsa_kid, self.ec_kid = f"rsa-{self.generation}", f"ec-{self.generation}"
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
            {**json.loads(ECAlgorithm.to_jwk(self.ec_key.public_key())), "kid": self.ec_kid, "use": "sig", "alg": "ES256"}]}

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

            def handle_any(self):
                path = self.path.split("?")[0]
                if path == "/.well-known/openid-configuration":
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
