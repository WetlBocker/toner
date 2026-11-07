# Run directly (python tests/test_oidc.py) or all together (python tests/run_all.py).
# OpenID Connect discovery and ID-token checks (core/oidc.py) against a fake local provider (tests/fake_oidc.py).
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import base64, hashlib, hmac, json, time
from core import oidc
from fake_oidc import FakeProvider

oidc._TEST_ALLOW_HTTP = True
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(exc, fn, *a, token=None, **k):
    """True when fn raises exactly `exc` (or a subclass), with a message that holds neither the token nor a '?'."""
    try:
        fn(*a, **k)
    except exc as e:
        return "?" not in str(e) and not (token and token in str(e))
    except Exception:
        return False
    return False

def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

P = FakeProvider()
ISS = P.start()
CFG = {"issuer": ISS, "client_id": "toner-app"}
V = lambda t, nonce=None, **k: oidc.verify_id_token(CFG, t, nonce, **k)

print("== good tokens")
check("RS256 accepted, sub returned", V(P.token(sub="abc"))["sub"] == "abc")
check("ES256 accepted", V(P.token_es256(sub="e"))["sub"] == "e")
check("matching nonce accepted", V(P.token(nonce="n1"), "n1")["nonce"] == "n1")
check("several audiences with azp accepted", V(P.token(aud=["toner-app", "x"], azp="toner-app"))["sub"] == "sub-1")
check("auth_time not asked for: absent is fine", V(P.token(auth_time=None), None, max_age=None)["sub"] == "sub-1")
check("auth_time 40 s old (inside max_age) accepted", V(P.token(auth_time=int(time.time()) - 40))["sub"] == "sub-1")
meta = oidc.discover(ISS)
check("discovery returns the document", meta["issuer"] == ISS and meta["jwks_uri"].endswith("/jwks"))

print("== refused (BadAnswer)")
B = oidc.BadAnswer
now = int(time.time())
for name, tok in [("another aud", P.token(aud="other-app")), ("another iss", P.token(iss="http://evil.example")),
                  ("expired token", P.token(exp=now - 120)), ("iat 120 s in the future", P.token(iat=now + 120)),
                  ("several audiences without azp", P.token(aud=["toner-app", "x"])),
                  ("several audiences, azp another", P.token(aud=["toner-app", "x"], azp="x")),
                  ("missing exp", P.token(exp=None)), ("unknown kid", P.token(_kid="nope"))]:
    check(name, raises(B, V, tok, token=tok))
t = P.token(nonce="n1")
check("wrong nonce", raises(B, V, t, "n2", token=t))
t = P.token()
check("missing nonce when one is asked for", raises(B, V, t, "n2", token=t))
t = b64({"alg": "none", "typ": "JWT"}) + "." + b64({**{"iss": ISS, "aud": "toner-app", "exp": now + 600, "iat": now, "auth_time": now}}) + "."
check("alg none", raises(B, V, t, token=t))
h = b64({"alg": "HS256", "typ": "JWT", "kid": P.rsa_kid}) + "." + b64({"iss": ISS, "aud": "toner-app", "exp": now + 600, "iat": now, "auth_time": now})
t = h + "." + base64.urlsafe_b64encode(hmac.new(P.public_pem(), h.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
check("HS256 signed with the public key's PEM", raises(B, V, t, token=t))
t = P.token(sub="a"); head, body, sig = t.split(".")
evil = b64({**json.loads(base64.urlsafe_b64decode(body + "==")), "sub": "admin"})
t = f"{head}.{evil}.{sig}"
check("tampered payload", raises(B, V, t, token=t))
check("not a token at all", raises(B, V, "garbage", token="garbage"))
t = P.token_es256(sub="a"); head, body, sig = t.split(".")
t = P.token().split(".")[0] + "." + body + "." + sig
check("RS256 header over an ES256 signature", raises(B, V, t, token=t))

print("== fresh sign-in (NotFresh)")
t = P.token(auth_time=now - 400)
check("auth_time 400 s old", raises(oidc.NotFresh, V, t, token=t))
t = P.token(auth_time=None)
check("missing auth_time with max_age=300", raises(oidc.NotFresh, V, t, token=t))
check("now= is honoured (a token made now is stale a day later)", raises(oidc.BadAnswer, V, P.token(), now=time.time() + 86400))
check("auth_time 400 s old is fine with max_age=None", V(P.token(auth_time=now - 400), None, max_age=None)["sub"] == "sub-1")
check("auth_time in the future by 120 s", raises(B, V, P.token(auth_time=now + 120)))

print("== key rotation")
hits = P.jwks_hits
P.rotate()
check("a token from the rotated key passes", V(P.token(sub="new"))["sub"] == "new")
check("... after exactly one refetch", P.jwks_hits == hits + 1)
check("... and an ES256 one from the rotated key without another fetch", V(P.token_es256(sub="new2"))["sub"] == "new2" and P.jwks_hits == hits + 1)
hits = P.jwks_hits
check("an unknown kid refetches once, then is refused", raises(B, V, P.token(_kid="ghost")) and P.jwks_hits == hits + 1)

print("== discovery")
P.issuer_claim = "http://127.0.0.1:1/other"
oidc._meta_cache.clear()
check("document issuer differs from the asked issuer", raises(B, oidc.discover, ISS))
P.issuer_claim = None
P.meta_extra = {"userinfo_endpoint": "ftp://plain.example/userinfo"}
oidc._meta_cache.clear()
check("an endpoint that is not https is refused", raises(B, oidc.discover, ISS))
P.meta_extra = {}
oidc._meta_cache.clear()
check("discovery works again, and is cached", oidc.discover(ISS)["issuer"] == ISS and oidc.discover(ISS) is oidc.discover(ISS))
print("== unreachable")
P.stop()
oidc._meta_cache.clear()
check("a stopped provider raises Unreachable", raises(oidc.Unreachable, oidc.discover, ISS))
check("... through verify_id_token too", raises(oidc.Unreachable, V, "x.y.z"))
check("Cancelled, Refused, NotFresh, BadAnswer, Unreachable are OidcErrors", all(issubclass(c, oidc.OidcError) for c in
      (oidc.Cancelled, oidc.Refused, oidc.NotFresh, oidc.BadAnswer, oidc.Unreachable)))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
