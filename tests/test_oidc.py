# Run directly (python tests/test_oidc.py) or all together (python tests/run_all.py).
# OpenID Connect discovery and ID-token checks (core/oidc.py) against a fake local provider (tests/fake_oidc.py).
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import base64, hashlib, hmac, json, threading, time
import requests
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
print("== 5xx and 429 are an outage (Unreachable), other 4xx stay BadAnswer")
SECRETS = {}
oidc.osstore.get = lambda n, file=None: SECRETS.get(n)    # never the real store
oidc._meta_cache.clear()
P.force = 503
check("discovery 503", raises(oidc.Unreachable, oidc.discover, ISS))
P.force = 429
check("discovery 429", raises(oidc.Unreachable, oidc.discover, ISS))
P.force = 404
check("discovery 404 is BadAnswer", raises(B, oidc.discover, ISS))
P.force = None
oidc.discover(ISS)
P.force = 502
check("keys 502 (unknown kid forces a fetch)", raises(oidc.Unreachable, V, P.token(_kid="ghost2")))
check("token endpoint 503", raises(oidc.Unreachable, oidc.refresh, dict(CFG, id="c1"), "rt-1"))
P.force = 400
check("token endpoint 400 without invalid_grant is BadAnswer", raises(B, oidc.refresh, dict(CFG, id="c1"), "rt-1"))
P.force = None

print("== numbers must be finite; PS256")
for name, kw in [("auth_time NaN", {"auth_time": float("nan")}), ("auth_time Infinity", {"auth_time": float("inf")}),
                 ("exp Infinity", {"exp": float("inf")}), ("exp NaN", {"exp": float("nan")})]:
    check(name, raises(B, V, P.token(**kw)))
check("PS256 accepted (the provider's key says PS256)", V(P.token_ps256(sub="ps"))["sub"] == "ps")

print("== browser sign-in")
CFG = {**CFG, "id": "c1", "groups_claim": "groups"}
V = lambda t, nonce=None, **k: oidc.verify_id_token(CFG, t, nonce, **k)
page = []

LOOP = lambda b: b.redirect_uri.replace("localhost", "127.0.0.1")     # the listener is on 127.0.0.1 only

def browse(url):
    def go():
        try:
            r = requests.get(url, timeout=10, **oidc._DIRECT)
            page.append((r.status_code, r.text))
        except requests.RequestException:
            page.append(None)
    threading.Thread(target=go, daemon=True).start()

def flow(**k):
    page.clear()
    b = oidc.BrowserSignIn(CFG, open_url=browse, **k)
    b.open()
    return b, b.run(threading.Event(), timeout=10)

SECRETS["oidc:c1"] = b"the-secret"
b, tok = flow(login_hint="ann@example.com")
seen = P.authorize_seen[-1]
check("full flow returns Tokens", tok.claims["sub"] == "sub-1" and tok.access_token == "at-1" and tok.refresh_token == "rt-1" and tok.id_token)
check("provider saw prompt=login and max_age=0", seen["prompt"] == "login" and seen["max_age"] == "0")
check("... S256, nonce, hint, loopback redirect", seen["code_challenge_method"] == "S256" and seen["nonce"] == b.nonce and seen["login_hint"] == "ann@example.com"
      and seen["redirect_uri"].startswith("http://localhost:") and seen["response_type"] == "code" and seen["client_id"] == "toner-app" and seen["state"])
check("the code exchange used the identical redirect_uri", P.token_requests[-1]["redirect_uri"] == seen["redirect_uri"] == b.redirect_uri)
check("PKCE verifier matched the challenge", P.pkce_ok is True)
check("client secret from the store was sent", P.token_requests[-1].get("client_secret") == "the-secret")
check("the browser got the approved page", oidc.SSO_DONE_PAGE == "You're signed in. You can close this tab and go back to Toner."
      and page[0][0] == 200 and oidc.SSO_DONE_PAGE in page[0][1] and "http" not in page[0][1])
check("a second request to the port gets nothing (port closed)", raises(requests.ConnectionError, requests.get, LOOP(b), timeout=3, **oidc._DIRECT))
SECRETS.clear()
flow()
check("no stored secret: none sent", "client_secret" not in P.token_requests[-1])
check("a given nonce is used", flow(nonce="mine")[0].nonce == "mine" and P.authorize_seen[-1]["nonce"] == "mine")
P.id_claims = {"auth_time": now - 1000}
check("a stale auth_time from the provider is NotFresh", raises(oidc.NotFresh, flow))
P.id_claims = {}
P.mode = "bad_state"
check("wrong state is BadAnswer", raises(B, flow))
P.mode = "denied"
check("error=access_denied is Refused", raises(oidc.Refused, flow))
P.mode = "ok"

b = oidc.BrowserSignIn(CFG, open_url=lambda u: None)
port = int(b.redirect_uri.split(":")[2].rstrip("/"))
cancel = threading.Event()
threading.Timer(0.3, cancel.set).start()
threading.Timer(0.1, lambda: page.append(requests.get(LOOP(b) + "favicon.ico", timeout=3, **oidc._DIRECT).status_code)).start()
page.clear()
t0 = time.monotonic()
check("Cancel raises Cancelled", raises(oidc.Cancelled, b.run, cancel, 30))
check("... within 1.5 s of the click", time.monotonic() - t0 < 1.5, time.monotonic() - t0)
check("a stray path got 404 and did not end the wait", page == [404])
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port)); freed = True
except OSError:
    freed = False
s.close()
check("... and the port is free again", freed)
check("a timeout also raises Cancelled", raises(oidc.Cancelled, oidc.BrowserSignIn(CFG, open_url=lambda u: None).run, threading.Event(), 0.3))

print("== refresh")
tk = oidc.refresh(CFG, "rt-1")
check("refresh gives new tokens", tk.access_token == "at-2" and tk.refresh_token == "rt-2" and tk.claims["sub"] == "sub-1")
P.revoked.add("rt-1")
check("a revoked refresh token is Refused", raises(oidc.Refused, oidc.refresh, CFG, "rt-1"))
P.revoked.clear()

print("== groups, user_from, search_groups")
oidc.GRAPH = ISS + "/graph"
check("groups from the claim", oidc.groups(CFG, {"groups": ["a", "b"]}, "at-1") == ("a", "b"))
check("no claim name: no groups", oidc.groups({**CFG, "groups_claim": ""}, {"groups": ["a"]}, "at-1") == ())
ptr = {"_claim_names": {"groups": "src1"}, "oid": "oid-1"}
check("a _claim_names pointer is fetched from Graph", oidc.groups(CFG, ptr, "at-1") == ("g-1", "g-2")
      and P.graph_seen[-1][0] == "/graph/me/getMemberObjects")
P.graph_me_id = "someone-else"
check("Graph /me for another person is BadAnswer", raises(B, oidc.groups, CFG, ptr, "at-1"))
P.graph_me_id = "oid-1"
u = oidc.user_from({**CFG, "id_claim": "oid"}, {"sub": "s", "oid": "o1", "preferred_username": "Ann@Example.com", "name": "Ann A"}, ["g"])
check("user_from with id_claim=oid", u.guid == "o1" and u.name == "ann@example.com" and u.display == "Ann A" and u.groups == ("g",) and u.enabled)
u = oidc.user_from(CFG, {"sub": "s", "email": "B@x.org"}, ())
check("user_from defaults: sub, email, display is name", u.guid == "s" and u.name == "b@x.org" and u.display == "b@x.org")
check("search_groups returns (id, name)", oidc.search_groups("at-1", "Al") == [("id-a", "Alpha"), ("id-b", "Beta")])
path, q, hdr = P.graph_seen[-1]
check("... with $search and ConsistencyLevel", q["$search"] == '"displayName:Al"' and hdr.get("ConsistencyLevel") == "eventual" and q["$select"] == "id,displayName")
oidc.search_groups("at-1", "")
check("empty text: first page, no $search", "$search" not in P.graph_seen[-1][1])
check("search_groups cap", len(oidc.search_groups("at-1", "", cap=1)) == 1)

print("== unreachable")
P.stop()
oidc._meta_cache.clear()
check("a stopped provider raises Unreachable", raises(oidc.Unreachable, oidc.discover, ISS))
check("... through verify_id_token too", raises(oidc.Unreachable, V, "x.y.z"))
check("Cancelled, Refused, NotFresh, BadAnswer, Unreachable are OidcErrors", all(issubclass(c, oidc.OidcError) for c in
      (oidc.Cancelled, oidc.Refused, oidc.NotFresh, oidc.BadAnswer, oidc.Unreachable)))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
