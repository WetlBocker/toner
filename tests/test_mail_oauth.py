# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and vault; the identity provider (tests/fake_oidc.py) and the mail server are fakes on 127.0.0.1.
# Email channels that sign in with OAuth 2.0 (core/mailauth.py, core/notify.py): the sign-in, its renewal, XOAUTH2, the errors.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, json, logging, os, smtplib, socket, socketserver, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "mailoauth%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring, keyring.backend, requests
from core import alerts, audit, db, mailauth, notify, oidc, passvault, vault
from fake_oidc import FakeProvider, leaks
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

class OldStore(keyring.backend.KeyringBackend):        # never the computer's own credential store
    priority = 1
    def __init__(self): self.d = {}
    def get_password(self, s, u): return self.d.get(u)
    def set_password(self, s, u, p): self.d[u] = p
    def delete_password(self, s, u): self.d.pop(u)
keyring.set_keyring(OldStore())
passvault.open_with(os.urandom(32))
passvault.install()

logged = []
class Grab(logging.Handler):
    def emit(self, r): logged.append(r.getMessage())
logging.getLogger().addHandler(Grab()); logging.getLogger().setLevel(logging.DEBUG)

AT, RT1, RT2, APPAT, CS = "at-secret-AAAA1111", "rt-secret-BBBB2222", "rt-secret-CCCC3333", "at-app-DDDD4444", "cs-secret-EEEE5555"
SECRETS = [AT, RT1, RT2, APPAT, CS, "at-code-0000"]

# ---------------------------------------------------------------- the fake provider's token endpoint
oidc._TEST_ALLOW_HTTP = True
P = FakeProvider(); ISS = P.start()
mailauth.MS_ISSUER = mailauth.GOOGLE_ISSUER = ISS
STATE = {"code_rt": True, "error": None, "status": 400, "rotate": True, "hook": None}
REVOKED = set()

def token_route(prov, h):
    f = {k: v[0] for k, v in urllib.parse.parse_qs(h.body().decode()).items()}
    prov.token_requests.append(f)
    if STATE["hook"]:
        STATE["hook"](f)
    if STATE["error"]:
        return h.send_json({"error": STATE["error"], "error_description": f"refused {AT} {RT1} {CS} {APPAT}"}, STATE["status"])
    if f.get("grant_type") == "client_credentials":
        return h.send_json({"access_token": APPAT, "token_type": "Bearer"})
    if f.get("grant_type") == "refresh_token":
        if f.get("refresh_token") in REVOKED:
            return h.send_json({"error": "invalid_grant", "error_description": f"AADSTS70000 {f.get('refresh_token')}"}, 400)
        out = {"access_token": STATE.get("at") or AT, "id_token": prov.token()}
        if STATE["rotate"]:
            out["refresh_token"] = RT2
        return h.send_json(out)
    _challenge, nonce = prov.codes.pop(f.get("code"), (None, None))
    out = {"access_token": "at-code-0000", "id_token": prov.token(nonce=nonce, auth_time=None, email="mailbox@example.com")}
    if STATE["code_rt"]:
        out["refresh_token"] = RT1
    h.send_json(out)
P.routes["/token"] = token_route

def browse(url):
    threading.Thread(target=lambda: requests.get(url, timeout=10, **oidc._DIRECT), daemon=True).start()
mailauth.open_url = browse

# ---------------------------------------------------------------- the fake mail server (AUTH XOAUTH2; STARTTLS is stood in for)
conns, mails = [], []
SMTP_MODE = {"auth": "ok"}
class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())
        conn = {"auth": None, "reply": None, "starttls": False}; conns.append(conn)
        w("220 test ESMTP"); data = False; buf = []; rcpt = []; waiting = None
        echo = lambda: (conn["auth"] or "").split("Bearer ", 1)[-1].rstrip("\x01")      # the access token, said back
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == "." and SMTP_MODE.get("data") == "echo": w(f"550 5.7.1 message refused for {echo()}"); data = False; buf = []
                elif line == ".": mails.append({"rcpt": rcpt, "text": "\n".join(buf)}); w("250 queued"); data = False; buf = []
                else: buf.append(line[1:] if line.startswith("..") else line)
                continue
            if waiting is not None:                        # the client's answer to our error challenge
                conn["reply"] = line; w(f"535 5.7.8 Username and Password not accepted for token {waiting}"); waiting = None
                continue
            cmd = line.upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"): w("250-test"); w("250-AUTH XOAUTH2 PLAIN LOGIN"); w("250 8BITMIME")
            elif cmd.startswith("AUTH XOAUTH2 "):
                conn["auth"] = base64.b64decode(line.split(" ", 2)[2]).decode()
                if SMTP_MODE["auth"] == "ok": w("235 2.7.0 Accepted")
                else:
                    waiting = conn["auth"].split("Bearer ", 1)[1].rstrip("\x01")
                    w("334 " + base64.b64encode(json.dumps({"status": "400", "schemes": "Bearer", "scope": "https://mail.google.com/"}).encode()).decode())
            elif cmd.startswith("MAIL"): w("250 ok")
            elif cmd.startswith("RCPT") and SMTP_MODE.get("rcpt") == "echo": w(f"550 5.7.1 recipient refused for {echo()}")
            elif cmd.startswith("RCPT"): rcpt.append(line.split(":", 1)[1].strip(" <>")); w("250 ok")
            elif cmd == "DATA": w("354 go"); data = True
            elif cmd == "QUIT" and SMTP_MODE.get("quit") == "echo": w(f"554 5.0.0 not like this {echo()}"); return
            elif cmd == "QUIT": w("221 bye"); return
            else: w("250 ok")
class TS(socketserver.ThreadingTCPServer): allow_reuse_address = True; daemon_threads = True
smtp_srv = TS(("127.0.0.1", 0), Smtp); SP_PORT = smtp_srv.server_address[1]
threading.Thread(target=smtp_srv.serve_forever, daemon=True).start()
def fake_starttls(self, context=None):                 # no real TLS in the fake: record it and carry on in the clear
    conns[-1]["starttls"] = True
    return 220, b"ready"
smtplib.SMTP.starttls = fake_starttls

# ---------------------------------------------------------------- a webhook channel that collects the notice
hooked = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        hooked.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)))))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
web = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=web.serve_forever, daemon=True).start()
HOOK = {**notify.new_channel("webhook"), "id": "hook0001", "name": "Ops hook"}
notify.set_secrets(HOOK, {"url": f"http://127.0.0.1:{web.server_address[1]}/hook"})
db.set_setting("notify_enabled", True)

def chan(auth, cid=None, **kw):
    return {**notify.new_channel("email"), "id": cid or f"c-{auth}", "name": f"Mail {auth}", "auth": auth, "tenant": "tenant-1",
            "client_id": "toner-app", "smtp_host": "127.0.0.1", "smtp_port": SP_PORT, "security": "STARTTLS",
            "username": "mailbox@example.com", "from_addr": "toner@example.com", "to_addrs": "a@example.com", **kw}
def stored(ch):
    raw = passvault.get(mailauth.PREFIX + ch["id"])
    return json.loads(raw) if raw else None
def plant(ch, rt, age_days=0, account="mailbox@example.com"):
    passvault.put(mailauth.PREFIX + ch["id"], json.dumps({"refresh_token": rt, "account": account, "renewed": time.time() - age_days * 86400}))
msg = notify.build_message([alerts.Event("new", "core", "cpu", "FAIL", "OK", "95%", "")])
def send(ch, secrets=None):
    return notify.deliver(ch, msg, secrets={} if secrets is None else secrets, retry_delay=0)
def audits(action):
    return [r for r in audit.recent(500) if r["action"] == action]
MS_GONE = "Microsoft 365 no longer accepts this sign-in. Edit the channel and choose Sign in again."
MS_DOWN = "Microsoft 365 can't be reached, so the email wasn't sent."
MS_APP = "Microsoft 365 refused the app. Check the tenant ID, client ID and client secret."
SERVER = "The mail server refused the sign-in. Check the username, that the app may send from this mailbox, and that authenticated SMTP is on for it."

print("== the methods")
check("METHODS as approved", mailauth.METHODS == [("password", "Password"), ("ms_account", "Microsoft 365 account"),
                                                  ("ms_app", "Microsoft 365 app (no person)"), ("google_account", "Google account")])
check("provider()", [mailauth.provider(a) for a in ("ms_account", "ms_app", "google_account")] == ["Microsoft 365", "Microsoft 365", "Google"])
check("needs_sign_in(): the two account methods", [mailauth.needs_sign_in(a) for a, _ in mailauth.METHODS] == [False, True, False, True])
fields = {k: (kind, extra) for k, _l, kind, extra in notify.CHANNEL_TYPES["email"]["fields"]}
check("email fields: auth (default password), tenant, client_id plain, client_secret a secret",
      fields["auth"][1].get("default") == "password" and fields["tenant"][0] == "text" and fields["client_id"][0] == "text"
      and fields["client_secret"][0] == "secret", fields.keys())
check("a new email channel signs in with a password", notify.new_channel("email")["auth"] == "password")
mailauth.MS_ISSUER = "https://login.example/{tenant}/v2.0"
got = mailauth._cfg({"auth": "ms_account", "tenant": " ABCDEF12-3456-7890-ABCD-EF1234567890 ", "client_id": "x"})["issuer"]
mailauth.MS_ISSUER = ISS
check("an upper-case tenant ID is lower-cased in the issuer (discovery's issuer check)", got == "https://login.example/abcdef12-3456-7890-abcd-ef1234567890/v2.0", got)

print("== signing in (browser)")
MS = chan("ms_account")
check("not signed in yet", mailauth.signed_in_as(MS) is None)
who = mailauth.sign_in(MS, {})
seen, form = P.authorize_seen[-1], P.token_requests[-1]
check("sign_in returns the account", who == "mailbox@example.com", who)
check("...and stores the refresh token with the account and the time", stored(MS)["refresh_token"] == RT1 and stored(MS)["account"] == who
      and abs(stored(MS)["renewed"] - time.time()) < 60, stored(MS))
check("signed_in_as names it", mailauth.signed_in_as(MS) == who)
check("the person picks the account (prompt=select_account); no max_age and no auth_time needed", seen.get("prompt") == "select_account" and "max_age" not in seen, (seen.get("prompt"), seen.get("max_age")))
check("Microsoft scopes: SMTP.Send, offline_access and the account's name", set(seen["scope"].split()) >= {"https://outlook.office.com/SMTP.Send", "offline_access", "openid"}, seen["scope"])
check("PKCE and the loopback redirect, as single sign-on", seen["code_challenge_method"] == "S256" and seen["redirect_uri"].startswith("http://localhost:"))
check("no client secret given: none sent", "client_secret" not in form, form)
a = audits("email sign-in")
check("audit 'email sign-in' with channel, provider, account", len(a) == 1 and a[0]["detail"] == "Mail ms_account, Microsoft 365, mailbox@example.com", a)
G = chan("google_account")
mailauth.sign_in(G, {"client_secret": CS})
gs = P.authorize_seen[-1]
check("Google: the mail.google.com scope and the account's email, no offline_access scope", set(gs["scope"].split()) == {"openid", "email", "https://mail.google.com/"}, gs["scope"])
check("Google: prompt=select_account too, no max_age", gs.get("prompt") == "select_account" and "max_age" not in gs, (gs.get("prompt"), gs.get("max_age")))
check("Google: the client secret is sent with the code", P.token_requests[-1].get("client_secret") == CS)
STATE["code_rt"] = False
X = chan("ms_account", "c-norefresh")
try:
    mailauth.sign_in(X, {}); e = None
except mailauth.MailAuthError as ex:
    e = ex
check("no refresh token at sign-in: the approved error, nothing stored",
      e is not None and str(e) == "Microsoft 365 didn't give Toner a sign-in it can keep. Check the app's setup, then sign in again." and stored(X) is None, e)
STATE["code_rt"] = True
cancel = threading.Event(); cancel.set()
mailauth.open_url = lambda u: None
try:
    mailauth.sign_in(chan("ms_account", "c-cancel"), {}, cancelled=cancel); got = None
except oidc.Cancelled as ex:
    got = ex
check("a cancelled sign-in raises Cancelled and stores nothing", got is not None and stored(chan("ms_account", "c-cancel")) is None)
mailauth.open_url = browse

print("== sending with XOAUTH2")
mails.clear(); n = len(P.token_requests)
okd, d = send(MS)
check("Microsoft 365 account: sent", okd and len(mails) == 1, d)
check("the XOAUTH2 string is exact", conns[-1]["auth"] == f"user=mailbox@example.com\x01auth=Bearer {AT}\x01\x01", repr(conns[-1]["auth"]))
check("STARTTLS came first", conns[-1]["starttls"])
check("one token call per mail, a refresh", len(P.token_requests) == n + 1 and P.token_requests[-1]["grant_type"] == "refresh_token"
      and P.token_requests[-1]["refresh_token"] == RT1)
check("a refresh that sends a new refresh token stores it", stored(MS)["refresh_token"] == RT2)
plant(MS, RT2, age_days=3); STATE["rotate"] = False
send(MS)
check("a refresh without one keeps the old, and the renewal time is updated", stored(MS)["refresh_token"] == RT2 and time.time() - stored(MS)["renewed"] < 60, stored(MS))
STATE["rotate"] = True
okd, d = send(G, {"client_secret": CS})
check("Google account: sent, exact XOAUTH2", okd and conns[-1]["auth"] == f"user=mailbox@example.com\x01auth=Bearer {AT}\x01\x01", (d, conns[-1]))
check("...the refresh carried the client secret", P.token_requests[-1].get("client_secret") == CS)
APP = chan("ms_app")
okd, d = send(APP, {"client_secret": CS})
f = P.token_requests[-1]
check("Microsoft 365 app: sent, exact XOAUTH2 with the app's token", okd and conns[-1]["auth"] == f"user=mailbox@example.com\x01auth=Bearer {APPAT}\x01\x01", (d, conns[-1]))
check("...the client-credentials form carries the scope and the secret", f.get("grant_type") == "client_credentials"
      and f.get("scope") == "https://outlook.office365.com/.default" and f.get("client_secret") == CS and f.get("client_id") == "toner-app", f)
check("...and no sign-in is stored for it", stored(APP) is None)

print("== the mail server refuses")
SMTP_MODE["auth"] = "challenge"
okd, d = send(MS)
check("334 is answered with an empty line, then 535 gives the approved text", not okd and d == SERVER and conns[-1]["reply"] == "", (d, conns[-1]))
check("...and the token the server echoed is not in it", not leaks([d], SECRETS))
SMTP_MODE["auth"] = "ok"

print("== Security None and the proxy")
before_c, before_t = len(conns), len(P.token_requests)
okd, d = send(chan("ms_account", security="None"))
check("Security None is refused before any connection or token call", not okd and d == "Signing in with Microsoft 365 or Google needs STARTTLS or SSL/TLS."
      and len(conns) == before_c and len(P.token_requests) == before_t, d)
proxied = []
real_for, real_connect = notify.proxy.for_device, notify.proxy.connect
notify.proxy.for_device = lambda dev=None, host=None: {"stand-in": True}
notify.proxy.connect = lambda cfg, host, port, timeout=15: (proxied.append(host), socket.create_connection((host, port), timeout))[1]
okd, d = send(MS)
check("an OAuth channel connects directly, whatever the proxy", okd and proxied == [], (d, proxied))
okd, d = send({**chan("password"), "username": "", "security": "STARTTLS"})
check("a password channel still goes through the proxy", okd and proxied == ["127.0.0.1"], (d, proxied))
notify.proxy.for_device, notify.proxy.connect = real_for, real_connect

print("== the provider refuses the sign-in for good")
notify.save_channels([MS, HOOK]); hooked.clear()
REVOKED.add(RT2); plant(MS, RT2)
n_aud = len(audits("email sign-in refused"))
okd, d = send(MS)
check("invalid_grant: the approved text", not okd and d == MS_GONE, d)
check("...the sign-in is removed", stored(MS) is None)
ra = audits("email sign-in refused")
check("...one audit line with channel, provider, account", len(ra) == n_aud + 1 and ra[0]["detail"] == "Mail ms_account, Microsoft 365, mailbox@example.com", ra[:1])
texts = [json.dumps(b) for b in hooked]
check("...one notice, on the other channels", len(hooked) == 1 and "Mail ms_account needs a new sign-in. Edit it in Settings > Notifications and choose Sign in again." in texts[0], texts)
check("...and not on the refused channel itself", [r["channel"] for r in alerts.recent_deliveries(500)] == ["Ops hook"], alerts.recent_deliveries(500))
okd, d = send(MS)
check("a second failing mail tells nobody again", not okd and len(hooked) == 1 and len(audits("email sign-in refused")) == n_aud + 1, (d, len(hooked)))
check("...and says it isn't signed in", d == "Toner isn't signed in to Microsoft 365 for this channel. Edit the channel and choose Sign in.", d)
check("an account method with no sign-in can't name an account", mailauth.signed_in_as(MS) is None)

print("== another process renewed it meanwhile")
plant(MS, "rt-old-1111"); REVOKED.add("rt-old-1111"); hooked.clear()
STATE["hook"] = lambda f: f.get("refresh_token") == "rt-old-1111" and plant(MS, "rt-newer-2222")
n = len(P.token_requests)
okd, d = send(MS)
STATE["hook"] = None
check("invalid_grant with a newer token in the vault: one retry with it, sent", okd and len(P.token_requests) == n + 2
      and P.token_requests[-1]["refresh_token"] == "rt-newer-2222", (d, P.token_requests[n:]))
check("...nothing removed, nobody told", stored(MS) is not None and not hooked)

print("== a sign-in removed or replaced while its token call runs stays so")
DRAFT = chan("ms_account", "c-ms.form1", draft=True)
for what, ch, during in (("a form's draft removed (Save, Cancel or an edit)", DRAFT, lambda f: passvault.remove(mailauth.PREFIX + DRAFT["id"])),
                         ("a channel's sign-in removed (Remove)", MS, lambda f: passvault.remove(mailauth.PREFIX + MS["id"]))):
    plant(ch, RT1); STATE["hook"] = during
    okd, d = send(ch)
    check(f"{what} during the send's token call is not put back", okd and stored(ch) is None, (d, bool(stored(ch))))
plant(MS, RT1); STATE["hook"] = lambda f: plant(MS, "rt-replaced-8888", account="new@example.com")
okd, d = send(MS)
STATE["hook"] = None
check("a sign-in replaced during the send's token call (Sign in again, then Save) keeps the replacement",
      okd and stored(MS)["refresh_token"] == "rt-replaced-8888" and stored(MS)["account"] == "new@example.com", (d, (stored(MS) or {}).get("account")))

print("== a locked vault")
notify.save_channels([MS, HOOK]); plant(MS, RT1)
key = passvault._key; passvault._key = None
okd, d = send(MS)
okf, df = notify.mail_files("boss@example.com", "Weekly report", "Attached.", [])
check("a windowless send says the vault is locked, not 'sign in'", not okd and d == "Locked: The vault is locked." and not leaks([d], SECRETS), d)
check("...so does a scheduled report's mail", not okf and df == "Locked: The vault is locked." and not leaks([df], SECRETS), df)
check("...and signed_in_as names nobody", mailauth.signed_in_as(MS) is None)
passvault._key = key
check("...and the sign-in is still there once it opens", stored(MS)["refresh_token"] == RT1)

print("== the provider can't be reached")
plant(MS, RT1)
P.force = 503
okd, d = send(MS)
P.force = None
check("a 503: 'can't be reached', the sign-in kept", not okd and d == MS_DOWN and stored(MS)["refresh_token"] == RT1, d)
mailauth.MS_ISSUER = "http://127.0.0.1:9"
okd, d = send(MS)
mailauth.MS_ISSUER = ISS
check("no connection: the same, the sign-in kept", not okd and d == MS_DOWN and stored(MS)["refresh_token"] == RT1, d)

print("== the provider refuses the app")
STATE["error"], STATE["status"] = "invalid_client", 401
okd, d = send(APP, {"client_secret": CS})
check("invalid_client on the client-credentials call: 'refused the app'", not okd and d == MS_APP, d)
STATE["error"], STATE["status"] = "unauthorized_client", 400
okd, d = send(MS)
check("unauthorized_client on a refresh: 'refused the app', the sign-in kept", not okd and d == MS_APP and stored(MS) is not None, d)
STATE["error"] = None

print("== no secret in a detail, a log or an audit line")
details = [r["detail"] or "" for r in alerts.recent_deliveries(500)] + [r["detail"] or "" for r in audit.recent(500)]
okd, d = notify.deliver(APP, msg, secrets={"client_secret": CS}, retry_delay=0)
STATE["error"], STATE["status"] = "invalid_client", 401
okd2, d2 = notify.send_test(APP, {"client_secret": CS})
STATE["error"] = None
SMTP_MODE["auth"] = "challenge"
okd3, d3 = notify.send_test(MS, {})
SMTP_MODE["auth"] = "ok"
everything = details + [d, d2, d3] + logged + [r["detail"] or "" for r in alerts.recent_deliveries(500)] + [r["detail"] or "" for r in audit.recent(500)]
check("the provider's and the mail server's echoes stay out", not okd2 and not okd3 and not leaks(everything, SECRETS), leaks(everything, SECRETS)[:3])

print("== a mail server that says the token back after AUTH")
notify.save_channels([MS, HOOK]); plant(MS, RT1); STATE["rotate"] = False
out = {}
for mode in ("rcpt", "data"):
    SMTP_MODE[mode] = "echo"
    out[mode] = [notify.send_test(MS, {}), notify.mail_files("boss@example.com", "Weekly report", "Attached.", []),
                 notify.send_test(APP, {"client_secret": CS})]
    SMTP_MODE[mode] = None
STATE["rotate"] = True
got = [d for runs in out.values() for _ok, d in runs]
everything = got + logged + [r["detail"] or "" for r in alerts.recent_deliveries(500)] + [r["detail"] or "" for r in audit.recent(500)]
check("a 550 to RCPT or DATA that echoes the token: refused, and the token is in no detail, log or audit line",
      not any(okx for runs in out.values() for okx, _d in runs) and not leaks(everything, SECRETS), (got, leaks(everything, SECRETS)[:3]))
check("...the details still say what the server said, by type", all("SMTPRecipientsRefused" in d and "550" in d for _ok, d in out["rcpt"])
      and all("SMTPDataError" in d and "550" in d for _ok, d in out["data"]), got)

print("== nothing that leaves _mail holds the token: not its text, attributes, __context__ or __cause__")
def holds(e, token, depth=0):
    """True when the exception, its attributes or anything chained to it still has the token."""
    if e is None or depth > 5:
        return False
    if token in repr(e.args) or any(token in repr(v) for v in vars(e).values() if not isinstance(v, BaseException)) \
            or token in repr(getattr(e, "object", "")):
        return True
    return holds(e.__context__, token, depth + 1) or holds(e.__cause__, token, depth + 1)
def raised_by_mail(ch, secrets=None):
    try:
        notify._mail(ch, secrets or {}, "s", "b")
    except Exception as ex:
        return ex
plant(MS, RT1); STATE["rotate"] = False
cases = {}
SMTP_MODE["rcpt"] = SMTP_MODE["quit"] = "echo"
cases["550 to RCPT, then a bad reply to QUIT"] = raised_by_mail(MS)
SMTP_MODE["rcpt"] = SMTP_MODE["quit"] = None
SMTP_MODE["auth"] = "challenge"
cases["535 after the 334 challenge"] = raised_by_mail(MS)
SMTP_MODE["auth"] = "ok"
P.force = 503
cases["the provider can't be reached"] = raised_by_mail(MS)
P.force = None
STATE["at"] = "at-\u00fcnicode-FFFF6666"
cases["an access token smtplib can't encode"] = raised_by_mail(MS)
STATE["at"] = None
for name, ex in cases.items():
    check(f"{name}: raised, no token anywhere on it, nothing chained", ex is not None and not holds(ex, AT) and not holds(ex, "FFFF6666")
          and ex.__context__ is None and ex.__cause__ is None, (type(ex).__name__, ex, ex and ex.__context__))
check("...and the QUIT case still says what the server said", "554" in str(cases["550 to RCPT, then a bad reply to QUIT"]))
n_conn, n = len(conns), len(P.token_requests)
okd, d = send(chan("ms_account", username="m\u00e4ilbox@example.com"))
check("a username that is not ASCII is refused before any token call or connection, with the existing address text",
      not okd and d == "'m\u00e4ilbox@example.com' is not a valid email address." and len(conns) == n_conn and len(P.token_requests) == n, d)
check("...and validation says so too", "'m\u00e4ilbox@example.com' is not a valid email address." in notify.validate(chan("ms_account", username="m\u00e4ilbox@example.com"), {}))
check("...but a password channel's username is left as it was", not [x for x in notify.validate({**chan("password"), "username": "m\u00e4ilbox"}, {}) if "m\u00e4ilbox" in x])
STATE["rotate"] = True

print("== a password manager as the store never gets a sign-in")
from core import extstore, extvault
MANAGER = {"items": {}, "containers": {}}
class FakeManager(extvault.Provider):
    kind = "bitwarden"
    def connect(self): pass
    def containers(self): return {nm: cid for cid, nm in MANAGER["containers"].items()}
    def create_container(self, name):
        cid = f"c{len(MANAGER['containers']) + 1}"; MANAGER["containers"][cid] = name; return cid
    def all_items(self, cid):
        return [extvault.Item(ref=r, title=i["title"], username=i["user"], value=i["pw"], toner_id=i["tid"], container=MANAGER["containers"][cid], raw=i)
                for r, i in MANAGER["items"].items() if i["cid"] == cid]
    def put(self, cid, toner_id, title, username, value, item=None):
        ref = item.ref if item else f"i{len(MANAGER['items']) + 1}"
        MANAGER["items"].setdefault(ref, {}).update({"cid": cid, "tid": toner_id, "title": title, "user": username, "pw": value}); return ref
    def delete(self, item): MANAGER["items"].pop(item.ref, None)
    def delete_container(self, cid): MANAGER["containers"].pop(cid)
    def search(self, text): return []
    def read(self, ref): return MANAGER["items"][ref]["pw"]
extvault.CONNECTORS["bitwarden"] = FakeManager
extstore.start = lambda: None
check("a sign-in's name is one Toner's vault keeps to itself", mailauth.PREFIX.startswith(extstore.LOCAL) and extstore.is_internal(mailauth.PREFIX + "x"))
STATE["rotate"] = False; plant(MS, RT1); passvault.put(mailauth.PREFIX + MS["id"] + ".form1", json.dumps({"refresh_token": "rt-draft-7777"}))
db.set_secret("sw-mgr", "pw-mgr")
extstore.use("bitwarden")
for copies in (False, True):
    db.set_setting("vault_keep_copies", copies); MANAGER["items"].clear()      # each mode on its own: the manager starts empty
    db.set_secret("sw-mgr", "pw-mgr")                                            # (with copies off, only what is saved then is sent)
    st = extstore.sync_once()
    sent = [i["tid"] + " " + i["pw"] for i in MANAGER["items"].values()]
    check(f"copies {'kept' if copies else 'off'}: the manager got the other passwords but no sign-in and no draft",
          st["connected"] and any("pw-mgr" in x for x in sent) and not [x for x in sent if "mail-refresh" in x or "rt-" in x], (st, sent))
    check("...the names offered to it hold none", not [x for x in extstore.local_names() if "mail-refresh" in x], extstore.local_names())
    check("...and the sign-in still reads, renews and stays in the vault", mailauth.signed_in_as(MS) == "mailbox@example.com"
          and send(MS)[0] and stored(MS) is not None and mailauth.PREFIX + MS["id"] in passvault.names(), (copies, mailauth.signed_in_as(MS), send(MS), stored(MS)))
had_draft = passvault.remove(mailauth.PREFIX + MS["id"] + ".form1")
mailauth.sign_out(MS)
check("copies off: the sign-in and the draft are removed from the vault", had_draft and stored(MS) is None
      and not [x for x in passvault.names() if x.startswith(mailauth.PREFIX + MS["id"])], [x for x in passvault.names() if "mail-refresh" in x])
extstore.use("toner"); STATE["rotate"] = True
db.set_setting("vault_keep_copies", True)

print("== renewal of quiet sign-ins")
OLD, YOUNG = chan("ms_account", "c-old"), chan("ms_account", "c-young")
notify.save_channels([OLD, YOUNG, HOOK])
plant(OLD, RT1, age_days=8); plant(YOUNG, RT1, age_days=6)
n = len(P.token_requests); young = stored(YOUNG)["renewed"]
mailauth.renew_stale()
check("an 8-day-old sign-in is renewed, a 6-day-old one is left", len(P.token_requests) == n + 1 and time.time() - stored(OLD)["renewed"] < 60
      and stored(YOUNG)["renewed"] == young, P.token_requests[n:])
plant(OLD, RT1, age_days=8); n = len(P.token_requests)
notify.process_run([], [], True)
check("process_run renews first", len(P.token_requests) == n + 1 and time.time() - stored(OLD)["renewed"] < 60)

print("== renewal: an outage, a bad stored value, disabled channels, form drafts")
plant(OLD, RT1, age_days=8); STATE["error"], STATE["status"] = "temporarily_unavailable", 503; n = len(P.token_requests)
mailauth.renew_stale()
first = len(P.token_requests) - n
mailauth.renew_stale(); notify.process_run([], [], True)
check("a provider outage: one attempt, then none again within the retry interval", first == 1 and len(P.token_requests) == n + 1
      and stored(OLD)["refresh_token"] == RT1, P.token_requests[n:])
mailauth.renew_stale(now=time.time() + mailauth.RETRY + 1)
STATE["error"] = None
check("...and another once the interval has passed", len(P.token_requests) == n + 2, P.token_requests[n:])
check("the retry interval is an hour", mailauth.RETRY == 3600)
notify.save_channels([YOUNG, OLD, HOOK])
plant(YOUNG, RT1, age_days=8); plant(OLD, RT1, age_days=8); n = len(P.token_requests)
real_access = mailauth.access_token
def failing_for_young(ch, secrets):
    if ch["id"] == YOUNG["id"]:
        raise RuntimeError("something unexpected")
    return real_access(ch, secrets)
mailauth.access_token = failing_for_young
mailauth.renew_stale()
mailauth.access_token = real_access
check("one channel's unexpected failure does not stop the next channel's renewal", len(P.token_requests) == n + 1 and time.time() - stored(OLD)["renewed"] < 60)
for odd in ({"renewed": "not a time"}, {"renewed": time.time() - 8 * 86400, "tried": "not a time"}, {"renewed": None, "tried": [1]}):
    passvault.put(mailauth.PREFIX + "c-young", json.dumps({"refresh_token": RT1, "account": "x", **odd})); n = len(P.token_requests)
    mailauth.renew_stale()
    check(f"an unreadable stored time counts as never ({odd})", len(P.token_requests) == n + 1 and time.time() - stored(YOUNG)["renewed"] < 60, P.token_requests[n:])
real_channels = notify.channels
notify.channels = lambda: 1 / 0
try:
    mailauth.renew_stale(); raised = None
except Exception as ex:
    raised = ex
notify.channels = real_channels
check("renew_stale never raises (channels can't be read)", raised is None, raised)
notify.save_channels([chan("password", "c-pw"), {**OLD, "enabled": False}, HOOK]); plant(OLD, RT1, age_days=8); n = len(P.token_requests)
mailauth.renew_stale()
check("a disabled channel's sign-in is not renewed", len(P.token_requests) == n)
notify.save_channels([{**OLD, "enabled": False}, chan("password", "c-pw"), HOOK]); n = len(P.token_requests)
mailauth.renew_stale()
check("...unless it is the first Email channel, which the scheduled reports still mail through", len(P.token_requests) == n + 1
      and time.time() - stored(OLD)["renewed"] < 60, len(P.token_requests) - n)
from core import orgs
arc = orgs.create("Archived Co", "ARC"); ARC = chan("ms_account", "c-arch")
with db.within(arc):
    notify.save_channels([ARC])
plant(ARC, RT1, age_days=8); orgs.set_archived(arc, True); n = len(P.token_requests)
mailauth.renew_stale()
check("an archived organization's channels are not renewed", len(P.token_requests) == n and time.time() - stored(ARC)["renewed"] > 7 * 86400, len(P.token_requests) - n)
orgs.set_archived(arc, False)
mailauth.renew_stale()
check("...and are once it is back", len(P.token_requests) == n + 1 and time.time() - stored(ARC)["renewed"] < 60, len(P.token_requests) - n)
notify.save_channels([OLD, HOOK]); plant(OLD, RT1)
draft = lambda n_, **kw: passvault.put(mailauth.PREFIX + n_, json.dumps({"refresh_token": "rt-draft-9999", "account": "d@example.com", **kw}))
draft("c-old.form1", renewed=time.time() - 9 * 86400); draft("c-old.form2", renewed=time.time() - 25 * 3600); draft("c-old.form3")
draft("c-old.form4", renewed="not a time"); draft("c-old.form5", renewed=time.time() - 3600)
plant(chan("ms_account", "c-orphan"), RT1, age_days=30)
n = len(P.token_requests)
mailauth.renew_stale()
left = [x[len(mailauth.PREFIX):] for x in passvault.names() if x.startswith(mailauth.PREFIX + "c-o")]
check("form drafts more than a day old, or with no readable time, are removed, never renewed", len(P.token_requests) == n
      and not {"c-old.form1", "c-old.form2", "c-old.form3", "c-old.form4"} & set(left), left)
check("...a recent draft is left as it was", "c-old.form5" in left and json.loads(passvault.get(mailauth.PREFIX + "c-old.form5"))["refresh_token"] == "rt-draft-9999", left)
check("...and a channel's own sign-in is never swept, however old", "c-orphan" in left and mailauth.signed_in_as(OLD) == "mailbox@example.com", left)
passvault.remove(mailauth.PREFIX + "c-old.form5"); passvault.remove(mailauth.PREFIX + "c-orphan")

print("== sign_in for a method with no browser sign-in")
for auth in ("ms_app", "password"):
    try:
        mailauth.sign_in(chan(auth), {}); err = None
    except ValueError as ex:
        err = ex
    except Exception as ex:
        err = ("wrong type", ex)
    check(f"{auth}: a ValueError naming the method, nothing stored", isinstance(err, ValueError) and auth in str(err) and stored(chan(auth)) is None, err)

print("== validation")
v = lambda ch, s=None: notify.validate(ch, s or {})
check("a signed-in account channel validates", v(OLD) == [], v(OLD))
check("Security None", "Signing in with Microsoft 365 or Google needs STARTTLS or SSL/TLS." in v({**OLD, "security": "None"}))
check("no username", "Username is required: the mailbox Toner sends from." in v({**OLD, "username": ""}))
check("not signed in", "Sign in first." in v(chan("ms_account", "c-never")))
check("tenant and client ID required", {"Tenant ID is required.", "Client ID is required."} <= set(v({**OLD, "tenant": "", "client_id": ""})))
check("Google needs no tenant", v({**G, "tenant": ""}) == [], v({**G, "tenant": ""}))
check("Microsoft 365 app: client secret required, no sign-in needed", v(APP) == ["Client secret is required."] and v(APP, {"client_secret": CS}) == [], v(APP))
oldch = {k: val for k, val in notify.new_channel("email").items() if k not in ("auth", "tenant", "client_id")}
oldch.update(smtp_host="127.0.0.1", smtp_port=SP_PORT, security="None", from_addr="toner@example.com", to_addrs="a@example.com")
mails.clear()
okd, d = send(oldch)
check("a channel saved before this change (no auth) validates and sends as before", v(oldch) == [] and okd and len(mails) == 1 and conns[-1]["auth"] is None, (v(oldch), d))

print("== removing a channel")
notify.set_secrets(G, {"client_secret": CS, "password": "pw-1234567"})
n_rm = len(audits("email sign-in removed"))
notify.delete_secrets(G)
check("delete_secrets leaves nothing of the channel in the vault", not [x for x in passvault.names() if G["id"] in x], [x for x in passvault.names() if G["id"] in x])
check("...and the audit says the sign-in was removed", len(audits("email sign-in removed")) == n_rm + 1)
mailauth.sign_out(G)
check("sign_out with nothing stored writes nothing", len(audits("email sign-in removed")) == n_rm + 1)

print("== password export and import")
notify.save_channels([OLD, G, HOOK]); notify.set_secrets(G, {"client_secret": CS})
got = vault.collect()
check("a password export carries the client secret but no sign-in", CS in got.values() and not [k for k in got if "mail-refresh" in k], sorted(got))
evil = json.dumps({"refresh_token": "rt-evil"})
data, _n = vault.export_bytes("a long enough password", {"sw1": "pw", "mail-refresh:c-planted": evil, mailauth.PREFIX + "c-planted": evil,
                                                          mailauth.PREFIX + "c-planted.form1": evil})
vault.import_bytes(data, "a long enough password")
check("an import carrying a sign-in does not store it (today's name, a draft, or the name before ~toner/)",
      [n for n in passvault.names() if "c-planted" in n] == [] and passvault.get("sw1") == "pw", [n for n in passvault.names() if "c-planted" in n])

print("== scheduled reports (mail_files)")
notify.save_channels([MS, HOOK]); plant(MS, RT1)
path = os.path.join(SP, "report-oauth.csv")
with open(path, "w") as fh: fh.write("a,b\n1,2\n")
mails.clear()
okd, d = notify.mail_files("boss@example.com", "Weekly report", "Attached.", [path])
check("an attachment goes through an OAuth channel", okd and len(mails) == 1 and "report-oauth.csv" in mails[0]["text"]
      and mails[0]["rcpt"] == ["boss@example.com"] and conns[-1]["auth"].startswith("user=mailbox@example.com\x01auth=Bearer "), d)
check("...the renewal stored the provider's new refresh token, which it has since revoked", stored(MS)["refresh_token"] == RT2 and RT2 in REVOKED)
okd, d = notify.mail_files("boss@example.com", "Weekly report", "Attached.", [path])
check("...and a refused sign-in there gives the approved text", not okd and d == MS_GONE, d)

P.stop()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
