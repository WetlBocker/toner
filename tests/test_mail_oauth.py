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
        out = {"access_token": AT, "id_token": prov.token()}
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
    raw = passvault.get("mail-refresh:" + ch["id"])
    return json.loads(raw) if raw else None
def plant(ch, rt, age_days=0, account="mailbox@example.com"):
    passvault.put("mail-refresh:" + ch["id"], json.dumps({"refresh_token": rt, "account": account, "renewed": time.time() - age_days * 86400}))
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

print("== signing in (browser)")
MS = chan("ms_account")
check("not signed in yet", mailauth.signed_in_as(MS) is None)
who = mailauth.sign_in(MS, {})
seen, form = P.authorize_seen[-1], P.token_requests[-1]
check("sign_in returns the account", who == "mailbox@example.com", who)
check("...and stores the refresh token with the account and the time", stored(MS)["refresh_token"] == RT1 and stored(MS)["account"] == who
      and abs(stored(MS)["renewed"] - time.time()) < 60, stored(MS))
check("signed_in_as names it", mailauth.signed_in_as(MS) == who)
check("no 'sign in again now' demands (prompt, max_age) and no auth_time needed", "prompt" not in seen and "max_age" not in seen, seen)
check("Microsoft scopes: SMTP.Send, offline_access and the account's name", set(seen["scope"].split()) >= {"https://outlook.office.com/SMTP.Send", "offline_access", "openid"}, seen["scope"])
check("PKCE and the loopback redirect, as single sign-on", seen["code_challenge_method"] == "S256" and seen["redirect_uri"].startswith("http://localhost:"))
check("no client secret given: none sent", "client_secret" not in form, form)
a = audits("email sign-in")
check("audit 'email sign-in' with channel, provider, account", len(a) == 1 and a[0]["detail"] == "Mail ms_account, Microsoft 365, mailbox@example.com", a)
G = chan("google_account")
mailauth.sign_in(G, {"client_secret": CS})
gs = P.authorize_seen[-1]
check("Google: the mail.google.com scope and the account's email, no offline_access scope", set(gs["scope"].split()) == {"openid", "email", "https://mail.google.com/"}, gs["scope"])
check("Google: no prompt or max_age either", "prompt" not in gs and "max_age" not in gs, gs)
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
passvault.put("mail-refresh:c-young", json.dumps({"refresh_token": RT1, "account": "x", "renewed": "not a time"}))
plant(OLD, RT1, age_days=8); n = len(P.token_requests)
mailauth.renew_stale()
check("a malformed stored sign-in does not stop the next channel's renewal", len(P.token_requests) == n + 1 and time.time() - stored(OLD)["renewed"] < 60)
real_channels = notify.channels
notify.channels = lambda: 1 / 0
try:
    mailauth.renew_stale(); raised = None
except Exception as ex:
    raised = ex
notify.channels = real_channels
check("renew_stale never raises (channels can't be read)", raised is None, raised)
notify.save_channels([{**OLD, "enabled": False}, HOOK]); plant(OLD, RT1, age_days=8); n = len(P.token_requests)
mailauth.renew_stale()
check("a disabled channel's sign-in is not renewed", len(P.token_requests) == n)
notify.save_channels([OLD, HOOK]); plant(OLD, RT1)
passvault.put("mail-refresh:c-old.form", json.dumps({"refresh_token": "rt-draft-9999", "account": "d@example.com", "renewed": time.time() - 9 * 86400}))
n = len(P.token_requests)
mailauth.renew_stale()
check("a form's draft sign-in (mail-refresh:<id>.form) is not renewed or changed", len(P.token_requests) == n
      and json.loads(passvault.get("mail-refresh:c-old.form"))["refresh_token"] == "rt-draft-9999")
check("...and is not the channel's sign-in", mailauth.signed_in_as(OLD) == "mailbox@example.com")
passvault.remove("mail-refresh:c-old.form")

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
check("a password export carries the client secret but no sign-in", CS in got.values() and not [k for k in got if k.startswith("mail-refresh:")], sorted(got))
data, _n = vault.export_bytes("a long enough password", {"sw1": "pw", "mail-refresh:c-planted": json.dumps({"refresh_token": "rt-evil"})})
vault.import_bytes(data, "a long enough password")
check("an import carrying a sign-in does not store it", passvault.get("mail-refresh:c-planted") is None and passvault.get("sw1") == "pw")

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
