"""Deliver notifications: message formatting and the channels (desktop, email, Teams, Slack, Discord,
generic webhook, ntfy). Which events to send is decided in core/alerts.py.

Secrets (webhook URLs, passwords, tokens) are kept in Windows Credential Manager, never in the database
or in exported settings, and are scrubbed from any error text that is shown or logged.
"""
import json
import smtplib
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import urlparse

import keyring
import requests

from core import alerts, db, display, maintenance, proxy
from drivers.base import SEVERITY

MAX_LINES = 40
MIN_LEVELS = {"WARN and worse": 1, "FAIL and ERROR only": 2, "ERROR only": 3}
LOOPBACK = {"localhost", "127.0.0.1", "::1"}

# Field spec per channel type: (key, label, kind, extra). kind: text | int | choice | secret
CHANNEL_TYPES = {
    "desktop": {"label": "Windows notification", "fields": [],
                "help": "A pop-up from Toner's tray icon. Only works while Toner is running."},
    "email": {"label": "Email (SMTP)", "help": "Sent through your mail server. Passwords are kept in Credential Manager.",
              "fields": [("smtp_host", "SMTP server", "text", {"required": True, "placeholder": "smtp.example.com"}),
                         ("smtp_port", "Port", "int", {"default": 587, "range": (1, 65535)}),
                         ("security", "Security", "choice", {"choices": ["STARTTLS", "SSL/TLS", "None"], "default": "STARTTLS"}),
                         ("username", "Username", "text", {"placeholder": "blank if the server needs no login"}),
                         ("password", "Password", "secret", {}),
                         ("from_addr", "From", "text", {"required": True, "placeholder": "toner@example.com"}),
                         ("to_addrs", "To", "text", {"required": True, "placeholder": "a@example.com, b@example.com"}),
                         ("subject_prefix", "Subject prefix", "text", {"default": "[Toner]"})]},
    "teams": {"label": "Microsoft Teams", "help": "Create a Workflows webhook in Teams ('Post to a channel when a "
              "webhook request is received') and paste its URL. Old 'Incoming Webhook' connectors are being retired.",
              "fields": [("url", "Webhook URL", "secret", {"required": True, "https": True})]},
    "slack": {"label": "Slack", "help": "Create an Incoming Webhook for your workspace and paste its URL.",
              "fields": [("url", "Webhook URL", "secret", {"required": True, "https": True})]},
    "discord": {"label": "Discord", "help": "Channel settings > Integrations > Webhooks > Copy Webhook URL.",
                "fields": [("url", "Webhook URL", "secret", {"required": True, "https": True})]},
    "webhook": {"label": "Generic webhook (JSON)", "help": "POSTs a JSON document to any URL, for your own tooling.",
                "fields": [("url", "URL", "secret", {"required": True}),
                           ("bearer", "Bearer token (optional)", "secret", {})]},
    "ntfy": {"label": "ntfy (push to phone)", "help": "A simple push service (ntfy.sh or your own server). "
             "Install the ntfy app and subscribe to your topic. Treat the topic name as a password.",
             "fields": [("server", "Server", "text", {"default": "https://ntfy.sh", "required": True}),
                        ("topic", "Topic", "secret", {"required": True}),
                        ("token", "Access token (optional)", "secret", {})]},
}


# ------------------------------------------------------------------ channel storage
def channels():
    return [c for c in db.get_setting("notify_channels") if isinstance(c, dict) and c.get("type") in CHANNEL_TYPES]


def save_channels(chs):
    db.set_setting("notify_channels", chs)


def new_channel(ctype):
    spec = CHANNEL_TYPES[ctype]
    ch = {"id": uuid.uuid4().hex[:8], "type": ctype, "name": spec["label"], "enabled": True,
          "min": "WARN and worse", "recoveries": True}
    for key, _label, kind, extra in spec["fields"]:
        if kind != "secret":
            ch[key] = extra.get("default", "")
    return ch


def _secret_name(cid, key):
    return f"notify:{cid}:{key}"


def get_secrets(ch):
    out = {}
    for key, _l, kind, _e in CHANNEL_TYPES[ch["type"]]["fields"]:
        if kind == "secret":
            try:
                out[key] = keyring.get_password(db.SERVICE, _secret_name(ch["id"], key)) or ""
            except Exception:
                out[key] = ""
    return out


def set_secrets(ch, secrets):
    """Store non-empty secrets; an empty value means 'keep what is stored'."""
    for key, val in secrets.items():
        if val:
            keyring.set_password(db.SERVICE, _secret_name(ch["id"], key), val)


def delete_secrets(ch):
    for key, _l, kind, _e in CHANNEL_TYPES[ch["type"]]["fields"]:
        if kind == "secret":
            try:
                keyring.delete_password(db.SERVICE, _secret_name(ch["id"], key))
            except Exception:
                pass


def validate(ch, secrets):
    """Problems that make a channel unusable (empty list = fine). `secrets` is what would be stored."""
    probs = []
    if not str(ch.get("name", "")).strip():
        probs.append("Give the channel a name.")
    for key, label, kind, extra in CHANNEL_TYPES[ch["type"]]["fields"]:
        val = (secrets.get(key) if kind == "secret" else ch.get(key)) or ""
        val = str(val).strip()
        if extra.get("required") and not val:
            probs.append(f"{label} is required.")
            continue
        if val and kind == "secret" and key in ("url",) or (val and key == "server"):
            u = urlparse(val)
            host = (u.hostname or "").lower()
            ok_scheme = u.scheme == "https" or (u.scheme == "http" and not extra.get("https")) \
                or (u.scheme == "http" and host in LOOPBACK)
            if not (u.netloc and ok_scheme):
                probs.append(f"{label} must be a full {'https' if extra.get('https') else 'http(s)'}:// address.")
        if kind == "int" and val:
            lo, hi = extra.get("range", (0, 10 ** 9))
            if not str(val).isdigit() or not lo <= int(val) <= hi:
                probs.append(f"{label} must be a number from {lo} to {hi}.")
    if ch["type"] == "email":
        for field in ("from_addr", "to_addrs"):
            for a in str(ch.get(field, "")).replace(";", ",").split(","):
                if a.strip() and ("@" not in a or " " in a.strip() or "\n" in a):
                    probs.append(f"'{a.strip()}' is not a valid email address.")
    return probs


# ------------------------------------------------------------------ messages
@dataclass
class Message:
    title: str
    lines: list          # [(status_word, text)] already ordered
    events: list
    problems: int
    recoveries: int

    def plain(self):
        body = "\n".join(t for _s, t in self.lines)
        return f"{self.title}\n\n{body}\n\nSent by Toner at {datetime.now():%Y-%m-%d %H:%M}"


def _line(e):
    what = f"{e.device} - {display.check_name(e.check)}"
    val = display.value(e.value)
    detail = f": {val}" if val else ""
    if e.message and e.kind != "recovered":
        detail += f" ({e.message})"
    if e.kind == "recovered":
        return "OK", f"RECOVERED  {what} (was {e.prev})"
    if e.kind == "worse":
        return e.status, f"{e.status:<5} {what}{detail}  [worse, was {e.prev}]"
    if e.kind == "reminder":
        return e.status, f"{e.status:<5} {what}{detail}  [still failing since {e.since}]"
    return e.status, f"{e.status:<5} {what}{detail}"


def build_message(events, org=""):
    ordered = sorted(events, key=lambda e: (e.kind == "recovered", -SEVERITY[e.status], e.device, e.check))
    problems = sum(e.kind != "recovered" for e in events)
    recov = len(events) - problems
    bits = ([f"{problems} problem{'s' if problems != 1 else ''}"] if problems else []) + \
           ([f"{recov} recovered"] if recov else [])
    title = f"Toner{f' ({org})' if org else ''}: {', '.join(bits)}"
    lines = [_line(e) for e in ordered]
    if len(lines) > MAX_LINES:
        extra = len(lines) - MAX_LINES
        lines = lines[:MAX_LINES] + [("", f"... and {extra} more (see the Results tab)")]
    return Message(title, lines, list(events), problems, recov)


def sample_message():
    """What the Test button sends."""
    e = alerts.Event("new", "Test device", "cpu", "WARN", "OK", "85%", "this is a test notification from Toner")
    return build_message([e])


# ------------------------------------------------------------------ transport
def _scrub(text, secrets):
    """Keep webhook URLs and tokens out of any error text."""
    for s in secrets.values():
        if s and len(s) > 5:
            text = text.replace(s, "***")
            u = urlparse(s)
            if u.scheme and (u.path or u.query):
                text = text.replace(u.path + (f"?{u.query}" if u.query else ""), "/***") if len(u.path) > 3 else text
    return text


class _SMTP(smtplib.SMTP):
    """SMTP that goes through the global proxy when one applies to the mail server."""
    def _get_socket(self, host, port, timeout):
        cfg = proxy.for_device(None, host)
        return proxy.connect(cfg, host, port, timeout) if cfg else super()._get_socket(host, port, timeout)


class _SMTP_SSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        cfg = proxy.for_device(None, host)
        if not cfg:
            return super()._get_socket(host, port, timeout)
        return self.context.wrap_socket(proxy.connect(cfg, host, port, timeout), server_hostname=host)


def _post(url, secrets, json_body=None, data=None, headers=None):
    r = requests.post(url, json=json_body, data=data, headers=headers or {}, timeout=10, allow_redirects=False,
                      **proxy.requests_kwargs(None, urlparse(url).hostname))
    if r.status_code >= 300:
        where = f" to {urlparse(r.headers.get('Location', '')).netloc}" if 300 <= r.status_code < 400 else ""
        raise RuntimeError(f"the service answered HTTP {r.status_code}{where}: {r.text[:120].strip()}")
    return f"HTTP {r.status_code}"


def _escape_slack(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _teams_card(msg):
    color = {"FAIL": "Attention", "ERROR": "Attention", "WARN": "Warning", "OK": "Good"}
    body = [{"type": "TextBlock", "text": msg.title, "weight": "Bolder", "size": "Medium", "wrap": True}]
    for status, text in msg.lines:
        body.append({"type": "TextBlock", "text": text, "wrap": True, "fontType": "Monospace", "spacing": "None",
                     "color": color.get(status, "Default")})
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4", "body": body}}]}


def _send_email(ch, secrets, msg):
    to = [a.strip() for a in str(ch["to_addrs"]).replace(";", ",").split(",") if a.strip()]
    em = EmailMessage()
    em["Subject"] = f"{ch.get('subject_prefix', '').strip()} {msg.title}".strip()
    em["From"], em["To"] = ch["from_addr"].strip(), ", ".join(to)
    em.set_content(msg.plain())
    port, mode = int(ch.get("smtp_port") or 587), ch.get("security", "STARTTLS")
    ctx = ssl.create_default_context()
    if mode == "SSL/TLS":
        smtp = _SMTP_SSL(ch["smtp_host"].strip(), port, timeout=15, context=ctx)
    else:
        smtp = _SMTP(ch["smtp_host"].strip(), port, timeout=15)
    with smtp:
        smtp.ehlo()
        if mode == "STARTTLS":
            smtp.starttls(context=ctx)
            smtp.ehlo()
        if ch.get("username"):
            smtp.login(ch["username"], secrets.get("password", ""))
        smtp.send_message(em)
    return f"sent to {len(to)} recipient(s)"


def _send(ch, secrets, msg, desktop):
    t = ch["type"]
    if t == "desktop":
        if not desktop:
            raise RuntimeError("no system tray is available for Windows notifications")
        top = [text for _s, text in msg.lines[:4]]
        desktop(msg.title, "\n".join(top) + (f"\n+{len(msg.lines) - 4} more" if len(msg.lines) > 4 else ""))
        return "shown"
    if t == "email":
        return _send_email(ch, secrets, msg)
    if t == "teams":
        return _post(secrets["url"], secrets, json_body=_teams_card(msg))
    if t == "slack":
        text = f"*{_escape_slack(msg.title)}*\n```\n" + _escape_slack("\n".join(x for _s, x in msg.lines)) + "\n```"
        return _post(secrets["url"], secrets, json_body={"text": text[:39000]})
    if t == "discord":
        body = "\n".join(x for _s, x in msg.lines)
        budget = 1900 - len(msg.title) - 20
        body = body if len(body) <= budget else body[:budget].rsplit("\n", 1)[0] + "\n..."
        return _post(secrets["url"], secrets, json_body={"content": f"**{msg.title}**\n```\n{body}\n```"})
    if t == "webhook":
        headers = {"Authorization": f"Bearer {secrets['bearer']}"} if secrets.get("bearer") else {}
        doc = {"source": "Toner", "title": msg.title, "sent_at": datetime.now().isoformat(timespec="seconds"),
               "problems": msg.problems, "recovered": msg.recoveries,
               "events": [{"kind": e.kind, "device": e.device, "check": e.check, "status": e.status,
                           "previous": e.prev, "value": e.value, "message": e.message, "since": e.since}
                          for e in msg.events]}
        return _post(secrets["url"], secrets, json_body=doc, headers=headers)
    if t == "ntfy":
        worst = max((SEVERITY[e.status] for e in msg.events), default=0)
        headers = {"Title": msg.title.encode("ascii", "replace").decode(),
                   "Priority": "4" if worst >= 2 else "3",
                   "Tags": "rotating_light" if msg.problems else "white_check_mark"}
        if secrets.get("token"):
            headers["Authorization"] = f"Bearer {secrets['token']}"
        url = ch["server"].strip().rstrip("/") + "/" + secrets["topic"].strip().lstrip("/")
        return _post(url, secrets, data="\n".join(x for _s, x in msg.lines).encode("utf-8"), headers=headers)
    raise RuntimeError(f"unknown channel type {t}")


def deliver(ch, msg, desktop=None, secrets=None, retry_delay=2):
    """Send one message on one channel. Returns (ok, detail). One retry for network hiccups."""
    secrets = get_secrets(ch) if secrets is None else secrets
    for attempt in (1, 2):
        try:
            return True, _send(ch, secrets, msg, desktop)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, smtplib.SMTPServerDisconnected,
                TimeoutError, ConnectionError) as e:
            if attempt == 1:
                time.sleep(retry_delay)
                continue
            return False, _scrub(f"{type(e).__name__}: {e}", secrets)
        except Exception as e:
            return False, _scrub(f"{type(e).__name__}: {e}", secrets)
    return False, "unknown error"


def snoozed(now=None):
    until = db.get_setting("notify_snooze_until")
    try:
        return bool(until) and (now or datetime.now()) < datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False


def process_run(results, ran, scheduled, desktop=None, retry_delay=2):
    """Called after every run. Works out what changed and sends it to each channel that wants it.
    Returns a short text saying what happened (used by tests and the log)."""
    if not db.get_setting("notify_enabled"):
        return "off"
    if snoozed():
        return "snoozed"
    chs = [c for c in channels() if c.get("enabled", True)]
    if not chs:
        return "no channels"
    if not scheduled and not db.get_setting("notify_on_manual"):
        return "manual runs are not notified"
    held = maintenance.devices_in_maintenance()
    if held:                                       # planned work: say nothing, and leave the alert state as it was
        results = [r for r in results if alerts.base(r.device) not in held]
        ran = [d for d in ran if alerts.base(d) not in held]
    events = alerts.evaluate(results, ran, consecutive=int(db.get_setting("notify_consecutive")),
                             remind_hours=int(db.get_setting("notify_remind_hours")))
    if not events:
        return "no changes"
    org = db.get_setting("report_org").strip()
    attempted = delivered = 0
    for ch in chs:
        mine = [e for e in events if wants(ch, e)]
        if not mine:
            continue
        attempted += 1
        ok, detail = deliver(ch, build_message(mine, org), desktop, retry_delay=retry_delay)
        alerts.log_delivery(ch["name"], ok, len(mine), detail)
        delivered += ok
    if attempted and not delivered:                # nobody got it: announce again next run
        alerts.unmark(events)
    return f"{delivered}/{attempted} channels"


def send_test(ch, secrets=None, desktop=None):
    ok, detail = deliver(ch, sample_message(), desktop, secrets)
    alerts.log_delivery(f"{ch['name']} (test)", ok, 1, detail)
    return ok, detail


def wants(ch, event):
    """Does this channel want this event? (its minimum level, and whether it wants recoveries)"""
    if event.kind == "recovered" and not ch.get("recoveries", True):
        return False
    return event.severity >= MIN_LEVELS.get(ch.get("min"), 1)
