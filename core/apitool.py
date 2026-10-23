"""API Tester (Tools > Connect > API Tester): send one HTTP request and look at the reply, like a small Postman.

Saved requests are kept per organization (Global's can be marked Shared, like sessions), in folders. Variables ({{name}})
belong to the organization being looked at, so a Shared request can use each organization's own values. Tokens, passwords
and keys live in Toner's vault, never in the database: a request's under 'api-request:<id>', a secret variable's under
'api-var:<name>' (each under the organization's prefix, see db.qualify). History keeps the last N requests sent per
organization and never a secret.
"""
import base64
import json
import re
import time
from datetime import datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import keyring

from core import audit, db, profiles, proxy
from core.folders import FolderTree

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
BODY_TYPES = [("none", "None", ""), ("json", "JSON", "application/json"), ("xml", "XML", "application/xml"),
              ("form", "Form (urlencoded)", "application/x-www-form-urlencoded"), ("text", "Plain text", "text/plain")]
AUTH_TYPES = [("none", "No auth"), ("bearer", "Bearer token"), ("basic", "Basic"), ("apikey", "API key"),
              ("profile", "Credential profile")]
PROFILE_AS = [("bearer", "Bearer token"), ("basic", "Basic"), ("header", "API key in a header"),
              ("query", "API key in a query parameter")]
KEY_WHERE = [("header", "Header"), ("query", "Query parameter")]
AUTH_DEFAULTS = {"type": "none", "username": "", "key_name": "", "where": "header", "profile_id": None, "send_as": "bearer"}
FIELDS = ["name", "folder_id", "method", "url", "params", "headers", "body", "body_type", "auth", "timeout", "verify"]
HISTORY_FIELDS = ["method", "url", "params", "headers", "body", "body_type", "auth", "timeout", "verify"]
VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_-]+)\s*\}\}")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_BODY = 5 * 1024 * 1024               # of a reply, kept and shown
MASK = "****"
DEFAULT_TIMEOUT = 30

FOLDERS = FolderTree("api_folders", "api_requests")
list_folders, folder_paths, folder_descendants = FOLDERS.list, FOLDERS.paths, FOLDERS.descendants
create_folder, rename_folder, move_folder, delete_folder = FOLDERS.create, FOLDERS.rename, FOLDERS.move, FOLDERS.delete
move_requests = FOLDERS.move_members


def secret_name(request_id):
    return db.qualify(f"api-request:{request_id}")


def var_secret_name(name):
    return db.qualify(f"api-var:{name}")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _vault(name):
    try:
        return keyring.get_password(db.SERVICE, name) or ""
    except Exception:
        return ""


def blank():
    """An empty editor: what New gives."""
    return {"id": None, "name": "", "folder_id": None, "method": "GET", "url": "", "params": [], "headers": [], "body": "",
            "body_type": "none", "auth": dict(AUTH_DEFAULTS), "timeout": DEFAULT_TIMEOUT, "verify": True, "shared": 0}


def _load(text, default):
    try:
        v = json.loads(text) if isinstance(text, str) and text else text
    except ValueError:
        return default
    return v if isinstance(v, type(default)) else default


def _rows(row):
    """A params/headers list as [[on, name, value], ...] whatever was stored."""
    out = []
    for r in _load(row, []):
        if isinstance(r, (list, tuple)) and len(r) == 3:
            out.append([bool(r[0]), str(r[1]), str(r[2])])
    return out


def _clean(row):
    r = dict(row)
    r["params"], r["headers"] = _rows(r.get("params")), _rows(r.get("headers"))
    r["auth"] = {**AUTH_DEFAULTS, **_load(r.get("auth"), {})}
    r["timeout"] = int(r.get("timeout") or DEFAULT_TIMEOUT)
    r["verify"] = bool(r.get("verify", 1))
    r["body"], r["body_type"] = r.get("body") or "", r.get("body_type") or "none"
    if r["body_type"] not in {k for k, _, _ in BODY_TYPES}:
        r["body_type"] = "none"
    return r


# ---------------------------------------------------------------- saved requests
def _requests_here():
    with db.connect() as c:
        return [_clean(r) for r in c.execute("SELECT * FROM api_requests ORDER BY name COLLATE NOCASE")]


def list_requests():
    """The requests of the organization being looked at plus Global's Shared ones (each with 'org'); in Global, Global's own."""
    return db.gather_own(_requests_here)


def get(request_id, org=None):
    with db.within(org):
        found = next((r for r in _requests_here() if r["id"] == request_id), None)
        if found:
            found["org"] = db.target()
    return found


def validate(req):
    name = (req.get("name") or "").strip()
    if not name:
        raise ValueError("Give the request a name so it can be found again.")
    if req.get("method") not in METHODS:
        raise ValueError("Choose a method.")
    return name


def save(req, secret=None):
    """Insert or update, in the request's own organization's file (req['org']; Shared ones in Global's). `secret` is the typed
    token, password or key value: None leaves the stored one alone, '' removes it. Returns the id. Raises ValueError."""
    with db.within(req.get("org")):
        return _save(req, secret)


def _save(req, secret):
    name = validate(req)
    known = {f["id"] for f in list_folders()}
    folder_id = req.get("folder_id") if req.get("folder_id") in known else None
    auth = {k: (req.get("auth") or {}).get(k, v) for k, v in AUTH_DEFAULTS.items()}
    row = {"name": name, "folder_id": folder_id, "method": req["method"], "url": (req.get("url") or "").strip(),
           "params": json.dumps(_rows(req.get("params") or [])), "headers": json.dumps(_rows(req.get("headers") or [])),
           "body": req.get("body") or "", "body_type": req.get("body_type") or "none", "auth": json.dumps(auth),
           "timeout": int(req.get("timeout") or DEFAULT_TIMEOUT), "verify": 1 if req.get("verify", True) else 0,
           "shared": 1 if req.get("shared") and db.target() == db.GLOBAL else 0}
    with db.connect() as c:
        clash = c.execute("SELECT id FROM api_requests WHERE name=? COLLATE NOCASE AND folder_id IS ? AND id IS NOT ?",
                          (name, folder_id, req.get("id"))).fetchone()
        if clash:
            where = folder_paths().get(folder_id)
            raise ValueError(f"A request named '{name}' already exists" + (f" in {where}." if where else " at the top level."))
        cols = FIELDS + ["shared"]
        if req.get("id"):
            c.execute("UPDATE api_requests SET " + ", ".join(f"{k}=?" for k in cols) + ", updated=? WHERE id=?",
                      [row[k] for k in cols] + [_now(), req["id"]])
            rid = req["id"]
        else:
            rid = c.execute(f"INSERT INTO api_requests ({','.join(cols)}, created, updated) VALUES ({','.join('?' * len(cols))}, ?, ?)",
                            [row[k] for k in cols] + [_now(), _now()]).lastrowid
    if secret is not None:
        if secret:
            db.set_secret(secret_name(rid), secret)
        else:
            db.delete_secret(secret_name(rid))
    return rid


def rename(request_id, name, org=None):
    r = get(request_id, org)
    if r:
        save({**r, "name": name})


def delete(request_id, org=None):
    with db.within(org):
        with db.connect() as c:
            c.execute("DELETE FROM api_requests WHERE id=?", (request_id,))
        db.delete_secret(secret_name(request_id))


def duplicate(request_id, org=None):
    with db.within(org):
        return _duplicate(request_id)


def _duplicate(request_id):
    r = get(request_id)
    if not r:
        return None
    names = {x["name"].lower() for x in _requests_here() if x["folder_id"] == r["folder_id"]}
    n, name = 2, f"{r['name']} (copy)"
    while name.lower() in names:
        name, n = f"{r['name']} (copy {n})", n + 1
    return save({**r, "id": None, "name": name}, request_secret(r) or None)


def request_secret(req):
    """The request's own token, password or key value, from its organization's vault names ('' when there is none)."""
    if not req or not req.get("id"):
        return ""
    with db.within(req.get("org")):
        return _vault(secret_name(req["id"]))


def has_secret(req):
    return bool(request_secret(req))


# ---------------------------------------------------------------- variables
def clean_variable_name(name):
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("A variable name can use letters, digits, _ and -.")
    return name


def list_variables():
    """The organization's variables, [{'name', 'value', 'secret'}] by name; a secret one's value is '' here (see variable_values)."""
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT name, value, secret FROM api_variables ORDER BY name COLLATE NOCASE")]


def variable_exists(name):
    with db.connect() as c:
        return bool(c.execute("SELECT 1 FROM api_variables WHERE name=? COLLATE NOCASE", ((name or "").strip(),)).fetchone())


def set_variable(name, value, secret=False, old_name=None):
    """Add or change a variable (`old_name` when renaming one). A secret one's value goes to the vault; an empty value for a secret
    one keeps what is stored."""
    name = clean_variable_name(name)
    with db.connect() as c:
        clash = c.execute("SELECT name FROM api_variables WHERE name=? COLLATE NOCASE AND NOT (name=? COLLATE NOCASE)",
                          (name, old_name or name)).fetchone()
        if clash:
            raise ValueError(f"There is already a variable named '{name}'.")
        if old_name and old_name != name:
            c.execute("DELETE FROM api_variables WHERE name=?", (old_name,))
            was = _vault(var_secret_name(old_name))
            db.delete_secret(var_secret_name(old_name))
            if secret and not value:
                value = was
        c.execute("INSERT OR REPLACE INTO api_variables(name, value, secret) VALUES(?,?,?)",
                  (name, "" if secret else str(value or ""), 1 if secret else 0))
    if secret:
        if value:
            db.set_secret(var_secret_name(name), str(value))
    else:
        db.delete_secret(var_secret_name(name))


def delete_variable(name):
    with db.connect() as c:
        c.execute("DELETE FROM api_variables WHERE name=?", (name,))
    db.delete_secret(var_secret_name(name))


def variable_values():
    """{name: value} with secret ones read from the vault, for filling in a request."""
    out = {}
    for v in list_variables():
        out[v["name"]] = _vault(var_secret_name(v["name"])) if v["secret"] else v["value"]
    return out


def secret_variable_values():
    return [_vault(var_secret_name(v["name"])) for v in list_variables() if v["secret"]]


def fill(text, values):
    """{{name}} replaced by its value. Names that have no value are left as they are."""
    return VAR_RE.sub(lambda m: str(values[m.group(1)]) if m.group(1) in values else m.group(0), text or "")


def names_in(text):
    return set(VAR_RE.findall(text or ""))


def _texts(req, secret=""):
    a = req.get("auth") or {}
    yield req.get("url") or ""
    for on, k, v in _rows(req.get("params") or []):
        if on:
            yield k
            yield v
    for on, k, v in _rows(req.get("headers") or []):
        if on:
            yield k
            yield v
    if (req.get("body_type") or "none") != "none":
        yield req.get("body") or ""
    yield a.get("username") or ""
    yield a.get("key_name") or ""
    yield secret or ""


def unresolved(req, values, secret=""):
    """The {{names}} used by the request that have no value, in the order they are first used."""
    out = []
    for t in _texts(req, secret):
        for n in VAR_RE.findall(t):
            if n not in values and n not in out:
                out.append(n)
    return out


# ---------------------------------------------------------------- the URL and its query string
def split_query(url):
    """[[True, name, value], ...] for the query string of a URL as typed (variables left alone)."""
    q = urlsplit(url or "").query
    return [[True, k, v] for k, v in parse_qsl(q, keep_blank_values=True)] if q else []


def with_query(url, params):
    """The URL with its query string replaced by the ticked params ('' when there are none)."""
    parts = urlsplit(url or "")
    pairs = [(k, v) for on, k, v in _rows(params) if on and k]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, safe="{}/:,"), parts.fragment))


def check_url(url):
    u = (url or "").strip()
    if not u:
        raise ValueError("Enter a URL.")
    if not re.match(r"^https?://", u, re.I):
        raise ValueError("The URL must start with http:// or https://.")
    if not urlsplit(u).netloc:
        raise ValueError("The URL needs a host name after http:// or https://.")
    return u


# ---------------------------------------------------------------- building and sending
def profile_secret(req):
    """(profile, secret) for a request that signs in with a credential profile, looked up in the request's own organization."""
    pid = (req.get("auth") or {}).get("profile_id")
    if not pid:
        raise ValueError("Choose a profile.")
    with db.within(req.get("org")):
        p = profiles.get(int(pid))
        if not p:
            raise ValueError("The profile this request used is gone. Choose another one.")
        value = profiles.secret({"profile_id": int(pid), "org": db.target()})
    if not value:
        raise ValueError(f"The profile '{p['name']}' has no password or token stored. Add one in Settings > Credentials.")
    return p, value


def build(req, secret="", values=None):
    """What goes on the wire, with every {{name}} filled in: {'method', 'url', 'headers', 'data', 'auth', 'timeout', 'verify',
    'secrets'} ('secrets': every value to mask in the audit log). Raises ValueError for anything the person must fix first."""
    values = values if values is not None else variable_values()
    missing = unresolved(req, values, secret)
    if missing:
        raise ValueError(f"No value for {{{{{missing[0]}}}}}. Add it on the Variables tab.")
    f = lambda t: fill(t, values)                     # noqa: E731
    a = {**AUTH_DEFAULTS, **(req.get("auth") or {})}
    secrets = [v for v in secret_variable_values() if v]
    params = [[on, f(k), f(v)] for on, k, v in _rows(req.get("params") or [])]
    url = check_url(with_query(f(req.get("url")), params) if params else f(req.get("url")).strip())
    headers = {}
    for on, k, v in _rows(req.get("headers") or []):
        if on and k.strip():
            headers[f(k).strip()] = f(v)
    body_type = req.get("body_type") or "none"
    data = None
    if body_type != "none":
        data = f(req.get("body") or "").encode("utf-8")
        ctype = dict((k, c) for k, _, c in BODY_TYPES)[body_type]
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = ctype + ("; charset=utf-8" if body_type != "form" else "")
    kind, user, value, key_name, where = a["type"], f(a.get("username") or ""), f(secret or ""), f(a.get("key_name") or ""), a.get("where")
    if kind == "profile":
        p, value = profile_secret(req)
        user = p.get("username") or ""
        send_as = a.get("send_as") or "bearer"
        kind, where = {"bearer": "bearer", "basic": "basic", "header": "apikey", "query": "apikey"}[send_as], \
            "query" if send_as == "query" else "header"
    if kind == "bearer":
        if not value:
            raise ValueError("Enter the token.")
        headers["Authorization"] = f"Bearer {value}"
    elif kind == "basic":
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{value}".encode("utf-8")).decode("ascii")
    elif kind == "apikey":
        if not key_name.strip():
            raise ValueError("Enter the key name (for example X-API-Key).")
        if where == "query":
            parts = urlsplit(url)
            q = parts.query + ("&" if parts.query else "") + f"{quote(key_name.strip(), safe='')}={quote(value, safe='')}"
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment))
        else:
            headers[key_name.strip()] = value
    if value and kind in ("bearer", "basic", "apikey"):
        secrets.append(value)
    return {"method": req["method"], "url": url, "headers": headers, "data": data, "timeout": int(req.get("timeout") or DEFAULT_TIMEOUT),
            "verify": bool(req.get("verify", True)), "secrets": [s for s in secrets if s]}


def mask(text, secrets):
    """Every secret value in `text` replaced by ****, longest first (also in the forms a URL carries them)."""
    for s in sorted({s for s in secrets if s}, key=len, reverse=True):
        for form in (s, quote(s, safe=""), quote(s)):
            text = text.replace(form, MASK)
    return text


def send(prepared, cancel=None):
    """Send it (on a worker thread) and read the reply. Returns {'status', 'reason', 'ms', 'size', 'headers', 'body', 'truncated',
    'error', 'url', 'cancelled'}: 'error' says what went wrong in plain words when nothing came back."""
    import requests
    out = {"status": 0, "reason": "", "ms": 0, "size": 0, "headers": [], "body": b"", "truncated": 0, "error": "", "url": prepared["url"],
           "cancelled": False}
    host = urlsplit(prepared["url"]).hostname or ""
    if not prepared["verify"]:
        import urllib3
        urllib3.disable_warnings()
    started = time.monotonic()
    try:
        r = requests.request(prepared["method"], prepared["url"], headers=prepared["headers"], data=prepared["data"],
                             timeout=prepared["timeout"], verify=prepared["verify"], allow_redirects=True, stream=True,
                             **proxy.web_kwargs(host))
        try:
            out.update(status=r.status_code, reason=r.reason or "", headers=list(r.headers.items()), url=r.url)
            chunks, size = [], 0
            for chunk in r.iter_content(65536):
                if cancel is not None and cancel.is_set():
                    out["cancelled"] = True
                    break
                size += len(chunk)
                if size <= MAX_BODY:
                    chunks.append(chunk)
                elif not out["truncated"]:
                    chunks.append(chunk[:max(0, MAX_BODY - (size - len(chunk)))])
                    out["truncated"] = 1
            out["body"], out["size"] = b"".join(chunks), size
        finally:
            r.close()
    except requests.exceptions.SSLError as e:
        out["error"] = f"Certificate not trusted: {_reason(e)}. Untick Verify certificate for a self-signed device."
    except requests.exceptions.Timeout:
        out["error"] = f"No reply within {prepared['timeout']} s."
    except requests.exceptions.ProxyError as e:
        out["error"] = f"The proxy refused the connection: {_reason(e)}"
    except requests.exceptions.ConnectionError as e:
        out["error"] = f"Could not connect: {_reason(e)}"
    except requests.exceptions.RequestException as e:
        out["error"] = f"The request failed: {_reason(e)}"
    out["ms"] = int((time.monotonic() - started) * 1000)
    if out["cancelled"]:
        out["error"] = "Cancelled."
    return out


def _reason(e):
    """The useful part of a requests error, without the wrapper noise."""
    text = str(e)
    m = re.search(r"\(Caused by ([A-Za-z]+)\((.*)\)\)", text, re.S)
    if m:
        inner = m.group(2).strip()
        inner = re.sub(r"^<[^>]*>:\s*", "", inner)              # "<urllib3... object at 0x...>: Failed to ..."
        inner = re.sub(r"^\[[^\]]*\]\s*", "", inner)            # "[Errno 111] ..."
        inner = re.sub(r"\s*\(_ssl\.c:\d+\)", "", inner)
        text = inner.strip("'\" ") or m.group(1)
    return text[:300]


def record(req, prepared, result, request_id=None):
    """After a send: one audit line (secrets masked) and one history row (no secrets at all). Returns the history id."""
    shown = mask(prepared["url"], prepared["secrets"])
    if result.get("error"):
        audit.log("api request failed", f"{prepared['method']} {shown}: {result['error']}")
    else:
        audit.log("api request", f"{prepared['method']} {shown} -> {result['status']} in {result['ms']} ms")
    return add_history(req, result, request_id)


# ---------------------------------------------------------------- history
def add_history(req, result, request_id=None):
    row = {k: req.get(k) for k in HISTORY_FIELDS}
    auth = {k: (req.get("auth") or {}).get(k, v) for k, v in AUTH_DEFAULTS.items()}
    row.update(params=json.dumps(_rows(req.get("params") or [])), headers=json.dumps(_rows(req.get("headers") or [])),
               auth=json.dumps(auth), body=req.get("body") or "", body_type=req.get("body_type") or "none",
               timeout=int(req.get("timeout") or DEFAULT_TIMEOUT), verify=1 if req.get("verify", True) else 0)
    with db.connect() as c:
        hid = c.execute(f"INSERT INTO api_history ({','.join(HISTORY_FIELDS)}, at, request_id, status, reason, ms, size, error) "
                        f"VALUES ({','.join('?' * len(HISTORY_FIELDS))}, ?, ?, ?, ?, ?, ?, ?)",
                        [row[k] for k in HISTORY_FIELDS] + [_now(), request_id, int(result.get("status") or 0), result.get("reason") or "",
                                                            int(result.get("ms") or 0), int(result.get("size") or 0), result.get("error") or ""]).lastrowid
    prune()
    return hid


def history_keep():
    try:
        return max(1, int(db.get_setting("api_history_keep")))
    except (TypeError, ValueError):
        return 100


def prune(keep=None):
    keep = history_keep() if keep is None else max(1, int(keep))
    with db.connect() as c:
        c.execute("DELETE FROM api_history WHERE id NOT IN (SELECT id FROM api_history ORDER BY id DESC LIMIT ?)", (keep,))


def list_history():
    """Newest first, each as an editor state plus 'at', 'status', 'reason', 'ms', 'size', 'error', 'request_id'."""
    with db.connect() as c:
        rows = [_clean(r) for r in c.execute("SELECT * FROM api_history ORDER BY id DESC")]
    for r in rows:
        r["org"] = db.target()
    return rows


def clear_history():
    with db.connect() as c:
        c.execute("DELETE FROM api_history")


# ---------------------------------------------------------------- showing a reply
def _charset(headers):
    ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
    m = re.search(r"charset=([\w-]+)", ctype, re.I)
    return (m.group(1) if m else "utf-8"), ctype.split(";")[0].strip().lower()


def pretty(body, headers, want=True):
    """(text, kind): the reply body as text, pretty-printed when it is JSON ('json'), indented when XML ('xml'), as it came
    otherwise ('text'). `want` False gives the text as it came."""
    charset, ctype = _charset(headers)
    try:
        text = body.decode(charset, "replace")
    except LookupError:
        text = body.decode("utf-8", "replace")
    if not want or not text.strip():
        return text, "text"
    if "json" in ctype or text.lstrip()[:1] in "{[":
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False), "json"
        except ValueError:
            pass
    if "xml" in ctype or text.lstrip().startswith("<?xml") or text.lstrip().startswith("<"):
        try:
            from xml.dom import minidom
            out = minidom.parseString(text.encode("utf-8")).toprettyxml(indent="  ")
            return "\n".join(line for line in out.splitlines() if line.strip()), "xml"
        except Exception:
            pass
    return text, "text"


def format_json(text):
    """The body text pretty-printed if it is JSON; raises ValueError saying where it is not."""
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except ValueError as e:
        raise ValueError(f"This is not valid JSON: {e}")


def size_text(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


def status_text(result):
    """The status line: '200 OK  ·  123 ms  ·  4.2 KB', or what went wrong."""
    if result.get("error"):
        return result["error"]
    return f"{result['status']} {result.get('reason') or ''}".strip() + f"  ·  {result['ms']} ms  ·  {size_text(result['size'])}"
