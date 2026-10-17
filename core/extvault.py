"""The password managers Toner can keep its passwords in: Bitwarden, Vaultwarden, Keeper and 1Password.

Each one is a small connector with the same few calls (see Provider). Toner's own vault (core/passvault.py) stays underneath as
the encrypted local copy of everything, and core/extstore.py keeps the two in step; nothing here decides what goes where.

  * Bitwarden and Vaultwarden: Bitwarden's own command-line tool (bw.exe), logged in with a personal API key and unlocked with
    the master password. Toner gives it a folder of its own (BITWARDENCLI_APPDATA_DIR) so it never touches a bw the person uses
    themselves. Toner's items live in an organization, one collection per Toner organization.
  * 1Password: 1Password's command-line tool (op.exe) with a service account token. One vault per Toner organization.
  * Keeper: Keeper Secrets Manager (the keeper-secrets-manager-core library), bound once with a one-time access token; the
    configuration it gets back is what Toner keeps. One shared folder per Toner organization.

Every item Toner makes carries a hidden field 'toner_id' holding Toner's own name for that password (for example
'org3/edge-fw:snmp'), so Toner finds its items whatever their titles say. Passwords are never passed on a command line: they go
to bw and op through standard input.
"""
import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from core import db

TAG = "toner_id"
CREATE_NO_WINDOW = 0x08000000

KINDS = [("toner", "Toner's vault"), ("bitwarden", "Bitwarden"), ("vaultwarden", "Vaultwarden"), ("keeper", "Keeper"),
         ("onepassword", "1Password")]
LABELS = dict(KINDS)
CONTAINER_WORD = {"bitwarden": "Collection", "vaultwarden": "Collection", "onepassword": "Vault", "keeper": "Shared folder"}
BITWARDEN_REGIONS = [("United States", "https://vault.bitwarden.com"), ("Europe", "https://vault.bitwarden.eu")]
KEEPER_REGIONS = [("United States", "US"), ("Europe", "EU"), ("Australia", "AU"), ("Canada", "CA"), ("Japan", "JP"),
                  ("US Government", "GOV")]
DOWNLOADS = {"bitwarden": "https://bitwarden.com/help/cli/", "vaultwarden": "https://bitwarden.com/help/cli/",
             "onepassword": "https://developer.1password.com/docs/cli/get-started/"}


class ExtError(Exception):
    """The password manager could not be reached, or said no. The message is shown after 'Couldn't connect to X: '."""


class NotAllowed(ExtError):
    """A collection (vault, shared folder) is missing and Toner may not make it."""

    def __init__(self, name, provider):
        self.name = name
        super().__init__(f"{name} doesn't exist and Toner isn't allowed to create it. Create it in {provider}, or pick another.")


@dataclass
class Item:
    ref: str                        # the manager's id for the item
    title: str = ""
    username: str = ""
    value: str = None               # the password (None: not read, as in a search list)
    toner_id: str = ""              # '' for an item Toner did not make (one picked with Link...)
    container: str = ""             # the collection / vault / shared folder's name
    raw: object = field(default=None, repr=False)


class Provider:
    """What every connector offers. `cfg` holds the settings that are not secret, `secrets` the ones that are (from Toner's vault)."""
    kind = ""

    def __init__(self, cfg, secrets):
        self.cfg, self.secrets = dict(cfg or {}), dict(secrets or {})

    @property
    def label(self):
        return LABELS[self.kind]

    def connect(self):
        raise NotImplementedError

    def containers(self):
        """{name: id} of the collections (vaults, shared folders) this login can use."""
        raise NotImplementedError

    def ensure(self, name):
        """The id of the container called `name`, made when it is missing and the login is allowed to. Raises NotAllowed."""
        have = self.containers()
        found = next((cid for n, cid in have.items() if n.lower() == name.lower()), None)
        if found:
            return found
        return self.create_container(name)

    def create_container(self, name):
        raise NotAllowed(name, self.label)

    def items(self, cid):
        """{toner_id: Item} of Toner's items in one container."""
        raise NotImplementedError

    def put(self, cid, toner_id, title, username, value, item=None):
        """Make or change Toner's item. Returns its ref."""
        raise NotImplementedError

    def delete(self, item):
        raise NotImplementedError

    def search(self, text):
        """[Item] whose title contains `text` (values not read), for Link..."""
        raise NotImplementedError

    def read(self, ref):
        """The password of any item this login can see (a linked one). Raises ExtError."""
        raise NotImplementedError

    # (connectors may hand back settings to keep, such as Keeper's configuration after the one-time token)
    new_secrets = None


# ---------------------------------------------------------------- helpers for the command-line tools
def _last_line(text):
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    return lines[-1] if lines else ""


def _json_stream(text):
    """Several JSON documents one after another (op prints one per item)."""
    out, i, dec = [], 0, json.JSONDecoder()
    text = text or ""
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = dec.raw_decode(text, i)
        out.extend(obj if isinstance(obj, list) else [obj])


def saved_path():
    """PATH as Windows has it saved now (system, then user), not the copy Toner was started with: a folder added to PATH while
    Toner runs (bw.exe, op.exe) is found without restarting it."""
    try:
        import winreg
    except ImportError:
        return os.environ.get("PATH", "")
    parts = []
    for root, key in ((winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                      (winreg.HKEY_CURRENT_USER, "Environment")):
        try:
            with winreg.OpenKey(root, key) as k:
                parts.append(os.path.expandvars(winreg.QueryValueEx(k, "Path")[0]))
        except OSError:
            pass
    return os.pathsep.join(parts)


CLI_NAMES = {"bitwarden": "bw", "vaultwarden": "bw", "onepassword": "op"}
CLI_LABELS = {"bitwarden": "Bitwarden CLI", "vaultwarden": "Bitwarden CLI", "onepassword": "1Password CLI"}


def find_cli(kind, chosen=""):
    """The bw.exe / op.exe Toner would run: the one chosen in Settings, else the first on PATH (as Windows has it saved now).
    '' when there is none."""
    chosen = (chosen or "").strip()
    if chosen:
        return chosen if os.path.isfile(chosen) else ""
    name = CLI_NAMES[kind]
    return shutil.which(name) or shutil.which(name, path=saved_path()) or ""


class _Cli(Provider):
    exe_name = ""

    def exe(self):
        path = (self.cfg.get("cli") or "").strip()
        if path and not os.path.isfile(path):
            raise ExtError(f"{path} was not found.")
        found = find_cli(self.kind, path)
        if not found:
            raise ExtError(f"{self.exe_name}.exe was not found. Install the {self.label} CLI, or choose where it is.")
        return found

    def env(self):
        return dict(os.environ)

    def host(self):
        """The address the tool talks to (for the proxy's bypass list)."""
        return ""

    def run(self, *args, stdin=None, extra=None):
        from core import proxy
        env = proxy.child_env({**self.env(), **(extra or {})}, self.host(), direct())
        try:
            p = subprocess.run([self.exe(), *args], input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               env=env, timeout=180, creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
        except subprocess.TimeoutExpired:
            raise ExtError(f"{self.label} did not answer in time.") from None
        except OSError as e:
            raise ExtError(str(e)) from None
        if p.returncode != 0:
            raise ExtError(_last_line(p.stderr) or _last_line(p.stdout) or f"{self.exe_name} stopped with code {p.returncode}")
        return p.stdout

    def run_json(self, *args, stdin=None, extra=None):
        out = self.run(*args, stdin=stdin, extra=extra)
        try:
            return json.loads(out) if out.strip() else None
        except ValueError:
            raise ExtError(f"{self.label} gave an answer Toner could not read.") from None


# ---------------------------------------------------------------- Bitwarden and Vaultwarden (bw.exe)
class Bitwarden(_Cli):
    kind = "bitwarden"
    exe_name = "bw"

    def __init__(self, cfg, secrets):
        super().__init__(cfg, secrets)
        self.session = None
        self.org_id = None
        self._collections = None

    def server(self):
        return (self.cfg.get("region") or BITWARDEN_REGIONS[0][1]).rstrip("/")

    def host(self):
        from urllib.parse import urlparse
        try:
            return urlparse(self.server()).hostname or ""
        except ExtError:
            return ""

    def home(self):
        p = db.base_path().parent / "bitwarden-cli"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def env(self):
        env = {**os.environ, "BITWARDENCLI_APPDATA_DIR": str(self.home()), "BW_NOINTERACTION": "true"}
        if self.session:
            env["BW_SESSION"] = self.session
        return env

    def connect(self):
        for need, what in (("client_id", "client ID"), ("organization", "organization")):
            if not (self.cfg.get(need) or "").strip():
                raise ExtError(f"Enter the {what}.")
        for need, what in (("client_secret", "client secret"), ("master_password", "master password")):
            if not self.secrets.get(need):
                raise ExtError(f"Enter the {what}.")
        status = self.run_json("status") or {}
        here = (status.get("serverUrl") or BITWARDEN_REGIONS[0][1]).rstrip("/")
        if status.get("status") != "unauthenticated" and here != self.server():
            self.run("logout")
            status = {"status": "unauthenticated"}
        if status.get("status") == "unauthenticated":
            self.run("config", "server", self.server())
            self.run("login", "--apikey", extra={"BW_CLIENTID": self.cfg["client_id"].strip(),
                                                 "BW_CLIENTSECRET": self.secrets["client_secret"]})
        self.session = self.run("unlock", "--passwordenv", "TONER_BW_PASSWORD", "--raw",
                                extra={"TONER_BW_PASSWORD": self.secrets["master_password"]}).strip()
        if not self.session:
            raise ExtError("Bitwarden did not unlock.")
        self.run("sync")
        want = self.cfg["organization"].strip().lower()
        orgs = self.run_json("list", "organizations") or []
        org = next((o for o in orgs if o.get("id", "").lower() == want or (o.get("name") or "").lower() == want), None)
        if not org:
            raise ExtError(f"This account is not in an organization called {self.cfg['organization'].strip()}.")
        self.org_id = org["id"]

    def containers(self):
        if self._collections is None:
            rows = self.run_json("list", "collections", "--organizationid", self.org_id) or []
            self._collections = {r["name"]: r["id"] for r in rows}
        return dict(self._collections)

    def create_container(self, name):
        body = base64.b64encode(json.dumps({"organizationId": self.org_id, "name": name, "externalId": None,
                                            "groups": [], "users": []}).encode()).decode()
        try:
            made = self.run_json("create", "org-collection", "--organizationid", self.org_id, stdin=body)
        except ExtError:
            raise NotAllowed(name, self.label) from None
        self._collections = None
        return made["id"]

    def _item(self, r, names=None):
        tid = next((f.get("value") or "" for f in r.get("fields") or [] if f.get("name") == TAG), "")
        login = r.get("login") or {}
        cname = ", ".join(n for cid, n in (names or {}).items() if cid in (r.get("collectionIds") or []))
        return Item(ref=r["id"], title=r.get("name") or "", username=login.get("username") or "", value=login.get("password"),
                    toner_id=tid, container=cname, raw=r)

    def items(self, cid):
        rows = self.run_json("list", "items", "--collectionid", cid, "--organizationid", self.org_id) or []
        out = {}
        for r in rows:
            it = self._item(r)
            if it.toner_id:
                out[it.toner_id] = it
        return out

    def put(self, cid, toner_id, title, username, value, item=None):
        if item is not None:
            body = dict(item.raw or self.run_json("get", "item", item.ref))
            body["name"] = title
            body["login"] = {**(body.get("login") or {}), "username": username or None, "password": value}
            body = base64.b64encode(json.dumps(body).encode()).decode()
            return self.run_json("edit", "item", item.ref, stdin=body)["id"]
        body = {"organizationId": self.org_id, "collectionIds": [cid], "folderId": None, "type": 1, "name": title, "notes": None,
                "favorite": False, "reprompt": 0, "fields": [{"name": TAG, "value": toner_id, "type": 1}],
                "login": {"username": username or None, "password": value, "uris": [], "totp": None}}
        return self.run_json("create", "item", stdin=base64.b64encode(json.dumps(body).encode()).decode())["id"]

    def delete(self, item):
        self.run("delete", "item", item.ref)

    def search(self, text):
        names = {cid: n for n, cid in self.containers().items()}
        rows = self.run_json("list", "items", "--search", text) if text else self.run_json("list", "items")
        return [self._item(r, names) for r in rows or [] if r.get("type") == 1]

    def read(self, ref):
        r = self.run_json("get", "item", ref) or {}
        value = (r.get("login") or {}).get("password")
        if value is None:
            raise ExtError("The item has no password.")
        return value


class Vaultwarden(Bitwarden):
    """The same tool, pointed at your own server."""
    kind = "vaultwarden"

    def server(self):
        url = (self.cfg.get("server") or "").strip().rstrip("/")
        if not url:
            raise ExtError("Enter the server address.")
        return url if "://" in url else "https://" + url


# ---------------------------------------------------------------- 1Password (op.exe, service account)
class OnePassword(_Cli):
    kind = "onepassword"
    exe_name = "op"

    def env(self):
        return {**os.environ, "OP_SERVICE_ACCOUNT_TOKEN": self.secrets.get("token") or "", "OP_BIOMETRIC_UNLOCK_ENABLED": "false"}

    def host(self):
        return "1password.com"

    def connect(self):
        if not self.secrets.get("token"):
            raise ExtError("Enter the service account token.")
        self.run_json("whoami", "--format", "json")
        self._vaults = None

    def containers(self):
        if getattr(self, "_vaults", None) is None:
            self._vaults = {v["name"]: v["id"] for v in self.run_json("vault", "list", "--format", "json") or []}
        return dict(self._vaults)

    def create_container(self, name):
        try:
            made = self.run_json("vault", "create", name, "--format", "json")
        except ExtError:
            raise NotAllowed(name, self.label) from None
        self._vaults = None
        return made["id"]

    @staticmethod
    def _field(r, purpose=None, label=None):
        for f in r.get("fields") or []:
            if (purpose and f.get("purpose") == purpose) or (label and f.get("label") == label):
                return f.get("value")
        return None

    def _item(self, r):
        vault = r.get("vault") or {}
        return Item(ref=f"{vault.get('id', '')}/{r['id']}", title=r.get("title") or "", username=self._field(r, "USERNAME") or "",
                    value=self._field(r, "PASSWORD"), toner_id=self._field(r, label=TAG) or "", container=vault.get("name") or "", raw=r)

    def items(self, cid):
        rows = self.run_json("item", "list", "--vault", cid, "--format", "json") or []
        if not rows:
            return {}
        full = _json_stream(self.run("item", "get", "-", "--format", "json", stdin=json.dumps(rows)))   # every item in one call
        out = {}
        for r in full:
            it = self._item(r)
            if it.toner_id:
                out[it.toner_id] = it
        return out

    def put(self, cid, toner_id, title, username, value, item=None):
        body = {"title": title, "category": "LOGIN", "fields": [
            {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": username or ""},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": value},
            {"id": TAG, "type": "STRING", "label": TAG, "value": toner_id}]}
        made = self.run_json("item", "create", "--vault", cid, "--format", "json", "-", stdin=json.dumps(body))
        if item is not None:                       # (op edits take values on the command line: make the new one, then drop the old)
            self.delete(item)
        return f"{cid}/{made['id']}"

    def delete(self, item):
        vault, _, ident = item.ref.partition("/")
        self.run("item", "delete", ident, "--vault", vault)

    def search(self, text):
        rows = self.run_json("item", "list", "--format", "json") or []
        want = (text or "").lower()
        return [Item(ref=f"{(r.get('vault') or {}).get('id', '')}/{r['id']}", title=r.get("title") or "",
                     username=r.get("additional_information") or "", container=(r.get("vault") or {}).get("name") or "")
                for r in rows if want in (r.get("title") or "").lower()]

    def read(self, ref):
        vault, _, ident = ref.partition("/")
        r = self.run_json("item", "get", ident, "--vault", vault, "--format", "json") or {}
        value = self._field(r, "PASSWORD")
        if value is None:
            raise ExtError("The item has no password.")
        return value


# ---------------------------------------------------------------- Keeper (Secrets Manager)
class Keeper(Provider):
    kind = "keeper"

    def connect(self):
        try:
            from keeper_secrets_manager_core import SecretsManager
            from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
            from keeper_secrets_manager_core.keeper_globals import keeper_servers
        except ImportError:
            raise ExtError("Keeper Secrets Manager is not part of this copy of Toner.") from None
        self._records = None
        try:
            if self.secrets.get("config"):
                self.sm = SecretsManager(config=InMemoryKeyValueStorage(self.secrets["config"]), log_level="ERROR")
                _route(self.sm)
                self.sm.get_folders()
                return
            token = (self.secrets.get("token") or "").strip()
            if not token:
                raise ExtError("Enter the one-time access token.")
            storage = InMemoryKeyValueStorage()
            host = None if ":" in token else keeper_servers.get(self.cfg.get("region") or "US")
            self.sm = SecretsManager(token=token, hostname=host, config=storage, log_level="ERROR")
            _route(self.sm)
            self.sm.get_folders()                                   # binds the token (it works only once)
            self.new_secrets = {"config": json.dumps(storage.read_storage()), "token": ""}
        except ExtError:
            raise
        except Exception as e:
            raise ExtError(str(e) or e.__class__.__name__) from None

    def _call(self, fn, *a):
        try:
            return fn(*a)
        except ExtError:
            raise
        except Exception as e:
            raise ExtError(str(e) or e.__class__.__name__) from None

    def _folders(self):
        return self._call(self.sm.get_folders)

    def containers(self):
        return {f.name: f.folder_uid for f in self._folders()}

    def _all(self):
        if self._records is None:
            self._records = self._call(self.sm.get_secrets)
        return self._records

    def _item(self, r, names=None):
        tid = ""
        for f in r.dict.get("custom") or []:
            if f.get("label") == TAG and f.get("value"):
                tid = f["value"][0]
        try:
            user = r.field("login", single=True) or ""
        except ValueError:
            user = ""
        where = r.inner_folder_uid or r.folder_uid
        return Item(ref=r.uid, title=r.title or "", username=user, value=r.password, toner_id=tid,
                    container=(names or {}).get(where, ""), raw=r)

    def items(self, cid):
        out = {}
        for r in self._all():
            if (r.inner_folder_uid or r.folder_uid) == cid:
                it = self._item(r)
                if it.toner_id:
                    out[it.toner_id] = it
        return out

    def put(self, cid, toner_id, title, username, value, item=None):
        from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField
        from keeper_secrets_manager_core.dto.payload import CreateOptions
        if item is not None:
            r = item.raw
            r.title = title
            for kind, v in (("login", username or ""), ("password", value)):
                try:
                    r.field(kind, value=v)
                except ValueError:
                    r.dict.setdefault("fields", []).append({"type": kind, "value": [v]})
            r._update()
            self._call(self.sm.save, r)
            return r.uid
        folders = self._folders()
        by_uid = {f.folder_uid: f for f in folders}
        top = cid
        while by_uid.get(top) is not None and by_uid[top].parent_uid:
            top = by_uid[top].parent_uid                            # records go in a shared folder (and, maybe, a folder inside it)
        rec = RecordCreate("login", title)
        rec.fields = [RecordField("login", username or ""), RecordField("password", value)]
        rec.custom = [RecordField("text", toner_id, label=TAG)]
        uid = self._call(self.sm.create_secret_with_options, CreateOptions(top, cid if cid != top else None), rec, folders)
        self._records = None
        return uid

    def delete(self, item):
        self._call(self.sm.delete_secret, [item.ref])
        self._records = None

    def search(self, text):
        names = {f.folder_uid: f.name for f in self._folders()}
        want = (text or "").lower()
        return [self._item(r, names) for r in self._all() if want in (r.title or "").lower()]

    def read(self, ref):
        found = self._call(self.sm.get_secrets, [ref])
        if not found or found[0].password is None:
            raise ExtError("The item has no password.")
        return found[0].password


def direct():
    """Settings > Security > Connect directly to the password manager (ignore the proxy settings)."""
    return bool(db.get_setting("vault_direct"))


def _route(sm):
    """Keeper's requests go the way Settings > Proxy says (or directly), like the rest of Toner's web connections."""
    from urllib.parse import urlparse
    import requests
    from keeper_secrets_manager_core import core as K
    from core import proxy

    def post(url, transmission_key, payload, verify_ssl_certs=True, proxy_url=None):
        headers = {"Content-Type": "application/octet-stream", "Content-Length": str(len(payload.encrypted_payload)),
                   "PublicKeyId": str(transmission_key.publicKeyId), "TransmissionKey": K.bytes_to_base64(transmission_key.encryptedKey),
                   "Authorization": "Signature %s" % K.bytes_to_base64(payload.signature)}
        rs = requests.post(url, headers=headers, data=payload.encrypted_payload, verify=verify_ssl_certs, timeout=60,
                           **proxy.web_kwargs(urlparse(url).hostname, direct()))
        return K.KSMHttpResponse(rs.status_code, rs.content, rs)
    sm.post_function = post


CONNECTORS = {"bitwarden": Bitwarden, "vaultwarden": Vaultwarden, "onepassword": OnePassword, "keeper": Keeper}
SECRET_FIELDS = {"bitwarden": ("client_secret", "master_password"), "vaultwarden": ("client_secret", "master_password"),
                 "onepassword": ("token",), "keeper": ("token", "config")}


def make(kind, cfg, secrets):
    return CONNECTORS[kind](cfg, secrets)
