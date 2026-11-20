"""An Email channel that signs in to Microsoft 365 or Google with OAuth 2.0 instead of a password: the browser sign-in, the refresh
token kept in the vault (as single sign-on keeps its own, core/dirsignin.py), and an access token for each mail. The token calls are
core/oidc.py's and connect directly, never through Toner's proxy. No token, secret or URL reaches an error text, a log or the audit:
errors are the approved texts below, which name only the provider."""
import json
import threading
import time
import urllib.parse
import webbrowser

from core import audit, db, extstore, oidc, passvault, quiet

METHODS = [("password", "Password"), ("ms_account", "Microsoft 365 account"), ("ms_app", "Microsoft 365 app (no person)"),
           ("google_account", "Google account")]
MS_ISSUER = "https://login.microsoftonline.com/{tenant}/v2.0"
GOOGLE_ISSUER = "https://accounts.google.com"
SCOPES = {"ms_account": "openid profile offline_access https://outlook.office.com/SMTP.Send",
          # Google: no offline_access and no access_type. "Note that refresh tokens are always returned for installed applications."
          # (https://developers.google.com/identity/protocols/oauth2/native-app, the token response; [G2] in the design)
          "google_account": "openid email https://mail.google.com/",
          "ms_app": "https://outlook.office365.com/.default"}
PREFIX = extstore.LOCAL + "mail-refresh:"     # '~toner/': kept in Toner's vault only, never sent to a password manager
STALE = 7 * 86400
RETRY = 3600        # a failed renewal waits an hour: an outage then costs each run's alerts at most one slow token call an hour,
                    # and a sign-in that lasts 90 days (Microsoft) or 6 months unused (Google) loses nothing by the wait
open_url = webbrowser.open          # tests replace it

NOT_SIGNED_IN = "Toner isn't signed in to {provider} for this channel. Edit the channel and choose Sign in."
GONE = "{provider} no longer accepts this sign-in. Edit the channel and choose Sign in again."
UNREACHABLE = "{provider} can't be reached, so the email wasn't sent."
APP_REFUSED = "{provider} refused the app. Check the tenant ID, client ID and client secret."
NO_KEEPER = "{provider} didn't give Toner a sign-in it can keep. Check the app's setup, then sign in again."
SERVER_REFUSED = ("The mail server refused the sign-in. Check the username, that the app may send from this mailbox, and that "
                  "authenticated SMTP is on for it.")
NOTICE = "{channel} needs a new sign-in. Edit it in Settings > Notifications and choose Sign in again."


class MailAuthError(Exception):
    """Its text is one of the approved messages. gone: the provider refused the sign-in for good."""

    def __init__(self, text, gone=False):
        super().__init__(text)
        self.gone = gone


def provider(auth):
    return "Google" if auth == "google_account" else "Microsoft 365"


def needs_sign_in(auth):
    return auth in ("ms_account", "google_account")


def _cfg(ch):
    if ch.get("auth") == "google_account":
        return {"issuer": GOOGLE_ISSUER, "client_id": str(ch.get("client_id", "")).strip(), "provider": "google"}
    tenant = urllib.parse.quote(str(ch.get("tenant", "")).strip(), safe="")
    return {"issuer": MS_ISSUER.format(tenant=tenant), "client_id": str(ch.get("client_id", "")).strip()}


def _name(ch):
    return PREFIX + ch["id"]


def _stored(ch):
    """{"refresh_token", "account", "renewed"} of the channel's sign-in, or None (none, or the vault is locked)."""
    try:
        got = json.loads(passvault.get(_name(ch)) or "null")
    except Exception:
        return None
    return got if isinstance(got, dict) and got.get("refresh_token") else None


def _store(ch, refresh_token, account):
    passvault.put(_name(ch), json.dumps({"refresh_token": refresh_token, "account": account, "renewed": time.time()}))


def _note_try(ch, refresh_token, now):
    """Remember a failed renewal's time on the sign-in, in one locked step and only if it still holds the token tried (another
    process may have renewed it meanwhile, and that newer token must not be overwritten)."""
    def mark(data):
        try:
            got = json.loads(data.get(_name(ch)) or "null")
        except ValueError:
            return
        if isinstance(got, dict) and got.get("refresh_token") == refresh_token:
            data[_name(ch)] = json.dumps({**got, "tried": now})
    passvault._change(mark)


def signed_in_as(ch):
    got = _stored(ch)
    return got.get("account") if got else None


def _call(prov, fn):
    """fn's answer, with the provider's errors as the approved texts (oidc.Refused is left to the caller)."""
    try:
        return fn()
    except (oidc.Refused, oidc.Cancelled):
        raise
    except oidc.Unreachable:
        raise MailAuthError(UNREACHABLE.format(provider=prov)) from None
    except oidc.OidcError:              # invalid_client, unauthorized_client, a 401, a wrong tenant: the app's setup
        raise MailAuthError(APP_REFUSED.format(provider=prov)) from None


def sign_in(ch, secrets, cancelled=None):
    """The person signs in in their browser (the window only, off its thread). Stores the refresh token; returns the account.
    oidc.Cancelled when cancelled or not finished; other oidc errors as single sign-on raises them."""
    auth, prov = ch.get("auth"), provider(ch.get("auth"))
    if not needs_sign_in(auth):
        raise ValueError(f"{auth!r} has no browser sign-in")        # a caller's mistake, never shown to a person
    browser = oidc.BrowserSignIn(_cfg(ch), open_url=open_url, scopes=SCOPES[auth], fresh=False,
                                 client_secret=secrets.get("client_secret", ""))
    try:
        browser.open()
    except Exception:
        browser.close()
        raise
    tokens = browser.run(cancelled or threading.Event())
    if not tokens.refresh_token:
        raise MailAuthError(NO_KEEPER.format(provider=prov))
    account = tokens.claims.get("email") or tokens.claims.get("preferred_username") or ""
    _store(ch, tokens.refresh_token, account)
    audit.log("email sign-in", f"{ch['name']}, {prov}, {account}")
    return account


def sign_out(ch):
    got = _stored(ch)
    try:
        had = passvault.remove(_name(ch))
    except Exception:
        return
    if had:
        audit.log("email sign-in removed", f"{ch['name']}, {provider(ch.get('auth'))}, {(got or {}).get('account', '')}")


def _refused(ch, prov, stored):
    """The provider refused the sign-in for good: remove it, and (only the process that removed it) say so once. A sign-in the
    channel's form made and has not saved (ch["draft"], ui/settings_pages/notifications.py) is only removed: no channel lost one."""
    try:
        had = passvault.remove(_name(ch))
    except Exception:
        had = False
    if had and not ch.get("draft"):
        audit.log("email sign-in refused", f"{ch['name']}, {prov}, {stored.get('account', '')}")
        try:
            from core import notify      # notify imports this module
            notify.announce("Toner", "email sign-in", "", NOTICE.format(channel=ch["name"]), "FAIL", skip=ch["id"])
        except Exception:
            quiet.ignored()
    raise MailAuthError(GONE.format(provider=prov), gone=True)


def access_token(ch, secrets):
    """A new access token for one mail (nothing is cached). Raises MailAuthError."""
    auth, prov, cfg = ch.get("auth"), provider(ch.get("auth")), _cfg(ch)
    secret = secrets.get("client_secret", "")
    if auth == "ms_app":
        form = {"grant_type": "client_credentials", "scope": SCOPES["ms_app"]}
        try:
            return _call(prov, lambda: oidc._token_call(cfg, form, secret))[1]
        except oidc.Refused:
            raise MailAuthError(APP_REFUSED.format(provider=prov)) from None
    stored = _stored(ch)
    if not stored:
        raise MailAuthError(NOT_SIGNED_IN.format(provider=prov))
    retried = False
    while True:
        try:
            tokens = _call(prov, lambda: oidc.refresh(cfg, stored["refresh_token"], SCOPES[auth], client_secret=secret))
            break
        except oidc.Refused:
            again = _stored(ch)          # another process may have renewed it meanwhile (a provider that rotates refresh tokens)
            if retried or not again or again["refresh_token"] == stored["refresh_token"]:
                _refused(ch, prov, stored)
            stored, retried = again, True
    try:
        _store(ch, tokens.refresh_token or stored["refresh_token"], stored.get("account", ""))
    except Exception:
        quiet.ignored()
    return tokens.access_token


def renew_stale(now=None):
    """Renew every enabled channel's sign-in last renewed more than 7 days ago, so a quiet spell can't let one lapse; a failed
    renewal waits RETRY before the next try. Only names that are a channel's own (PREFIX + <channel id>) are looked at: a form's
    draft (PREFIX + <id>.form<n>) is never renewed. Never raises: it runs before a run's alerts."""
    from core import notify
    now = time.time() if now is None else now
    try:
        names = {n for n in passvault.names() if n.startswith(PREFIX)}
        orgs = [db.GLOBAL] + [r["id"] for r in db.org_rows()] if names else []
    except Exception:
        return
    done = set()
    for org in orgs:
        try:
            with db.within(org):
                chs = [c for c in notify.channels() if c.get("type") == "email" and c.get("enabled", True)
                       and needs_sign_in(c.get("auth")) and PREFIX + str(c.get("id")) in names and c["id"] not in done]
                for ch in chs:
                    done.add(ch["id"])
                    try:
                        _renew_one(ch, now, notify)
                    except Exception:
                        quiet.ignored()
        except Exception:
            quiet.ignored()


def _when(v):
    """A stored time; one that can't be read counts as never (so the sign-in is renewed, not stuck)."""
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _renew_one(ch, now, notify):
    got = _stored(ch)
    if not got or now - _when(got.get("renewed")) <= STALE or now - _when(got.get("tried")) < RETRY:
        return
    try:
        access_token(ch, notify.get_secrets(ch))
    except MailAuthError as e:
        if not e.gone:
            _note_try(ch, got["refresh_token"], now)
