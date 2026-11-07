# Sign-in part 4: SSO, the helper service, and directory admins approving — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sign in to Toner with any OpenID Connect provider (Entra first), let a copy accept mapped-group members without an approval through a system helper service that checks every sign-in itself, and let directory and SSO admins approve first sign-ins at the laptop.

**Architecture:** An SSO connection is one more entry in the signed `directories` list (kind `"oidc"`), so classification, group-to-role mapping, account records, PIN slots, approvals, re-checks and the offline rules all reuse the part 3 machinery. `core/oidc.py` does discovery, the browser flow (PKCE, loopback, nonce, fresh sign-in), token checks, refresh and Entra group lookups. The helper is a separate small program (`TonerHelper`, no Qt) running as LocalSystem / root. It keeps a spare copy of the data key and the rules key in a store only it can read, and releases them to the enrolled user's Toner only for a sign-in it checked itself. Toner then runs the existing `roles.approve`, with the helper as the approver.

**Tech Stack:** Python 3.13, PySide6, ldap3, `cryptography`, `requests`, PyJWT (new, needs the owner's approval), ctypes for the Windows service and named pipe, systemd on Linux, PyInstaller and Inno Setup.

**Spec:** `docs/superpowers/specs/2026-11-07-sign-in-part-4-design.md` (approved 2026-11-07), on top of `docs/superpowers/specs/2026-11-04-user-sign-in-design.md`. Code map: parts 1 to 3 and External Identities (`core/dirsignin.py`, `core/datakey.py`, `core/roles.py`, `core/dircheck.py`, `core/pinslot.py`, `ui/signinwindow.py`, `ui/identitywizard.py`, `ui/settings_pages/accounts.py`).

## Global Constraints

- Every user-facing string comes from "Wording to approve" below, verbatim. Anything not listed stops the task: report NEEDS_CONTEXT. Approved strings live as constants beside their code, as today (`core/dirsignin.py:18-31`, `ui/signinwindow.py:16-28`, `ui/settings_pages/accounts.py:19-23`), and tests assert them exactly.
- No secret in logs, the audit, exceptions, plain files or test output. That covers ID, access and refresh tokens, the client secret, the spare key, the rules private key, passwords, PINs, Duo keys and codes. Messages name the provider's host, never a token or URL query.
- **The helper never unpickles.** Its channel uses `multiprocessing.connection` `send_bytes`/`recv_bytes` with UTF-8 JSON only, each message at most 65,536 bytes. A bigger or non-JSON message closes the connection.
- **The helper's program and data are writable only by administrators/root.** Windows: `%ProgramFiles%\Toner Helper\` and `%ProgramData%\Toner Helper\` (ACL: SYSTEM and Administrators only). Linux: `/opt/toner-helper/` and `/var/lib/toner-helper/` (root, 0700/0600). The service never runs anything from the person's own Toner folder.
- The helper trusts connection settings only from the admin-signed rules in the enrolled copy's `netcheck.keys`, verified against the rules public key it pinned at enrollment. A mismatch means it refuses and reports `"rules_changed"`.
- SSO requests always carry `prompt=login`, `max_age=0`, PKCE S256, `state` and a `nonce`. An ID token is accepted only with an `auth_time` at most 300 s old (60 s clock leeway) and only `RS256`, `PS256` or `ES256`. Never `none` or HMAC.
- Providers are reached over https only. Tests use a flag, as `duo._TEST_ALLOW_HTTP` does (`oidc._TEST_ALLOW_HTTP`).
- macOS: nothing in this plan. There is no macOS app build yet (spec).
- One version for everything: the helper reports `core/version.py` `VERSION`, and `core/helper/protocol.py` `PROTOCOL = 1`.
- New dependency: **PyJWT** `>=2.10,<3`, only after the owner approves it with this plan. It is added to `requirements.txt` and to `requirements.lock` with hashes, and `tests/test_supply_chain.py` must still pass. No other new dependency (no pywin32, no msal, no authlib).
- Tests are standalone scripts ending `print(f"\n{ok} passed, {bad} failed")`, headless, copying the fakes in `tests/test_dirsignin.py:5-92` (keyring dict, osstore dict, `FakeTpm`, mock LDAP, local Duo server). They run on Windows and on WSL (`~/toner-venv/bin/python`).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never stage `.postman/`, `postman/`, `.impeccable/` or `.superpowers/`. No push.

## Review Focus

1. **A replaced helper program.** If the service's program path is in a folder the person can write to, anything running as them could become SYSTEM and read the spare key. Expect the service path and the copied files under the admin-only folders, and refuse to install from anywhere else. Pinned by Task 9's `test_helper_install` checks.
2. **A token meant for something else.** An ID token for another app ID, another issuer, an expired one, a reused or missing nonce, an old `auth_time`, `alg: none`, or HS256 signed with the public key: all refused, with no partial sign-in. Pinned by Task 1.
3. **The browser never comes back.** The person closes the tab, a second request hits the loopback port, `state` doesn't match, or the provider returns `error=access_denied`: Toner stops waiting, the port closes, and Cancel always works within a second. Pinned by Task 2.
4. **Another person on the same computer.** A helper client running as a different Windows/Linux user, or the same user with a different copy's `netcheck.keys`, gets nothing but `status`. Pinned by Tasks 8 and 9.
5. **Entra's group pointer.** Someone in more than about 200 groups gets `_claim_names` instead of `groups`. Toner and the helper fetch the list from Microsoft Graph, and refuse when Graph's `/me` isn't the same person (`id` ≠ the token's `oid`). Pinned by Tasks 2 and 8.

## Wording to approve

Approved by the owner with this plan; each line becomes a constant named as shown. `{provider}` is the connection's name as the admin typed it.

**Sign-in window (`ui/signinwindow.py`, `core/dirsignin.py`)**
- `SSO_TITLE`: "Continue in your browser"
- `SSO_TEXT`: "Sign in on the {provider} page that opened in your browser. Toner carries on when you're done."
- `SSO_AGAIN` (button): "Open the page again"
- `SSO_CANCELLED`: "The sign-in didn't finish in the browser."
- `SSO_NOT_FRESH`: "{provider} didn't confirm a fresh sign-in. Try again."
- `SSO_BAD_ANSWER`: "{provider}'s answer couldn't be checked, so the sign-in was refused."
- `SSO_UNREACHABLE`: "{provider} can't be reached, and this account hasn't been checked online in the last hour."
- `SSO_REFUSED` (re-check, lock screen): "{provider} no longer allows this account. Sign in again."
- `SSO_DONE_PAGE` (the browser tab after the redirect): "You're signed in. You can close this tab and go back to Toner."
- `APPROVE_WITH_ACCOUNT` (link on the approval page): "Approve with a directory account"
- `APPROVER_TITLE`: "Admin approval"
- `APPROVER_TEXT`: "An admin who has signed in on this computer before signs in with their own account, then types their Toner PIN."
- `NOT_HERE_BEFORE`: "That account hasn't signed in on this computer before, so it can't approve here."
- `HELPER_APPROVER` (approved-by name in the audit): "group membership"

**Accounts page (`ui/settings_pages/accounts.py`)**
- `SWITCH`: "Let group members sign in without approval"
- `SWITCH_TIP`: "Anyone in a mapped group can sign in on this computer for the first time without an admin."
- `WARN_TITLE`: "Let group members sign in without approval?"
- `WARN_TEXT`: "Toner's helper service will keep a spare copy of Toner's key on this computer, so anyone in a mapped group can sign in here for the first time without an admin. Programs running as you can't reach that copy, but an administrator of this computer can. Installing the helper service needs administrator rights. Turning this off deletes the spare copy."
- Buttons: "Turn on", "Cancel"
- `OFF_PORTABLE`: "A portable copy can't use this: it has no helper service."
- `OFF_OTHER_USER`: "Toner's helper service on this computer serves another user."
- `OFF_NOT_RUNNING`: "Toner's helper service is installed but not running."
- `OFF_OUTDATED`: "Toner's helper service is out of date. Turn this on again to update it."
- `OFF_RULES`: "Sign-in without approval was turned off because Toner's rules key was replaced. Turn it on again to use it."
- `INSTALL_FAILED`: "Toner's helper service couldn't be installed: {reason}"
- Accounts table, Type column: "SSO". 2FA column for SSO: "N/A".

**External Identities wizard (`ui/identitywizard.py`)**
- Type: "SSO (OpenID Connect)"
- Step titles (SSO): "Choose a type", "Provider", "Connection", "Who can sign in", "Roles"
- Providers: "Entra", "Okta", "Google Workspace", "Duo SSO", "Other"
- Fields: "Tenant ID" (Entra), "Issuer URL" (others), "App (client) ID", "Client secret (only if the provider requires one)", "Email domains", "Groups claim"
- `FOUND`: "Toner found {provider}'s sign-in settings."
- `NOT_FOUND`: "Toner couldn't read sign-in settings from {url}."
- `LIST_GROUPS` (button, Entra): "Sign in to list groups"
- `LIST_GROUPS_TEXT`: "Sign in with an Entra admin account. Toner uses it only to list and search groups, and keeps nothing but the groups you choose."
- `TYPE_GROUPS_TEXT` (other providers): "Type each group exactly as {provider} sends it, one per line."
- `EVERYONE` (Google, or no groups claim): "Role for everyone who signs in"
- Provider notes:
  - Entra: "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect URI http://localhost. Add the groups claim to its ID token, and grant GroupMember.Read.All with admin consent so Toner can list groups."
  - Okta: "In Okta, add an OIDC native app for Toner with the redirect URI http://localhost, and add a groups claim to its ID token."
  - Google Workspace: "In Google Cloud, create an OAuth client of type Desktop app for Toner. Google sends no groups, so everyone who signs in gets the role you choose under Roles."
  - Duo SSO: "In Duo, add a Generic OIDC Relying Party for Toner with the redirect URI http://localhost, and send the groups attribute in its ID token."
  - Other: "Register Toner as a native (desktop) app with the redirect URI http://localhost, and add the person's groups to its ID token."

**Audit entries** (action / detail)
- "sign-in without approval turned on" / "by {admin}"
- "sign-in without approval turned off" / "by {admin}", or "the rules key was replaced"
- "sign-in approved" / "{name}, approved by group membership" (existing action, the new approver name)

## File structure

- Create `core/oidc.py`: discovery, the browser flow, token checks, refresh, Entra groups. It has no Qt and no DB, because the helper imports it.
- Create `core/ssopresets.py`: the five provider presets and their notes.
- Modify `core/directory.py`, `core/roles.py`: kind `"oidc"` and its allowed keys; `role_for` with `everyone`.
- Modify `core/dirsignin.py`: the SSO stages, approval with a directory account, and the helper paths.
- Modify `core/dircheck.py`: SSO re-check through the refresh token.
- Modify `core/duo.py`: an optional `skey` argument, so the helper can call Duo.
- Modify `core/datakey.py`: `open_with_keys`. Modify `core/roles.py`: `hold`, the pending backups grants, and auto-off on rekey.
- Create `core/helper/__init__.py`, `protocol.py`, `store.py`, `server.py`, `windows.py`, `linux.py`; `packaging/toner_helper.py` (entry); `core/helperclient.py`.
- Modify `ui/signinwindow.py`, `ui/lockscreen.py`, `ui/identitywizard.py`, `ui/directorydlg.py` (`KINDS`), `ui/settings_pages/accounts.py`, `ui/testlogindlg.py`.
- Modify `packaging/build.ps1`, `packaging/build_linux.sh`, `packaging/toner.iss`, `requirements.txt`, `requirements.lock`, `README.md`.
- Tests: create `tests/fake_oidc.py` (a shared pretend provider: a local http.server with RSA and EC keys, issuing tokens on demand), and `tests/test_oidc.py`, `test_sso_config.py`, `test_sso_signin.py`, `test_sso_signin_ui.py`, `test_sso_recheck.py`, `test_sso_wizard.py`, `test_approve_with_account.py`, `test_helper_server.py`, `test_helper_platform.py`, `test_helper_client.py`, `test_helper_switch_ui.py`.

---

### Task 1: Discovery and ID-token checks

**Files:** Create `core/oidc.py` (first half), `tests/fake_oidc.py`, `tests/test_oidc.py`. Modify `requirements.txt`, `requirements.lock`.

**Interfaces — Produces:**
- Exceptions: `OidcError(Exception)`; `Unreachable(OidcError)`; `Refused(OidcError)`; `NotFresh(OidcError)`; `BadAnswer(OidcError)`; `Cancelled(OidcError)`. Messages carry the host only.
- `discover(issuer: str, timeout: float = 10) -> dict`: GETs `<issuer>/.well-known/openid-configuration`. Caches per issuer for 3600 s, and refuses (BadAnswer) when the document's `issuer` ≠ `issuer` or an endpoint isn't https. Network errors raise Unreachable.
- `keys(meta: dict, kid: str) -> jwt.PyJWK`: from `meta["jwks_uri"]`, cached. An unknown `kid` refetches once, then raises BadAnswer.
- `verify_id_token(cfg: dict, token: str, nonce: str | None, max_age: int | None = 300, now: float | None = None) -> dict`: returns the claims. Checks the algorithm against `ALGS = ("RS256", "PS256", "ES256")`; `iss == discover(cfg["issuer"])["issuer"]`; `aud` contains `cfg["client_id"]` (and `azp == client_id` when `aud` has several); `exp`/`iat` with `LEEWAY = 60`; `nonce` (when not None); `auth_time` within `max_age` (when not None, and required then). Failures raise BadAnswer, except a stale `auth_time`, which raises NotFresh.

- [ ] **Step 0:** Install PyJWT only after the owner's approval of this plan is recorded. Run `pip install "PyJWT>=2.10,<3"` (Windows) and `~/toner-venv/bin/pip install "PyJWT>=2.10,<3"` (WSL). Add it to `requirements.txt`, and add a hash-pinned line to `requirements.lock` the same way the other entries are made. Run `python tests/test_supply_chain.py`: 0 failed.
- [ ] **Step 1:** In `tests/fake_oidc.py`, write `class FakeProvider` with:
  - `start() -> issuer` (http://127.0.0.1:port);
  - `token(**claims) -> str`, signed by its RS256 key, with defaults `iss`, `aud="toner-app"`, `exp=now+600`, `iat=now`, `auth_time=now`, `sub`, `oid`, `preferred_username`, `groups`;
  - `token_es256(**claims)`;
  - `rotate()`, which serves a new key with a new `kid`;
  - a token endpoint and an authorize endpoint for Task 2;
  - `stop()`.
- [ ] **Step 2:** In `tests/test_oidc.py`, write checks with `oidc._TEST_ALLOW_HTTP = True`:
  - `verify_id_token` accepts a good RS256 token and a good ES256 token, and returns `sub`.
  - It refuses (BadAnswer):
    - another `aud`;
    - another `iss`;
    - an expired token (`exp=now-120`);
    - `iat` in the future by 120 s;
    - the wrong nonce, or a missing nonce when one is asked for;
    - `alg none` (a hand-built token);
    - HS256 signed with the PEM of the public key;
    - a tampered payload;
    - an unknown `kid` after one refetch.
  - `auth_time=now-400` raises NotFresh, and a missing `auth_time` raises NotFresh when `max_age=300`.
  - After `rotate()`, a token with the new kid passes (refetched once).
  - The discovery document's `issuer` ≠ the asked issuer raises BadAnswer.
  - A stopped provider raises Unreachable.
  - No exception text contains the token or `?`.
- [ ] **Step 3:** Run `python tests/test_oidc.py`. Expected: FAIL (no `core.oidc`).
- [ ] **Step 4:** Implement the interfaces above with `requests` (the same session and proxy handling as `core/duo.py`) and `jwt.decode(token, key, algorithms=[alg], audience=..., issuer=..., leeway=LEEWAY, options={"require": ["exp", "iat", "iss", "aud"]})`. Check `nonce` and `auth_time` yourself after the decode.
- [ ] **Step 5:** Run it on Windows and WSL. Expected: all pass. pyflakes clean.
- [ ] **Step 6:** Commit with the message "oidc: discovery and ID-token checks".

### Task 2: The browser flow, refresh and Entra groups

**Files:** Modify `core/oidc.py` (second half), `tests/fake_oidc.py`, `tests/test_oidc.py`.

**Interfaces — Consumes:** Task 1. **Produces:**
- `@dataclass Tokens(id_token: str, access_token: str, refresh_token: str | None, claims: dict)`.
- `class BrowserSignIn(cfg: dict, nonce: str | None = None, open_url=webbrowser.open, login_hint: str | None = None, scopes: str = "openid profile email offline_access")`:
  - `.nonce` is the given nonce or a fresh `secrets.token_urlsafe(32)`;
  - `.url` is the authorize URL with `response_type=code`, `client_id`, `redirect_uri=http://127.0.0.1:<port>/`, `scope`, `state`, `nonce`, `code_challenge` (S256), `prompt=login`, `max_age=0` and `login_hint`;
  - `.open()` calls `open_url(self.url)`;
  - `.run(cancel: threading.Event, timeout: float = 300) -> Tokens` waits for exactly one redirect, answers it with `SSO_DONE_PAGE`, then closes the port. It exchanges the code (with `client_secret` from `osstore.get(f"oidc:{cfg['id']}")` when one is stored), verifies the ID token with `.nonce` and `max_age=300`, and returns the Tokens.
  - `error=` in the redirect raises Refused. A `state` mismatch raises BadAnswer. Cancel or the timeout raises Cancelled.
  - It listens on `127.0.0.1` only, on a random port.
- `refresh(cfg: dict, refresh_token: str) -> Tokens`: the refresh grant. `invalid_grant` raises Refused, network errors raise Unreachable. The new ID token is verified with `nonce=None, max_age=None`, and `claims` is `{}` when the provider sends none.
- `groups(cfg: dict, claims: dict, access_token: str) -> tuple[str, ...]`:
  - the value at `cfg["groups_claim"]`, or `()` when there's no claim name;
  - when `"_claim_names"` has the claim name (Entra's pointer): GET `GRAPH + "/me"` and require `id == claims["oid"]` (else BadAnswer), then POST `GRAPH + "/me/getMemberObjects"` `{"securityEnabledOnly": false}`. `GRAPH = "https://graph.microsoft.com/v1.0"`; tests replace it.
- `user_from(cfg: dict, claims: dict, groups: tuple) -> directory.User`, with:
  - `guid = claims[cfg.get("id_claim", "sub")]`;
  - `name = (claims.get("preferred_username") or claims.get("email") or claims["sub"]).lower()`;
  - `display = claims.get("name") or name`;
  - `enabled = True`.
- `search_groups(access_token: str, text: str, cap: int = 200) -> list[tuple[str, str]]`: Entra Graph `/groups` with `$search="displayName:<text>"`, `ConsistencyLevel: eventual` and `$select=id,displayName`. An empty text gives the first page. Results are `(id, name)`.

- [ ] **Step 1:** Extend `FakeProvider`:
  - the authorize endpoint redirects to `redirect_uri` with a code and the same `state`, checks `code_challenge` against the verifier at the token endpoint, and records `prompt`/`max_age`;
  - the token endpoint returns the tokens, or `invalid_grant` for a revoked refresh token;
  - a fake Graph server for `/me`, `/me/getMemberObjects` and `/groups`.
- [ ] **Step 2:** Tests:
  - The full flow, with `open_url` doing a `requests.get` of the URL in a thread, returns Tokens. The provider saw `prompt=login` and `max_age=0`, and the PKCE check passed.
  - A redirect with the wrong `state` raises BadAnswer. `error=access_denied` raises Refused.
  - Setting the cancel event raises Cancelled within 1.5 s and frees the port (binding the same port succeeds).
  - A second request to the port after the first gets nothing.
  - `refresh` returns new tokens; a revoked token raises Refused.
  - `groups()` with `groups` in the claims returns them. With `_claim_names` it calls Graph; when Graph `/me` has a different `id` it raises BadAnswer.
  - `user_from` with `id_claim="oid"` uses `oid`.
  - `search_groups` passes `$search` and the ConsistencyLevel header.
- [ ] **Step 3:** Run the tests. Expected: FAIL.
- [ ] **Step 4:** Implement. The loopback server is a `http.server.HTTPServer` handling one request in a daemon thread. `.run` polls the cancel event every 0.1 s.
- [ ] **Step 5:** Run the tests on Windows and WSL. Expected: pass.
- [ ] **Step 6:** Commit with the message "oidc: browser sign-in with PKCE and a fresh sign-in, refresh, Entra groups".

### Task 3: SSO connections in the signed directories list

**Files:** Create `core/ssopresets.py`, `tests/test_sso_config.py`. Modify `core/directory.py` (`check_config` :36-45, `role_for` :293), `core/roles.py` (`_DIRECTORY` :37-39), `core/dirsignin.py` (`classify` :86), `ui/directorydlg.py:13` (`KINDS`), `ui/settings_pages/accounts.py:208-209`.

**Interfaces — Produces:**
- An SSO cfg (kind `"oidc"`) has these keys: `id, name, kind, provider, issuer, client_id, groups_claim, id_claim, suffixes, groups, group_names, everyone`. `provider` is one of `entra|okta|google|duo|other`, `group_names` is `{id: display name}`, and `everyone` is a role or None. Add the new keys to `roles._DIRECTORY`.
- `directory.check_config(cfg)` for `"oidc"`:
  - require `https://` in `issuer` (unless `oidc._TEST_ALLOW_HTTP`), a non-empty `client_id`, and at least one `suffixes` entry;
  - `servers` isn't required;
  - AD/LDAP rules are unchanged.
- `directory.role_for(cfg, groups, dn="")`: unchanged for AD/LDAP. When no group matches and `cfg.get("everyone") in ROLE_ORDER`, it returns `everyone`.
- `ssopresets.PRESETS: dict[str, dict]`, keyed `entra, okta, google, duo, other`, each with `label`, `field` ("Tenant ID" or "Issuer URL"), `groups_claim` (None for google), `id_claim` ("oid" for entra, else "sub"), `lists_groups` (True for entra only) and `note` (approved wording).
- `ssopresets.issuer_for(provider: str, value: str) -> str`: Entra gives `https://login.microsoftonline.com/<tenant>/v2.0`; the others return the value stripped of a trailing "/".
- `dirsignin.classify` matches an SSO cfg by email domain in `suffixes`, the same rule as UPN suffixes. Returns `("directory", cfg, login)`.
- `directorydlg.KINDS` gains `("SSO (OpenID Connect)", "oidc")`. The Accounts table shows Type "SSO" and 2FA "N/A" for kind oidc, and the right-click "Set up 2FA..." is hidden for it.

- [ ] **Step 1:** Tests:
  - `roles.set_directories` accepts an Entra cfg and refuses an `http://` issuer and an unknown key.
  - `classify("sam@acme.com")` picks the SSO cfg with suffix `acme.com`; a local account named `sam@acme.com` still wins.
  - `role_for` with `everyone="Tech"` and no groups returns "Tech"; without `everyone` it returns None.
  - `issuer_for("entra", "contoso-tenant-id")` gives `https://login.microsoftonline.com/contoso-tenant-id/v2.0`.
  - Every preset `note` equals its approved text.
  - The Accounts page shows "SSO" / "N/A" for an SSO row, and its menu has no "Set up 2FA...".
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the new file plus `test_directory.py`, `test_roles.py`, `test_dirsignin.py`, `test_identitywizard.py`, `test_accounts_page.py`. Expected: all pass.
- [ ] **Step 5:** Commit with the message "SSO connections: kind oidc in the signed directories, presets, classify by email domain".

### Task 4: SSO in the sign-in state machine and the sign-in window

**Files:** Modify `core/dirsignin.py`, `core/session.py` (only if a hook is needed), `ui/signinwindow.py`, `ui/lockscreen.py`. Test: `tests/test_sso_signin.py`, `tests/test_sso_signin_ui.py`.

**Interfaces — Consumes:** Tasks 1 to 3. **Produces:**
- `Attempt` gains `browser: oidc.BrowserSignIn | None` and `tokens: oidc.Tokens | None`, plus the new stage `"browser"`.
- `dirsignin.sso_start(cfg: dict, login: str, open_url=webbrowser.open, nonce: str | None = None) -> Attempt`: goes through `_tries()`, builds `a.browser`, calls `a.browser.open()`, and sets `stage = "browser"`.
- `dirsignin.sso_wait(a: Attempt, cancel: threading.Event) -> None`:
  1. runs `a.browser.run`, then `groups`, `user_from` and `role_for`;
  2. sets `a.user, a.name, a.role, a.tokens`;
  3. no role raises NotInGroup;
  4. `oidc.Unreachable` goes to `_offline(a)` exactly as `begin` does;
  5. Refused, BadAnswer, NotFresh and Cancelled count a failure on the shared throttle and re-raise;
  6. then `_onward(a, "sso")`.
- In `finish(a, pin)`, after `session.sign_in_pin` succeeds and when `a.tokens and a.tokens.refresh_token`: `passvault.put(f"sso-refresh:{a.name}", a.tokens.refresh_token)`.
- `dirsignin.reachable(cfg) -> bool`: `directory.reachable` for AD/LDAP, and `oidc.discover` succeeding for oidc. The lock screen's session-over check (`ui/lockscreen.py:236-270`) uses it.
- SignInWindow: after `classify` returns an oidc cfg, `_next` skips the password page and goes to a new `sso_page`:
  - it shows `SSO_TITLE`/`SSO_TEXT`, the `SSO_AGAIN` button (calls `a.browser.open()`) and Cancel;
  - a Job runs `sso_wait`, then `_route()` as today;
  - `_fail` maps Cancelled to `SSO_CANCELLED`, NotFresh to `SSO_NOT_FRESH`, BadAnswer/Refused to `SSO_BAD_ANSWER`, and Unreachable without the offline route to `SSO_UNREACHABLE`;
  - `{provider}` is `cfg["name"]`.

- [ ] **Step 1:** Core tests, with FakeProvider and `open_url` fetching the URL in a thread:
  - A first sign-in reaches stage "choose-pin". `choose_pin` then gives "approve" with `FIRST`, as for AD.
  - After a local Admin approves (the existing `approve`), `finish` gives "done", the session is open, and `passvault.get("sso-refresh:<name>")` holds the refresh token.
  - The next sign-in goes straight to "pin".
  - Someone not in a mapped group raises NotInGroup.
  - A stopped provider with `online_at` 30 minutes ago goes to the PIN-only offline route; with 2 hours ago it raises Unreachable.
  - A Cancelled attempt counts one failure.
  - The audit and log contain no token: search the audit table and the log handler for the token strings.
- [ ] **Step 2:** UI tests:
  - Typing `sam@acme.com` shows `sso_page` with the approved title and text.
  - Cancel shows `SSO_CANCELLED`.
  - A completed browser flow lands on the choose-PIN page.
  - The lock screen with `session_over()` and the provider reachable asks for a full sign-in.
- [ ] **Step 3:** Run the tests. Expected: FAIL.
- [ ] **Step 4:** Implement.
- [ ] **Step 5:** Run the new files plus `test_dirsignin.py`, `test_signin_directory_ui.py`, `test_lock_directory.py`, `test_session.py`. Expected: pass on Windows and WSL.
- [ ] **Step 6:** Commit with the message "SSO sign-in: browser step, PIN, offline hour, refresh token kept in the vault".

### Task 5: SSO background re-check

**Files:** Modify `core/dircheck.py`. Test: `tests/test_sso_recheck.py`.

**Interfaces — Produces:** in `dircheck.run_once()`, when the signed cfg's `kind == "oidc"`:
1. it reads `rt = passvault.get(f"sso-refresh:{name}")`; with no `rt` it returns `"skipped"`;
2. it calls `oidc.refresh(cfg, rt)` and stores the new refresh token when one is sent;
3. it takes groups from `oidc.groups(cfg, tokens.claims, tokens.access_token)`, using the account's last `groups_role` when `claims` is empty;
4. `role_for` then works as for AD;
5. Refused locks with `reason="refused"` and the audit entry "locked: the directory refused the account" (existing);
6. Unreachable/OidcError return `"offline"` and never lock.

The lock screen shows `SSO_REFUSED` for a refused SSO account.

- [ ] **Step 1:** Tests:
  - A refresh that's fine returns "ok" and rotates the stored refresh token.
  - A revoked token returns "refused", the session is locked, and the lock screen text is `SSO_REFUSED`.
  - Groups that now map to no role return "refused".
  - A group change to Engineer calls `roles.groups_changed()`.
  - A provider that's down returns "offline", unlocked.
  - With no stored refresh token it returns "skipped".
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests plus `test_dircheck.py`. Expected: pass.
- [ ] **Step 5:** Commit with the message "dircheck: SSO accounts re-checked through the refresh token".

### Task 6: SSO in the External Identities wizard, and Test login

**Files:** Modify `ui/identitywizard.py`, `ui/testlogindlg.py`, `core/dirsignin.py` (`TestLogin`). Test: `tests/test_sso_wizard.py`.

**Interfaces — Consumes:** Tasks 1 to 3. **Produces:** when "SSO (OpenID Connect)" is chosen, the wizard's five steps become:
1. **Choose a type.**
2. **Provider:** radio buttons for the five presets, and the preset's note in a word-wrapped label.
3. **Connection:**
   - `field` (Tenant ID or Issuer URL), "App (client) ID", "Client secret (only if the provider requires one)", "Email domains" (comma-separated, becoming `suffixes`), and "Groups claim" (pre-filled from the preset, editable);
   - Next runs `oidc.discover(issuer_for(...))` on a Job and shows `FOUND` or `NOT_FOUND`;
   - a client secret goes to `osstore.put(f"oidc:{id}", ...)` on Save.
4. **Who can sign in:**
   - **Entra:** the `LIST_GROUPS` button runs a `BrowserSignIn` with `scopes="openid profile GroupMember.Read.All"` (nonce checked, `prompt=login`), keeps the access token in memory only, and fills the existing Groups list through `oidc.search_groups`. The filter box searches through Graph after the existing 400 ms pause. The OUs column is hidden.
   - **Others:** a plain-text box with `TYPE_GROUPS_TEXT`, one group per line.
   - **No groups claim (Google):** this step shows only the `EVERYONE` role box.
5. **Roles:** the existing role-per-group boxes, showing `group_names` for Entra IDs. Saving writes `groups`, `group_names` and `everyone`.

Edit reopens with the saved values. Right-click Test login on an SSO row runs the browser flow once and shows the existing Test login result (groups found, and the role), keeping nothing. `TestLogin` gains `check_sso(open_url, cancel)`.

- [ ] **Step 1:** Tests, with FakeProvider plus fake Graph:
  - The Entra path goes Provider, Connection (`FOUND`), Sign in to list groups, search "Net" (Graph saw `$search`), tick one group, Roles Admin, Save. `roles.verified()["directories"]` then has `kind "oidc"`, the issuer from `issuer_for`, `groups {"Admin": [id]}` and `group_names {id: "Network Admins"}`.
  - The Okta path with typed groups saves them.
  - The Google path saves `everyone` and no groups.
  - A bad issuer shows `NOT_FOUND` and stays on the step.
  - No access token is written anywhere (search the keys file, DB settings and osstore fake).
  - Test login on the SSO row shows the role.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests plus `test_identitywizard.py`, `test_testlogin.py`, `test_testlogindlg.py`. Expected: pass.
- [ ] **Step 5:** Commit with the message "External Identities: SSO connections (Entra group search, typed groups, a role for everyone), SSO Test login".

### Task 7: Directory and SSO admins approve at the laptop

**Files:** Modify `core/dirsignin.py` (`_approve` :392, new function), `ui/signinwindow.py` (approval page :~ approve_page). Test: `tests/test_approve_with_account.py`.

**Interfaces — Produces:**
- `dirsignin.approve_with_account(a: Attempt, approver: Attempt, pin: str) -> None`. The approver must meet all of these, else `CannotApprove`:
  - `approver.stage == "pin"` and `approver.fresh`;
  - `approver.name != a.name`;
  - `datakey.directory_account(approver.name)["sealed"]` is set, else `NOT_HERE_BEFORE`;
  - `approver.role == "Admin"` from this sign-in's live groups, else `CANNOT_APPROVE`.

  It then calls `_approve(a, lambda: datakey.open_with_pin(approver.name, pin))`. A wrong PIN raises `pinslot.WrongPin` as at unlock. The audit's approved-by is `approver.name`.
- SignInWindow: the approval page gains the link `APPROVE_WITH_ACCOUNT`, which opens a nested `SignInWindow(approver_for=a)`:
  - It shows `APPROVER_TITLE`/`APPROVER_TEXT` on its name page.
  - It runs the approver's own sign-in (password and Duo, or SSO), stopping at its PIN page.
  - On the PIN it calls `approve_with_account(a, approver, pin)` and closes. The outer window then routes `a`.
  - It never opens a session for the approver.

- [ ] **Step 1:** Tests:
  - An AD Admin who has signed in before (sealed record) approves a new AD tech: the tech's record is sealed, the audit says "approved by <admin>", and the session is unchanged (still signed out).
  - An SSO Admin approves the same way.
  - An Admin with no record here gets `NOT_HERE_BEFORE`.
  - An Engineer gets `CANNOT_APPROVE`.
  - An Admin whose groups no longer map to Admin, though the stored role is Admin, gets `CANNOT_APPROVE`.
  - A wrong PIN counts on the throttle and approves nothing.
  - UI: the link opens the nested window with the approved title and text.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests plus `test_dirsignin.py`, `test_signin_directory_ui.py`, `test_roles.py`. Expected: pass.
- [ ] **Step 5:** Commit with the message "Approvals: a directory or SSO Admin who has signed in here before approves with their own sign-in and PIN".

### Task 8: The helper's core (protocol, store, checks)

**Files:** Create `core/helper/__init__.py`, `core/helper/protocol.py`, `core/helper/store.py`, `core/helper/server.py`. Modify `core/duo.py` (an optional `skey`). Test: `tests/test_helper_server.py`.

**Interfaces — Produces:**
- `protocol.PROTOCOL = 1`, `protocol.MAX = 65536`, `protocol.encode(obj) -> bytes`, `protocol.decode(b) -> dict` (ValueError on bad JSON, a non-dict, or size > MAX). Requests are `{"op": str, "v": PROTOCOL, ...}`. Answers are `{"ok": bool, "error": code}` plus fields, where the error codes are `not_owner, not_enrolled, rules_changed, refused, not_fresh, bad_answer, unreachable, not_in_group, throttled, bad_request, other_user`.
- `store.Store(path: Path, protect: Callable[[bytes], bytes], unprotect: Callable[[bytes], bytes])`:
  - `.load() -> dict | None` and `.save(rec: dict)`, written atomically;
  - `.clear()`.
  - The record is `{owner, keys_path, rules_pub (b64), spare (protected b64 of data_key‖rules_private), duo {conn_id: skey b64, protected}, enrolled_at}`.
- `server.Helper(store: Store, now=time.time)` with `.handle(req: dict, peer: str) -> dict`. `peer` is the caller's SID or uid as a string. Its ops:
  - `status {keys_path}` returns `{protocol, version, enrolled, owner: peer == owner and keys_path == pinned path, rules_changed}`.
  - `enroll {keys_path, data_key, rules_private, duo}` loads `netcheck.keys` at `keys_path`. It requires the rules private key's public half == `doc["rules_pub"]` and `roles`-style signature verification of the signed part to pass. It refuses `other_user` when it's already enrolled by another peer. It saves the record and pins `rules_pub`, `owner = peer`.
  - `forget {keys_path}` (owner only) clears the store.
  - `nonce {keys_path, connection}` (owner) returns a random 32-byte url-safe nonce, kept 600 s and single use.
  - `check_sso {keys_path, connection, id_token, access_token}` (owner):
    1. reads the cfg from the verified signed rules (refusing `rules_changed` when the file's `rules_pub` ≠ the pinned one or the signature fails);
    2. calls `oidc.verify_id_token(cfg, id_token, nonce=<an issued, unused nonce>, max_age=300)`, then `oidc.groups` and `directory.role_for`;
    3. answers `{name, role, guid, display, ticket}`, where the ticket is 600 s and single use, bound to name and role.
  - `check_directory {keys_path, connection, login, password}` (owner): `directory.sign_in(cfg, login, password)` then `role_for`. Every answer carries `{name, role, guid, display}`. With Duo off it adds a ticket. With Duo on it calls `duo.preauth(cfg, user, skey=...)`: `auth` adds `{duo: "auth", pending}`, `allow` adds a ticket, and deny/enroll give `refused`.
  - `duo_push {pending}` and `duo_code {pending, code}` (owner) answer with a ticket on success. The push uses `duo.push(cfg, user, cancel, skey=...)`, cancelled when the client disconnects.
  - `release {keys_path, ticket, name}` (owner) checks the ticket and returns `{data_key, rules_private}` (b64).
  - Failures count per peer: 5 free, then a wait doubling from 30 s to 15 min. Throttled requests get `throttled` with `wait`.
  - Every op except `status` and `enroll` requires `owner`.
- `duo.preauth/push/passcode(..., skey: bytes | None = None)` use `skey` instead of `osstore.get(f"duo:{id}")` when given.

- [ ] **Step 1:** Tests: a temp `netcheck.keys` made the part 3 way (`datakey.create`, `roles.set_directories` with an AD cfg with Duo, and an oidc cfg on FakeProvider), mock LDAP, the Duo fake, `Helper` with an identity protect function. Check:
  - Enrolling with the right rules key works; with a different Ed25519 key it's refused.
  - `status` from another peer has `owner False`. `forget`, `nonce` and `release` from another peer give `not_owner`, and `enroll` from another peer while enrolled gives `other_user`.
  - `check_sso`:
    - a good token with an issued nonce gives a ticket;
    - the same nonce twice gives `bad_answer`;
    - a nonce the helper never issued gives `bad_answer`;
    - `auth_time` 400 s old gives `not_fresh`;
    - a group not mapped gives `not_in_group`.
  - Editing the keys file's directories (adding a group mapping) without re-signing gives `rules_changed` and releases nothing.
  - Replacing `rules_pub` with a new signed set gives `rules_changed`.
  - `check_directory`: the right password with Duo push allowed gives a ticket; a wrong password gives `refused` and counts; six failures give `throttled`.
  - `release` with a valid ticket returns the data key and rules key, which equal the enrolled ones; the same ticket twice gives `refused`; a ticket for another name gives `refused`; an expired ticket (`now` + 601) gives `refused`.
  - `decode` of 70,000 bytes or of `pickle.dumps(...)` raises ValueError.
  - No answer or log line contains a password, token or key.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Rules verification reuses `envelope.verify` and `roles._signed` on the loaded doc. Don't import Qt or `core.db` (assert in the test that `PySide6` and `core.db` aren't in `sys.modules` after importing `core.helper.server` in a subprocess).
- [ ] **Step 4:** Run the tests plus `test_duo.py`. Expected: pass on Windows and WSL.
- [ ] **Step 5:** Commit with the message "helper: protocol, store and the checks it makes itself".

### Task 9: The helper on Windows and Linux, and packaging

**Files:** Create `core/helper/windows.py`, `core/helper/linux.py`, `packaging/toner_helper.py`. Modify `packaging/build.ps1`, `packaging/build_linux.sh`, `packaging/toner.iss`. Test: `tests/test_helper_platform.py`.

**Interfaces — Consumes:** Task 8. **Produces:**
- `ADDRESS`: Windows `r"\\.\pipe\TonerHelper"`; Linux `"/run/toner-helper/helper.sock"`.
- `serve(helper: server.Helper, stop: threading.Event)` accepts connections with `multiprocessing.connection.Listener(ADDRESS)` (authkey None). It runs one thread per connection, works out the peer, and loops `recv_bytes(protocol.MAX)` → `decode` → `helper.handle` → `send_bytes(encode(...))`.
- `peer_of(conn) -> str`:
  - **Windows:** `GetNamedPipeClientProcessId` on `conn.fileno()`, then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `OpenProcessToken`, `GetTokenInformation(TokenUser)` and `ConvertSidToStringSidW`.
  - **Linux:** `SO_PEERCRED` uid as a string.
- `protect`/`unprotect`:
  - **Windows:** `CryptProtectData`/`CryptUnprotectData` (`passvault.dpapi_protect`'s ctypes), running as LocalSystem.
  - **Linux:** identity. The file is root 0600 in a 0700 folder.
- `STORE_PATH`: Windows `%ProgramData%\Toner Helper\helper.json`; Linux `/var/lib/toner-helper/helper.json`.
- **The Windows service:** `run_service()` implements the SCM handshake with ctypes (`StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`; stop on `SERVICE_CONTROL_STOP`/`SHUTDOWN`).
- `install_plan(src_dir: Path) -> list[list[str]]` and `install(src_dir: Path)`. These run only elevated, from `packaging/toner_helper.py --install`.
  - **Windows:**
    1. stop and delete any existing `TonerHelper` service;
    2. copy `src_dir` to `%ProgramFiles%\Toner Helper\`;
    3. `icacls` both helper folders to `SYSTEM:(OI)(CI)F` and `Administrators:(OI)(CI)F` with inheritance removed;
    4. `sc.exe create TonerHelper binPath= "<ProgramFiles>\Toner Helper\TonerHelper.exe --service" start= auto obj= LocalSystem DisplayName= "Toner helper"`;
    5. `sc.exe failure TonerHelper reset= 86400 actions= restart/5000`;
    6. `sc.exe start TonerHelper`.
  - **Linux:**
    1. copy to `/opt/toner-helper/` (root, 0755);
    2. write `/etc/systemd/system/toner-helper.service` with `ExecStart=/opt/toner-helper/toner-helper --service`, `User=root`, `RuntimeDirectory=toner-helper`, `RuntimeDirectoryMode=0755`, `StateDirectory=toner-helper`, `StateDirectoryMode=0700`;
    3. `systemctl daemon-reload` and `systemctl enable --now toner-helper`.
  - **Both:** refuse unless running elevated, and refuse a destination inside the invoking user's profile.
  - The socket is created with mode 0666. Identity is checked through `SO_PEERCRED`, never the file mode.
- `uninstall()` (`--uninstall`) does the reverse and deletes the store.
- `packaging/toner_helper.py` handles `--service` (Windows SCM or the Linux foreground loop), `--install`, `--uninstall` and `--version`.
- **Builds:**
  - **`build.ps1`:** a third PyInstaller `--onedir --console` build named `TonerHelper` from `packaging/toner_helper.py`, with `--exclude-module PySide6`, copied to `build/dist/Toner/TonerHelper/`.
  - **`build_linux.sh`:** the same, as `toner-helper`, inside the AppDir under `usr/lib/toner-helper/`.
  - **`toner.iss`:** an `[UninstallRun]` that runs `{app}\TonerHelper\TonerHelper.exe --uninstall` with `Flags: shellexec runhidden`, `Verb: runas`, only when the service exists (a `Check:` function querying `sc query TonerHelper`).

- [ ] **Step 1:** Tests that run without admin rights:
  - **Windows only:** `serve` in a thread on a test pipe name. A client in the same process sends `status`, and `peer_of` equals the current user's SID (compared with `whoami /user`).
  - **Linux only:** the same over a temp socket path, where `peer_of` equals `str(os.getuid())`.
  - **Both:**
    - a 70,000-byte message closes the connection, and the server keeps serving;
    - a pickled object as bytes gets `bad_request`;
    - `install_plan(Path(r"C:\x\TonerHelper"))` (or the Linux path) contains the exact `sc.exe create` / unit text, and its service path starts with `%ProgramFiles%` (or `/opt/toner-helper/`);
    - `install` refuses a destination under the user profile, and refuses when not elevated (mocked check);
    - the generated unit file text has `User=root` and `StateDirectoryMode=0700`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests on Windows and WSL. Then run `powershell -File packaging/build.ps1` and `bash packaging/build_linux.sh`, which must produce `TonerHelper.exe` / `toner-helper` beside Toner. Run `TonerHelper.exe --version`, which prints the VERSION. Don't run `--install` in the session: the owner does that in the live check.
- [ ] **Step 5:** Commit with the message "helper: Windows service and Linux systemd unit, local channel with peer identity, admin-only install, builds".

### Task 10: Toner's helper client and the switch

**Files:** Create `core/helperclient.py`. Modify `ui/settings_pages/accounts.py`, `core/roles.py` (`_written` :594), `ui/twofadlg.py`, `core/updates.py` (`installed_kind` is only read). Test: `tests/test_helper_client.py`, `tests/test_helper_switch_ui.py`.

**Interfaces — Consumes:** Tasks 8 and 9. **Produces:**
- `helperclient.ADDRESS` (the same values as Task 9) and `helperclient.call(req: dict, timeout: float = 10) -> dict`, which raises `NotRunning` when it can't connect. Tests replace `_connect`.
- `helperclient.installed() -> bool`: Windows `sc query TonerHelper`; Linux `systemctl is-enabled toner-helper`.
- `helperclient.state(keys_path) -> str`, one of:
  - `"portable"` (when `updates.installed_kind() == "portable"`);
  - `"absent"`;
  - `"not_running"`;
  - `"outdated"` (protocol ≠ `PROTOCOL`);
  - `"other_user"` (enrolled, `owner False`);
  - `"rules_changed"`;
  - `"off"` (installed and running, not enrolled);
  - `"on"`.
- `helperclient.install_elevated(timeout=120) -> None`: Windows `ShellExecuteExW` with `runas` on `<app>\TonerHelper\TonerHelper.exe --install`, waiting; Linux `pkexec <AppDir>/usr/lib/toner-helper/toner-helper --install`. Raises `InstallFailed(reason)`. Afterwards it waits up to 15 s for `status`.
- `helperclient.enroll()` is called in an Admin session. It sends:
  - `data_key = datakey._key`;
  - `rules_private = roles._held["rules"]` raw bytes;
  - `duo = {id: osstore.get(f"duo:{id}")}` for every directory with Duo on;
  - `keys_path = datakey.path()`.
- `helperclient.forget()`.
- Accounts page:
  - the `SWITCH` checkbox under Session length, Admin only;
  - `load()` sets it from `state()`. For `portable`, `other_user` and `not_running` it's disabled with its `OFF_*` text as a note below. `outdated` and `rules_changed` show their notes and leave it enabled and unchecked.
  - **Ticking it:** the `WARN_TITLE`/`WARN_TEXT` box with "Turn on"/"Cancel". Then, when needed, `install_elevated()` (on InstallFailed, `INSTALL_FAILED` and unticked), then `enroll()` and the audit entry "sign-in without approval turned on".
  - **Unticking it:** `forget()` and the audit entry "turned off".
  - These act at once, through their own confirmation, and aren't a pending Save change (the same pattern as `test_extvault.py:503`).
- `roles._written(pub)`: when the stored `rules_key` fingerprint changes and `state()` was `"on"`, it calls `forget()` (best effort), writes the audit entry "sign-in without approval turned off" / "the rules key was replaced", and sets the DB flag `helper_off_notice = True`. The Accounts page then shows `OFF_RULES` once and clears the flag. Add `helper_off_notice` to `db.py`'s defaults, `NOT_PORTABLE`, the Global-only set and the cleanup list (the four places `signin_session_hours` is named).
- `roles.set_directories` and the 2FA dialog's save call `enroll()` again when `state() == "on"`, so the helper gets new Duo keys.

- [ ] **Step 1:** Tests:
  - **Client, against an in-process `server.Helper` through a fake `_connect`:** `state()` for each of the eight cases; `enroll` sends the right rules key; `forget` clears it; a rekey (`roles._rekey` through a recovery sign-in) while on calls forget, audits and sets the notice.
  - **UI:**
    - the checkbox has the approved label and tip;
    - ticking shows the approved warning;
    - Cancel changes nothing;
    - Turn on with `absent` calls `install_elevated` (mocked) then enroll and audits;
    - InstallFailed shows `INSTALL_FAILED` and leaves it unticked;
    - unticking calls forget and audits;
    - portable / other user / not running are disabled with their texts;
    - a Tech or Engineer doesn't see it;
    - `S.pending_changes()` stays empty after ticking.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests plus `test_accounts_page.py`, `test_roles.py`, `test_twofadlg.py`, `test_settings_dirty.py`. Expected: pass.
- [ ] **Step 5:** Commit with the message "Sign-in without approval: the switch, the helper client, auto-off when the rules key is replaced".

### Task 11: First sign-ins through the helper

**Files:** Modify `core/dirsignin.py`, `core/datakey.py`, `core/roles.py`, `ui/signinwindow.py`. Test: extend `tests/test_helper_client.py` and add `tests/test_helper_signin.py`.

**Interfaces — Consumes:** Tasks 4, 7, 8, 10. **Produces:**
- `datakey.open_with_keys(data_key: bytes) -> None` sets `_key` (and the sqldb key) with `_box = None` and `_name = None`, for approvals only.
- `roles.hold(kind: str, private) -> None` loads a role private key into `_held`.
- `dirsignin.helper_ready() -> bool` is `helperclient.state(datakey.path()) == "on"`, cached for the attempt.
- **AD/LDAP:** when `helper_ready()`, `begin` sends the password to the helper (`check_directory`) instead of binding itself, and fills `a.user/name/role` from the answer. Duo goes through `duo_push`/`duo_code` ops, and the ticket lands in `a.ticket`. `NotRunning` at any point falls back to today's own checks, with no ticket.
- **SSO:** when `helper_ready()`, `sso_start` takes its nonce from the helper's `nonce` op. After `sso_wait`'s own checks, it sends `check_sso` with the ID and access tokens, and the ticket lands in `a.ticket`.
- Where the flow would set stage `"approve"` (`choose_pin`, and `finish` with `needs_approval == "changed"`), when `a.ticket` is set it calls `approve_by_helper(a)` instead:
  1. `keys = release(ticket, a.name)`;
  2. `_approve(a, opener)`, where the opener calls `datakey.open_with_keys(...)` and `roles.hold("rules", ...)`, with approved-by `HELPER_APPROVER`;
  3. then the usual stage `"pin"`.

  Any helper error falls back to stage `"approve"` with `FIRST`/`CHANGED`, as today.
- **Pending backups key:** after `roles.unlock()` in a session holding `"backups"`, any vouched account whose effective role has `unmasked` and that has no backups grant gets one (`_sync`, signed). An account approved by the helper sees masked backups until then.
- The audit entry "sign-in approved" has the detail "{name}, approved by group membership".

- [ ] **Step 1:** Tests, with an in-process helper over the fake connect, mock LDAP, the Duo fake and FakeProvider:
  - With the switch on, an AD tech's first sign-in (password, Duo push) goes straight to choose-PIN, then "pin", then "done", with no approval page. The audit says "approved by group membership". Toner itself never bound to LDAP (count binds on the mock: only the helper's).
  - An SSO first sign-in gets its nonce from the helper, then reaches "done" with no approval.
  - A forgotten PIN (`restart_pin`) while on is re-approved by the helper.
  - With the helper stopped (`NotRunning`), the flow is today's: the approval page with `FIRST`.
  - A helper `rules_changed` answer gives the approval page and no keys.
  - A helper-approved Engineer whose role has `unmasked` has no backups grant. After a local Admin signs in, the grant exists and the signature still verifies.
  - A helper-approved person in an Admin group holds the rules key at their next sign-in (`roles.holds("rules")`).
  - Toner's process never keeps the helper's keys after the approval (`datakey._key is None` and `"rules" not in roles._held` when signed out after `_put_back`).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests plus every `test_*dir*`, `test_*signin*`, `test_roles.py`, `test_datakey*.py`, `test_session.py`, `test_lock_directory.py`. Expected: pass on Windows and WSL.
- [ ] **Step 5:** Commit with the message "First sign-ins through the helper: it checks the sign-in, then Toner approves as group membership".

### Task 12: README and the full run

**Files:** Modify `README.md`.

- [ ] **Step 1:** Draft the README changes (the sign-in section: SSO with the five presets, the switch and the helper service, directory admins approving) and send them to the owner for approval before writing. The README has no Development section.
- [ ] **Step 2:** Write the approved text.
- [ ] **Step 3:** Run `python tests/run_all.py` on Windows, then on WSL (`~/toner-venv/bin/python tests/run_all.py`), not at the same time, with output to files. Name every file that isn't clean, and run each one again on its own. Run pyflakes the way CI does.
- [ ] **Step 4:** Commit with the message "README: SSO, sign-in without approval and the helper service".

## Owner checks after the build (live)

1. Entra:
   - register the app as the Entra note says;
   - add an SSO connection with Sign in to list groups;
   - sign in as a tech in a mapped group, then as an Admin approving another person.
2. Turn the switch on (a UAC prompt). A new mapped tech signs in with no approval. Turn it off: the next new tech needs an approval.
3. Uninstall Toner: the helper service is removed after one UAC prompt.
