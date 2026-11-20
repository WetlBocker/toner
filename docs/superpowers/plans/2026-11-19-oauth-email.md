# OAuth 2.0 for Email Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Email channel can sign in to Microsoft 365 or Google with OAuth 2.0 instead of a password, for alerts and for the scheduled reports (Adjustments 2026-11-19, item 6).

**Architecture:** OAuth is a choice on the existing Email channel. A new small module holds the mail sign-in (token calls, the stored refresh token, renewal); `core/notify.py` asks it for an access token and authenticates the SMTP session with SASL XOAUTH2. The browser sign-in and the refresh call are the ones single sign-on already uses (`core/oidc.py`).

**Tech Stack:** Python 3.13, PySide6, `smtplib`, `requests`, the existing `core/oidc.py`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-oauth-email-design.md` (approved by the owner on 2026-11-19 with the decisions below). The spec and the decisions are binding; section 5 of the spec is the approved wording.

## Owner decisions (2026-11-19)

1. Both providers in the first version: Microsoft 365 account, Microsoft 365 app (no person), Google account.
2. No Google service account.
3. No HTTP mail APIs.
4. For a channel that signs in with Microsoft 365 or Google, the token calls **and the mail itself** connect directly and ignore Toner's proxy settings. (The spec's section 3 said the mail still used the proxy; this decision replaces that.) Password channels keep today's behaviour.
5. Deleting an organization also removes its channels' saved secrets, in this change.

## Global Constraints

- Every user-facing string comes from section 5 of the spec, or shipped before this plan (reusing an existing string for the same meaning is fine; required-field messages follow the existing pattern at `core/notify.py:120`). Anything else: stop and ask (NEEDS_CONTEXT).
- No token, client secret, password or authorization URL in any log, exception text, audit line, error detail shown to a person, settings file or test output. Error texts from a provider or a mail server are scrubbed of every secret before they are shown or logged.
- Never contact a real provider, mail server or password manager. Tests use a fake token endpoint and a fake SMTP server. Never capture the real display.
- Tests are plain scripts in the house style (`check(name, cond, extra)`), each printing `N passed, M failed`. Run one with `python tests/test_x.py 2>/dev/null | grep -a "^  FAIL\|passed, "`. Run the tests of every module you touch; the controller runs the full suite.
- TDD: write the test first and watch it fail for the right reason (a failing check, not an import error).
- The working tree has CRLF line endings (`core.autocrlf=true`). Keep them.
- No new dependencies. Never stage `.postman/`, `postman/`, `.impeccable/`, `.superpowers/` or `docs/Toner-Technical-Guide.pdf`. Commits end with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. No pushes, no merges.
- Slow work (token calls, SMTP, the browser sign-in) never runs on the UI thread.
- Password channels behave exactly as before: same fields, same proxy use, same errors.
- The smallest complete change: reuse `core/oidc.py`, the channel field list and the existing vault helpers; no second OAuth implementation.

## Review Focus

1. **A provider that refuses the stored sign-in** (revoked, password changed, 90 days unused). The mail fails with the approved message, the sign-in is removed once, the audit says so, and the other channels are told once, not on every alert. Task 1 tests it.
2. **A token endpoint that is down or slow.** The sign-in is kept (not removed), the mail fails with "can't be reached", and nothing blocks the UI thread. Task 1 tests the first two, Task 2 the third.
3. **Secrets in error text.** A mail server or token endpoint that echoes the token or the client secret in its error must not get it into a detail, log or audit line. Task 1 tests both.
4. **A channel edited after sign-in** (another mailbox, tenant, client ID or method). The old sign-in must not be used for the new settings. Task 2 tests it.
5. **A new channel whose dialog is cancelled after signing in.** No sign-in is left behind in the vault. Task 2 tests it.

---

### Task 1: Sending mail with an OAuth sign-in (core)

**Files:**
- Create: `core/mailauth.py`
- Modify: `core/notify.py` (`CHANNEL_TYPES["email"]` at line 35, `validate`, `delete_secrets`, `_mail` at line 274, `process_run` at line 363), `core/oidc.py` (`_token_call` at line 211, `BrowserSignIn` at line 267), `core/vault.py` (`PRIVATE_NAMES` at line 81)
- Test: new `tests/test_mail_oauth.py`; extend `tests/test_notify.py` and `tests/test_oidc.py`

**Interfaces (produces; Task 2 uses them):**
- Channel fields on the email type: `auth` (`"password"` default, `"ms_account"`, `"ms_app"`, `"google_account"`), `tenant`, `client_id` (plain), and the secret `client_secret` (kept like `password`). A channel saved before this change has no `auth` and behaves as `"password"`.
- `mailauth.METHODS`: `[("password", "Password"), ("ms_account", "Microsoft 365 account"), ("ms_app", "Microsoft 365 app (no person)"), ("google_account", "Google account")]`.
- `mailauth.provider(auth) -> str`: `"Microsoft 365"` or `"Google"`.
- `mailauth.needs_sign_in(auth) -> bool`: True for the two account methods.
- `mailauth.signed_in_as(ch) -> str | None`: the account of the stored sign-in, or None.
- `mailauth.sign_in(ch, secrets, cancelled=None) -> str`: the browser sign-in (through `oidc.BrowserSignIn`); stores the refresh token in the vault under `mail-refresh:<channel id>` with the account and the time; returns the account; writes the audit line "email sign-in". Window only.
- `mailauth.sign_out(ch)`: removes the stored sign-in; audit "email sign-in removed" when there was one.
- `mailauth.access_token(ch, secrets) -> str`: for an account method, a refresh call (the new refresh token is stored only when the provider sends one); for `ms_app`, a client-credentials call. Raises `mailauth.MailAuthError` whose text is one of the approved error messages.
- `mailauth.renew_stale(now=None)`: renews every stored sign-in last renewed more than 7 days ago; called at the start of `notify.process_run`.
- `mailauth.MailAuthError(Exception)`: `.gone` is True when the provider refused the sign-in for good.

**Behaviour:**
- **Providers.** Microsoft: issuer `https://login.microsoftonline.com/<tenant>/v2.0`; account scopes `https://outlook.office.com/SMTP.Send offline_access` plus what the sign-in needs to name the account; app-only scope `https://outlook.office365.com/.default` with `grant_type=client_credentials` and the client secret. Google: issuer `https://accounts.google.com`, scope `https://mail.google.com/` plus what names the account, with whatever Google's native-app documentation requires for a refresh token to be returned (the spec's sources [G2], [G3]; say in a code comment which parameter and which page). The client secret is passed to the token call as an argument; `oidc._token_call` gets that argument and single sign-on's callers are unchanged.
- **The browser sign-in** reuses `oidc.BrowserSignIn` with a switch that drops the "sign in again now" demands (`prompt=login`, `max_age=0`) and the `auth_time` check, which single sign-on keeps.
- **Sending.** `_mail`, for a channel whose `auth` is not `"password"`: get the access token, then `smtp.auth("XOAUTH2", ...)` with exactly `user=<mailbox>\x01auth=Bearer <token>\x01\x01`; a 334 challenge is answered with an empty line, as Google's page describes. The mailbox is the channel's username. The connection is direct: the proxy-aware `_SMTP` / `_SMTP_SSL` are not used for these channels (owner decision 4). Security "None" is refused before anything is sent. One token call per mail; nothing cached.
- **Errors** map to the approved texts: not signed in; no longer accepted (`invalid_grant`, `.gone`); can't be reached (connection error, timeout, 5xx); refused the app (`invalid_client`, `unauthorized_client`, a 401 on the client-credentials call); no sign-in it can keep (no refresh token returned at sign-in); the mail server refused the sign-in (`SMTPAuthenticationError`).
- **When a sign-in is refused for good:** before removing it, re-read the vault once and retry if the stored token changed (another process may have renewed it). Otherwise remove it, write the audit line "email sign-in refused" (channel, provider, account), and tell the other channels once with the approved notice (`notify.announce` at line 429 shows how). A sign-in that is already gone tells nobody again.
- **A provider that can't be reached keeps the sign-in.**
- **Validation** (`notify.validate`): the three approved checks; tenant ID, client ID and (for `ms_app`) client secret required by the existing pattern; "Sign in first." when an account method has no stored sign-in.
- **`delete_secrets(ch)`** also removes the client secret and the stored sign-in.
- **Vault:** `mail-refresh:` joins `vault.PRIVATE_NAMES`, so a password export never carries a sign-in and an import can never plant one.
- **Audit:** "email sign-in", "email sign-in removed", "email sign-in refused"; never a token, a secret or a URL.

- [ ] **Step 1: Write the failing tests** (a fake token endpoint served on loopback or patched at `oidc._send`, a fake SMTP class as `tests/test_notify.py:158` has):
  - the decoded XOAUTH2 string is exactly as above for each method; the 334-then-535 path gives the "mail server refused" text; a channel with Security "None" is refused before any connection;
  - the proxy-aware SMTP classes are not used for an OAuth channel and are still used for a password channel with a proxy set;
  - a refresh stores a new refresh token when one is sent and keeps the old one when none is; the renewal time is updated;
  - `invalid_grant`: the approved message, the sign-in removed, one audit line, one notice on the other channels; a second failing mail tells nobody again;
  - `invalid_grant` while the vault holds a newer token: one retry with it, nothing removed;
  - a 503 and a connection error: "can't be reached", the sign-in kept;
  - the client-credentials form carries the scope and the secret; `invalid_client` gives "refused the app";
  - a provider error text and an SMTP error text that contain the access token, the refresh token and the client secret: none of them is in the returned detail, the log or the audit line;
  - `renew_stale` renews a sign-in 8 days old and leaves one 6 days old;
  - `validate` gives each approved check; an old channel without `auth` validates and sends as before;
  - `delete_secrets` leaves nothing of the channel in the vault; a password export has no `mail-refresh:` entry and an import carrying one does not store it;
  - `mail_files` (the scheduled reports' path) sends an attachment through an OAuth channel;
  - single sign-on's existing tests still pass unchanged (`tests/test_oidc.py`, the directory sign-in tests).
- [ ] **Step 2:** Run them and see each fail on its own.
- [ ] **Step 3: Implement.** Keep `core/notify.py`'s growth small: the token and sign-in code lives in `core/mailauth.py`.
- [ ] **Step 4:** Run the new test, `tests/test_notify.py`, `tests/test_oidc.py`, every test that mentions `dirsignin`, `oidc` or `mail_files`, `tests/test_trends.py`, `tests/test_scan_reports.py` and the vault export tests.
- [ ] **Step 5:** Commit "Email: sign in to Microsoft 365 or Google with OAuth 2.0 (sending)".

### Task 2: The channel's form

**Files:**
- Modify: `ui/settings_pages/notifications.py` (`ChannelDialog` at line 46, the Send test handler at line 110, the remove prompt), the channel help text in `core/notify.py` (`CHANNEL_TYPES["email"]["help"]`)
- Test: `tests/test_notify_ui.py` (extend)

**Interfaces (consumes):** everything Task 1 produces.

**Behaviour:**
- "Sign in with" is a choice at the top of the Email channel's form with the four approved options. The form shows only the chosen method's fields:
  - Password: as today.
  - Microsoft 365 account: Tenant ID, Client ID, Username, the Sign in row.
  - Microsoft 365 app (no person): Tenant ID, Client ID, Client secret, Username.
  - Google account: Client ID, Client secret (with the approved placeholder), Username, the Sign in row.
  - Server, Port, Security and the recipients stay for all four.
- The approved help text for the chosen method shows under the form; the channel's help and the remove prompt take their approved new texts.
- The Sign in row: a button "Sign in" (or "Sign in again" when signed in) and the status "Not signed in." / "Signed in as {account}.". Signing in runs on a worker (the `Job` pattern at `ui/identitywizard.py:517-534`) with Cancel, using the existing texts `SSO_TEXT`, `SSO_CANCELLED` (`core/dirsignin.py:43-44`) and `SSO_DONE_PAGE` (`core/oidc.py:26`). A failure shows the approved error text.
- Changing the method, Tenant ID, Client ID, Client secret or Username after a sign-in removes that sign-in from the form's state: the status goes back to "Not signed in." and saving needs a new one.
- Nothing reaches the vault for good until Save: a new channel whose dialog is cancelled leaves no sign-in and no client secret behind; an existing channel whose dialog is cancelled keeps the sign-in it had before the dialog opened.
- Save runs `notify.validate`, so "Sign in first." and the other approved checks appear as the other channel types' checks do.
- Send test runs on a worker for every channel type (it blocks the window today), with the button disabled while it runs; its result appears where it does today.
- Removing a channel removes its sign-in and client secret (through `delete_secrets`).

- [ ] **Step 1: Write the failing tests:** the options and their order; the fields shown for each method; the help text per method; the two changed texts; Sign in runs off the UI thread, can be cancelled, and sets the status and the button's text; each of the five edits removes the sign-in; cancel on a new channel leaves the vault without anything of it; cancel on an existing channel keeps its earlier sign-in; "Sign in first." on Save; Send test does not block (the handler returns while a held fake send is still running) and re-enables its button; a password channel's form is as before.
- [ ] **Step 2:** Run and see them fail. **Step 3:** Implement.
- [ ] **Step 4: Look at it.** Off-screen screenshots of the dialog in each of the four methods, signed in and not; check alignment and that no text is cut.
- [ ] **Step 5:** Run `tests/test_notify_ui.py`, `tests/test_notify.py`, `tests/test_mail_oauth.py` and the settings tests. **Step 6:** Commit "Email: choose Microsoft 365 or Google sign-in in the channel's form; Send test no longer blocks".

### Task 3: Deleting an organization removes its channels' secrets

**Files:**
- Modify: `core/orgs.py` (the delete path near line 458)
- Test: the existing organization tests (`grep -ln "delete_org\|orgs.delete\|remove_org" tests/`)

**Interfaces (consumes):** `notify.delete_secrets(ch)` (after Task 1 it also removes the client secret and the stored sign-in).

- [ ] **Step 1: Write the failing test:** an organization with an Email channel (password), an OAuth Email channel (client secret and a stored sign-in) and a webhook channel; after the organization is deleted, the vault holds nothing of the three, and Global's and another organization's channel secrets are untouched.
- [ ] **Step 2:** Run and see it fail.
- [ ] **Step 3: Implement** by reading the organization's channels before its data is removed and calling `notify.delete_secrets` for each, in that organization's scope. If the delete can be undone or archived first (read the code), secrets go only when the data really goes; say in the report which case applies.
- [ ] **Step 4:** Run the organization, notify and vault tests. **Step 5:** Commit "Organizations: deleting one also removes its channels' saved secrets".
