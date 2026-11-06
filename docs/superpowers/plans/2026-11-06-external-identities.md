# External Identities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make joining a directory a short step-by-step Add flow under **Settings > Accounts > External Identities**, map OUs as well as groups to roles, move 2FA set-up to its own right-click item with a 2FA column, add a safe "Test login", make the session length an Admin setting, and fix the unsaved-changes dot and the Assistant panel's animation.

**Architecture:** Core gains OU-aware role mapping (`directory.role_for` gets the person's DN), discovery (`directory.discover`, `directory.tree`) and a side-effect-free test sign-in (`dirsignin.TestLogin`). The single Directory dialog is split: `ui/identitywizard.py` (the five Add steps, also used by Edit), `ui/twofadlg.py` (Set up 2FA) and `ui/testlogindlg.py` (Test login). The Accounts page shows the identities as a table with a right-click menu. The session length replaces the fixed 12-hour constant.

**Tech Stack:** Python 3.13, PySide6, ldap3 2.9.1 (already installed), SQLCipher. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-04-user-sign-in-design.md`, plus the design and wording the owner approved in chat on 2026-11-06 (copied below under "Approved design" and "Approved wording"; those two sections are binding).

## Approved design (owner, 2026-11-06)

- **Page.** "Accounts and sign-in" is renamed "Accounts". Its "Directories" section is "External Identities": a table with columns Name, Type, 2FA; buttons Add, Edit..., Remove; a right-click menu with Test login..., Set up 2FA..., Edit..., Remove.
- **2FA column:** "On" (Duo on), "Off" (Duo off), "N/A" for a type without 2FA (Entra, when Part 4 adds it). AD and LDAP are never "N/A".
- **Add flow, five steps** (Edit opens the same steps filled in; the type can't change on Edit):
  1. Choose a type: Active Directory or LDAP. (Entra joins this list in Part 4.)
  2. Server and service account: one host name, IP address or FQDN (a comma-separated list is still accepted, as today), the service account and its password.
  3. Connection: security, port, certificate, prefilled LDAPS / 636 / the system trust store. Next tests the connection and reads the base DN, the NetBIOS name (AD) and the DNS domain; a failure stays on this step with the reason.
  4. Who can sign in: the OUs and the security groups the service account can see, each with a tick box. Next needs at least one ticked.
  5. Roles: each ticked OU or group gets Admin, Engineer or Tech. Under them: Name, Base DN, Domain (NetBIOS), Email and UPN suffixes, filled from step 3 and editable. Save signs the list.
- **Mapping:** a role is granted by an OU (the account sits in it or in an OU below it) or by a group (direct or nested, as today). The highest matching role wins. Only DNs the server wrote are stored and compared (case of ASCII letters only).
- **Duo** is no longer in the Add flow: right-click > Set up 2FA... holds Second step (Off / Duo), Duo API hostname, Integration key, Secret key, Save.
- **Test login** (Admins only): username, password, Test; then the real Duo step when 2FA is on. It never opens the data key, never makes a PIN slot, account record or session, and writes nothing to the person's account. Wrong passwords count on the shared wait. The password is dropped when the test ends. The audit gets "test login" with detail "{name}, {result}"; never a password.
- **Session length:** one setting for everyone, Admin-only (it is on the Accounts page), "Session length (hours)", default 12. After it, the next unlock with the directory reachable asks for the full sign-in ("Please sign in again."). "Workday" becomes "session" in code and docs.
- **Unsaved changes:** no dot when a page is opened and nothing changes, and none when values are changed back to what was saved.
- **Assistant panel:** a smooth slide-and-fade in and out.
- Existing directories keep their group mappings; they show on the Roles step with no OUs.

## Approved wording (owner, 2026-11-06) — use verbatim

- Page "Accounts"; section "External Identities"; buttons "Add", "Edit...", "Remove"; menu "Test login...", "Set up 2FA..."; column "2FA" with "On", "Off", "N/A" (the other columns reuse "Name" and "Type").
- Step titles: "Choose a type", "Server and service account", "Connection", "Who can sign in", "Roles".
- Step 4: a filter box over each list that also searches the directory when the list is too long to load whole (owner, 2026-11-06; it needs no label text beyond the "OUs" and "Groups" headings).
- Fields: "Host name, IP address or FQDN", "Service account", "Password", "Security", "Port", "Certificate"; step 4 headings "OUs", "Groups"; step 5 rows "{OU or group}" with a role box "Admin" / "Engineer" / "Tech".
- Messages: "Connected. Choose who can sign in.", "Toner couldn't connect: {reason}", "Choose at least one OU or group."
- Test login: title "Test login"; fields "Username", "Password"; button "Test"; results "Signed in as {name}. Role: {role}. Signed out.", "That username or password isn't right.", "{name} isn't in an OU or group that Toner maps to a role.", plus the already approved Duo texts ("Approve on your phone", "Duo sent a request to your phone. Approve it to finish signing in.", "Cancel", "Enter a code instead", "Duo code", "Sign in", "Duo didn't approve the sign-in.", "That code isn't right.", "Toner can't reach Duo, so you can't sign in right now. Try again in a minute.", "Toner can't reach the directory. Connect to the network, then try again.").
- Audit: action "test login", detail "{name}, {result}" where {result} is the sentence the window showed.
- Setting: "Session length (hours)".
- Still approved from Part 3 and reused: "Name", "Type", "Active Directory", "LDAP", "LDAPS", "StartTLS", "System trust store", "CA file...", "Base DN", "Domain (NetBIOS)", "Email and UPN suffixes", "Second step" (Off / Duo), "Duo API hostname", "Integration key", "Secret key", "Save", "Next", the CA, duplicate, group-name and protected-store messages in ui/directorydlg.py, "Removing this directory signs out its accounts on this copy. Remove {name}?", "Please sign in again.", "Sign in".

## Global Constraints

- Every user-facing string comes from the approved wording above or shipped before this plan; anything else: stop and ask (NEEDS_CONTEXT).
- No password, PIN, Duo code or secret in logs, the audit, exceptions, netcheck.keys or a widget that outlives its page.
- The directory list shown or edited comes only from `roles.verified()`; a sign-in or test reads a config only after `dirsignin.classify`'s fingerprint check or from the verified list.
- Windows, Linux and macOS ship together; tests run headless (`QT_QPA_PLATFORM=offscreen`) on Windows and WSL (`~/toner-venv/bin/python`).
- Tests are plain scripts in the house style (`check(name, cond)`; run as `python tests/<file>.py`); `tests/run_all.py` must stay green apart from known flakes (test_nettools2; test_reach, test_duo under load pass alone).
- No new dependencies. Never stage `.postman/`, `postman/`, `.impeccable/`, `.superpowers/`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No pushes.
- Slow work (LDAP, Duo, `best_kind`) never runs on the UI thread: use `ui.signinwindow.Job`.

## Review Focus

1. A directory with thousands of OUs and groups: step 4 must stay usable (a filter box over each list that also searches the directory when the list was capped, paged reads, no freeze) — Task 1 caps `tree` at 5000 per kind and searches by text; Task 5 tests 3000 rows, the filter and the directory search.
2. An OU mapping must not match a sibling with a longer name ("OU=IT" vs "OU=IT-Old"): Task 1 tests the DN-suffix match on a comma boundary.
3. Test login while someone is signed in must leave that session exactly as it was (keys, name, role, session clock): Task 2 tests it.
4. Editing an existing identity must keep its stored service password and Duo secret when the password box is left empty: Task 5 tests it.
5. Closing any of the new windows while a Job runs must not crash or leave a thread: Tasks 5–7 each test close-during-Job.

---

### Task 1: Directory core — OU mapping and discovery

**Files:**
- Modify: `core/directory.py`, `core/roles.py` (`set_directories` accepts `"ous"`), `core/dirsignin.py` and `core/dircheck.py` (pass the person's DN to `role_for`)
- Test: `tests/test_directory.py`, `tests/test_directory_accounts.py`

**Interfaces:**
- Produces:
  - `User` gains `dn: str = ""` (last field, default keeps old constructors working); `_user_from` fills it with the entry's DN.
  - Config gains `"ous": {"Admin": [dn...], "Engineer": [...], "Tech": [...]}` (absent = none).
  - `role_for(cfg, groups, dn="") -> str | None`: highest role whose group DNs meet `groups` or whose OU DN is a DN-suffix of `dn` (`_key(dn).endswith("," + _key(ou))`).
  - `discover(cfg, service_password) -> {"base_dn": str, "netbios": str, "suffixes": [str]}`: base DN from the rootDSE (`defaultNamingContext` on AD, the first `namingContexts` value on LDAP); NetBIOS via `netbios()` on AD ("" on LDAP); suffixes `[the DNS domain from the base DN's DC= parts, lowercased]`. Raises `Unreachable` when the base DN can't be read.
  - `tree(cfg, service_password, cap=5000, text="") -> {"ous": [dn...], "groups": [dn...], "more": bool}`: paged SUBTREE reads under `base_dn` (`(objectClass=organizationalUnit)`; groups with `AD_GROUP`/`LDAP_GROUP`), DNs as the server wrote them, sorted case-insensitively, at most `cap` each; `more` is True when either kind had more than `cap`. With `text`, only entries whose `ou` (OUs) or `cn` (groups) contains it (`*text*`, filter-escaped with `escape_filter_chars`) are read: the directory search behind step 4's search box.

- [ ] **Step 1: Write the failing tests** (MOCK_SYNC, as the file does now):
  - `role_for` with an OU mapping: a user at `CN=Bob,OU=Ops,OU=IT,DC=acme,DC=com` matches `OU=IT,DC=acme,DC=com`; a user in `OU=IT-Old,DC=acme,DC=com` does not; case of ASCII letters doesn't matter; group and OU mappings together give the highest role; no `"ous"` key behaves as today.
  - `sign_in` returns `User.dn` equal to the entry's DN; `dirsignin.begin` grants the OU-mapped role.
  - `discover` on the mock returns the base DN, NetBIOS "ACME" and `["acme.com"]` (stub `_config_nc`/rootDSE reads where the mock can't serve them, as `netbios`'s test does).
  - `tree` returns both lists sorted, stops at `cap` with `more` True, and with `text="ops"` returns only matching OUs and groups; a `text` holding `*`, `(` or `)` is escaped, never widening the search.
  - `roles.set_directories` accepts and signs `"ous"`; a hand edit of `"ous"` in the file reads "tampered".
- [ ] **Step 2: Run them to see them fail:** `python tests/test_directory.py`, `python tests/test_directory_accounts.py`.
- [ ] **Step 3: Implement** the interfaces above; update every `role_for` caller (`dirsignin`, `dircheck`) to pass `user.dn`.
- [ ] **Step 4: Run** test_directory, test_directory_accounts, test_dirsignin, test_dircheck on Windows and WSL.
- [ ] **Step 5: Commit** "Directory: roles from OUs as well as groups; discover the base DN and list OUs and groups".

### Task 2: Test login, in core

**Files:**
- Modify: `core/dirsignin.py`
- Test: `tests/test_testlogin.py`

**Interfaces:**
- Consumes: `directory.sign_in`, `directory.role_for(cfg, groups, dn)`, `duo.preauth/push/passcode`, the shared counter helpers in `dirsignin` (`_tries`), `perms.is_admin()`.
- Produces: `class TestLogin` with `__init__(self, cfg)` (cfg from `roles.verified()`), `stage` ("password", "duo", "done"), `check_password(login, password) -> None`, `duo_push(cancel) -> None`, `duo_code(code) -> None`, `result -> str` (the sentence shown). Raises the same exceptions as `begin`/`duo_*` (`datakey.WrongPassword`, `directory.Unreachable`, `NotInGroup`, `duo.Denied`, `duo.Unavailable`, `perms.Denied` when the signed-in person isn't an Admin).
- Texts: `TEST_OK = "Signed in as {name}. Role: {role}. Signed out."`, `TEST_NOT_MAPPED = "{name} isn't in an OU or group that Toner maps to a role."`.

- [ ] **Step 1: Write the failing test** `tests/test_testlogin.py` (fakes from test_dirsignin: MOCK_SYNC, fake Duo, fake chip):
  - An Admin tests Bob with Duo off: `result == TEST_OK.format(name="bob@acme.com", role="Engineer")`; the keys file is byte-identical before and after; no PIN slot exists; `session.user()`, `datakey.is_open()`, the held role keys are unchanged (run once signed in as Admin1, once with a held session of another account).
  - With Duo on: stage goes "duo"; a push approves → `result` is TEST_OK; a deny raises `duo.Denied`; a code works.
  - A wrong password raises `datakey.WrongPassword` and the shared count goes up by one; a right one doesn't clear it (a test doesn't count as a sign-in).
  - An unmapped person: `NotInGroup`, and the shown text is TEST_NOT_MAPPED.
  - An Engineer gets `perms.Denied` before any bind (count the binds).
  - The audit has one "test login" row per test with detail `"bob@acme.com, <the sentence>"`; no password, code or secret appears in the audit, the log, or any exception text.
- [ ] **Step 2: Run** it to see it fail.
- [ ] **Step 3: Implement `TestLogin`** by reusing `begin`/`after_password`'s directory and Duo calls without `set_online`, `set_groups_role`, `_clear_tries`, `start_directory_account` or any session call; unbind at once; drop the password reference after `check_password`.
- [ ] **Step 4: Run** test_testlogin and test_dirsignin on Windows and WSL.
- [ ] **Step 5: Commit** "Test login: a directory sign-in and its 2FA, with nothing kept".

### Task 3: Session length

**Files:**
- Modify: `core/session.py` (`WORKDAY` → `SESSION_HOURS = 12`; `workday_over()` → `session_over()`), `ui/lockscreen.py`, `core/datakey.py` (comments), `ui/settings_pages/accounts.py` (the field)
- Test: `tests/test_lock_directory.py`, `tests/test_dirsignin.py`, `tests/test_dircheck.py`, `tests/test_directory_accounts.py`, `tests/test_accounts_page.py`

**Interfaces:**
- Produces: `session.session_over() -> bool` (true when the last full check is more than `session_hours()` hours ago); `session.session_hours() -> int` (setting `signin_session_hours`, default 12, clamped 1–72); every former `workday_over` caller uses `session_over`.

- [ ] **Step 1: Write the failing tests:** `session_over()` false at 11 h and true at 13 h by default; with `signin_session_hours` = 2, true at 3 h; the Accounts page shows "Session length (hours)" with 12, saves the value, and an Engineer never reaches it; rename the existing workday checks to the new names (their assertions unchanged).
- [ ] **Step 2: Run** them to see them fail.
- [ ] **Step 3: Implement**; the field is a `spin(1, 72, "")` on the Accounts page form under "Lock after", labelled "Session length (hours)". Replace "workday" with "session" in code comments and identifiers.
- [ ] **Step 4: Run** the five test files on Windows and WSL; `grep -rni workday core ui` finds nothing.
- [ ] **Step 5: Commit** "Session length: an Admin setting, 12 hours by default".

### Task 4: The Accounts page — External Identities

**Files:**
- Modify: `ui/settings_pages/accounts.py`, `ui/settings.py` (the page name in `GROUPS` and `GLOBAL_PAGES`), `core/perms.py` (comment), every test naming "Accounts and sign-in" (`tests/test_accounts_page.py`, `tests/test_directorydlg.py`, `tests/test_perms.py`, `tests/test_role_ui.py`)
- Test: `tests/test_accounts_page.py`

**Interfaces:**
- Consumes: `roles.verified()`, `osstore.get("duo:"+id)` presence is NOT read — the 2FA column reads `cfg["duo"]["on"]` only.
- Produces: `AccountsPage.title = "Accounts"`; `self.idents` a `QTableWidget` (columns "Name", "Type", "2FA"); `self.add_ident`, `self.edit_ident`, `self.remove_ident` buttons ("Add", "Edit...", "Remove"); `_ident_menu(pos)` with "Test login...", "Set up 2FA...", "Edit...", "Remove". Task 5 supplies `IdentityWizard`, Task 6 `TwoFactorDialog`, Task 7 `TestLoginDialog`; until they land the menu items call the existing `DirectoryDialog` (Edit/Add) and are disabled (2FA, Test login).

- [ ] **Step 1: Write the failing tests:** the page title is "Accounts" and it sits in "Security and data"; the heading "External Identities"; a verified AD directory with Duo on shows a row `["ACME", "Active Directory", "On"]`, one with Duo off shows "Off"; the right-click menu lists exactly the four items; Remove asks the approved confirmation; an Engineer never reaches the page; no row shows when `roles.verified()` is None and Add is disabled. Update the other test files' page-name strings.
- [ ] **Step 2: Run** them to see them fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** test_accounts_page, test_directorydlg, test_perms, test_role_ui on Windows and WSL.
- [ ] **Step 5: Commit** "Accounts page: External Identities with a 2FA column and a right-click menu".

### Task 5: The Add flow

**Files:**
- Create: `ui/identitywizard.py`
- Modify: `ui/settings_pages/accounts.py` (Add and Edit open it), `ui/directorydlg.py` (keep `words`, `with_ca`, `service_key`, the message constants and `_netbios`/`_split`; remove the single-pane dialog once nothing uses it)
- Test: `tests/test_identitywizard.py` (move what still applies from `tests/test_directorydlg.py`, then delete that file's dialog checks)

**Interfaces:**
- Consumes: `directory.discover`, `directory.tree`, `directory.test`, `directory.check_config`, `with_ca`, `words`, `roles.set_directories(list, edited=id)`, `passvault.put(service_key(id), pw)`.
- Produces: `IdentityWizard(dirs, cfg=None, parent=None)`, a `QDialog` with a `QStackedWidget` of the five steps and Back / Next / Save; `exec()` is truthy after a successful Save.

- [ ] **Step 1: Write the failing test** (MOCK_SYNC, a fake protected store, isolated APPDATA):
  - Add AD: step titles appear in order; Next on step 3 runs on a Job and shows "Connected. Choose who can sign in."; step 4 lists the mock's OUs and groups; Next with nothing ticked shows "Choose at least one OU or group."; step 5 maps OU=IT → Engineer and Toner Admins → Admin; the Name, Base DN, Domain (NetBIOS) and suffixes are prefilled; Save writes a verified directory with `ous` and `groups` holding server DNs, the service password only in the vault, an audit "directory added".
  - A failed connection stays on step 3 with "Toner couldn't connect: {reason}".
  - Edit: the type can't change; ticks and roles come back from the saved config; an empty password keeps the stored one; Save re-hashes only this directory (Ruling 32).
  - 3000 OUs render, and the filter box over each list narrows it at once (Review Focus 1).
  - Search in large directories (owner, 2026-11-06): when `tree` said `more`, typing in the filter box also searches the directory (`tree(..., text=...)` on a Job, after the typing pauses for 400 ms) and adds the matches to the list, keeping ticks already made; a later search's result never overwrites a newer one. Test with `cap=5` on the mock.
  - Closing during the step-3 Job: no crash, no thread left (Review Focus 5).
  - Duplicate suffix or NetBIOS and the CA messages still show their approved texts.
- [ ] **Step 2: Run** it to see it fail.
- [ ] **Step 3: Implement.** Secrets are captured when Next/Save is clicked, never read when a Job lands; the form is disabled while a Job runs; the password box is cleared on Save and on close.
- [ ] **Step 4: Run** test_identitywizard, test_accounts_page, test_directory, test_dirsignin on Windows and WSL.
- [ ] **Step 5: Commit** "External Identities: a five-step Add flow with OUs and groups to roles".

### Task 6: Set up 2FA

**Files:**
- Create: `ui/twofadlg.py`
- Modify: `ui/settings_pages/accounts.py` (enable the menu item)
- Test: `tests/test_twofadlg.py`

**Interfaces:**
- Produces: `TwoFactorDialog(dirs, cfg, parent=None)` with Second step (Off / Duo), Duo API hostname, Integration key, Secret key, Save. Save: secret to `osstore.put("duo:"+id)` (an empty box keeps the stored one), `cfg["duo"] = {"on", "host", "ikey"}` signed through `roles.set_directories(list, edited=None)` (no CA re-hash). With no protected store, Duo is disabled and "This computer has no protected store, so Duo can't be turned on here." shows (`osstore.available()` read on a Job).

- [ ] **Step 1: Write the failing test:** turning Duo on writes the secret only to the fake store and shows "On" in the 2FA column; off shows "Off"; an empty secret on a second save keeps the first; a Duo host typed as `https://api-x.duosecurity.com/` is saved as `api-x.duosecurity.com` (scheme and path stripped; no new wording); no secret in the keys file, the audit or the log; close-during-Job is safe.
- [ ] **Step 2: Run** it to see it fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** test_twofadlg and test_accounts_page on Windows and WSL.
- [ ] **Step 5: Commit** "External Identities: Set up 2FA on its own".

### Task 7: Test login window

**Files:**
- Create: `ui/testlogindlg.py`
- Modify: `ui/settings_pages/accounts.py` (enable the menu item)
- Test: `tests/test_testlogindlg.py`

**Interfaces:**
- Consumes: `dirsignin.TestLogin` (Task 2); the Duo page pattern from `ui/signinwindow.py` (reuse its helpers `heading`, `words`, `field`, `primary`, `link`, `Job`).
- Produces: `TestLoginDialog(cfg, parent=None)`: title "Test login"; Username, Password, Test; the Duo push page ("Approve on your phone" …, "Cancel", "Enter a code instead") and the code page ("Duo code", "Sign in"); the result sentence; every network step on a Job.

- [ ] **Step 1: Write the failing test:** a good test shows TEST_OK; a wrong password shows "That username or password isn't right."; an unmapped person shows TEST_NOT_MAPPED; with Duo, the push page then the result; "Enter a code instead" reaches the code page; the password box is empty after Test and after close; closing during a push cancels it and leaves no thread; the session in this process is unchanged.
- [ ] **Step 2: Run** it to see it fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** test_testlogindlg and test_testlogin on Windows and WSL.
- [ ] **Step 5: Commit** "External Identities: Test login".

### Task 8: Unsaved changes

**Files:**
- Modify: `ui/settings.py` (and the page(s) found at fault)
- Test: `tests/test_settings_dirty.py`

- [ ] **Step 1: Write the failing test:** open Settings headless; for every page in `Settings.pages`, select it, wait two watch ticks (`check_dirty` is on a 500 ms timer; call it directly), and assert no page is dirty and "Unsaved changes" is empty; then on three representative pages (General, Accounts, Security) change one field and change it back, and assert not dirty again.
- [ ] **Step 2: Run** it and note every page that comes up dirty with nothing changed — use superpowers:systematic-debugging to find why (likely values that change after `load()`: lazily filled combos, normalised text, timers), and record the cause per page in the report.
- [ ] **Step 3: Fix the cause** (take the baseline after a page's deferred filling, or make `signature` read the settled value) — not by hiding the dot.
- [ ] **Step 4: Run** test_settings_dirty plus test_settings* and test_accounts_page on Windows and WSL.
- [ ] **Step 5: Commit** "Settings: no unsaved-changes dot without a real change".

### Task 9: The Assistant panel's motion

**Files:**
- Modify: `app.py` (`show_assistant`, `_slide_panel`), `ui/motion.py` if a helper is needed
- Test: `tests/test_assistant_motion.py`

- [ ] **Step 1: Write the failing test:** opening and closing the panel with motion on sets the splitter sizes at most twice per transition (once at the start, once at the end; patch `self.body.setSizes` to count) and the page widget is laid out at most twice; the transition lasts 180–260 ms; with motion off it is instant; opening then closing quickly ends closed with no error.
- [ ] **Step 2: Run** it to see it fail (the current bounce resizes the splitter every frame).
- [ ] **Step 3: Implement:** an overlay snapshot of the panel slides in from the right edge with an opacity fade (ease-out cubic, no bounce, about 220 ms) over the page; the real splitter sizes change once at the start (closing) or end (opening). `motion.enabled()` off: instant.
- [ ] **Step 4: Run** test_assistant_motion and the assistant/app tests on Windows and WSL; look at it once by hand in the running app and say so in the report.
- [ ] **Step 5: Commit** "Assistant: a smooth slide and fade".

### Task 10: Docs and the whole suite

**Files:**
- Modify: `README.md`, `docs/release-notes-sign-in.md`, the spec (one note: OUs as well as groups; session length is an Admin setting)

- [ ] **Step 1:** Replace "Settings > Accounts and sign-in" with "Settings > Accounts" in the README and release notes (the owner approved the rename; no other sentence changes).
- [ ] **Step 2:** Run the whole suite on Windows, then WSL (not at once), and pyflakes as CI runs it (`python -m pyflakes core drivers ui app.py cli.py`, no undefined name / redefinition / syntax lines). Re-run any unclean file alone.
- [ ] **Step 3: Commit** "Docs: External Identities and the session length".
