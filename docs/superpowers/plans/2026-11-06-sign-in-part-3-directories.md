# Sign-in, part 3: AD and LDAP, with Duo, the PIN and admin approval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Techs sign in with their Active Directory or LDAP account. Duo push (or a code) is the second step where an admin turns it on. A PIN protects the data key on each computer, and an admin approves each person's first sign-in to a copy.

**Architecture:**
- **Connections and roles.** An admin adds a directory connection: LDAPS or StartTLS only, the certificate always checked, a service account, a group-to-role map, and optionally Duo. The connection settings live in `netcheck.keys`, under the rules signature, because they are needed before the encrypted database opens.
- **The PIN seal.** A directory account's copy of the data key is sealed under a PIN slot. On Windows the slot is a TPM key (a 6-digit PIN, guessing limited by the chip). Elsewhere it is the OS protected store plus a PIN of at least 8 characters, or that PIN alone when there is no store.
- **First sign-in.** The account's first sign-in to a copy stops at an approval step. An admin (or the recovery key) signs in on that screen. Toner then seals the data key into the slot and vouches for the account's box key.
- **Roles.** Permissions follow the person's current groups. Role keys follow the role the admin approved, so moving into a role that sees unmasked backups needs approval again.

**Tech Stack:** Python 3.13, PySide6, `cryptography`. New: `ldap3==2.9.1` (pure Python; needs the owner's yes). Duo's Auth API is called with `requests`, which is already installed. The TPM is reached through `ctypes` and Windows' NCrypt, with nothing new to install.

**Spec:** `docs/superpowers/specs/2026-11-04-user-sign-in-design.md` ("Signing in", "Locking the data", "Setting up a copy", "Around the edges"). It builds on Parts 1 and 2 (`docs/superpowers/plans/2026-11-04-sign-in-part-1-the-lock.md`, `docs/superpowers/plans/2026-11-05-sign-in-part-2-roles.md`): `core/datakey.py`, `core/roles.py`, `core/perms.py`, `core/session.py`, `ui/signinwindow.py`, `ui/lockscreen.py` and `ui/settings_pages/accounts.py`.

**Plan order (owner, 2026-11-06).** This plan merges the old Part 3 (the PIN and enrolment) and Part 4 (AD and LDAP, with Duo), so the first directory user gets the whole flow. Single sign-on is now Part 4, and it reuses this plan's PIN, approval and role pieces.

## Global Constraints

- **Wording.** Every piece of text a person sees is in "Wording to approve" below. Execution starts only after the owner has answered it. Any other string goes to the owner before it is built.
- **Dependencies.** `ldap3==2.9.1` is the only new package. It goes into `requirements.txt` and `requirements.lock` with its hashes, and only after the owner says yes. Nothing else is installed.
- **Platforms.** Windows, Linux and macOS ship together. CI runs Windows and Linux on Python 3.13. CI machines have no TPM, so tests use a fake NCrypt; the real chip is checked by hand on the owner's laptop (Task 3).
- **Tests.**
  - Tests run headless and keep passing. With no `netcheck.keys`, or with no directory configured, nothing changes.
  - New test files start with `tests/test_hardening.py` lines 1-18 and end with `print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)`.
  - Tests use `from core.sqldb import sqlite3`.
  - Tests never touch the real `%APPDATA%\NetCheck`.
  - Run one file: `PYTHONUTF8=1 QT_QPA_PLATFORM=offscreen "/c/Users/Joshua Wetlesen/AppData/Local/Programs/Python/Python313/python.exe" tests/test_x.py`. Run all: the same with `tests/run_all.py`.
  - Linux: `MSYS_NO_PATHCONV=1 wsl.exe -e bash -lc 'cd "/mnt/c/Claude Code/netcheck" && QT_QPA_PLATFORM=offscreen ~/toner-venv/bin/python tests/run_all.py'`.
  - Never run the Windows and Linux suites at the same time.
- **LDAP tests** use `ldap3`'s `MOCK_SYNC` strategy. No real server is needed.
- **Git.**
  - Work on branch `directories`, made from `main`. Commit locally; the owner pushes.
  - Never stage `.postman/`, `postman/`, `.impeccable/` or `.superpowers/`.
- **Secrets.**
  - No password, PIN, key, Duo secret or wrapped key goes in a log, an exception message or the audit detail.
  - Plain LDAP (no TLS) is refused, and so is turning off certificate checks.

## Review Focus

1. **The directory can't be reached at sign-in.** Within an hour of the last good online check, the person goes from username straight to their PIN. Past the hour, they're refused with the approved sentence. A person already signed in keeps working, and PIN unlocks keep working, while offline. Test in Task 7.
2. **Duo answers "deny", times out, or can't be reached while the directory says yes.** Sign-in is refused, and the second step is never skipped. Test in Task 2 and Task 7.
3. **Wrong PINs.** On the chip, the TPM's own lockout answers, and Toner shows the wait. On the store and PIN-only kinds, Toner's shared failure counter throttles as it does for passwords. Either way, five wrong PINs never let a sixth try through faster. Test in Task 3.
4. **The directory account is disabled, or leaves every Toner group, while the person is signed in.** The next background check, within 15 minutes, locks Toner. The PIN no longer unlocks it, and only a full sign-in (which the directory then refuses) gets back in. Test in Task 8.
5. **A hand-edit of `netcheck.keys`.** Changing a directory's server, its group map, the Duo host, or an account's approved role makes the roles read "tampered" (Part 2 behaviour). A cached group list edited to "Admin" changes only window permissions, never role keys. Test in Task 4.

## Decisions in this plan (my calls; the owner should check them)

- **The chip on Windows only for now.** The 6-digit TPM PIN is built for Windows in this plan. macOS (the Secure Enclave needs a code-signed app with keychain entitlements) and Linux (TPM 2.0 needs a native library, `tpm2-tss`) use the spec's fallback: the OS protected store plus a PIN of at least 8 characters. The chip can come to those platforms in a follow-up. The Accounts page shows which kind each account uses.
- **The Duo secret key is kept in the OS protected store** (DPAPI on Windows, the Keychain or Secret Service elsewhere), not in the keys file. A portable copy moved to another computer needs Duo's secret entered again there. Directory users need an admin's approval on a new computer anyway. With no protected store, Duo can't be turned on for that computer, and the page says why.
- **The certificate is always checked**, against the system's trust store or a CA file the admin picks. There is no "ignore certificate" option.
- **Groups.** On AD, nested groups count (the `1.2.840.113556.1.4.1941` in-chain rule). On other LDAP servers, direct membership counts: `member`, `uniqueMember` or `memberUid`. With more than one matching group, the highest role wins: Admin, then Engineer, then Tech. With no matching group, the person can't sign in.
- **Which role does what.** Permissions follow the role from the person's current groups. Role keys (backups and rules) follow the role an admin last approved. Moving into a role that may see unmasked backups, or into Admin, stops at the approval step at the next sign-in. Until then, the person signs in with the permissions of their new groups but without the new keys. That matches the spec's "an admin approves... when a group change moves someone into a role that can see unmasked backups".
- **The workday.** A full sign-in (directory, Duo and PIN) lasts 12 hours. Within it, idle locks ask only for the PIN. After it, the next unlock asks for the full sign-in when the directory can be reached. When it can't, the PIN keeps working, because the owner's priority is never locking a tech out mid-job. A disabled account still locks at once when the check gets through.
- **The background check** runs every 15 minutes while someone with a directory account is signed in. It runs as the service account, and it only reads.
- **The command line.** Directory users can sign in at a terminal with password, Duo and PIN. A first sign-in, or one that needs approval, is refused there: approval happens at the laptop, in the window.
- **Usernames.**
  - `DOMAIN\user` is matched to the directory with that NetBIOS name.
  - `user@suffix` is matched to the directory listing that suffix. The admin lists the suffixes, which is the spec's "map a domain by hand".
  - Anything else is a local account. A local username can't contain `@` or `\`.

## Wording to approve (drafts, before Task 1)

- **Sign-in window**
  - Duo push page: title "Approve on your phone", text "Duo sent a request to your phone. Approve it to finish signing in.", button "Cancel", link "Enter a code instead".
  - Code page: field "Duo code", button "Sign in".
  - PIN page: field "PIN", button "Sign in", link "Forgot your PIN?".
  - Choose a PIN:
    - title "Choose a PIN";
    - text "You'll use this PIN to unlock Toner on this computer.";
    - fields "PIN" and "Confirm PIN";
    - button "Next";
    - errors "Use 6 digits.", "Use at least 8 characters.", "The two PINs don't match.", "Avoid simple PINs like 123456.".
  - Approval page:
    - title "An admin needs to approve this";
    - text for a first sign-in: "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it.";
    - text after a role change or a new PIN: "Your access changed. Ask an admin to sign in here to approve it.";
    - fields "Admin username" and "Password", button "Approve", link "Use the recovery key".
  - Errors:
    - "Toner can't reach the directory. Connect to the network, then try again."
    - "Toner can't reach Duo, so you can't sign in right now. Try again in a minute."
    - "Duo didn't approve the sign-in."
    - "That code isn't right."
    - "That PIN isn't right."
    - "Too many wrong PINs. Wait {n} seconds, then try again."
    - "Your account isn't in a Toner group. Ask an admin."
    - "That account can't approve sign-ins."
  - Command line:
    - "Approve the sign-in on your phone. (Press Ctrl+C to enter a code instead.)"
    - "Duo code: "
    - "PIN: "
    - "Sign in to Toner's window once first, so an admin can approve this computer."
- **Lock screen**
  - Field "PIN" for directory users.
  - After the background check fails: "Your account can't sign in to Toner any more. Ask an admin.", with only "Sign in as someone else" offered.
- **Accounts page, Directories section**
  - Heading "Directories"; buttons "Add directory...", "Edit...", "Remove".
  - New Type values in the accounts table: "Active Directory" and "LDAP". New column "Unlocks with", showing "PIN (security chip)", "PIN (protected store)", "PIN" or "Password".
- **Directory dialog**
  - Title "Directory".
  - Fields:
    - "Name";
    - "Kind" (Active Directory / LDAP);
    - "Servers" (hint "One or more, separated by commas");
    - "Port";
    - "Security" (LDAPS / StartTLS);
    - "Certificate" (System trust store / CA file...);
    - "Base DN";
    - "Domain (NetBIOS)";
    - "Email and UPN suffixes" (hint "Separated by commas");
    - "Service account";
    - "Service account password";
    - "Admin groups", "Engineer groups", "Tech groups" (hint "Group names, one per line");
    - "Second step" (Off / Duo);
    - "Duo API hostname";
    - "Integration key";
    - "Secret key".
  - Buttons "Test connection" and "Save".
  - Messages:
    - "Connected. Found {n} groups."
    - "Toner couldn't connect: {reason}"
    - "This computer has no protected store, so Duo can't be turned on here."
    - "Removing this directory signs out its accounts on this copy. Remove {name}?"
- **Audit entries:** "signed in" (as today, with the directory name in the detail), "sign-in approved" (detail `{user}, approved by {admin}`), "PIN set", "PIN reset", "Duo denied a sign-in", "locked: the directory refused the account", "directory added", "directory changed", "directory removed".
- **Release notes:**
  - "People can sign in with their Active Directory or LDAP account. An admin adds the directory in Settings > Accounts and sign-in and maps its groups to roles."
  - "Duo push or a Duo code can be required as a second step."
  - "On Windows, a 6-digit PIN protected by the computer's security chip unlocks Toner. Elsewhere, the PIN is at least 8 characters."
  - "A person's first sign-in to a copy needs an admin to approve it at that computer."

---

### Task 1: The directory client

**Files:**
- Create: `core/directory.py`
- Modify: `requirements.txt`, `requirements.lock` (`ldap3==2.9.1` with hashes), `packaging/build.ps1` and `packaging/build_linux.sh` (`--collect-all ldap3` if PyInstaller misses it)
- Test: `tests/test_directory.py`

**Interfaces:**
- Produces, in `core/directory.py`:
  - **The connection.** `Config`, a dict with: `id` (a stable random hex string), `name`, `kind` ("ad" or "ldap"), `servers` (a list), `port`, `security` ("ldaps" or "starttls"), `ca_file` ("" means the system store), `base_dn`, `netbios`, `suffixes` (lowercase list), `service_dn`, `groups` (`{"Admin": [...], "Engineer": [...], "Tech": [...]}`, as group CNs), `duo` (`{"on": bool, "host": str, "ikey": str}`). The service password and the Duo secret are NOT in it.
  - **The person.** `User`, a frozen dataclass: `guid: str` (AD `objectGUID` or LDAP `entryUUID`, as text), `name: str` (the UPN, or `uid@first-suffix`, lowercase), `display: str`, `groups: tuple[str, ...]`, `enabled: bool`.
  - **Exceptions:** `Unreachable(Exception)`, `BadCredentials(Exception)`, `InsecureConfig(ValueError)`.
  - **Calls:**
    - `connect(cfg, who, password) -> ldap3.Connection`: TLS only, with `ssl.CERT_REQUIRED` and the system store or `ca_file`. It tries each server in turn. A refused or timed-out server raises `Unreachable`, and a refused bind raises `BadCredentials`.
    - `sign_in(cfg, login, password, service_password) -> User`: binds as the person (`DOMAIN\user` or the UPN form), then reads their entry and groups.
    - `look_up(cfg, guid, service_password) -> User | None`: binds as the service account. None means not found.
    - `role_for(cfg, groups) -> str | None`: the highest mapped role, or None.
    - `test(cfg, service_password) -> int`: the number of groups the service account can see.
  - `check_config(cfg)` raises `InsecureConfig` for a non-TLS port with no StartTLS, or for an empty server list.
  - **Disabled:** on AD, `enabled` is False when `userAccountControl & 2`. On LDAP it is False when `nsAccountLock` is "true" or `pwdAccountLockedTime` is set.

- [ ] **Step 1: Ask the owner to approve installing `ldap3==2.9.1`, and wait.**
- [ ] **Step 2: Write the failing test** with `ldap3`'s `MOCK_SYNC`, using an AD-shaped tree and an LDAP-shaped tree. Assert:
  - `sign_in` returns the right `User`, including groups reached through a nested group on AD.
  - A wrong password raises `BadCredentials`.
  - A disabled AD user has `enabled` False.
  - `role_for` picks Admin over Tech when both match, and returns None for no match.
  - `look_up` of a removed GUID returns None.
  - `check_config` refuses port 389 with security "ldaps" off.
  - An unreachable server (a closed port, without mock) raises `Unreachable` within the timeout. Use a 3-second connect timeout.
- [ ] **Step 3: Run it to make sure it fails.**
- [ ] **Step 4: Implement it, then update the lock file with `ldap3`'s hashes.**
- [ ] **Step 5: Run it on Windows and WSL to make sure it passes.**
- [ ] **Step 6: Commit** "Directory client: LDAPS or StartTLS binds, groups to roles, the account's state".

### Task 2: The Duo client and the protected store

**Files:**
- Create: `core/duo.py`, `core/osstore.py`
- Test: `tests/test_duo.py`

**Interfaces:**
- Produces, in `core/osstore.py`, the OS protected store:
  - `available() -> bool`
  - `put(name: str, secret: bytes)`
  - `get(name: str) -> bytes | None`
  - `delete(name: str)`

  On Windows it uses DPAPI (`passvault.dpapi_protect` and `dpapi_unprotect`), with the protected blob kept beside `netcheck.keys` in `netcheck.store` (JSON, name to base64). Elsewhere it uses the OS keyring backend that `passvault` keeps as `_old_backend` (the Keychain or Secret Service). `available()` is False where `passvault.NoKeyring` would be raised.
- Produces, in `core/duo.py`:
  - `Unavailable(Exception)` and `Denied(Exception)`.
  - `preauth(cfg, user) -> str`, returning "auth", "allow", "deny" or "enroll".
  - `push(cfg, user, cancel: threading.Event) -> None`. It raises `Denied` on deny, timeout or cancel, and `Unavailable` when Duo can't be reached. It uses `/auth/v2/auth` with `factor=push`, `async=1`, then polls `/auth/v2/auth_status` for up to 60 seconds.
  - `passcode(cfg, user, code) -> None`, raising `Denied` or `Unavailable`.
  - **Signing.** Requests are signed as Duo's Auth API v2 documents. Use the current signature version in Duo's docs (HMAC-SHA512 with `X-Duo-Date`, or HMAC-SHA1 if those docs still give it as the default), and add a test vector worked from the docs' own example.
  - **The secret.** It comes from `osstore.get("duo:" + cfg["id"])`. It is never a parameter, and never logged.
  - **What is never a pass.** "enroll" and "deny" from preauth are refusals. "allow" (Duo's bypass) passes only because the Duo admin chose it.

- [ ] **Step 1: Write the failing test.** Fake Duo with a local `http.server` on 127.0.0.1, setting `cfg["host"]` to it and allowing plain HTTP only in tests through a module flag that tests set. Assert:
  - The signature matches the docs' vector.
  - A push answered "allow" returns.
  - Answered "deny" raises `Denied`.
  - No answer within the time limit (shortened in the test) raises `Denied`.
  - Setting the cancel event raises `Denied` within 1 second.
  - A closed port raises `Unavailable`.
  - A right passcode returns, and a wrong one raises `Denied`.
  - The secret appears in no exception text.
  - `osstore` round-trips a value on this platform, or reports `available()` False in WSL without Secret Service.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it on Windows and WSL to make sure it passes.**
- [ ] **Step 5: Commit** "Duo Auth API client (push first, a code as backup) and the OS protected store".

### Task 3: PIN slots

**Files:**
- Create: `core/pinslot.py`, `core/tpm_windows.py`, `tests/manual_tpm_check.py`
- Test: `tests/test_pinslot.py`

**Interfaces:**
- Produces, in `core/pinslot.py`:
  - `best_kind() -> str`: "chip" (Windows, with the Microsoft Platform Crypto Provider opening), "store" (`osstore.available()`), or "pin".
  - `problem(kind, pin) -> str | None`:
    - "chip": exactly 6 digits, and not all one digit or a straight run up or down. These give the approved error sentences.
    - "store" and "pin": at least 8 characters.
  - `class Slot`. It has `.rec: dict`, which is stored, and `.seal(secret: bytes) -> dict`.
  - `new(kind, slot_id, pin) -> Slot`:
    - "chip": a persisted TPM RSA-2048 key named `Toner-` + `slot_id`, protected by the PIN. `seal` encrypts a random KEK with the public key (RSA-OAEP-SHA256), and AES-GCM seals the secret under the KEK.
    - "store": a random 32-byte pepper in `osstore` under `"pin:" + slot_id`. The KEK is HKDF(scrypt(PIN, salt, n=2**15) ‖ pepper).
    - "pin": the KEK is scrypt(PIN, salt, n=2**16).
  - `open(rec, slot_id, pin, sealed) -> bytes`: raises `WrongPin` or `PinLocked(seconds)`. It raises `SlotMissing` when the TPM key or the pepper isn't on this computer. That covers a different computer and a portable copy, which the spec says need a new PIN and an admin's approval.
  - `remove(rec, slot_id)`: deletes the TPM key or the pepper, if present on this computer.
- Produces, in `core/tpm_windows.py`, the NCrypt calls: `available()`, `create(name, pin) -> public_der`, `decrypt(name, pin, data) -> bytes`, `delete(name)`, and `LockedOut(seconds)`. They are all done through `ctypes`. Tests replace the module with a fake.
- **Wrong tries.**
  - "chip": the TPM counts. A lockout error becomes `PinLocked`. Toner also counts wrong PINs on the shared counter, so the window can show a wait before the chip's own lockout.
  - "store" and "pin": Toner's shared counter in `netcheck.keys` throttles, as for passwords: 5 free tries, then waits from 30 seconds, doubling, up to a cap of 900 seconds.

- [ ] **Step 1: Spike on the owner's Windows laptop before any test.** Create a PCP key with a PIN, encrypt with its public key, then:
  - decrypt with the right PIN;
  - decrypt with a wrong PIN (refused);
  - try again until the lockout and read its wait;
  - delete the key.

  Write the exact NCrypt calls and properties that worked (the PIN property, or usage auth) into the report. If the PCP can't take a PIN without the Windows Security prompt, stop with BLOCKED and say so. "chip" then waits, and Windows uses "store".
- [ ] **Step 2: Write the failing test** with a fake `tpm_windows`, plus the real "store" and "pin" kinds. Assert:
  - Round-trips for all three kinds.
  - A wrong PIN raises `WrongPin`.
  - The fake's lockout raises `PinLocked` with its seconds.
  - Five wrong PINs on "pin" then raise `PinLocked(30)`. The count survives reopening the keys file.
  - `problem("chip", "123456")` and `problem("chip", "111111")` give the approved sentence. `problem("chip", "12345")` gives "Use 6 digits.". `problem("store", "1234567")` gives "Use at least 8 characters.".
  - `remove` deletes the pepper.
- [ ] **Step 3: Run it to make sure it fails.**
- [ ] **Step 4: Implement it.** Add `tests/manual_tpm_check.py`: a script the owner runs by hand on a real TPM, covering the Step 1 cases and printing pass or fail. It isn't part of `run_all`.
- [ ] **Step 5: Run it on Windows and WSL. The owner runs `manual_tpm_check.py`.**
- [ ] **Step 6: Commit** "PIN slots: the TPM on Windows, the protected store, or a long PIN".

### Task 4: Directory accounts and connections in the keys file

**Files:**
- Modify: `core/datakey.py`, `core/roles.py`
- Test: `tests/test_directory_accounts.py`

**Interfaces:**
- Consumes: `directory.Config`, `directory.User`, `pinslot.*` and `envelope.*`.
- **The keys file.**
  - It gains `"directories": [Config, ...]`.
  - A directory account record is: `{"kind": "directory", "directory": id, "guid", "display", "slot_kind", "slot": rec, "sealed": {...} | None, "box_pub", "approved_role": str | None, "online_at": epoch, "groups_role": str | None, "created"}`.
  - The account's key in `accounts` is `User.name`.
- **The rules signature** now also covers `directories` (without secrets) and each directory account's `approved_role` and attested box key. Hand-edits of these read "tampered".
- Produces, in `core/datakey.py`:
  - `directory_account(name) -> dict | None`
  - `start_directory_account(user: User, directory_id, slot: Slot)`: writes an unapproved record with a new box key. The box key's private half is held in memory until approval.
  - `open_with_pin(name, pin) -> int`: opens the data key and the box key from `sealed`, through `pinslot.open`. Returns earlier fails, as `open_with_password` does.
  - `check_pin(name, pin) -> bool`
  - `set_online(name, at)` and `set_groups_role(name, role)`: these two fields are not signed. `online_at` is capped at now, so a clock moved back can't extend the offline hour.
- Produces, in `core/roles.py`:
  - `approve(name, slot: Slot)`: needs the rules key (an Admin) or `_root`.
    - It seals the data key and the account's box private under the slot.
    - It sets `approved_role` to the account's `groups_role`.
    - It attests `box_pub`, re-signs and syncs grants.
    - It audits "sign-in approved".
  - `needs_approval(name) -> str | None`:
    - "first", when there's no `sealed`;
    - "changed", when the groups role is above `approved_role` in keys terms: it allows unmasked or is Admin, and the approved role doesn't;
    - None otherwise.
  - `role_of(name)` for a directory account returns `groups_role` (permissions). Grants (`_sync`) use `approved_role`.
  - `set_directories(list)`: Admin only. It re-signs and audits "directory added", "directory changed" or "directory removed". Removing a directory removes its accounts and their slots.

- [ ] **Step 1: Write the failing test.** Assert:
  - An Admin approves a started account. Then `open_with_pin` opens the same data key, the account holds the backups key only if its approved role allows it, and an audit row names both people.
  - An Engineer can't approve, and gets `perms.Denied`.
  - The recovery key can approve.
  - A hand-edit of a directory's server, of its group map, or of an account's `approved_role` makes the state "tampered".
  - Editing `groups_role` to "Admin" makes `perms.is_admin()` True for that session, but no new grant is wrapped.
  - Moving the groups role from Tech to Engineer makes `needs_approval` "changed". Approving again grants the backups key.
  - `online_at` set an hour into the future is read as now.
  - Removing a directory removes its accounts.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, plus `tests/test_roles.py`, `tests/test_datakey*.py` and `tests/test_session.py`.**
- [ ] **Step 5: Commit** "Directory accounts and connections in netcheck.keys, signed; approval seals the data key into the PIN slot".

### Task 5: The sign-in steps, in core

**Files:**
- Create: `core/dirsignin.py`
- Modify: `core/session.py`
- Test: `tests/test_dirsignin.py`

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces, in `core/dirsignin.py`:
  - `classify(login) -> ("local", name) | ("directory", cfg, login)`: follows the Decisions' username rules. It reads the directories from the keys file without the data key open.
  - `class Attempt`. It holds the state of one sign-in: `cfg`, `user: User | None`, `stage` ("password", "duo", "pin", "choose-pin", "approve", "done"), and `offline: bool`.
  - `begin(login, password) -> Attempt`. It calls `directory.sign_in`.
    - When the directory is `Unreachable`: if the account exists, has `sealed`, and `online_at` is within 3600 seconds, it goes offline to "pin". Otherwise it raises `Unreachable`.
    - It raises `NotInGroup` when `role_for` is None, and `BadCredentials` as `datakey.WrongPassword`.
    - Every failure counts on the shared password counter.
    - On success it sets `online_at` and the groups role.
  - `after_password(a)`: moves to "duo" when `cfg["duo"]["on"]`, else to "pin" or "choose-pin". `preauth` "deny" or "enroll" raises `duo.Denied`.
  - `duo_push(a, cancel)` and `duo_code(a, code)` move to "pin" or "choose-pin".
  - `choose_pin(a, pin)`: makes the slot with `pinslot.best_kind()` and calls `datakey.start_directory_account`, then moves to "approve".
  - `approve(a, admin_name, admin_password)` and `approve_recovery(a, recovery)`:
    - open the data key as that admin with no session change: `datakey.open_with_password` (or `open_with_recovery`), then `roles.unlock()` so the rules key is held;
    - call `roles.approve`;
    - then `roles.close()` and `datakey.close()`, in a `finally`;
    - then the PIN signs the person in.
    - An admin that isn't an Admin raises `CannotApprove`.
  - `finish(a, pin)`: calls `session.sign_in_pin(a.user.name, pin)`. When `needs_approval` says "changed", it moves to "approve" first. `pinslot.SlotMissing` (a different computer, or a portable copy) moves to "choose-pin" and then "approve", with the "Your access changed" text.
  - "Forgot your PIN?" is `restart_pin(a)`. It is only allowed after a fresh online password check (and Duo). It removes the old slot, then moves to "choose-pin".
- Produces, in `core/session.py`:
  - `sign_in_pin(name, pin)`: like `sign_in`, with audit "signed in" and detail `directory {name}`. It records `full_at` (now) in memory.
  - `unlock_pin(pin)`.
  - `kind()`, returning "local", "directory" or "recovery".
  - `workday_over() -> bool`: `full_at` was more than 12 hours ago.
  - `lock(reason=None)`: a `reason` of "refused" makes `unlock_pin` and `unlock` refuse until a new sign-in.

- [ ] **Step 1: Write the failing test.** Use mocks: ldap3 `MOCK_SYNC`, the fake Duo from Task 2, and the fake TPM from Task 3. Walk:
  - a first sign-in: password → Duo push → choose PIN → approve as Admin → PIN → open;
  - a second sign-in: password → push → PIN;
  - offline within the hour: PIN only. Offline past the hour: `Unreachable`;
  - Duo unreachable: refused. Duo deny: refused and audited;
  - not in a group: `NotInGroup`;
  - a role change to Engineer: "approve" again before "done";
  - forgot PIN: a new slot, and approval again;
  - another computer (the fake TPM has no key): a new PIN, and approval again;
  - an Engineer trying to approve: `CannotApprove`;
  - `classify` for `ACME\bob`, `bob@acme.com`, `bob@other.com` (local, when no directory lists that suffix) and `admin`.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, plus `tests/test_session.py`, `tests/test_roles.py` and `tests/test_signin_ui.py`.**
- [ ] **Step 5: Commit** "Directory sign-in steps: password, Duo, the PIN and approval, with the offline hour".

### Task 6: The sign-in window

**Files:**
- Modify: `ui/signinwindow.py`
- Test: `tests/test_signin_directory_ui.py`

**Interfaces:**
- Consumes: `dirsignin.*`.
- **The flow.**
  - Next calls `classify`. A local name keeps today's flow. A directory name goes to the password page (offline: to the PIN page), and from there through Duo push (with "Enter a code instead"), the code page, choose PIN, approval (with "Use the recovery key") and PIN.
  - The Duo push runs on a worker thread, and "Cancel" sets its event. No step blocks the UI thread.
  - A wrong-PIN wait uses the existing `Wait` helper.
- [ ] **Step 1: Write the failing test.** Build the window headless with the same mocks, and drive each page as Task 5's walk does. Assert each page's approved title and texts, the order of pages, that "Not you?" returns to the name page from any page, and that the window accepts when the session is open.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, plus `tests/test_signin_ui.py`.**
- [ ] **Step 5: Commit** "Sign-in window: directory accounts, Duo, the PIN and approval".

### Task 7: The lock screen, the workday and offline

**Files:**
- Modify: `ui/lockscreen.py`
- Test: `tests/test_lock_directory.py`

- [ ] **Step 1: Write the failing test.** Assert:
  - A directory user's lock screen shows "PIN", and `unlock_pin` opens it.
  - After `lock(reason="refused")`, only the refusal sentence and "Sign in as someone else" show.
  - With `workday_over()` and the directory reachable (mocked), the PIN is refused and the screen offers "Sign in as someone else" to a full sign-in.
  - With `workday_over()` and the directory unreachable, the PIN still unlocks.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, plus `tests/test_signin_ui.py`.**
- [ ] **Step 5: Commit** "Lock screen: the PIN for directory accounts, the workday, and refused accounts".

### Task 8: The background check

**Files:**
- Create: `core/dircheck.py`
- Modify: `app.py` (start and stop it with the session)
- Test: `tests/test_dircheck.py`

**Interfaces:**
- `dircheck.run_once() -> str`, returning "ok", "refused", "offline" or "skipped". It uses `directory.look_up` as the service account (the service password comes from Toner's vault under `service:directory-<id>`).
  - Found, enabled and in a group: it sets `online_at` and the groups role, and returns "ok".
  - Not found, disabled, or in no group: it calls `session.lock(reason="refused")`, audits "locked: the directory refused the account", and returns "refused".
  - Unreachable: "offline", with nothing changed.
  - Not a directory session: "skipped".
- `dircheck.start()` and `stop()`: a 15-minute timer on a worker thread. It never runs on the UI thread.
- [ ] **Step 1: Write the failing test.** Cover each outcome, with ldap3 mocks and the session states. Also assert that the service password appears in no log.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it.**
- [ ] **Step 5: Commit** "Background check: a disabled or removed directory account locks Toner".

### Task 9: The Directories section on the Accounts page

**Files:**
- Modify: `ui/settings_pages/accounts.py`
- Create: `ui/directorydlg.py`
- Test: `tests/test_accounts_page.py` (extend it), `tests/test_directorydlg.py`

- **The dialog.**
  - It edits a `Config`. The service password goes to the vault (`service:directory-<id>`), and the Duo secret to `osstore` (`duo:<id>`).
  - "Test connection" runs `directory.test` on a worker thread.
  - When `osstore.available()` is False, "Second step: Duo" is disabled, with the approved sentence.
  - Saving calls `roles.set_directories`.
- **The accounts table** adds "Active Directory" and "LDAP" as Type values, and the "Unlocks with" column.
- **Removing** a directory account removes its slot from this computer, after the approved confirmation.
- [ ] **Step 1: Write the failing test.** Assert:
  - Add an AD directory, then edit it, then remove it. The keys file and audit rows follow.
  - The service password and the Duo secret never appear in `netcheck.keys`.
  - "Test connection" shows "Connected. Found {n} groups." on the mock, and "Toner couldn't connect: ..." on a closed port.
  - Plain LDAP is refused, with the reason in the message.
  - An Engineer never reaches the page (Part 2).
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, plus `tests/test_role_ui.py`.**
- [ ] **Step 5: Commit** "Accounts page: directories, with a connection test, groups to roles and Duo".

### Task 10: The command line

**Files:**
- Modify: `cli.py`
- Test: `tests/test_cli_signin.py` (extend it)

- [ ] **Step 1: Write the failing test.** Assert:
  - A directory user signs in with prompts "Username: ", "Password: ", then the Duo push line (Ctrl+C falls back to "Duo code: "), then "PIN: ". The command then runs.
  - A first sign-in, or one needing approval, prints the approved sentence and exits with code 3.
  - Offline within the hour asks only for "PIN: ".
  - No terminal still prints "Sign in needs a terminal." and exits with code 3.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it on Windows and WSL.**
- [ ] **Step 5: Commit** "Command line: directory accounts with Duo and the PIN".

### Task 11: Docs and the whole suite

**Files:**
- Modify: `README.md` (Signing in), `docs/release-notes-sign-in.md` (the approved lines), and the spec (mark the decisions above as built, and the new plan order).

- [ ] **Step 1: Show the owner the README paragraph, and wait.**
- [ ] **Step 2: Write the docs.**
- [ ] **Step 3: Run the whole suite on Windows, then on WSL (not at the same time), and pyflakes as CI runs it.** Every file passes except known flakes, each re-run alone.
- [ ] **Step 4: Commit** "Docs: directory sign-in".
