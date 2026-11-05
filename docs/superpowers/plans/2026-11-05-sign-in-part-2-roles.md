# Sign-in, part 2: roles and permissions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every account has a role: Admin, Engineer or Tech. An admin ticks what Engineers and Techs may do: push changes to devices, see config backups with passwords showing, the AI assistant, each tool, and each Settings page. Toner hides or locks what a role can't use. Unmasked config backups are encrypted so that a Tech's copy really can't show them.

**Architecture:**
- **Two new role keys, kept in `netcheck.keys`.**
  - A *rules key* (Ed25519) signs the roles, the account-to-role map and the backups public key.
  - A *backups key* (X25519) encrypts the secrets in config backups.
  - Anyone can encrypt to the backups key's public half. Only accounts whose role may see unmasked backups get its private half.
- **Each account gets its own box key** (X25519).
  - Its private half is sealed with the data key under the account's password: one seal holding 64 bytes, so sign-in still runs scrypt only once.
  - Role keys are wrapped to an account's public half. This lets an admin grant a key without knowing that person's password.
- **The recovery key gets a box key the same way.** A recovery sign-in acts as an Admin.
- **The rules key's fingerprint is also kept inside the encrypted database.** So stripping or downgrading the signature in `netcheck.keys` is caught.
- **Checks.** `core/perms.py` answers `allowed(key)` for the signed-in person. The window hides switched-off tools and the AI, disables push actions with a reason, and shows locked Settings pages read-only. Core functions that write to devices call `perms.require("push")` as a second line.

**Tech Stack:** Python 3.13, PySide6, `cryptography` (already there: X25519, Ed25519, HKDF, AES-GCM). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-04-user-sign-in-design.md` ("Roles and permissions", "Who decides what", "Around the edges"). Part 1's plan, `docs/superpowers/plans/2026-11-04-sign-in-part-1-the-lock.md`, built what this one stands on: `core/datakey.py`, `core/session.py`, and `ui/settings_pages/accounts.py`.

## Global Constraints

- **Wording.** Every piece of text a person sees is shown to the owner before it is built. All of this plan's text is in "Wording to approve" below. Execution starts only after the owner has answered that list. Any string not on it goes back to the owner before it is built.
- **Dependencies.** Nothing new is installed.
- **Platforms.** Windows, Linux and macOS ship together under one version. CI runs Windows and Linux on Python 3.13.
- **Tests.** Tests run headless and must keep passing.
  - A test with no `netcheck.keys` has sign-in switched off. There, `perms.allowed()` is `True` for everything, so existing tests run unchanged.
  - Tests use `from core.sqldb import sqlite3`, never the stdlib module.
  - Run all: `PYTHONUTF8=1 QT_QPA_PLATFORM=offscreen "/c/Users/Joshua Wetlesen/AppData/Local/Programs/Python/Python313/python.exe" tests/run_all.py`
  - Run one file: the same command with `tests/test_x.py`.
  - Linux (WSL): `MSYS_NO_PATHCONV=1 wsl.exe -e bash -lc 'cd "/mnt/c/Claude Code/netcheck" && QT_QPA_PLATFORM=offscreen ~/toner-venv/bin/python tests/run_all.py'`
- **Test files.** New test files start with the same lines as `tests/test_hardening.py` lines 1-18 and end with `print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)`.
- **Git.**
  - Work on branch `roles`, made from `main`.
  - Commit locally; the owner pushes.
  - Never stage `.postman/`, `postman/`, `.impeccable/` or `.superpowers/`.
- **Secrets.**
  - Masked inspection only.
  - No secret, password, key or wrapped key goes in a log, an exception message or the audit detail.
- **Old copies.** A Part 1 `netcheck.keys` (accounts with 32-byte seals, no roles) must keep opening. Every account on it becomes an Admin: on a Part 1 copy every account could already do everything.

## Review Focus

1. **Someone edits `netcheck.keys` by hand.** Examples: a role changed to Admin, the signature removed, the file put back to Part 1's format, or the backups public key swapped. Everyone then gets the Tech defaults, the Accounts page explains why, and only a recovery-key sign-in that saves the roles puts it right. Test in Task 4.
2. **Upgrading a busy Part 1 copy.** Take 40 organizations, with config backups kept unmasked ("Hide passwords in backups" off). The first Admin sign-in moves every unmasked body behind the backups key, with the "Encrypting Toner's data" progress window. A crash halfway finishes on the next sign-in, and nothing is lost or left showing. Test in Task 5.
3. **A Tech is signed in when a scheduled backup runs with masking off.** The secrets are still kept, encrypted to the backups key. The Tech can't read them, and an Admin later can. Test in Task 5.
4. **The last Admin.** Demoting or removing the only Admin is refused with "Toner needs at least one Admin." Test in Task 4.
5. **An account is granted "see unmasked" before it has a box key.** This is a Part 1 account that hasn't signed in since the upgrade. It gets the key at its first sign-in after an Admin has been signed in once. Until then the Configs page says why it can't show passwords, and nothing fails. Test in Task 4.

## Decisions in this plan (my calls; the owner should check them)

- **Admin is fixed.** It has every permission and can't be edited, so an admin can't lock everyone out of the Accounts page. Only Engineer and Tech have tick boxes. There are three roles and no way to add more yet.
- **Engineer by default:** everything is on.
- **A new account starts as a Tech** in the Add account dialog. Every account on an upgraded Part 1 copy starts as an Admin.
- **Tech by default:**
  - Push is off, and seeing unmasked backups is off.
  - Every Settings page is locked except Appearance and Terminal.
  - Every tool and the AI are on.
- **How a switched-off feature looks.** Tools and the AI are hidden. Push actions stay in view but are disabled, with a reason as the tooltip. Locked Settings pages show read-only under a banner.
- **What "push changes to devices" covers.** These are the paths Toner has today:
  - Command Runner commands that aren't read-only (`cmdrun.read_only_for`);
  - the firmware transfer, clean-up and boot changes;
  - Ansible playbook runs;
  - SSH Keys "Add to device";
  - SCP uploads to a device;
  - API Tester requests other than GET, HEAD and OPTIONS.

  Toner has no config push, config restore or device factory reset yet. When one is added it must call `perms.require("push")`.
- **The interactive terminal is not split into reading and changing.** "Sessions (SSH, Telnet, serial)" is a tool that is either on or off. A person with a terminal can type anything.
- **A tampered rules file gives everyone the Tech defaults,** Admins included, until someone signs in with the recovery key and saves the roles.
- **A Part 1 copy's recovery key gets its box key the next time it is used.** Until then the recovery key opens the data, but not the backups key. If every Admin's password is lost before that, the unmasked parts of old backups are gone; the masked backups stay. "Make a new recovery key..." on the Accounts page closes that gap at once.
- **Role changes reach a person at their next sign-in.** Only the Accounts page's own account sees them at once. Signing in always restarts the window, so a running window keeps the role it opened with.

## Wording to approve (drafts, before Task 1)

- **Roles:** "Admin", "Engineer", "Tech".
- **Permission names:**
  - "Push changes to devices"
  - "See passwords in config backups"
  - "AI assistant"
  - each Tools entry by the name it has in Tools today
  - "Sessions (SSH, Telnet, serial)", "Remote desktop (RDP)", "Automation (Ansible)"
  - each Settings page by its title
- **Disabled action tooltip:** "Your role doesn't allow this. Ask an admin."
- **Locked Settings page banner:** "Your role can view this page but not change it."
- **Command Runner refusal:** "Your role can't run commands that change a device: {commands}"
- **Configs page, when passwords stay hidden:**
  - for a role without the permission: "Passwords are hidden for your role."
  - for a role with it but no key yet: "An admin needs to sign in to this copy once before you can see passwords in backups."
- **Accounts page:**
  - The table gets a column "Role". The Add account dialog gets a "Role" drop-down. A new button reads "Change role...".
  - A section "Roles" with: "Admins can do everything. Tick what Engineers and Techs can do." It holds a table of permissions with an Engineer column and a Tech column, and a "Save roles" button.
  - "Toner needs at least one Admin."
  - Tamper banner: "The roles were changed outside Toner, so everyone has a Tech's permissions for now. Sign in with the recovery key, then save the roles to put them right."
- **Audit entries:** "role changed" (detail `{name}: {old} to {new}`), "role permissions changed" (detail `{role}: {permission} on` or `off`, one entry per change), "roles were changed outside Toner".
- **Release notes, three lines:**
  - "Accounts now have a role: Admin, Engineer or Tech. Every account on an upgraded copy starts as an Admin."
  - "An admin chooses what Engineers and Techs can do in Settings > Accounts and sign-in."
  - "Passwords kept in config backups are now encrypted separately, and only roles allowed to see them can."

---

### Task 1: Envelope crypto

**Files:**
- Create: `core/envelope.py`
- Test: `tests/test_envelope.py`

**Interfaces:**
- Produces, in `core/envelope.py`:
  - `new_box_key() -> (private: bytes, public: bytes)`: raw 32-byte X25519.
  - `wrap(public: bytes, secret: bytes, aad: bytes) -> str`: base64 of the ephemeral public key (32 bytes), then the nonce (12), then the AES-GCM ciphertext. The key comes from HKDF-SHA256 over the shared secret with `info=b"toner-envelope"`, 32 bytes.
  - `unwrap(private: bytes, blob: str, aad: bytes) -> bytes`: raises `cryptography.exceptions.InvalidTag` on a wrong key, wrong AAD or tampering. Raises `ValueError` on a blob too short to hold the header.
  - `new_signing_key() -> (private: bytes, public: bytes)`: raw Ed25519.
  - `sign(private: bytes, data: bytes) -> str`: base64.
  - `verify(public: bytes, data: bytes, sig: str) -> bool`: never raises on bad input.
  - `canonical(obj) -> bytes`: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
  - `fingerprint(public: bytes) -> str`: SHA-256 hex.

- [ ] **Step 1: Write the failing test.**
  - A round trip of `wrap`/`unwrap` returns the secret.
  - `unwrap` with another key, or with `aad` changed by one byte, raises `InvalidTag`.
  - Two wraps of the same secret differ.
  - `sign`/`verify` is True. One flipped byte in the data, a signature made by another key, `"not base64"` and `""` all give False.
  - `canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()`.
- [ ] **Step 2: Run it to make sure it fails** (`ModuleNotFoundError`).
- [ ] **Step 3: Implement `core/envelope.py`** with `cryptography`'s X25519, Ed25519, HKDF and AESGCM.
- [ ] **Step 4: Run it to make sure it passes.**
- [ ] **Step 5: Commit** "Envelope crypto: X25519 wraps and Ed25519 signatures for role keys".

### Task 2: Box keys for accounts and the recovery key

**Files:**
- Modify: `core/datakey.py`
- Test: `tests/test_datakey_boxes.py`

**Interfaces:**
- Consumes: `envelope.new_box_key`.
- Produces, in `core/datakey.py`:
  - **The seal format.** An account's (or the recovery key's) seal now holds `data key (32) + box private (32)`. Its record gains `"box_pub"` (base64). A 32-byte seal is a Part 1 record. `open_with_password` and `open_with_recovery` upgrade it while they hold the password or code: they make a box key, re-seal and write, under the file lock and in the same `_attempt` write.
  - `_account(...)` (used by `create`, `add_local` and `set_password`) always makes a new box key.
  - `create` and `new_recovery` give the recovery seal a box key.
  - `box_private() -> bytes | None`: the signed-in account's (or the recovery key's) private box key. It is held from opening until `close()`.
  - `box_public(name: str | None) -> bytes | None`: `None` as the name means the recovery key. Returns `None` for a Part 1 record.
  - `signed_in_name() -> str | None`: the stored spelling, or `None` for a recovery sign-in.
  - `read() -> dict`: a deep copy of the file, under the lock.
  - `edit(fn)`: the public name of `_change`.
  - New account records gain `"role"`, which defaults to `"Admin"` when missing. `add_local(name, password, role="Admin")` takes the role. `accounts()` returns `"role"` too.

- [ ] **Step 1: Write the failing test.**
  - `create` makes `box_pub` for the account and the recovery key. The seal opens to 64 bytes, and `box_private()` matches `box_pub`.
  - Write a Part 1-shaped file by hand: a 32-byte seal, no `box_pub` and no role. Then:
    - `open_with_password` opens it, adds `box_pub`, keeps the data key the same, and `accounts()` shows the role `"Admin"`;
    - opening again works;
    - the throttle count is unchanged by the upgrade.
  - The same holds for a Part 1 recovery seal opened with `open_with_recovery`.
  - `set_password` gives that account a new `box_pub`.
  - `close()` makes `box_private()` `None`.
  - An unknown name still costs one scrypt. Time it against a known name, as Part 1's test does.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement.** Keep one scrypt per attempt: the KEK opens one seal, and its payload's length tells the format.
- [ ] **Step 4: Run it, then `tests/test_datakey.py`, `tests/test_session.py` and `tests/test_signin_ui.py`.** All pass.
- [ ] **Step 5: Commit** "Account and recovery box keys, upgraded from Part 1 seals at sign-in".

### Task 3: The permission catalogue

**Files:**
- Create: `core/perms.py`
- Test: `tests/test_perms.py`

**Interfaces:**
- Consumes: nothing from earlier tasks. This task is data only; Task 4 adds the checks to the same module.
- Produces, in `core/perms.py`:
  - `TOOLS`: a list of `(key, label)`, in Tools order:
    - `tool:command-runner`, `tool:api-tester`, `tool:ping`, `tool:live-ping`, `tool:path-monitor`, `tool:port-scanner`, `tool:iperf`
    - `tool:find-devices`, `tool:topology`, `tool:wifi`, `tool:snmp`, `tool:syslog`
    - `tool:firmware`, `tool:tftp`, `tool:sftp`, `tool:ftp`, `tool:scp`, `tool:copy-files`
    - `tool:tls`, `tool:openssl`, `tool:ssh-keys`, `tool:playbook-editor`, `tool:mac-lookup`, `tool:wol`, `tool:subnet`
    - then `tool:sessions`, `tool:rdp`, `tool:automation`

    The labels are the Tools names, plus the three approved names.
  - `SETTINGS_PAGES`: the 21 page titles from the spec, as keys `settings:<title>`.
  - `PERMISSIONS = [("push", ...), ("unmasked", ...), ("ai", ...)] + TOOLS + SETTINGS`: every switchable key with its approved label.
  - `DEFAULTS = {"Engineer": {every key: True}, "Tech": {...}}`, as listed under "Decisions in this plan".
  - `REASON`: the approved tooltip, and `class Denied(PermissionError)` whose default message is `REASON`.

- [ ] **Step 1: Write the failing test.**
  - `DEFAULTS["Tech"]`: `push` and `unmasked` are False, `settings:Appearance` and `settings:Terminal` are True, every other `settings:` key is False, and every `tool:` key and `ai` are True.
  - Every value in `DEFAULTS["Engineer"]` is True.
  - Every key in `DEFAULTS["Tech"]` and `DEFAULTS["Engineer"]` is in `PERMISSIONS`, and the reverse holds too.
  - `len(SETTINGS_PAGES) == 21`, and each title is one of `ui/settings.py`'s page titles. Import the module and read `GROUPS`.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it to make sure it passes.**
- [ ] **Step 5: Commit** "Permissions: the catalogue and the role defaults".

### Task 4: Signed roles, role keys and the checks

**Files:**
- Create: `core/roles.py`
- Modify: `core/perms.py` (add the checks), `core/session.py` (call `roles.unlock()` after a successful open and `roles.close()` in `_close`), `core/db.py` (setting `rules_key`, default `""`, in `GLOBAL_ONLY` and `NOT_PORTABLE`)
- Test: `tests/test_roles.py`

**Interfaces:**
- Consumes: `datakey.read`, `datakey.edit`, `datakey.box_private`, `datakey.box_public`, `datakey.signed_in_name`, `envelope.*`, and `perms.DEFAULTS`.
- Produces, in `core/perms.py` (it imports `roles`; `roles` reads `perms.DEFAULTS` inside its functions, so neither import loops):
  - `allowed(key) -> bool`:
    - True when `not datakey.exists()`.
    - False when nobody is signed in (`session.state() == "signed_out"`).
    - Otherwise `roles.permissions(roles.role_of(datakey.signed_in_name()))[key]`.
  - `is_admin() -> bool`: the role of the signed-in person is Admin, or sign-in isn't set up.
  - `require(key)`: raises `Denied` when not `allowed(key)`.
- Produces, in `core/roles.py`:
  - `ROLES = ("Admin", "Engineer", "Tech")`
  - **What the file holds.**
    - The keys file gains `"roles": {"Engineer": {perm: bool}, "Tech": {perm: bool}}`, `"rules_pub"`, `"rules_sig"`, `"backups_pub"`, `"grants": {account name: {"rules": wrap, "backups": wrap}}` and `"recovery_grants": {...}`.
    - The signature covers `canonical({"roles": ..., "accounts": {name: role}, "backups_pub": ...})`.
    - Wraps use the AAD `b"toner-role-key:" + kind + b":" + name` (`kind` is `rules` or `backups`; the name is empty for the recovery key).
  - `state() -> "off" | "unsigned" | "ok" | "tampered"`:
    - `"off"` means there is no keys file.
    - `"unsigned"` means a Part 1 file, before any Admin has signed in under Part 2. It is only valid while the DB setting `rules_key` is empty.
    - `"tampered"` means any of these: the signature fails; `rules_pub`'s fingerprint differs from `rules_key`; or `rules_key` is set but the file has no signature.
  - `role_of(name: str | None) -> str`:
    - `None` (a recovery sign-in) gives `"Admin"`.
    - When the state is `"tampered"`, every name gives `"Tech"`.
    - When it is `"off"` or `"unsigned"`, every name gives `"Admin"`.
  - `permissions(role) -> dict[str, bool]`:
    - Admin gets every key True.
    - When the state is `"tampered"`, every role gets `perms.DEFAULTS["Tech"]`.
    - Otherwise it is the stored value, with missing keys taken from `perms.DEFAULTS[role]`.
  - `unlock()`, called by `session` after sign-in, does four things:
    1. It unwraps this account's grants with `datakey.box_private()`.
    2. When the signed-in person is an Admin (or the recovery key), the state isn't `"tampered"`, and no rules key exists yet, it makes both role keys, signs, and sets `rules_key`. This is the Part 1 upgrade: every account is already `"Admin"`.
    3. It runs `sync_grants()` when it holds the rules key.
    4. When the state is `"tampered"`, it audits "roles were changed outside Toner" once per sign-in.
  - `sync_grants()`: for every account with a `box_pub`, it wraps the rules key when the role is Admin, and the backups key when `permissions(role)["unmasked"]`. It does the same for the recovery key, which counts as an Admin. It removes grants that no longer apply. A grant is written only when the caller holds that role key.
  - `holds(kind) -> bool`, `backups_public() -> bytes | None`, `backups_private() -> bytes | None`
  - `set_role(name, role)`:
    - It needs the rules key, else raises `datakey.Locked("Sign in first.")`.
    - It refuses to leave no Admin: `ValueError("Toner needs at least one Admin.")`.
    - It then re-signs, runs `sync_grants()`, audits "role changed", and notifies.
  - `set_permissions(role, changes: dict[str, bool])`:
    - `role` must be Engineer or Tech.
    - It re-signs, runs `sync_grants()`, audits one "role permissions changed" per changed key, and notifies.
  - **Repairing a tampered file.** On a recovery sign-in when the state is `"tampered"`, `set_permissions` and `set_role` make a new rules key. They replace `rules_pub` and `rules_key`, and re-sign what the Accounts page shows. That is the fix.
  - `on_change(fn)` and `close()`.
  - `datakey.remove(name)` refuses to remove the last Admin and drops that account's grants. The refusal goes through `roles`, so `datakey` doesn't import `roles`: `roles` passes a check into `datakey.remove`'s `_change`, or `remove` moves into `roles`. Pick one and note it.

- [ ] **Step 1: Write the failing test.**
  - **A Part 1 file opened by its Admin.** The state goes `"unsigned"` → `"ok"`, `rules_key` is set, and the Admin holds both role keys.
  - **A second Admin added through `datakey.add_local(..., role="Admin")`.** After `sync_grants()`, they hold both keys at their sign-in. A Tech holds neither.
  - **A Part 1 Admin with no `box_pub`.** They get grants at their first sign-in once another Admin has run `sync_grants()` after it. Until then `holds("backups")` is False and nothing raises.
  - **Making a Tech's role allow `unmasked`.** That Tech holds the backups key at their next sign-in. Turning it off again removes the grant.
  - **Tampering**, each making the state `"tampered"`, `role_of` give `"Tech"` for an Admin, and one audit row appear:
    - (a) change a role in the JSON by hand;
    - (b) delete `rules_sig`;
    - (c) put back the Part 1 file saved earlier;
    - (d) replace `backups_pub` with a new key.
  - **The repair.** A recovery sign-in, then `set_permissions("Tech", {})`, makes the state `"ok"` again.
  - **The checks.**
    - With no keys file, `perms.allowed(k)` is True for every key in `PERMISSIONS`, and `is_admin()` is True.
    - Signed in as a Tech on defaults: `allowed("push")` and `allowed("unmasked")` are False, `allowed("settings:Appearance")` is True, `allowed("settings:Security")` is False, `allowed("tool:snmp")` is True, and `require("push")` raises `Denied` with the approved text.
    - Signed in as an Engineer: every key is True and `is_admin()` is False.
    - Signed out: `allowed("tool:snmp")` is False.
  - **The last Admin.** Demoting it, or removing it, raises "Toner needs at least one Admin."
  - **No secrets in the audit.** No audit detail contains `wrap`, `sig` or any base64 key.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, then `tests/test_session.py`, `tests/test_datakey.py` and `tests/test_accounts_page.py`.**
- [ ] **Step 5: Commit** "Roles: signed rules, role keys granted per account, the checks; tamper falls back to Tech".

### Task 5: Config backup secrets behind the backups key

**Files:**
- Modify: `core/db.py` (`config_backups` gains `secret BLOB`, added by the existing column-migration helper), `core/backup.py` (`store`, `get_text`), `core/lockdown.py` (or a new `core/backupsplit.py` if `lockdown.py` grows past one screen), `ui/setupdlg.py` (run it with the progress window), `ui/configs.py`, `core/orgs.py` only if it copies columns by name
- Test: `tests/test_backup_secrets.py`

**Interfaces:**
- Consumes: `roles.backups_public`, `roles.backups_private`, `roles.holds`, `perms.allowed`, `envelope.wrap`, `envelope.unwrap`.
- Produces:
  - **Storing.** `backup.store(device, text, mask=True, keep=None)`:
    - `body` is always `clean(text, mask=True)`.
    - When `mask` is False and `roles.backups_public()` exists, `secret` is `envelope.wrap(backups_pub, zlib(clean(text, mask=False)), b"toner-backup:" + sha)`.
    - `sha` is the digest of `clean(text, mask)` as before, so changing only a password still counts as a change.
    - `added`/`removed` come from the masked bodies.
    - When `mask` is False with sign-in off (no keys file), it behaves as today: `body` is unmasked and `secret` is `None`.
  - **Reading.** `backup.get_text(backup_id, org=None, unmasked=False)`:
    - With `unmasked=True`, `perms.allowed("unmasked")` and `roles.holds("backups")`, it returns the decrypted secret text when the row has one.
    - Otherwise it returns `body`.
    - It never raises for a row it can't decrypt: it returns `body`.
  - `backup.secrets_hidden_reason(row) -> str | None`: the approved Configs sentence that applies, or `None`.
  - **The upgrade split.** `backupsplit.pending() -> list[Path]` lists the databases that have a `config_backups` row whose `body` differs from `clean(body, mask=True)`. `backupsplit.run(progress)` moves each one: it sets `secret` to that body wrapped, and `body` to the masked text, in one transaction per database. It is idempotent, because a masked body masks to itself.
    - It runs after `roles.unlock()` has made the backups key, at the same sign-in step that runs `lockdown`.
    - It uses `setupdlg.EncryptDialog`, with no new wording.
  - **The Configs page.** View, compare, Save as... and Copy ask for `unmasked=True`. When `secrets_hidden_reason` gives a sentence, it is shown in the page's existing status line.

- [ ] **Step 1: Write the failing test.**
  - An Admin stores a backup with `mask=False`. The row's `body` is masked and `secret` is set. `get_text(..., unmasked=True)` gives the password back, and `unmasked=False` doesn't.
  - Signed in as a Tech, `store(mask=False)` still writes `secret`. `get_text(unmasked=True)` gives the masked text, and `secrets_hidden_reason` is "Passwords are hidden for your role."
  - An Engineer with the permission but no grant yet gets the "An admin needs to sign in..." sentence.
  - Changing only the enable secret between two backups counts as `"changed"`.
  - **The split.** Two organization databases, made before sign-in with unmasked bodies, are split by `backupsplit.run()`. Run it again and nothing changes. Kill it halfway: monkeypatch it to raise after the first database, then run again, and every row is split with the right text.
  - **Moving a device** to another organization (`core/orgs.py`) keeps its secret readable.
  - **With sign-in off,** existing behaviour is unchanged: `body` is unmasked when `mask=False`.
  - **The secret is encrypted on disk.** No row's `secret` column contains the password's bytes.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, then `tests/test_backup*.py`, `tests/test_demarc.py`, `tests/test_hardening.py`, `tests/test_configs*.py` and `tests/test_lockdown*.py`.**
- [ ] **Step 5: Measure.** Split 2,000 devices × 50 versions (100,000 rows) on Windows. Note the time in the report. Above 60 seconds, batch the rows in one `executemany` per database and measure again.
- [ ] **Step 6: Commit** "Config backups: passwords kept encrypted to the backups key; upgrade moves old unmasked bodies".

### Task 6: Pushing changes needs the permission

**Files:**
- Modify:
  - `core/cmdrun.py` (`run_on_device` and `run_many`: refuse when `risky_commands` is not empty and push isn't allowed);
  - `core/firmware.py` (`transfer`, `cleanup`, and the boot change in `staged`);
  - `core/ansible.py` (`run`);
  - `core/sshkeys.py` (`add_to_device`);
  - the SCP upload path in `core/scp.py`, and the API Tester's send in `ui/apitool.py` (non-GET/HEAD/OPTIONS);
  - plus the matching buttons in `ui/tools2.py` (Command Runner), `ui/firmware.py`, `ui/playbookeditor.py`, `ui/automation.py`, `ui/sshkeysui.py`, `ui/tools3.py` (SCP) and `ui/apitool.py`.
- Test: `tests/test_push_perms.py`

**Interfaces:**
- Consumes: `perms.allowed("push")`, `perms.require("push")`, `perms.REASON`.
- Produces: the core functions above raise `perms.Denied` before connecting.
  - The UI disables each push button with `perms.REASON` as the tooltip.
  - The Command Runner shows "Your role can't run commands that change a device: {commands}" and runs nothing when any command isn't read-only. Read-only commands still run.

- [ ] **Step 1: Write the failing test.** Do it as a Tech, with every core entry point monkeypatched below the check so nothing connects.
  - Each of the six core paths raises `Denied`.
  - `cmdrun.run_on_device` with `"show version"` doesn't raise.
  - Each UI button above is disabled and has the tooltip.
  - The same calls as an Engineer don't raise, and the buttons are enabled.
  - With no keys file, nothing changes.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.** Put the check in the core function first, then the button. Never check only in the UI.
- [ ] **Step 4: Run it, then `tests/test_cmdrun*.py`, `tests/test_firmware*.py`, `tests/test_ansible*.py`, `tests/test_sshkeys*.py`, `tests/test_scp.py` and `tests/test_apitool*.py`.**
- [ ] **Step 5: Commit** "Pushing to devices needs the role's permission, checked in core and shown in the window".

### Task 7: Tools, the AI and Settings pages follow the role

**Files:**
- Modify:
  - `ui/nav.py`: `PageStack.setTabVisible(widget, on)` and `NavStack.setTabVisible(widget, on)`. A hidden entry leaves the list, its shortcut skips it, and selecting it is refused.
  - `ui/tools.py`: `ToolsTab.apply_permissions()`. Each entry is shown when its `tool:` key is allowed. `show_tool` refuses a hidden one.
  - `app.py`: `apply_permissions()`, run after the window is built.
    - Sessions, Automation/AI and the Assistant panel follow `tool:sessions`, `tool:automation` and `ai`.
    - The "Open RDP" and "Open in Tools" menu entries hide for hidden tools.
    - `open_tool`, `open_rdp_console` and `open_ssh_console` return early when not allowed.
  - `ui/settings.py`: `apply_role()`.
    - A page whose `settings:` key isn't allowed shows read-only, through the same path that shows "Managed by Global", under the approved banner.
    - "Accounts and sign-in" is hidden unless `perms.is_admin()`.
    - `ask_save` never writes a locked page.
- Test: `tests/test_role_ui.py`

**Interfaces:**
- Consumes: `perms.allowed`, `perms.is_admin`, `perms.TOOLS`.
- Produces: `MainWindow.apply_permissions()`, `ToolsTab.apply_permissions()` and `SettingsTab.apply_role()`, each safe to call again.

- [ ] **Step 1: Write the failing test.** Build the window headless, as `tests/test_signin_ui.py` does.
  - **As a Tech with `tool:snmp` turned off:** the SNMP entry is gone from Tools, and `show_tool(tools.snmp)` doesn't switch to it.
  - **As a Tech on defaults:**
    - the Security page is disabled and shows the banner;
    - Appearance is enabled;
    - "Accounts and sign-in" isn't in the list;
    - Settings search for "lock" still finds the Security page.
  - **With `ai` off:** the Assistant panel's button is hidden, and every other way to open the panel does nothing (find them with `grep -n "assistant" app.py`).
  - **Both cases together:** a Tech in an organization, whose Security page is locked by role *and* managed by Global, shows one banner, not two. The role banner wins.
  - **As an Engineer:** everything is shown and enabled, except "Accounts and sign-in".
  - **With no keys file:** nothing is hidden.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run it, then `tests/test_ui.py`, `tests/test_settings*.py`, `tests/test_tools*.py` and `tests/test_signin_ui.py`.**
- [ ] **Step 5: Commit** "Tools, the AI and Settings pages follow the signed-in role".

### Task 8: The Accounts page manages roles

**Files:**
- Modify: `ui/settings_pages/accounts.py`
- Test: `tests/test_accounts_page.py` (extend it)

**Interfaces:**
- Consumes: `datakey.accounts` (with `role`), `datakey.add_local(..., role=)`, `roles.set_role`, `roles.set_permissions`, `roles.permissions`, `roles.state`, `perms.PERMISSIONS`.
- Produces: the page's Role column, the role drop-down on Add account, "Change role...", and the Roles section with "Save roles". The tamper banner shows when `roles.state() == "tampered"`.

- [ ] **Step 1: Write the failing test.**
  - The Add account dialog's Role drop-down starts at "Tech" (my call: the least a new account can do).
  - Adding an account as a Tech shows "Tech" in the Role column.
  - "Change role..." to Engineer updates it and writes one audit row.
  - Demoting the only Admin shows "Toner needs at least one Admin." and changes nothing.
  - **The Roles section.** Unticking "Push changes to devices" for Engineer, then "Save roles":
    - stores the change;
    - writes one audit row;
    - makes `perms.allowed("push")` False for an Engineer who signs in afterwards.
  - The Admin column isn't shown.
  - With a tampered file, the banner shows. After a recovery sign-in, "Save roles" clears it.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.** The permission table groups rows as `PERMISSIONS` lists them: actions, then tools, then Settings pages.
- [ ] **Step 4: Run it to make sure it passes.**
- [ ] **Step 5: Commit** "Accounts page: roles for each account and the Engineer and Tech permissions".

### Task 9: Docs and the whole suite

**Files:**
- Modify: `README.md` (the Signing in section: one paragraph on roles, in the approved words), `docs/release-notes-sign-in.md` (the three approved lines), `docs/superpowers/specs/2026-11-04-user-sign-in-design.md` (mark the "my call" decisions above as built)
- Test: the whole suite on Windows and Linux, and pyflakes as CI runs it.

- [ ] **Step 1: Show the owner the README paragraph, and wait.**
- [ ] **Step 2: Write the docs.**
- [ ] **Step 3: Run the whole suite on Windows and on WSL, and pyflakes.** Every file passes except the known `test_nettools2` traceroute/MTR flake.
- [ ] **Step 4: Commit** "Docs: roles in the README and release notes".
