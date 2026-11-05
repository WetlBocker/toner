# Sign-in, part 1: the lock — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Toner's data is encrypted at rest under one data key. It opens only when someone signs in with a local account, or uses the recovery key. A lock screen covers Toner after it has been idle. The vault's master password goes away.

**Architecture:**
- **The data key.** A random 32-byte key in `core/datakey.py` is sealed once for each local account (scrypt over the password, then AES-GCM), and once under a recovery key. The seals are kept in `netcheck.keys` beside `netcheck.db`.
- **Databases.** Every database connection goes through `core/sqldb.py`, which uses SQLCipher (`sqlcipher3`) and applies the key.
- **Side files** (session logs, saved host keys) are sealed with AES-GCM by `core/sealedfile.py`.
- **Signing in.** `core/session.py` holds who is signed in and whether Toner is locked. Signing out ends the process and starts Toner again at the sign-in window, so no key survives in memory.

**Tech Stack:** Python 3.13, PySide6, `cryptography` (already there), SQLCipher via `sqlcipher3-wheels` (new: needs the owner's approval), `keyring` (already there).

**Spec:** `docs/superpowers/specs/2026-11-04-user-sign-in-design.md`

**The whole design is built in five plans, one after another.** Each one ships working software:

1. **The lock** (this plan): data key, local accounts, recovery key, encryption, the sign-in and lock screens, upgrade from the master password, and the command line.
2. **Roles and permissions:** Admin, Engineer and Tech; per-role switches for tools, AI, pushing changes, unmasked backups and Settings pages; signed rules; a second key for unmasked backups.
3. **The PIN and enrolment:** a TPM or Secure Enclave PIN with a fallback, and an admin approving a directory or SSO user's first sign-in.
4. **AD and LDAP, with Duo:** LDAPS bind, group-to-role mapping, Duo push and code, the service-account re-check, the one-hour offline rule and the workday length.
5. **Single sign-on:** OpenID Connect with PKCE and a loopback redirect, presets for Entra, Okta, Google Workspace and Duo SSO, groups mapped to roles, and the refresh-token re-check.

## Global Constraints

- **Wording.** Every piece of text a person sees is shown to the owner before it is built. The text in this plan is a draft. Tasks that add text have a "show the wording" step, and building waits for the owner's answer.
- **Dependencies.** Nothing new is installed without the owner's yes. This plan needs `sqlcipher3-wheels==0.5.7` (Task 1) and a common-password list (Task 3).
- **Platforms.** Windows, Linux and macOS ship together under one version. CI runs Windows and Linux on Python 3.13 with `pip install --require-hashes --only-binary=:all: -r requirements.lock`, so every new package needs binary wheels for cp313 on win_amd64 and manylinux x86_64, and also on macOS arm64 for the Mac build.
- **Tests.** Tests run headless and must keep passing. A test database with no data key stays plain SQLite, so existing tests run unchanged.
  - Run all: `PYTHONUTF8=1 QT_QPA_PLATFORM=offscreen "/c/Users/Joshua Wetlesen/AppData/Local/Programs/Python/Python313/python.exe" tests/run_all.py`
  - Run one file: the same with `tests/test_x.py`.
  - Linux (WSL): `MSYS_NO_PATHCONV=1 wsl.exe -e bash -lc 'cd "/mnt/c/Claude Code/netcheck" && QT_QPA_PLATFORM=offscreen ~/toner-venv/bin/python tests/run_all.py'`
- **Test files.** New test files start with the same lines as `tests/test_hardening.py` lines 1-18: a temporary `SP`, `NETCHECK_DB`, `APPDATA`, a fake keyring and the `check(name, cond, extra="")` helper. They end with `print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)` as the other files do.
- **Git.** Commit locally, and only when the owner says to commit. The owner pushes. Never stage `.postman/`, `postman/` or `.impeccable/`. Work on branch `sign-in`.
- **Passwords.**
  - Inspection is masked only.
  - Toner never decrypts other apps' stored passwords.
  - A secret never goes in a log, an exception message or the audit detail.
- **Exceptions to encryption.** These files stay plain: `toner.log`, `toner-service.log`, `ssh-tunnel.log` (logs written before sign-in or by another program, and none keeps secrets), `oui.txt`, `ca-bundle.pem` and `updates/` (public data), and the Ansible playbook library (spec, "What's covered").

## Review Focus

1. **A crash or power cut halfway through encrypting an existing copy.** Every row and file must survive. Toner must finish the job on the next start, not start over on half-encrypted files or lose data. Test in Task 7.
2. **Toner locked while scheduled checks run.** Worker threads open new database connections, so the key must stay set while locked. Only signing out removes it. Test in Task 5.
3. **Large inventories.** Opening in Global with 40 organizations and 2000 devices must not get noticeably slower. The key is applied once per connection, and the main thread's pooled connections are reused. Measure in Task 1.
4. **Wrong passwords across restarts.** The slow-down after repeated failures is stored in `netcheck.keys`, so closing and reopening Toner doesn't reset it. An unknown username takes the same time and gets the same answer as a wrong password. Test in Task 4.
5. **A portable copy on another computer.** Local accounts and the recovery key still open it, because everything they need is in the data folder. Test in Task 4.

---

### Task 1: SQLCipher behind one module

**Files:**
- Create: `core/sqldb.py`
- Modify: `core/db.py:236,424` (both `sqlite3.connect` calls), `core/demarc.py:410,477`, `ui/settings_pages/security.py:229`, and every other `import sqlite3` outside `tests/`. There are 8 files; find them with `grep -rln "import sqlite3" --include=*.py . | grep -v tests`.
- Modify: `requirements.txt`, `requirements.lock`, `packaging/build.ps1:10`, `packaging/build_linux.sh:11` (add `--collect-all sqlcipher3`)
- Test: `tests/test_sqldb.py`

**Interfaces:**
- Produces:
  - `core.sqldb.sqlite3`: the DB-API module, `sqlcipher3.dbapi2`. It falls back to the standard `sqlite3` only while `sqlcipher3` is missing, so tests can run before the install.
  - `connect(path, **kw) -> Connection`: the same parameters as `sqlite3.connect`. Applies the current key.
  - `set_key(key: bytes | None) -> None`
  - `current_key() -> bytes | None`
  - `encrypt_file(path: Path, key: bytes) -> None`
  - `is_encrypted(path: Path) -> bool`
  - `export_copy(src_conn, dest: Path, passphrase: str) -> None`

- [ ] **Step 1: Ask the owner to approve `sqlcipher3-wheels==0.5.7`.** Before asking, check its files on PyPI (`pip index versions` and the project's file list) for cp313 wheels on win_amd64, manylinux x86_64 and macOS arm64, and give the owner the name, version and sizes. Stop if any platform has no wheel.
- [ ] **Step 2: Write the failing test** `tests/test_sqldb.py`:
  - `set_key(None)`, then `connect(p)` makes a database whose first 16 bytes are `b"SQLite format 3\x00"`.
  - With `set_key(os.urandom(32))`, a new file's first 16 bytes are not that header, `is_encrypted(p)` is True, and rows round-trip.
  - Opening that file with `set_key(None)`, then running `SELECT count(*) FROM sqlite_master`, raises `sqlite3.DatabaseError`.
  - `encrypt_file` on a plain file with 3 rows leaves an encrypted file that still has the same 3 rows, and leaves no `*.encrypting` file behind.
  - `export_copy(conn, dest, "correct horse battery")` makes a file that opens with that passphrase (`PRAGMA key = '<passphrase>'`) and not without it.
  - `except sqldb.sqlite3.Error` catches a `sqldb.sqlite3.IntegrityError`, and `db.NameTaken` is still a subclass of `sqldb.sqlite3.IntegrityError`.
- [ ] **Step 3: Run it to make sure it fails.** Run: `python tests/test_sqldb.py`. Expected: `ModuleNotFoundError: core.sqldb`.
- [ ] **Step 4: Install the approved package and implement `core/sqldb.py`.**
  - **Key.** Apply it right after opening, with `PRAGMA key = "x'<64 hex>'"` (a raw key, no KDF), then read `sqlite_master` once so a wrong key fails at connect.
  - **`encrypt_file`.**
    1. Open the plain file.
    2. Run `ATTACH DATABASE '<path>.encrypting' AS enc KEY "x'<hex>'"`, then `SELECT sqlcipher_export('enc')`, then `DETACH`.
    3. fsync, then `os.replace` over the original. Delete any `-wal` and `-shm` files of the plain file first, after a `PRAGMA wal_checkpoint(TRUNCATE)`.
  - **`export_copy`.** Same `ATTACH` with `KEY '<passphrase>'` (SQLCipher's own KDF), then `sqlcipher_export`.
  - **Routing.** Point every `import sqlite3` outside tests at `from core.sqldb import sqlite3`, and every `sqlite3.connect(` at `sqldb.connect(`.
  - **Dependency files.** Add `sqlcipher3-wheels==0.5.7` to `requirements.txt` and to `requirements.lock` with every file hash PyPI lists. Add `--collect-all sqlcipher3` to both build scripts.
- [ ] **Step 5: Run it and the whole suite.** Run: `python tests/test_sqldb.py`, then the full suite. Expected: all pass. Nothing sets a key yet, so existing tests see plain files.
- [ ] **Step 6: Measure Global.** With a key set, run the scratchpad's `perf_switch.py` against the perfdata set (40 organizations, 2000 devices). Then run it with no key. Expected: the keyed run takes no more than 25% longer. Note both times in the commit message.
- [ ] **Step 7: Commit:** `git add core/sqldb.py tests/test_sqldb.py requirements.txt requirements.lock packaging/ <the routed files>`, then `git commit -m "Databases open through SQLCipher, keyed when a data key is set"`

### Task 2: Sealed side files

**Files:**
- Create: `core/sealedfile.py`
- Test: `tests/test_sealedfile.py`

**Interfaces:**
- Consumes: a key from `core.sqldb.current_key()`. One data key serves both, so files and databases always agree.
- Produces:
  - `read_bytes(path) -> bytes`
  - `write_bytes(path, data: bytes) -> None` (atomic: a temporary file, then `os.replace`)
  - `read_text(path) -> str`
  - `write_text(path, text: str) -> None`
  - `class Appender(path)`: `.write(text: str)`, `.close()`. Each `write` appends one sealed frame.
  - `seal_existing(path) -> bool`: True when it sealed a plain file.
  - `is_sealed(path) -> bool`
  - `class Locked(RuntimeError)`

- [ ] **Step 1: Write the failing test** `tests/test_sealedfile.py`:
  - With a key set, `write_text(p, "abc")` gives a file that starts with `MAGIC = b"TONERSEAL1\n"` and doesn't contain `abc`, and `read_text(p) == "abc"`.
  - An `Appender` writing `"one\n"` and then `"two\n"` reads back as `"one\ntwo\n"`.
  - Flipping one byte of the ciphertext makes `read_bytes` raise `ValueError`.
  - A plain file (no magic) reads back as it is. `seal_existing` returns True and the file is then sealed. A second call returns False.
  - With no key set, `write_bytes` raises `sealedfile.Locked`, and so does `read_bytes` on a sealed file.
- [ ] **Step 2: Run it to make sure it fails.** Run: `python tests/test_sealedfile.py`. Expected: `ModuleNotFoundError`.
- [ ] **Step 3: Implement `core/sealedfile.py`.**
  - **Format:** `MAGIC`, then frames. Each frame is a 4-byte big-endian length, a 12-byte nonce and the AES-GCM ciphertext.
  - **Associated data:** `b"toner-file:" + path.name.encode()`, so a frame can't be moved into another file.
  - **Reading** stops cleanly at a short final frame, which is what a crash in the middle of an append leaves behind.
- [ ] **Step 4: Run it again.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "Sealed side files: AES-GCM frames under the data key"`

### Task 3: Password rules

**Files:**
- Create: `core/passwords.py`, `core/data/common-passwords.txt`
- Test: `tests/test_passwords.py`

**Interfaces:**
- Produces:
  - `MIN_LENGTH = 12`
  - `problem(password: str, username: str = "") -> str | None`: None when the password is fine, otherwise the sentence to show.

- [ ] **Step 1: Ask the owner to approve the list.** It is the 10,000 most common passwords from SecLists (`Passwords/Common-Credentials/10k-most-common.txt`, MIT licence). Give the URL and size. Once approved, save it as `core/data/common-passwords.txt` and add the folder to both build scripts with `--add-data`.
- [ ] **Step 2: Write the failing test.** Check that:
  - `problem("short")` mentions 12.
  - `problem("password1234")` says it's too common. The match ignores case, and also catches a list entry followed only by digits.
  - `problem("jsmith-jsmith", "jsmith")` says it contains the username.
  - `problem("correct horse battery staple") is None`.
- [ ] **Step 3: Run it to make sure it fails.** Expected: `ModuleNotFoundError`.
- [ ] **Step 4: Implement it.** Load the list once into a frozenset. The sentences are drafts, to be shown to the owner with Task 9's wording:
  - "Use at least 12 characters."
  - "That password is too common. Choose one that's harder to guess."
  - "Don't include your username in your password."
- [ ] **Step 5: Run it again.** Expected: PASS.
- [ ] **Step 6: Commit:** `git commit -m "Password rules: length, common passwords, no username"`

### Task 4: The data key and its seals

**Files:**
- Create: `core/datakey.py`
- Test: `tests/test_datakey.py`

**Interfaces:**
- Consumes:
  - `passwords.problem` (Task 3)
  - `sqldb.set_key` (Task 1)
- Produces:
  - `path() -> Path`: `db.base_path().with_suffix(".keys")`
  - `exists() -> bool`
  - `is_open() -> bool`
  - `create(name: str, password: str) -> str`: makes the key, the first account and the recovery seal; opens the key; returns the recovery key.
  - `open_with_password(name: str, password: str) -> None`
  - `open_with_recovery(recovery: str) -> None`
  - `check_password(name: str, password: str) -> bool`: for unlocking. Throttled the same way.
  - `add_local(name: str, password: str) -> None`
  - `set_password(name: str, password: str) -> None`
  - `remove(name: str) -> None`: refuses to remove the last account.
  - `accounts() -> list[dict]`: `{"name", "kind", "created"}`, sorted by name.
  - `new_recovery() -> str`: replaces the recovery seal.
  - `close() -> None`: wipes the key here and in `sqldb`.
  - Exceptions:
    - `WrongPassword(ValueError)`
    - `Throttled(Exception)`, with `.seconds: int`
    - `Locked(RuntimeError)`
    - `NameTaken(ValueError)`
    - `LastAccount(ValueError)`

- [ ] **Step 1: Write the failing test** `tests/test_datakey.py`:
  - `r = create("admin", "correct horse battery staple")`. Then `is_open()` is True, `sqldb.current_key()` has 32 bytes, and `r` matches `^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$` (32 base32 characters, 160 bits).
  - `close()`, then `open_with_password("admin", <same>)` opens with the same key bytes as before.
  - `close()`, then `open_with_recovery(r.lower().replace("-", " "))` opens. Input ignores case, spaces and dashes.
  - After `add_local("jsmith", "another long password 9")`, both accounts open the same key.
  - `remove("jsmith")` works. `remove("admin")` then raises `LastAccount`.
  - `new_recovery()` returns a different key, and the old one now raises `WrongPassword`.
  - Five wrong passwords raise `WrongPassword` each time. The sixth raises `Throttled` with `seconds == 30`. After the wait (patch `time.time`), the next wrong one raises `Throttled` with `seconds == 60`. The wait doubles each time and stops growing at 900. A correct password after the wait resets the count.
  - The failure count is still there after the module is reloaded, read back from `netcheck.keys`.
  - An unknown name raises `WrongPassword` with the same message as a wrong password, and takes at least 80% of a real check's time.
  - **Portable copy:** copy `netcheck.db` and `netcheck.keys` to a new folder, point `NETCHECK_DB` at it, and `open_with_password` still opens it.
  - `netcheck.keys` doesn't contain the password, the key or the recovery key in any form: raw, hex or base64.
- [ ] **Step 2: Run it to make sure it fails.** Expected: `ModuleNotFoundError`.
- [ ] **Step 3: Implement it.**
  - **The file** is JSON: `{"format": "toner-keys", "version": 1, "accounts": {name: {"kind": "local", "kdf": {...}, "key": b64, "created": iso, "fails": n, "until": epoch}}, "recovery": {"kdf": {...}, "key": b64}}`. It is written atomically, as `passvault._write` does, under a file lock beside it (`platforms.FileLock`).
  - **Passwords** use scrypt with `n=2**16, r=8, p=1`, and the seal is AES-GCM with associated data `b"toner-datakey:" + name.encode()`.
  - **The recovery key** uses scrypt `n=2**14` with associated data `b"toner-datakey:recovery"`.
  - **An unknown name** runs scrypt against a fixed dummy salt before failing, so it takes as long as a real check.
  - Messages (drafts):
    - `WrongPassword`: "That username or password isn't right."
    - `Throttled`: "Too many tries. Wait {n} seconds, then try again."
- [ ] **Step 4: Run it again.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "Data key sealed per local account and under a recovery key"`

### Task 5: Who is signed in, locked or signed out

**Files:**
- Create: `core/session.py`
- Modify: `core/audit.py:10-14` (`actor()`), `core/sessionlog.py:60` (`operator`)
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: `datakey` (Task 4)
- Produces:
  - `state() -> str`: one of `"signed_out"`, `"locked"`, `"open"`
  - `user() -> str | None`
  - `sign_in(name: str, password: str) -> None`: `datakey.open_with_password`, then the vault opens (Task 6), then audit "signed in".
  - `sign_in_recovery(recovery: str) -> None`: audit "signed in with the recovery key".
  - `lock() -> None`: the key stays open; audit "locked".
  - `unlock(password: str) -> None`: `datakey.check_password(user(), password)`; audit "unlocked", or "unlock failed".
  - `sign_out() -> None`: audit "signed out", then `passvault.lock()`, `db.release()`, `datakey.close()`.
  - `on_change(fn) -> None`: `fn(state)` is called after every change.

- [ ] **Step 1: Write the failing test** `tests/test_session.py`:
  - After `datakey.create("admin", PW)` and `session.sign_out()`: `state() == "signed_out"` and `user() is None`.
  - `sign_in("admin", PW)`: then `state() == "open"`, `user() == "admin"`, `audit.actor() == "admin"`, and the newest audit row is "signed in".
  - **While locked, worker threads still read:** after `lock()`, a `threading.Thread` doing `with db.connect() as c: c.execute("SELECT count(*) FROM devices")` succeeds.
  - `unlock("wrong")` raises `datakey.WrongPassword` and leaves the state `"locked"`. `unlock(PW)` makes it `"open"`.
  - After `sign_out()`: `datakey.is_open()` is False, `sqldb.current_key() is None`, and `passvault.is_open()` is False.
  - When nobody is signed in, `audit.actor()` falls back to the operating-system user name, as it does today.
- [ ] **Step 2: Run it to make sure it fails.** Expected: `ModuleNotFoundError`.
- [ ] **Step 3: Implement `core/session.py`** with module-level state under a `threading.RLock`. Change `audit.actor()` to `session.user() or getpass.getuser()`, and make `sessionlog` take its operator from `audit.actor()`.
- [ ] **Step 4: Run it again.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "Session: signed in, locked or signed out; audit names the Toner user"`

### Task 6: The vault opens with the data key

**Files:**
- Modify: `core/passvault.py` (`create`, `unlock`, `unlock_remembered`, `set_remembered`, `change_master`, and the module docstring)
- Modify: `ui/settings_pages/security.py:40-49,93-118` (remove Change master password and Remember; "Lock now" calls `session.lock()`)
- Modify: `ui/vaultdlg.py` (keep only what the upgrade needs: `UnlockDialog`, with the old master password)
- Modify: `ui/statusstrip.py:203`, `ui/linkitem.py:16` (`is_open` still works; check that their text still makes sense)
- Test: `tests/test_vault_datakey.py`; update `tests/test_*vault*` and any test that calls `passvault.create(master, ...)`, `change_master` or `set_remembered`.

**Interfaces:**
- Consumes: `datakey` (Task 4)
- Produces:
  - `passvault.open_with(datakey_bytes: bytes) -> None`: opens the vault, creating an empty one when there's none.
  - `passvault.adopt(datakey_bytes: bytes) -> None`: reseals an already-open, master-password vault's own key under the data key, and deletes the `-key` file that "Remember on this computer" left.
  - `passvault.uses_master() -> bool`: True for a vault still sealed by a master password.
  - The file's `kdf` becomes `{"name": "datakey"}`. The vault keeps its own inner key, sealed by the data key with AES-GCM and associated data `KEY_AAD`.

- [ ] **Step 1: Write the failing test** `tests/test_vault_datakey.py`:
  - **An old vault:** `passvault.create("old master password!", remember=False, carry={"a": "1"})`. Then `uses_master()` is True. After `adopt(k)` and `lock()`, `open_with(k)` gives `get("a") == "1"`, and `uses_master()` is False.
  - **A remembered old vault:** the `-key` file is gone after `adopt`.
  - `open_with(wrong_key)` raises `passvault.WrongPassword`.
  - **No vault yet:** `open_with(k)` creates one, `put("b", "2")` works, and it reopens.
- [ ] **Step 2: Run it to make sure it fails.** Expected: `AttributeError: open_with`.
- [ ] **Step 3: Implement it.**
  - Hook `session.sign_in` and `sign_in_recovery` so they call `passvault.open_with(datakey key)`.
  - Remove the master-password paths from Settings > Security.
  - Keep `left_in_credential_manager` and `forget_credential_manager`, which the upgrade still uses.
- [ ] **Step 4: Run it and the vault tests.** Run: `python tests/run_all.py vault`. Expected: all pass, after updating the old tests to the new calls.
- [ ] **Step 5: Commit:** `git commit -m "The vault opens with the data key; the master password goes away"`

### Task 7: Encrypting an existing copy

**Files:**
- Create: `core/lockdown.py`
- Modify:
  - `core/nettools.py:212-260`: `known_hosts` is read and written through `sealedfile`, and paramiko's `HostKeys` loads it from memory, one `HostKeyEntry.from_line` per line.
  - `core/sessionlog.py:52`: `Appender` replaces `open(..., "x")`, and readers use `read_text`.
  - `core/agents.py:44-60`: the TLS key is written as PEM encrypted with `BestAvailableEncryption(hkdf(datakey, b"toner-agent-key"))`. The receiver passes that password to `load_cert_chain`.
  - `core/sessions.py:353`: `.rdp` files go into a temporary folder and are deleted 60 s after launch.
- Test: `tests/test_lockdown.py`

**Interfaces:**
- Consumes:
  - `sqldb.encrypt_file`, `sqldb.is_encrypted` (Task 1)
  - `sealedfile.seal_existing` (Task 2)
- Produces:
  - `lockdown.pending() -> list[Path]`: the files still to encrypt.
  - `lockdown.run(progress: Callable[[int, int], None] | None = None) -> None`: encrypts them, one file at a time. Safe to run again after a crash.
  - `class lockdown.Busy(RuntimeError)`: raised when another Toner process has the data open.
  - What it covers:
    - every `db.org_path` file, including Global,
    - `demarc-queue.db`,
    - everything in `ssh-logs/`,
    - `known_hosts`,
    - `agent/toner-agent.key`, rewritten as encrypted PEM,
    - and `rdp/`, which is deleted.

- [ ] **Step 1: Write the failing test** `tests/test_lockdown.py`:
  - Build a plain copy: Global plus 2 organization files with devices, a session log, `known_hosts` with one key, and an agent key. Run `datakey.create(...)`, then `lockdown.run()`.
  - Afterwards every database `is_encrypted`, every side file `is_sealed`, `pending() == []`, and `db.list_devices()` and `nettools.list_host_keys()` return what was there before.
  - **Crash halfway:** patch `sqldb.encrypt_file` to raise after the first organization file. Then `run()` raises, `pending()` lists the rest, and the first file's rows are intact. Remove the patch, call `run()` again, and every file is encrypted with no rows lost.
  - A leftover `*.encrypting` file from a crash is deleted and redone, not trusted.
  - **No other program has the data open:** the other program is Toner's command-line service, the only thing besides the window that opens the data. If its schedule lock is held (`service.owns_schedule()` from another process), `run()` raises `lockdown.Busy`.
- [ ] **Step 2: Run it to make sure it fails.** Expected: `ModuleNotFoundError`.
- [ ] **Step 3: Implement `core/lockdown.py` and the four reader and writer changes.**
- [ ] **Step 4: Run it, then the session-log, host-key, agent and RDP tests.** Run: `python tests/run_all.py lockdown sessionlog nettools agent rdp`. Expected: all pass.
- [ ] **Step 5: Commit:** `git commit -m "Encrypt an existing copy file by file, resuming after a crash"`

### Task 8: The database backup is password-protected

**Files:**
- Modify: `ui/settings_pages/security.py:221-237` (`backup`)
- Test: `tests/test_security_page.py` (add to it, or create it)

**Interfaces:**
- Consumes: `sqldb.export_copy` (Task 1), `passwords.problem` (Task 3)

- [ ] **Step 1: Write the failing test.** Patch the password prompt to answer the same password twice and the save dialog to return a path. Then check that:
  - the saved file opens with that password and not without it,
  - two different answers save nothing,
  - an answer that fails `passwords.problem` saves nothing.
- [ ] **Step 2: Run it to make sure it fails.**
- [ ] **Step 3: Implement it.** Use the same two-prompt pattern as `export_passwords`, just below it in the same file. Draft text:
  - "Choose a password to protect the backup (at least 12 characters). You'll need it to open the backup, and it can't be recovered."
  - The success message replaces the vault sentence with: "The backup is encrypted with the password you chose."
- [ ] **Step 4: Run it again.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "Database backups are encrypted with a password chosen at export"`

### Task 9: First start, sign-in window and lock screen

**Files:**
- Create:
  - `ui/setupdlg.py`: the first admin account, the recovery key, and the upgrade's old master password
  - `ui/signinwindow.py`: username first, then password, or "Use the recovery key"
  - `ui/lockscreen.py`: covers the main window
- Modify:
  - `app.py:1050-1056`: replace `vaultdlg.open_at_start()`
  - `app.py` class `Main`: idle timer, the user menu, sign out
  - `app.py:900`: `closeEvent` honours `_signing_out`
- Test: `tests/test_signin_ui.py`

**Interfaces:**
- Consumes: `session` (Task 5), `datakey` (Task 4), `lockdown` (Task 7), `passvault.uses_master` and `adopt` (Task 6)
- Produces:
  - `setupdlg.run_first_start(parent=None) -> bool`: True once an account exists and the data is encrypted.
  - `signinwindow.SignInWindow(QDialog)`: `.exec()` returns Accepted once `session.state() == "open"`.
  - `lockscreen.LockScreen(QWidget)`, a child of `Main`: `.show_locked()`; it hides itself on unlock.
  - New settings in `db.DEFAULT_SETTINGS`: `"signin_idle_minutes": 15`.

- [ ] **Step 1: Show the owner the wording, and wait for their answer.** All text is draft:
  - **Sign-in, step 1:** title "Sign in", field "Username or email", button "Next".
  - **Sign-in, step 2:** the username as the heading, field "Password", button "Sign in", link "Not you?", and the link "Use the recovery key".
  - **Recovery:** "Enter the recovery key you saved when Toner was set up." Field "Recovery key", button "Sign in".
  - **First start:** "Set up Toner". Then: "Create the first admin account. Toner's data stays encrypted until someone signs in." Fields "Username", "Password" and "Confirm password", then "Create account".
  - **The upgrade adds:** "Enter the master password you used to unlock Toner's vault. Toner moves your saved passwords into the new account and won't ask for it again." There's a link "I don't know it", which warns: "The saved passwords will be lost. Everything else is kept."
  - **Recovery key screen:** "Save your recovery key". Then: "If every password is forgotten, this key is the only way back in. Store it somewhere safe, like your password manager. Toner shows it only once." The key is shown in monospace with a Copy button. A tick box reads "I've saved the recovery key", and the "Continue" button only becomes active once it's ticked.
  - **Encrypting:** "Encrypting Toner's data", with "{n} of {m} files" and a progress bar.
  - **Lock screen:** "Toner is locked", then "Locked after {n} minutes without use." or "Locked by {user}."; the label "{user}, local account"; the field "Password"; the button "Unlock"; and the link "Sign in as someone else".
  - **User menu** in the window header: "{user}", "Lock (Ctrl+Shift+L)", "Sign out".
- [ ] **Step 2: Write the failing test** `tests/test_signin_ui.py`, offscreen:
  - **First start:** fill the fields in `run_first_start` and accept. Then `datakey.exists()`, an account named as typed, the recovery screen showing a key that matches Task 4's pattern, and Continue disabled until the box is ticked.
  - **Upgrade:** with a master-password vault holding `{"a": "1"}`, the old master password moves `a` into the new vault, and `lockdown.pending() == []`.
  - **`SignInWindow`:**
    - "Next" with an unknown name still shows the password step, so it doesn't reveal which names exist.
    - A wrong password shows Task 4's message.
    - The right password accepts.
    - `Throttled` disables the Sign in button and shows the countdown.
  - **`LockScreen` on a `Main`:**
    - Ctrl+Shift+L calls `session.lock()` and covers the window.
    - The idle timer at `signin_idle_minutes` locks. Patch the clock; don't wait.
    - Unlock with the right password uncovers the window.
    - "Sign in as someone else" signs out.
  - **Sign out:** sets `_signing_out`, closes `Main`, and `app.main` then starts a new Toner process. Patch `QProcess.startDetached` and check its arguments are `sys.executable` plus the original arguments, without `--minimized`.
- [ ] **Step 3: Run it to make sure it fails.**
- [ ] **Step 4: Implement it.**
  - **Layout.** Follow the mockups in `docs/superpowers/specs/2026-11-04-user-sign-in-mockups/`: layout C for sign-in and B for the lock screen. Use Toner's theme tokens (`ui/theme.py tokens()`): `surface` for the card, `edge` for fields, `ring` for focus and `accent` for the main button.
  - **Order in `app.main()`:**
    1. If there's no `datakey.exists()`, run `run_first_start`, or quit if it's cancelled.
    2. Otherwise show `SignInWindow`, or quit if it's cancelled.
    3. If `lockdown.pending()` isn't empty, finish encrypting with the progress dialog.
    4. Open `Main`.
  - **The idle timer** restarts on mouse and key events through the app's event filter (`KeyboardAccess` is already installed there), and it runs only while `state() == "open"`.
  - **The tray.** While locked, the tray's "Open Toner" shows the lock screen.
  - **Signing out** runs the normal `closeEvent` checks: unsaved settings, a running playbook, firmware transfers. If any of them is refused, signing out is cancelled.
- [ ] **Step 5: Run it, then the full suite.** Expected: all pass. Existing UI tests construct `Main` directly. Give them a helper, `tests/_signed_in.py`, that sets up `datakey.create` and `session.sign_in`. Import it in any test that builds `Main` and then fails.
- [ ] **Step 6: Take screenshots of all four windows,** offscreen, in the Midnight and Daylight themes, at 1024 px wide. Send them to the owner.
- [ ] **Step 7: Commit:** `git commit -m "First start, sign-in window and lock screen"`

### Task 10: Accounts and sign-in page

**Files:**
- Create: `ui/settings_pages/accounts.py`
- Modify: `ui/settings.py:44-56` (add "Accounts and sign-in" to the "Security and data" group, and to `GLOBAL_PAGES`)
- Test: `tests/test_accounts_page.py`

**Interfaces:**
- Consumes: `datakey.accounts`, `add_local`, `set_password`, `remove`, `new_recovery` (Task 4); `passwords.problem` (Task 3)
- Produces: a page with the local-accounts list and buttons, plus "Lock after {n} minutes without use" (`signin_idle_minutes`, 1-240).

In this plan every account can open this page. Part 2 limits it to Admins.

- [ ] **Step 1: Show the owner the wording, and wait.** Drafts:
  - Buttons: "Add account...", "Reset password...", "Remove", "Make a new recovery key...".
  - The new-recovery-key confirmation: "The old recovery key will stop working. Make a new one?"
  - Removing your own account: "You can't remove the account you're signed in with."
- [ ] **Step 2: Write the failing test.**
  - "Add" with a good password adds a row. A bad one shows `passwords.problem`'s sentence and adds nothing.
  - "Remove" on the signed-in user is refused.
  - "Make a new recovery key" shows the Task 9 recovery screen, and the old key stops working.
  - Every change writes an audit row: "account added", "password reset", "account removed" or "recovery key replaced". The row has no secret in it.
- [ ] **Step 3: Run it to make sure it fails.**
- [ ] **Step 4: Implement it.** Reuse `setupdlg`'s recovery-key screen.
- [ ] **Step 5: Run it again.** Expected: PASS.
- [ ] **Step 6: Commit:** `git commit -m "Settings: Accounts and sign-in for local accounts and the recovery key"`

### Task 11: The command line and the service

**Files:**
- Modify: `app.py:982-1000` (`run_cli`: drop `unlock_remembered`), `cli.py:39-80`
- Test: `tests/test_app_cli.py`, `tests/test_cli_checks.py` (update both); `tests/test_cli_signin.py` (new)

**Interfaces:**
- Consumes: `session.sign_in`, `session.sign_out` (Task 5)
- Produces:
  - `cli.main(argv)` signs in before `run`, `backup`, `status` or `metrics`, and refuses `service` once a keys file exists.
  - New option `--user NAME`. The password is read with `getpass.getpass`, never from an argument or an environment variable.

- [ ] **Step 1: Show the owner the wording, and wait.** Drafts:
  - "Toner's background service is off while sign-in is turned on. Scheduled checks and backups run while someone is signed in to Toner's window."
  - Prompts: "Username: " and "Password: ".
  - After a failure, Task 4's message, then exit code 3.
- [ ] **Step 2: Write the failing test** `tests/test_cli_signin.py`:
  - With a keys file present, `cli.main(["service"])` returns 3 and prints the message.
  - `cli.main(["status", "--user", "admin"])`, with `getpass.getpass` patched to return the right password, returns 0 and prints results.
  - With the wrong password it returns 3.
  - With no keys file (the existing tests), everything behaves as today.
- [ ] **Step 3: Run it to make sure it fails.**
- [ ] **Step 4: Implement it.** Call `session.sign_out()` in a `finally` once the command ends.
- [ ] **Step 5: Run it and the CLI tests.** Run: `python tests/run_all.py cli`. Expected: all pass.
- [ ] **Step 6: Commit:** `git commit -m "Command line signs in; the background service waits for centralization"`

### Task 12: README and release notes

**Files:**
- Modify: `README.md`: a short "Signing in" section, plus updates to anything that mentions the master password, "Remember on this computer" or the service. Never touch the Development section.
- Create: `docs/release-notes-sign-in.md`, a draft for the release that ships this.

- [ ] **Step 1: Show the owner both texts, and wait for approval.** The release notes must say:
  - existing copies ask for the old master password once, then encrypt their data;
  - the first person to open the upgraded Toner creates the admin account and gets the recovery key;
  - `Toner.exe cli service` and scheduled command-line runs stop working until centralization;
  - database backups now ask for a password.
- [ ] **Step 2: Check every mention is gone:** `grep -rn "master password\|Remember on this computer" README.md ui core`. Expected: only the upgrade's own text in `ui/setupdlg.py` and `ui/vaultdlg.py`.
- [ ] **Step 3: Run the full suite on Windows and on Linux (WSL).** Expected: every file clean on both.
- [ ] **Step 4: Commit:** `git commit -m "README and release notes for sign-in"`
