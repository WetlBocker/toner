# Hardware Security Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local, AD or LDAP account can add FIDO2 security keys; once it has one, signing in needs the password or PIN, the key's own PIN and a touch, and unlocking needs the password or PIN and a touch.

**Architecture:** One module, `core/fidokey.py`, is the only code that talks to a key (through the `fido2` library); tests replace its three functions with a fake. `core/datakey.py` gains a keyed form of an account's seal: the data key is sealed under the password key mixed with a random 32-byte account half ("K2"), and K2 is wrapped once per security key under that key's `hmac-secret` value. Directory accounts keep the same structure inside what their PIN slot seals. The sign-in window, the lock screen and the command line pass `datakey` a callable that asks the key, so the blocking prompt runs off the UI thread.

**Tech Stack:** Python 3.13, PySide6, `cryptography` (scrypt, AES-GCM, HKDF), `fido2` 2.2.1 (new, approved), SQLCipher. Tests are plain scripts under `tests/` using `check(name, cond)`, run with `python tests/run_all.py <file names>`; there is no pytest.

**Spec:** `docs/superpowers/specs/2026-11-12-hardware-security-keys-design.md`. Read it first. Its Wording table is the copy: every user-facing string in this plan is quoted from it and tests assert the exact text.

## Global Constraints

- Windows and Linux ship together under one version number; the code must also run on macOS, which has no build or test job here.
- Every user-facing string comes from the spec's Wording table, verbatim. A string not in the table is not built: stop and ask the owner. The six strings under "Wording still to approve" below are not approved yet; tasks that need them wait for the owner.
- No secret in logs, exceptions, audit rows or test output: not the password, the Toner PIN, the key's value, K2, or the key's own PIN.
- An account's box key does not change when a key is added or removed.
- An account without keys is stored byte-for-byte as today, and every existing test stays green.
- SSO accounts (a directory whose `kind` is `"oidc"`) are never offered, asked for or required to have a key.
- The relying-party name is exactly `toner.invalid`; the origin is `https://toner.invalid`.
- The secret is always read with user verification `"required"`; the presence check with `"discouraged"`.
- python-fido2 2.2.1 drops an empty `prf` request on Windows: a `prf` request always carries `eval`.
- Key failures (no key, not touched, cancelled, wrong key PIN) never count on `netcheck.keys`' password throttle. Wrong passwords and Toner PINs count exactly as today.
- Commit only when the owner says so. Each task ends with its tests green and its files ready to commit; do not commit, push or merge on your own.
- `tests/test_supply_chain.py` must pass: every `requirements.txt` entry is hash-pinned in `requirements.lock`.

## Wording still to approve

Ask the owner before the task that uses each. Audit actions follow the existing style ("account added", "sign-in without approval turned on").

| Where | Text | Task |
|---|---|---|
| Audit: a person added a key | `security key added` (detail: the key's name) | 2, 3 |
| Audit: a person removed a key | `security key removed` (detail: the key's name) | 2, 3 |
| Audit: an admin cleared an account's keys | `security keys removed` (detail: `{name}, by {actor}`) | 3 |
| Audit: the require switch | `security keys required turned on` / `security keys required turned off` (detail: `by {actor}`) | 4 |
| Turning the helper switch on while an AD or LDAP account has keys | "Remove the security keys from AD and LDAP accounts first. This can't be on while they have keys." | 7 |

## Review Focus

1. **A forged hint.** `keys_n` in an account's record is unsigned. Someone with the directory password edits it to make Toner skip Duo for an account that has no keys. Expected: they are sent back to Duo; nothing opens on the password and PIN alone. (Task 4)
2. **The key goes away mid sign-in** (unplugged, cancelled, timed out) after the password was right. Expected: nothing is open, the session is signed out, no throttle count, the window is back on the page before with the approved message. (Tasks 2, 5)
3. **Changing your own password while you have keys.** Expected: the keys still work with the new password; nothing asks for a touch. (Task 2)
4. **Two Toner processes** (the window and the command line) add and remove keys of one account at the same moment. Expected: the file lock serialises them; the key list and the wraps never disagree. (Task 2)
5. **A wrong key PIN typed three times on Linux.** Expected: the approved retry message, the key's own counter is not burned further, Toner's password throttle is untouched, and the PIN appears in no log. (Task 1)

---

## File Structure

| File | Responsibility |
|---|---|
| `core/fidokey.py` (new) | Talk to a security key: register, read the value, check presence. The only importer of `fido2`. |
| `tests/fakekey.py` (new) | A fake key that replaces `fidokey`'s three functions in tests. |
| `core/datakey.py` | The keyed seal for local and directory records; add, remove, clear; the key list of the signed-in account. |
| `core/pinslot.py` | `reseal`: put a new secret under an existing slot, given its PIN. |
| `core/session.py`, `core/dirsignin.py` | Pass the key callables through; the Duo skip; `full_at` after the key. |
| `core/roles.py`, `core/helper/server.py` | The require switch in the signed rules; an approval clears key fields. |
| `ui/keyask.py` (new) | Bridge between a worker thread asking a key and the window showing "touch" and "key PIN" pages. |
| `ui/signinwindow.py`, `ui/lockscreen.py` | The key step at sign-in, approval and unlock. |
| `ui/keysdialog.py` (new), `app.py` | "Security keys..." in the user menu; the forced add when keys are required. |
| `ui/settings_pages/accounts.py` | The Keys column, "Remove keys...", the require switch, the two refusals. |
| `cli.py` | The key step at the terminal. |
| `requirements.txt`, `requirements.lock`, `packaging/build.ps1`, `packaging/build_linux.sh` | The new library. |

---

### Task 1: The key seam and its fake

**Files:**
- Create: `core/fidokey.py`, `tests/fakekey.py`
- Modify: `requirements.txt`, `requirements.lock`, `packaging/build.ps1` (the `$common` array), `packaging/build_linux.sh` (lines 11-14)
- Test: `tests/test_fidokey.py`

**Interfaces:**
- Produces, in `core/fidokey.py`:
  - `RP_ID = "toner.invalid"`, `ORIGIN = "https://toner.invalid"`
  - `class Failed(Exception)` with attribute `text`, and subclasses whose `text` is the spec's string: `NoKey`, `NotRegistered`, `NotTouched` ("The key wasn't touched. Sign in again."), `Unsupported`, `WrongKeyPin`, `KeyPinRetry` ("Too many wrong PINs. Unplug the key..."), `KeyPinLocked`, `NoKeyPin`
  - `@dataclass(frozen=True) class Cred: id: bytes; salt: bytes; public: bytes` (`public`: the COSE key, CBOR-encoded)
  - `register(label: str, salt: bytes, *, ask_pin=None, cancel=None, window=None) -> tuple[Cred, bytes]`: the new credential and its 32-byte value
  - `value(creds: Sequence[Cred], *, ask_pin=None, cancel=None, window=None) -> tuple[bytes, bytes]`: the id of the credential that answered and its 32-byte value
  - `present(creds: Sequence[Cred], *, cancel=None, window=None) -> bytes`: the id of the credential that signed a fresh 32-byte challenge; the signature is verified against `Cred.public` before returning
  - `ask_pin`: `Callable[[], str | None]` (None: cancelled), called only off Windows. `cancel`: a `threading.Event`. `window`: a Windows HWND as int.
- Produces, in `tests/fakekey.py`: `class FakeKey` with `register`, `value`, `present` of the same signatures, attributes `plugged: bool`, `touch: bool`, `pin: str | None`, `calls: list[str]`, and `install() -> FakeKey`, which sets `core.fidokey.register/value/present` to a new fake's methods.

- [ ] **Step 1: Add the dependency.** `requirements.txt`: `fido2>=2.2.1,<3`. `requirements.lock`: `fido2==2.2.1` with every sha256 hash PyPI lists for it (the lock's header says how). Build scripts: `--collect-all fido2` beside the other `--collect-all` lines (it ships a data file).
- [ ] **Step 2: Run** `python tests/test_supply_chain.py`. Expected: all checks pass.
- [ ] **Step 3: Write the failing test** `tests/test_fidokey.py`. A stub client stands in for `fido2`'s client (`fidokey._client = lambda window: stub`); the stub records the options it is given and returns canned results.

```python
cred, val = fidokey.register("Blue key", SALT)
check("registration asks under toner.invalid, cross-platform, with the number in the request", stub.created["rp"]["id"] == "toner.invalid"
      and stub.created["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform" and stub.created["extensions"] == {"prf": {"eval": {"first": SALT}}})
check("it gives the credential and a 32-byte value", cred.salt == SALT and len(val) == 32 and cred.public)
check("no value at registration: it reads it once more", stub_without_result.calls == ["make", "get"])
check("a key without the feature is refused in the approved words", raised(fidokey.Unsupported, register_on(stub_no_prf)).text
      == "This key can't be used: it doesn't support what Toner needs (FIDO2 hmac-secret).")
cid, val2 = fidokey.value([cred])
check("the value is read with the key's PIN required, each credential with its own number", stub.got["userVerification"] == "required"
      and stub.got["extensions"]["prf"]["evalByCredential"] == {websafe(cred.id): {"first": SALT}})
check("presence is a touch alone, on a fresh challenge each time", fidokey.present([cred]) == cred.id and stub.got["userVerification"] == "discouraged"
      and "extensions" not in stub.got and challenge_1 != challenge_2)
check("a signature that does not match what was registered is not presence", raised(fidokey.NotRegistered, present_with_forged_signature))
check("three wrong key PINs: the retry message, and the PIN is in no log", raised(fidokey.KeyPinRetry, value_with_wrong_pins).text
      == "Too many wrong PINs. Unplug the key, plug it back in and try again." and "1234" not in captured_log)
check("a key whose PIN is locked for good", raised(fidokey.KeyPinLocked, value_on_blocked_key).text == "The key's PIN is locked. The key has to be reset before it can be used again.")
check("a key with no PIN set, off Windows", raised(fidokey.NoKeyPin, register_on_key_without_pin).text == "This key has no PIN yet. Set one with the key's own software, then add it here.")
check("no key plugged in", raised(fidokey.NoKey, value_with_no_device).text == "Toner can't find a security key. Plug yours in and try again.")
check("cancel set before the touch: NotTouched", raised(fidokey.NotTouched, value_with_cancel_set))
check("the fake keeps the same promises", fake_round_trip_matches_the_contract)
```

- [ ] **Step 4: Run** `python tests/test_fidokey.py`. Expected: FAIL (no module `core.fidokey`).
- [ ] **Step 5: Implement `core/fidokey.py`.** `_client(window)` returns `fido2.client.windows.WindowsClient(DefaultClientDataCollector(ORIGIN), handle=window)` on Windows, else `Fido2Client` on the first `CtapHidDevice` with a `UserInteraction` whose `request_pin` calls `ask_pin`. Map the library's `ClientError`/`CtapError` codes to the `Failed` subclasses (PIN_INVALID, PIN_AUTH_BLOCKED, PIN_BLOCKED, PIN_NOT_SET, NO_CREDENTIALS, timeouts and cancels). Build options with `fido2.server.Fido2Server({"id": RP_ID, "name": "Toner"})`, as the spike does (`scratchpad\seckey\spike_key.py` in the session that wrote this plan; the calls are `register_begin`, `register_complete`, `authenticate_begin`, `authenticate_complete`).
- [ ] **Step 6: Implement `tests/fakekey.py`.** Each registered credential keeps a random secret; `value` returns `HMAC-SHA256(secret, salt)`; `present` returns the id; `plugged=False` raises `NoKey`, `touch=False` raises `NotTouched`, a credential it never registered raises `NotRegistered`.
- [ ] **Step 7: Run** `python tests/test_fidokey.py`. Expected: all pass.

---

### Task 2: Keyed local accounts

**Files:**
- Modify: `core/datakey.py`
- Test: `tests/test_datakey_keys.py`

**Interfaces:**
- Consumes: `fidokey.Cred`, `fidokey.NotRegistered` (Task 1).
- Produces, in `core/datakey.py`:
  - `class KeyNeeded(Exception)`: the account has keys and the caller gave no way to ask one.
  - `open_with_password(name, password, key=None) -> int` where `key: Callable[[list[fidokey.Cred]], tuple[bytes, bytes]]`
  - `check_password(name, password, present=None) -> bool` where `present: Callable[[list[fidokey.Cred]], bytes]`
  - `add_key(secret: str, cred: fidokey.Cred, value: bytes, label: str) -> None`: the signed-in account; `secret` is its password (Task 3: or PIN)
  - `remove_key(secret: str, index: int) -> None`
  - `my_keys() -> list[dict]`: `[{"name", "added"}]` of the signed-in account, from memory, `[]` when it has none
  - `has_keys(name) -> bool`: the record's `keys_n` hint; never proof
- The keyed local record (decided here; nothing else may differ from an unkeyed record):
  - `kdf`: as today. `key`: absent. `keys_n`: int, the hint.
  - `keys`: `nonce + AESGCM(KEK_pw)` over JSON `{"list": [{"id", "salt", "pub", "name", "added"}], "wraps": [b64]}`, aad `b"toner-datakey-keys:" + name`. `wraps[i] = nonce + AESGCM(HKDF-SHA256(value_i, info=b"toner-datakey:key"))` over K2.
  - `sealed_k`: `nonce + AESGCM(HKDF-SHA256(KEK_pw + K2, info=b"toner-datakey:keyed"))` over the same 64-byte payload as today, aad `_aad(name)`.
  - In memory while signed in: `_keys` (the list) and `_k2`; `close()` drops both.

- [ ] **Step 1: Write the failing test** `tests/test_datakey_keys.py` (`fakekey.install()`, `datakey.create("Admin1", PW)`, sign in, as `tests/test_datakey.py` does).

```python
box_before = datakey.box_public("Admin1")
cred, val = fake.register("Blue", os.urandom(32)); datakey.add_key(PW, cred, val, "Blue")
rec = datakey.read()["accounts"]["Admin1"]
check("the first key takes the password-only seal away, in the same write", "key" not in rec and rec["keys_n"] == 1 and "sealed_k" in rec)
check("the box key is the same", datakey.box_public("Admin1") == box_before)
check("the key's name is listed; its id, number and public half are not in the file in the clear", datakey.my_keys()[0]["name"] == "Blue"
      and b64(cred.id) not in json.dumps(rec))
datakey.close()
check("the password alone no longer opens it", raised(datakey.KeyNeeded, lambda: datakey.open_with_password("Admin1", PW)))
check("...and nothing is left open", not datakey.is_open())
check("the password and the key open it", datakey.open_with_password("Admin1", PW, key=fake.value) == 0 and datakey.is_open())
check("a wrong password is refused before the key is asked, and counts as today", raised(datakey.WrongPassword, wrong_pw_with_key) and fake.calls == [] and throttle_fails() == 1)
fake.touch = False
check("no touch: NotTouched, nothing open, no throttle count", raised(fidokey.NotTouched, open_again) and not datakey.is_open() and throttle_fails() == 0)
check("a key of another account: NotRegistered", raised(fidokey.NotRegistered, open_with_other_fake))
check("a second key works alone", second_key_opens)
check("unlock: the password and presence, without reading the value", datakey.check_password("Admin1", PW, present=fake.present) and "value" not in fake.calls)
check("unlock with no way to ask: KeyNeeded", raised(datakey.KeyNeeded, lambda: datakey.check_password("Admin1", PW)))
datakey.set_password("Admin1", PW2)                               # your own password, while signed in
check("your keys still work with the new password, with no touch asked for the change", fake.calls == [] and reopens_with(PW2, fake.value))
datakey.remove_key(PW2, 0)
check("removing one of two keeps the other", [k["name"] for k in datakey.my_keys()] == ["Spare"])
datakey.remove_key(PW2, 0)
rec = datakey.read()["accounts"]["Admin1"]
check("removing the last: stored as an account without keys is", set(rec) == set(plain_record) and reopens_with(PW2, None))
check("a wrong password cannot add or remove", raised(datakey.WrongPassword, lambda: datakey.add_key("nope", cred, val, "x")))
check("an admin's reset of someone else clears their keys", reset_of_tech_by_admin_leaves_no_key_fields and tech_opens_with(NEW_PW, None))
check("two processes adding at once: both keys are there, list and wraps the same length", concurrent_adds_agree)
check("no secret in any log line of this test", not any(s in captured_log for s in (PW, PW2, val.hex(), k2_hex)))
```

- [ ] **Step 2: Run** `python tests/test_datakey_keys.py`. Expected: FAIL (`add_key` is not defined).
- [ ] **Step 3: Implement.** In `_attempt`, a record with `keys` proves the password by opening that blob and returns `(kek, list, wraps)` instead of a payload; the key callable is called after `_lock` and the file lock are released, never under them. `InvalidTag` on a wrap is `fidokey.NotRegistered`. `add_key` and `remove_key` go through `_change` with `accounts=False` (the box key and the signed fields do not change). `set_password` on the signed-in account's own keyed record re-seals `sealed_k` and `keys` under the new password with the held `_k2`; on anyone else's record it builds a plain record as today.
- [ ] **Step 4: Run** `python tests/test_datakey_keys.py tests/test_datakey.py tests/test_datakey_boxes.py tests/test_session.py`. Expected: all pass.
- [ ] **Step 5: Audit.** `add_key` and `remove_key` write `security key added` / `security key removed` with the key's name. (Wording to approve first.)

---

### Task 3: Keyed directory accounts

**Files:**
- Modify: `core/pinslot.py`, `core/datakey.py`, `core/roles.py` (`approve`, lines 754-755)
- Test: `tests/test_datakey_keys_directory.py`

**Interfaces:**
- Consumes: Task 2's key list and wrap format.
- Produces:
  - `pinslot.reseal(rec, slot_id, pin, sealed, secret: bytes) -> dict`: opens the slot exactly as `open` does (same errors, same counting), then returns what `Slot.seal(secret)` gives for that slot.
  - `datakey.open_with_pin(name, pin, key=None) -> int`, `datakey.check_pin(name, pin, present=None) -> bool`
  - `datakey.add_key` / `remove_key` accept the Toner PIN as `secret` when the signed-in account is a directory account.
  - `datakey.clear_keys(name) -> None`: an admin, for an AD or LDAP account: drops its slot (`drop_slot`) and its `keyed` and `keys_n` fields. Raises `ValueError` for a local or SSO account.
- The keyed directory record: `keyed: True`, `keys_n: int`, and `sealed` is the slot's seal of `b"K1" + JSON {"list", "wraps", "sealed_k"}`, where `sealed_k = nonce + AESGCM(HKDF-SHA256(K2, info=b"toner-datakey:keyed:" + name))` over today's slot payload (`seal_payload`). Whether the blob is keyed is read from inside the opened seal (its `K1` prefix), never from the `keyed` field.

- [ ] **Step 1: Write the failing test**, set up as `tests/test_dirsignin.py` does (`pinslot.tpm_windows = FakeTpm`, an approved AD account `ana`).

```python
check("the PIN alone no longer opens a keyed account", raised(datakey.KeyNeeded, lambda: datakey.open_with_pin("ana", PIN)))
check("the PIN and the key open it, with the same box key as before", datakey.open_with_pin("ana", PIN, key=fake.value) == 0 and datakey.box_public("ana") == box_before)
check("a wrong PIN counts as today and never reaches the key", raised(pinslot.WrongPin, wrong_pin_with_key) and fake.calls == [])
check("the keyed field cleared by hand does not open it without the key", raised(datakey.KeyNeeded, open_after_deleting_keyed_field))
check("unlock: the PIN and presence", datakey.check_pin("ana", PIN, present=fake.present))
check("removing the last key: the slot seals today's payload again", plain_again and datakey.open_with_pin("ana", PIN) == 0)
datakey.clear_keys("ana")                                         # as an admin
rec = datakey.read()["accounts"]["ana"]
check("an admin's clear drops the slot and the key fields", "keyed" not in rec and "keys_n" not in rec and raised(pinslot.SlotMissing, open_ana))
check("the next approval makes a seal with no keys", approve_new_slot("ana") and datakey.open_with_pin("ana", NEW_PIN) == 0)
check("a forgotten-PIN approval of a keyed account clears its key fields too", forgot_pin_approval_leaves_no_key_fields)
check("clear_keys refuses a local account and an SSO account", raised(ValueError, lambda: datakey.clear_keys("Admin1")) and raised(ValueError, lambda: datakey.clear_keys("sso-user")))
```

- [ ] **Step 2: Run it.** Expected: FAIL (`reseal` is not defined).
- [ ] **Step 3: Implement** `pinslot.reseal`, the directory branches of the four `datakey` functions, `clear_keys`, and in `roles.approve` drop `keyed` and `keys_n` wherever it writes a new `sealed`.
- [ ] **Step 4: Run** this test with `tests/test_pinslot.py tests/test_dirsignin.py tests/test_roles.py tests/test_approve_with_account.py`. Expected: all pass.
- [ ] **Step 5: Audit.** `clear_keys` writes `security keys removed` with `{name}, by {actor}`. (Wording to approve first.)

---

### Task 4: Sessions, directory sign-in and the require switch

**Files:**
- Modify: `core/session.py`, `core/dirsignin.py`, `core/roles.py`, `core/helper/server.py`
- Test: `tests/test_session_keys.py`, `tests/test_dirsignin_keys.py`, `tests/test_roles_require_keys.py`

**Interfaces:**
- Consumes: Tasks 2 and 3.
- Produces:
  - `session.sign_in(name, password, key=None)`, `session.sign_in_pin(name, pin, key=None)`, `session.unlock(password, present=None)`, `session.unlock_pin(pin, present=None)`. Audit actions unchanged.
  - `dirsignin.finish(a, pin, key=None)`, `dirsignin.approve(a, admin_name, admin_password, key=None)`, `dirsignin.approve_with_account(a, approver, pin, key=None)`
  - `dirsignin.keys_allowed(name) -> bool`: False for an SSO account, and for an AD or LDAP account while the helper switch is on (read the switch the way `ui/settings_pages/accounts.py` does today).
  - `roles.require_keys() -> bool` (from the verified rules) and `roles.set_require_keys(on: bool) -> None` (an admin; same write pattern as `set_role`). `set_require_keys(True)` raises `ValueError` with the spec's "Turn off "Let group members sign in without approval" first. It can't be on while security keys are required." when the helper switch is on.
  - `roles.must_add_key() -> bool`: the require switch is on, the signed-in account is local, AD or LDAP, and `datakey.my_keys()` is empty.
- The signed body gains `"require_keys": True` only while the switch is on; when off the key is absent, so the body of a copy that never used it is unchanged. `core/helper/server.py` builds the same body.
- `datakey.add_key` raises `ValueError` with the spec's "Security keys can't be added to this account while "Let group members sign in without approval" is on." when `keys_allowed` is False for the signed-in account.

- [ ] **Step 1: Write the failing tests.**

```python
# tests/test_dirsignin_keys.py: a directory with Duo on, the helper off
a = sign_in_until_pin("ana", DIR_PW)
check("an account with a key is not asked for Duo", a.stage == "pin" and duo_requests == [])
check("the full check is not recorded before the key", datakey.directory_account("ana")["full_at"] == full_at_before)
dirsignin.finish(a, PIN, key=fake.value)
check("after the key it is", a.stage == "done" and datakey.directory_account("ana")["full_at"] > full_at_before)
forge_keys_n("bob", 1)                                            # bob has no key; his record's hint is edited
b = sign_in_until_pin("bob", DIR_PW); dirsignin.finish(b, BOB_PIN, key=fake.value)
check("a forged hint is sent back to Duo with nothing open", b.stage == "duo" and session.state() == "signed_out" and not datakey.is_open())
check("an SSO account is never asked for a key or allowed one", not dirsignin.keys_allowed("sso-user") and sso_sign_in_calls_no_key)
check("with the helper switch on an AD account cannot add a key, in the approved words", raised(ValueError, add_key_as_ana_with_helper_on).args[0]
      == 'Security keys can\'t be added to this account while "Let group members sign in without approval" is on.')
check("an admin with a key approving someone: their key is asked", approve_with_keyed_admin_calls_key)

# tests/test_roles_require_keys.py
check("off by default, and the signed body is what it was", not roles.require_keys() and "require_keys" not in roles._signed(datakey.read()))
roles.set_require_keys(True)
check("on: signed, verified, and a Tech cannot turn it off", roles.require_keys() and roles.verified() and raised(Exception, tech_sets_it_off) and roles.require_keys())
check("an account without a key must add one; one with a key need not; an SSO account is not asked", must_add_for == {"Tech1": True, "Admin1": False, "sso-user": False})
check("it cannot go on while the helper switch is on", raised(ValueError, require_with_helper_on).args[0].startswith('Turn off "Let group members sign in without approval" first.'))
check("the helper verifies the rules with the switch off, as before", helper_verifies_rules)

# tests/test_session_keys.py
check("sign in, lock, unlock with presence, sign out: the audit rows are today's", actions == ["signed in", "locked", "unlocked", "signed out"])
check("unlock without the touch stays locked", raised(fidokey.NotTouched, unlock_no_touch) and session.state() == "locked")
```

- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** In `after_password` (line 324) an AD or LDAP account with `datakey.has_keys` and no helper ticket skips Duo and is marked `a.duo_skipped`; `_onward` does not call `set_full` for it. In `finish`, after `session.sign_in_pin`, a `duo_skipped` attempt whose `datakey.my_keys()` is empty is signed out and sent to Duo (`duo.preauth`, stage "duo"); otherwise `set_full` is written there.
- [ ] **Step 4: Run** the three new tests with `tests/test_dirsignin.py tests/test_helper_signin.py tests/test_helper_server.py tests/test_roles.py tests/test_lock_directory.py`. Expected: all pass.
- [ ] **Step 5: Audit.** `set_require_keys` writes `security keys required turned on` / `off` with `by {actor}`. (Wording to approve first.)

---

### Task 5: The key step in the sign-in window and on the lock screen

**Files:**
- Create: `ui/keyask.py`
- Modify: `ui/signinwindow.py`, `ui/lockscreen.py`
- Test: `tests/test_signin_keys_ui.py`

**Interfaces:**
- Consumes: Tasks 1 and 4.
- Produces, in `ui/keyask.py`: `class KeyAsk(QObject)` with signals `touching = Signal()` and `pin_wanted = Signal()`; methods `key(creds) -> tuple[bytes, bytes]` and `present(creds) -> bytes`, safe to call from a worker thread (they emit the signals, call `fidokey.value` / `fidokey.present` with `window=` the window's handle, and on Linux and macOS block on the key PIN); `give_pin(text: str | None)`; `cancel()`.

- [ ] **Step 1: Write the failing test**, offscreen, with `fakekey.install()`, built like `tests/test_signin_ui.py`.

```python
check("after a right password the window shows the key page", page_title() == "Touch your security key"
      and page_text() == "Plug it in if it isn't already, then touch it." and link_text() == "Use a different account")
check("the window stays responsive while it waits (the key is asked off the UI thread)", asked_on is not threading.main_thread())
check("a touch signs in", wait_for(lambda: win.result() == win.DialogCode.Accepted) and session.state() == "open")
check("a wrong password never shows the key page", error_text() == "That username or password isn't right." and page_is("password"))
check("no key plugged in", error_after(plugged=False) == "Toner can't find a security key. Plug yours in and try again.")
check("another account's key", error_after(other_key=True) == "That key isn't registered to this account.")
check("not touched: back on the password page, signed out, the box empty", error_after(touch=False) == "The key wasn't touched. Sign in again."
      and page_is("password") and session.state() == "signed_out" and win.password.text() == "")
check("Use a different account cancels the wait and goes back to the name page", cancelled and page_is("name"))
check("off Windows the key's PIN is asked in Toner's window", pin_page_title() == "Enter your security key's PIN"
      and pin_page_text() == "This is the PIN set on the key itself, not the one you use for Toner.")
check("a wrong key PIN says so and asks again", error_after(wrong_key_pin=True) == "That key PIN isn't right." and page_is("keypin"))
check("a directory account: password, no Duo, PIN, then the key page", stages == ["password", "pin", "key", "done"])
check("an admin with a key approving: their key is asked before the approval lands", approver_touched_before_approved)
# the lock screen
check("unlock: the password, then a touch", lock_text() == "Touch your security key" and wait_for(lambda: session.state() == "open"))
check("not touched at unlock: stays locked, in the unlock words", lock_error(touch=False) == "The key wasn't touched. Try again." and session.state() == "locked")
check("an account without keys signs in and unlocks exactly as before", plain_account_never_shows_the_key_page)
```

- [ ] **Step 2: Run it.** Expected: FAIL (no module `ui.keyask`).
- [ ] **Step 3: Implement.** Two new pages in `SignInWindow` ("key", "keypin"). `_sign_in` (line 433) and the lock screen's `_try` (line 289) move onto the existing `Job` pattern (`_run`), passing `self.keyask.key` / `self.keyask.present`; `fidokey.Failed` is shown with its `text` through `_fail`, except `NotTouched` at unlock, which shows "The key wasn't touched. Try again.". The same callables go to `dirsignin.finish` (line 622), `dirsignin.approve` (line 695) and `approve_with_account` (line 620).
- [ ] **Step 4: Run** this test with `tests/test_signin_ui.py tests/test_signin_fixes.py tests/test_signin_directory_ui.py tests/test_sso_signin_ui.py tests/test_lock_quit.py tests/test_lock_directory.py`. Expected: all pass.

---

### Task 6: "Security keys..." and the forced add

**Files:**
- Create: `ui/keysdialog.py`
- Modify: `app.py` (the user menu at lines 301-307; the start-up sign-in)
- Test: `tests/test_keysdialog.py`

**Interfaces:**
- Consumes: `datakey.my_keys/add_key/remove_key`, `dirsignin.keys_allowed`, `roles.require_keys/must_add_key`, `KeyAsk`, `fidokey.register`.
- Produces: `class KeysDialog(QDialog)` with `__init__(self, parent=None, must_add=False)`.

- [ ] **Step 1: Write the failing test.**

```python
check("the menu under your name has Security keys... between Lock and Sign out", menu_texts() == ["Admin1", "Lock (Ctrl+Shift+L)", "Security keys...", "Sign out"])
check("not for an SSO account, nor a recovery-key sign-in", "Security keys..." not in menu_texts_for("sso-user") and "Security keys..." not in menu_texts_for(None))
check("the dialog is headed Security keys, with Add a key... and Remove", d.windowTitle() == "Security keys" and buttons == ["Add a key...", "Remove"])
check("empty, a local account", d.empty.text() == "No security keys. Add one to need it, with your password, every time you sign in.")
check("empty, an AD account", d_ad.empty.text() == "No security keys. Add one to need it, with your PIN, every time you sign in.")
check("adding asks, in order", add_steps(d) == ["Enter your password", "Touch the key you want to add", "Name this key"]
      and add_steps(d_ad)[0] == "Enter your PIN" and name_hint == "for example, Blue YubiKey on my keyring")
check("after the first key", said == "From now on, signing in needs this key. Add a second key and keep it somewhere safe: if you lose your only key, an admin has to reset your account.")
check("...the only admin is told about the recovery key instead", said_only_admin == "You are the only admin. If you lose your only key, the recovery key is the only way back in.")
check("the list shows each key's name and when it was added", rows(d) == [("Blue", today)])
check("removing asks first", asked == "Remove Blue? You won't be able to sign in with it.")
check("the last key, a local account", asked_last == "This is your last key. Your account will sign in with its password alone.")
check("the last key, an AD account", asked_last_ad == "This is your last key. Your account will sign in without one.")
check("the last key while keys are required cannot go", refused == "An admin requires a security key. Add another key before removing this one." and len(datakey.my_keys()) == 1)
check("an AD account on a copy with the helper switch on", d_helper.note.text() == 'Security keys can\'t be added to this account while "Let group members sign in without approval" is on.'
      and not d_helper.add.isEnabled())
check("a wrong password in the add dialog adds nothing", error == "That username or password isn't right." and datakey.my_keys() == before)
# required at sign-in
check("keys required and none yet: the dialog opens before the main window, saying why", forced.must_add and forced.reason.text() == "An admin requires a security key. Add one to continue.")
check("closing it without adding signs out", session.state() == "signed_out" and main_window_never_shown)
check("adding one lets Toner open", main_window_shown_after_add)
```

- [ ] **Step 2: Run it.** Expected: FAIL (no module `ui.keysdialog`).
- [ ] **Step 3: Implement** the dialog (the key work on a `Job`, through `KeyAsk`), the menu action, and in `app.py` after a successful sign-in: `if roles.must_add_key(): KeysDialog(must_add=True)`; rejected means `session.sign_out()` and back to the sign-in window.
- [ ] **Step 4: Run** this test with `tests/test_signin_ui.py tests/test_ui.py`. Expected: all pass.

---

### Task 7: Settings > Accounts

**Files:**
- Modify: `ui/settings_pages/accounts.py` (the table at lines 149-150, `refresh` at 234-239, the buttons at 157-158, `_selection` at 272-276, `AccountDialog.accept` at 105-119, the helper switch at 341-378)
- Test: `tests/test_accounts_keys.py`

**Interfaces:**
- Consumes: `datakey.has_keys`, the records' `keys_n`, `datakey.clear_keys`, `roles.require_keys/set_require_keys`.

- [ ] **Step 1: Write the failing test**, built like `tests/test_accounts_page.py`.

```python
check("the list has a Keys column with each account's count; SSO rows are blank", headers[-1] == "Keys" and keys_cells == {"Admin1": "2", "Tech1": "0", "ana": "1", "sso-user": ""})
check("resetting a local password says what it does to keys", reset_dialog_note == "Resetting the password also removes this account's security keys.")
check("Remove keys... is enabled for an AD or LDAP row that has keys, and only then", enabled_for == {"ana": True, "bob": False, "Tech1": False, "sso-user": False})
check("it asks first", asked == "Remove ana's security keys? They will set a new PIN, with an admin's approval, the next time they sign in.")
check("yes clears them and the row shows 0", keys_cell("ana") == "0" and audit_last == ("security keys removed", f"ana, by {actor}"))
check("the require switch is labelled as approved and follows the signed rules", switch.text() == "Require a security key for every local, AD and LDAP account" and switch.isChecked() == roles.require_keys())
check("turning it on while the helper switch is on is refused and stays off", warned == 'Turn off "Let group members sign in without approval" first. It can\'t be on while security keys are required.' and not roles.require_keys())
check("turning the helper switch on while keys are required is refused", warned2 == 'Turn off "Require a security key for every local, AD and LDAP account" first. It can\'t be on while group members sign in without approval.')
check("turning the helper switch on while an AD account has keys is refused", warned3 == "Remove the security keys from AD and LDAP accounts first. This can't be on while they have keys.")
```

- [ ] **Step 2: Run it.** Expected: FAIL.
- [ ] **Step 3: Implement.** (The last refusal's wording is to approve first.)
- [ ] **Step 4: Run** this test with `tests/test_accounts_page.py tests/test_directory_accounts.py tests/test_helper_client.py`. Expected: all pass.

---

### Task 8: The command line

**Files:**
- Modify: `cli.py` (`_sign_in` at 85-139, `_directory_sign_in` at 142-151)
- Test: `tests/test_cli_keys.py`

**Interfaces:**
- Consumes: `session.sign_in(..., key=)`, `dirsignin.finish(..., key=)`, `fidokey.value`.

- [ ] **Step 1: Write the failing test**, built like `tests/test_cli_signin.py` (a fake tty and `getpass`).

```python
check("a keyed local account: the terminal says to touch the key, then signs in", "Touch your security key" in out and code == 0)
check("off Windows the key's PIN is asked without echo, in the approved words", prompts == ["Password: ", "Enter your security key's PIN: "])
check("not touched: the approved line on stderr and exit code 3", err.strip() == "The key wasn't touched. Sign in again." and code == 3)
check("a keyed AD account: no Duo code is asked", "Duo code: " not in prompts and code == 0)
check("an account without keys is as before", prompts_plain == ["Password: "])
```

- [ ] **Step 2: Run it.** Expected: FAIL.
- [ ] **Step 3: Implement** a `key` callable in `cli.py` that prints "Touch your security key" and calls `fidokey.value` with `ask_pin=lambda: getpass.getpass("Enter your security key's PIN: ")`; add `fidokey.Failed` to the exception list at lines 133-135, printing its `text`.
- [ ] **Step 4: Run** this test with `tests/test_cli_signin.py`. Expected: all pass.

---

### Task 9: The whole suite, the release note and the owner's checks

**Files:**
- Modify: the release notes file the last release edited (find it with `git log -3 --stat` on the previous version bump)

- [ ] **Step 1: Run** `python tests/run_all.py`. Expected: every file clean.
- [ ] **Step 2: Add the release note:** security keys for local, AD and LDAP accounts; an older Toner shows an account that has keys as damaged; not available to AD and LDAP accounts while "Let group members sign in without approval" is on. (Wording is the owner's to approve.)
- [ ] **Step 3: Hand the owner this list of checks on a real key**, none of which a test can do:
  - Windows: add a key, sign out, sign in (password, key PIN, touch), lock, unlock (password, touch alone; note whether Windows asks for the key's PIN), remove the key.
  - Windows: an AD account the same way, with Duo on for its directory (no Duo push once it has a key).
  - Windows: lose the key (unplug it): the messages, then an admin's reset and "Remove keys...".
  - Linux: the same local-account round, with Toner's own key-PIN page.
  - The spike's `--touch` run on Windows, and the plain spike on Linux, to confirm the value and the touch-only check there.

---

## Self-review notes

- Spec coverage: goals 1-7 map to Tasks 2-8; the staged helper rule to Tasks 4, 6 and 7; "Losing a key" to Tasks 2, 3 and 7; the Wording table is asserted across Tasks 1 and 5-8.
- Not built here, by the owner's decision: SSO accounts, and keys for AD and LDAP accounts on copies with the helper switch on.
- Unproven after this plan: macOS (no build), and every path on a real key until Task 9's checks are done.
