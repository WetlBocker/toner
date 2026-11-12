# Hardware security keys as a second sign-in step: design

Status: built on branch security-keys (2026-11-12) from the owner's decisions of the same day; not yet merged or released. Items marked *(owner)* are the owner's decisions; items marked *(my call)* are choices the owner has not made yet.

## Why

Local accounts have no second step today, and directory accounts have Duo or nothing. A password that is guessed, reused or phished
opens everything on that copy. A hardware security key (a YubiKey or any FIDO2 key) closes that: getting in then needs what the
person knows and the key in their hand.

Success means two things:

- A copy of the data folder plus the right password or PIN still opens nothing without the key.
- It costs one touch each time the person signs in or unlocks, and nothing more.

## Goals

1. A local, AD or LDAP account can have one or more security keys. *(owner)* Once it has one, signing in and unlocking need
   one of its keys as well as the password or PIN.
2. The key is a second step, never a replacement for the password or PIN. *(owner)*
3. The key takes part in unlocking the data, not only in a check after the password.
4. For a directory with Duo on, a key is a choice beside Duo: a person with a key uses the key and is not asked for Duo. *(owner)*
5. Each person decides whether to add a key; an admin can require one for every local, AD and LDAP account on the copy. *(owner)*
6. Works on Windows, Linux and macOS in the same release.
7. A lost key has a way back that does not weaken the rest.

## Non-goals (for now)

- Copies where "Let group members sign in without approval" is on, for AD and LDAP accounts. *(owner: staged)* See "Sign in
  without approval". Teaching the helper service about keys is a second piece of work.
- SSO accounts. *(owner)* The provider handles hardware tokens itself, in its own sign-in. Nothing in this work changes how an
  SSO account signs in, unlocks or is approved, and the require switch does not apply to it.
- Signing in with a key instead of a password or PIN (passwordless).
- Phone passkeys, Windows Hello and other built-in authenticators. Only keys you plug in or tap. *(my call)*
- Old U2F-only keys. They cannot do what goal 3 needs.
- One registration that follows a person from laptop to laptop. Keys are registered per copy, as PINs are.

## Anti-goals: a failure even if it works

- A key that is only checked. If Toner compares an answer and then opens the data with the password or PIN alone, someone with the
  data folder and that secret skips the check.
- A way round the key: any path that lets an account with a key in without it, short of an admin or the recovery key.
- A way back in that skips the recovery key.
- A sign-in screen that tells a stranger which names exist or which of them have keys.

## How it works

**The key's part.** FIDO2 keys can keep a secret per registration and answer with a value made from it and a number Toner supplies
(the `hmac-secret` feature, called PRF in WebAuthn). The value never leaves the key without a touch, and the same key and number
always give the same value. Toner mixes that value into what seals the account's copy of the data key. Without the key, the
account's seal cannot be opened.

**Local accounts.** Today the account's copy of the data key is sealed under a key made from the password. With security keys:

- a small blob sealed under the password alone holds the list of the account's keys (each key's credential id, its number, the
  name the person gave it, when it was added). Opening it proves the password and tells Toner which keys to ask for;
- there is one seal of the data key and box key per security key, each under the password key mixed with that key's value;
- there is no password-only seal of the data key any more.

**AD and LDAP accounts.** Today their copy of the data key is sealed in a PIN slot (the security chip, or the protected
store, or the PIN alone). With security keys, what the slot gives back is itself sealed once more, under each key's value: one
such seal per key. The PIN opens the slot; the key opens what the slot held. The list of the account's keys is kept so that it
only reads after the PIN is right. *(my call: the layering; the builder may order the two layers either way as long as both are
needed)*

An account without keys is stored exactly as today.

**Signing in, a local account.**

1. Name and password, as today. Wrong: today's message, counted on today's shared counter.
2. Right, and the account has keys: Toner asks for a key. On Windows this is Windows' own "Windows Security" prompt; on Linux and
   macOS it is a page in Toner's sign-in window. The person touches the key.
3. Toner opens the data.

**Signing in, an AD or LDAP account.**

1. The directory password, as today.
2. Duo, only when the directory has Duo on and the account has no key. An account with a key skips Duo. *(owner)*
3. The PIN, as today.
4. The key, when the account has keys.

**The choice beside Duo.** The person makes it by adding a key. From then on the key is that account's second step on that copy,
because the key is needed to open its data and Duo gives Toner nothing it could open the data with. There is no "use Duo today
instead": that would need a copy of the data key the key does not protect, which is the anti-goal.

**After an idle lock.** *(owner)* Unlocking needs the key again, by a touch alone: the Toner password and a touch for a local
account, the Toner PIN and a touch for an AD or LDAP account. The key's own PIN is not asked for here. The data key stays in
memory while Toner is locked (scheduled checks keep running), so the key only has to prove it is present: Toner asks it to sign a
fresh challenge and checks the signature against what the key registered. The secret is not read. The files themselves are
guarded by the key whenever Toner is signed out or closed, where the full sign-in reads the secret.

If an OS will not do the plain check without the key's PIN, unlock on that OS asks for the PIN and a touch; nothing else changes.

**Other places that sign in.** The same steps apply wherever an account signs in: an admin approving someone else's request with
their own account, and the command line's sign-in prompt.

A key that is not one of the account's is refused by the key or by Windows before anything is tried. Cancelling, or no key within
the time limit, returns to the page before.

## Registering and removing keys

- **Where.** *(owner)* "Security keys..." in the menu under your name, beside Lock and Sign out, which every role can open. It
  opens a dialog: a list of your keys with Add and Remove. (Settings > Security is locked for Techs by default.)
- **Adding.** Toner asks for your password or PIN again (it needs it to make the new seal), then for a touch on the new key, then
  for a name for it. Adding the first key removes the account's seal that the key does not protect, in the same write.
- **Two keys.** Toner recommends a second key when the first is added, and says what losing the only one means. It does not force it.
  *(my call)*
- **Removing.** Removing a key needs the password or PIN. Removing the last one returns the account to how it was before, unless
  the admin requires keys, in which case the last one cannot be removed.
- **Admins.** Settings > Accounts shows, per account, how many keys it has. An admin cannot add a key for someone else: the key has
  to be in that person's hand.
- **Requiring keys.** *(owner: an admin can set it; my call: one switch for the whole copy)* A switch in Settings > Accounts, the admin-only page
  that holds the sign-in settings, kept in the admin-signed rules so a non-admin cannot turn it off: every local, AD and LDAP
  account must have a key. SSO accounts are not asked. An account without one signs in as it does today, and is taken straight
  to adding a key before anything else opens.

## Losing a key

In this order:

1. Another key registered to the account.
2. An admin:
   - **a local account:** the admin resets its password, which clears its keys. This works because the admin's own sign-in holds
     the data key. A reset with the recovery key clears them the same way.
   - **an AD or LDAP account:** the admin removes the account's keys in Settings > Accounts. The person then signs in and sets a
     new PIN with an admin's approval, through the existing new-PIN approval; that approval makes a fresh seal with no keys.
3. The recovery key, as today.

There is no fourth way. An only admin who loses their only key needs the recovery key. Toner says so when that admin adds a key.

## Sign in without approval (the helper service)

Where that switch is on, the helper keeps a spare copy of Toner's key and hands it over for a directory password (and Duo). That
is a way round a key, and the helper has no way to learn who has one: a person adds their own key, but only an admin can write
what the helper trusts. *(owner, 2026-11-12: staged)* For this release:

- On a copy with the switch on, AD and LDAP accounts are not offered keys. Local accounts are unaffected.
- The switch and "Require a security key..." cannot both be on. Turning either on while the other is on is refused, with a reason.
- The switch cannot be turned on while an AD or LDAP account on the copy has keys. *(my call)*
- SSO accounts are untouched.

A later piece of work teaches the helper which accounts have keys, so that it can refuse them and skip Duo for them.

## What it needs

- **A library.** `fido2` (Yubico's python-fido2, BSD licence, pure Python on top of `cryptography`, which Toner already has). It
  talks to keys directly on Linux and macOS and through Windows' own WebAuthn service on Windows, which is the only way a program
  without administrator rights can reach a key there. *(owner: approved 2026-11-12)*
- **Windows.** Windows 10 1903 or later. The key prompt is Windows' own dialog; Toner cannot restyle it.
- **Linux.** The user needs access to the key's device, which current distributions grant through the udev rules that ship with
  `libfido2` or systemd. Where they are missing, Toner says the key was not found and how to check.
- **The key.** Any FIDO2 key with `hmac-secret`: YubiKey 5 and Security Key series, current Feitian, Nitrokey, SoloKeys, Titan (v2).

## Constraints

- Windows, Linux and macOS ship together under one version number.
- Every user-facing string needs the owner's approval before it is built.
- No secret in logs, exceptions or the audit log: not the password, not the PIN, not the key's value, not the key's own PIN.
- `netcheck.keys` written by this version is not readable by an older Toner for accounts that have keys. Accounts without keys are
  unchanged.
- An account's box key must not change when a key is added or removed, or the permissions granted to it would be dropped.
- The test suite stays headless: the part that talks to a key sits behind one small module that tests replace.
- The audit log records a key added, a key removed, keys cleared by an admin, and the require switch changing, with the key's name
  and never its credential id.
- There is no macOS build or test job in this repository. The code is written to work there and stays unproven until a Mac build
  exists.
- An older Toner shows a local account that has keys as damaged, not as too new. For an AD or LDAP account that has keys it says the
  PIN is wrong, and counts it on the wrong-tries wait. The release notes say so.
- Signing in often is the owner's standing worry (the first sign-in design's anti-goal). The owner chose a touch at every unlock
  knowingly; nothing else in this work may add a prompt.

## Limits found while building (2026-11-12)

- **A copy taken before a key was added.** A copy holds one data key and it is never changed. A copy of `netcheck.keys` made before an
  account's first key was added (or before a key was removed) still opens with that account's password alone, because it holds the
  seal from that time. A key protects every copy of the data folder made after it was added, not one made before. Closing this would
  mean re-encrypting the copy under a new data key, which needs every account's password at once.
- **AD and LDAP accounts on a computer with no security chip and no protected store** (the PIN-only slot). There an older seal put
  back into `netcheck.keys` by hand still opens with the Toner PIN, for the same reason. With a chip or a protected store, every key
  change moves the account to a fresh PIN slot and deletes the old one, so an older seal opens nothing.
- **Forgetting the Toner PIN, with a key.** An AD or LDAP person with a key who uses "Forgot your PIN?" is asked for Duo first (when
  their directory has Duo on), then sets a new PIN with an admin's approval, and the approved account has no keys. Skipping Duo is
  only good for the one path where the key then proves itself.
- **Several Toner windows on one account.** A process may change its account's keys only if the file still holds what it last saw.
  Otherwise nothing changes and it says "Sign in first." (an existing sentence).
- **The helper service, when in doubt, counts as on.** AD and LDAP accounts cannot add keys, and the require switch cannot go on,
  whenever this copy may be enrolled with the helper: the service installed but stopped or disabled, the service manager not
  answering, or the helper enrolled by another user of the computer. On Linux without systemd there is no helper.
- **The refusal to turn the helper switch on while an AD or LDAP account has keys** reads a count in the account's record that is not
  signed. A person who edits it can hide their own keys from that check; their keys themselves are sealed and unaffected.
- **Windows shows its own dialog for the key.** A missing or unregistered key ends with that dialog being dismissed, so Toner shows
  "The key wasn't touched..." there. "Toner can't find a security key..." and "That key isn't registered to this account." appear
  on Linux and macOS, where Toner talks to the key itself.
- **Wording used in one more place than the table says.** In the "Security keys" dialog a key that is not touched shows the unlock
  row, "The key wasn't touched. Try again.". The key-PIN page's button is the sign-in window's existing "Next".
- **After a recovery-key sign-in** the person is not sent to add a key for that one sign-in, even when keys are required, so an only
  admin who lost their key can get in and put things right.
- **Unlock trusts the session, not the file.** Once signed in with a key, unlocking asks for one of the keys that session signed in with, whatever netcheck.keys says by then.
- **The helper "in doubt" sentences.** With the helper installed but stopped, or enrolled by another user, an AD or LDAP person reads "...while "Let group members sign in without approval" is on" and an admin reads "Turn off ... first", while the Accounts page shows that switch off and greyed out. A truer sentence needs the owner's wording.

## Release note (draft; the wording is the owner's to approve)

- Security keys: a local, AD or LDAP account can add FIDO2 security keys under your name > "Security keys...". Once it has one,
  signing in needs your password or PIN, the key's own PIN and a touch; unlocking needs your password or PIN and a touch. An admin
  can require a key for every local, AD and LDAP account in Settings > Accounts.
- Not available to AD and LDAP accounts while "Let group members sign in without approval" is on. SSO accounts are unchanged.
- An older Toner shows a local account that has security keys as damaged; for an AD or LDAP account with keys it says the PIN is
  wrong and counts it on the wrong-tries wait. Update every copy that shares the data before adding a key.
- A security key protects copies of the data folder made after the key was added.

## What the spike found (Windows, the owner's key, 2026-11-12)

A throwaway script registered a test credential and read the key's value twice.

1. **Windows and `hmac-secret`: works.** The key gave a 32-byte value, the same on both reads, through Windows' own prompt.
2. **The name Toner registers under: `toner.invalid` works.** No website can have that name, so no web page can ask the key for
   Toner's value.
3. **The key's own PIN: Windows always asks for it** when the secret is read, even when Toner asks for a touch only. A key answers
   with a different value depending on whether its PIN was entered, so Toner asks for the PIN on every OS (user verification
   "required"): the value is then the same everywhere and an account cannot lock itself out. On Linux and macOS Toner's own window
   asks for the key's PIN and hands it to the key; it is never stored or logged.
4. **A library quirk to build round:** python-fido2 2.2.1 reads an empty `prf` request on Windows as "not asked". The number must go
   in with the registration request.

**What point 3 costs.** Every read of the secret is the key's PIN and a touch, on top of the Toner password or PIN. At the full
sign-in that is unavoidable. At an unlock the owner chose a touch alone (see "After an idle lock"). Whether Windows lets that plain
check through without the key's PIN is the spike's last open point (`--touch`), not yet run.

Still to run before release: the same script on Linux and on macOS.

## Wording

Every row approved by the owner on 2026-11-12. Toner's own window asks for the key's PIN on Linux and macOS; Windows asks in its
own dialog.

| Where | Text |
|---|---|
| Sign-in and unlock, waiting for the key | "Touch your security key" |
| Under it | "Plug it in if it isn't already, then touch it." |
| Its link back | "Use a different account" |
| No key found | "Toner can't find a security key. Plug yours in and try again." |
| Not one of the account's keys | "That key isn't registered to this account." |
| Timed out or cancelled | "The key wasn't touched. Sign in again." |
| Timed out or cancelled, at unlock | "The key wasn't touched. Try again." |
| The menu item under your name | "Security keys..." |
| The dialog's heading | "Security keys" |
| Empty list, a local account | "No security keys. Add one to need it, with your password, every time you sign in." |
| Empty list, an AD or LDAP account | "No security keys. Add one to need it, with your PIN, every time you sign in." |
| Buttons | "Add a key...", "Remove" |
| Add dialog, step 1, a local account | "Enter your password" |
| Add dialog, step 1, an AD or LDAP account | "Enter your PIN" |
| Add dialog, step 2 | "Touch the key you want to add" |
| Add dialog, step 3 | "Name this key" (hint: "for example, Blue YubiKey on my keyring") |
| After the first key | "From now on, signing in needs this key. Add a second key and keep it somewhere safe: if you lose your only key, an admin has to reset your account." |
| Same, for the only admin | "You are the only admin. If you lose your only key, the recovery key is the only way back in." |
| Remove confirmation | "Remove {name}? You won't be able to sign in with it." |
| Removing the last key, a local account | "This is your last key. Your account will sign in with its password alone." |
| Removing the last key, an AD or LDAP account | "This is your last key. Your account will sign in without one." |
| Last key while keys are required | "An admin requires a security key. Add another key before removing this one." |
| The require switch (was "...for every local account") | "Require a security key for every local, AD and LDAP account" |
| Sent to add a key at sign-in | "An admin requires a security key. Add one to continue." |
| Accounts list column | "Keys" |
| Admin reset note, a local account | "Resetting the password also removes this account's security keys." |
| Admin's button on an AD or LDAP account | "Remove keys..." |
| Its confirmation | "Remove {name}'s security keys? They will set a new PIN, with an admin's approval, the next time they sign in." |
| Linux and macOS, asking for the key's PIN | "Enter your security key's PIN" |
| Under it | "This is the PIN set on the key itself, not the one you use for Toner." |
| Wrong key PIN | "That key PIN isn't right." |
| The key wants to be re-inserted after wrong PINs | "Too many wrong PINs. Unplug the key, plug it back in and try again." |
| The key has locked its PIN for good | "The key's PIN is locked. The key has to be reset before it can be used again." |
| Linux and macOS, a key with no PIN set | "This key has no PIN yet. Set one with the key's own software, then add it here." |
| An AD or LDAP person on a copy with the helper switch on | "Security keys can't be added to this account while "Let group members sign in without approval" is on." |
| Turning the require switch on while the helper switch is on | "Turn off "Let group members sign in without approval" first. It can't be on while security keys are required." |
| Turning the helper switch on while keys are required | "Turn off "Require a security key for every local, AD and LDAP account" first. It can't be on while group members sign in without approval." |
| Key cannot do it | "This key can't be used: it doesn't support what Toner needs (FIDO2 hmac-secret)." |

## Left to the builder

- The exact record layout in `netcheck.keys` and its version number.
- How the password key or the slot's payload is mixed with the key's value (HKDF over both is the expected choice).
- How the sign-in window, the lock screen and the command line share the "ask the key" step.
- The time limit on the key prompt, and how Cancel is offered on Linux and macOS.
- How the helper learns which accounts have keys (see "Sign in without approval").
- How the key's public half is kept for the unlock check, and that the check uses a fresh challenge every time.
- Where the fake key for tests lives, and what the owner checks by hand on each OS before release.
