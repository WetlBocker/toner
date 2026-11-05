# User sign-in for Toner: design

Date: 2026-11-04. Status: draft, waiting for approval.

Notes in *italics marked "(my call)"* are decisions made while writing this up, not ones the owner made. Everything else is what the owner said.

## Why

Toner holds sensitive details about customers' infrastructure: addresses, configurations and config backups, check results, and device passwords. Today anyone who can open Toner, or copy its data folder, can read all of it.

Techs and engineers are the people who sign in. Each tech runs their own copy of Toner on their own laptop, with their own copy of the data. A central data store comes later, and nothing here should make it harder to add.

Success means two things:

- Toner's data on disk can't be read without signing in. Copying the data folder off a lost laptop gets nothing usable.
- Each person can do only what an admin has allowed. This holds without making techs sign in so often, or for so long, that they go looking for a way around it.

## Goals

1. Sign-in with local accounts, Active Directory, LDAP, and single sign-on through OpenID Connect (OAuth 2.0). The providers are Entra, Okta, Google Workspace and Duo SSO.
2. A second step (MFA) for AD and LDAP accounts, turned on per directory by an admin. SSO accounts use their provider's own MFA. Local accounts have none.
3. All of Toner's data is encrypted at rest and stays locked until someone signs in.
4. Roles with adjustable permissions, set by an admin.
5. The vault's master password goes away. Signing in opens the vault.
6. Signing in costs little in a workday: one full sign-in a day, and a quick PIN after an idle lock.

## Non-goals (for now)

- A central server, or shared accounts and data across laptops. This comes later.
- Scheduled checks and backups while nobody is signed in. This comes back with centralization.
- Setup files an admin builds once and hands out. For now an admin sets up each copy by hand.
- Per-person permissions, or locking single settings inside a page. Permissions are per role, and settings lock a whole page at a time.

## Anti-goals: a failure even if it works

- Signing in many times a day, or a sign-in that takes a long time. This is the owner's main worry: techs will hate it and work around it.
- A login screen in front of data that's still readable on disk.
- A way back in that skips the recovery key. If the recovery key is lost, the data is gone for good. That's the owner's decision.

## Who decides what

- **Admin.** Sets up each copy: the local accounts, the directory and SSO connections, which groups map to which roles, and the role permissions. Keeps the recovery key.
- **Directory and SSO users.** Their role comes from group membership in AD, LDAP, Entra, Okta, Google Workspace or Duo SSO. They can't change it.
- **Local users.** Their role is set by an admin on that copy.

## Signing in (the owner chose this layout)

The mockups from the conversation are beside this document: `2026-11-04-user-sign-in-mockups/signin-layout.html` (option C for sign-in, B for the lock screen) and `signin-mfa.html` (push first, with the code as the backup).

1. **Username first.** One box: "Username or email", then Next. Toner works out the account type:
   - an email domain or UPN suffix matched to a configured SSO provider or directory,
   - a `DOMAIN\user` form,
   - or a local account name.

   *(my call: an admin can also map a domain to a method by hand when the two would clash.)*
2. **The method's own step.**
   - **SSO:** Toner opens the provider's sign-in page in the system browser, using the authorization code flow with PKCE and a loopback redirect. The provider handles the password and MFA.
   - **AD and LDAP:** a password, checked by binding to the directory over LDAPS, or over StartTLS. Plain LDAP is refused.
   - **Local:** a password.
3. **Second step (AD and LDAP, when turned on).** A Duo push first, with "Enter a code instead" as the backup: a 6-digit code. The push screen reads "Approve on your phone" and waits, with Cancel.
4. **The Toner PIN** (directory and SSO users only). On the first sign-in to a copy, the person sets a PIN. After that, the full sign-in asks for it as well. The PIN is 6 digits, protected by the computer's security chip (see "Locking the data"). *(my call: the PIN comes last, after the directory or provider has said yes.)*
5. **Admin approval, the first time only.** When a directory or SSO user signs in to a copy for the first time, an admin approves it at the laptop, by signing in or by using the recovery key. Nothing the user types can unlock the data yet. The directory only answers yes or no. The same approval is needed after a forgotten PIN, on a different computer, and when a group change moves someone into a role that can see unmasked backups. The owner decided this.
6. Toner opens.

**Lock screen (layout B).**
- Toner's window stays open behind a cover reading "Toner is locked".
- To unlock, a local user types their password and a directory or SSO user types their PIN.
- "Sign in as someone else" goes back to step 1.
- The lock comes after a stretch of no use. *(my call: 15 minutes by default, set by an admin.)*
- Locking with a keyboard shortcut is also available.

**How often.**
- *(my call: a full sign-in, with the directory and the second step, lasts the workday, 12 hours by default and set by an admin.)* Within that, idle locks only ask for the PIN or password.
- While online, Toner re-checks directory and SSO accounts quietly in the background. If an admin disables someone, or removes them from Toner's groups, that person's Toner locks at the next check. *(my call: about every 15 minutes. AD and LDAP need a service account the admin enters, kept in the vault. SSO uses the refresh token.)*

**Offline.** A new full sign-in for a directory or SSO account needs a connection, or a successful online check in the last hour. Local accounts work offline. Within that hour, the PIN is what unlocks.

A tech who is already signed in and goes offline keeps working: on a console cable, say, or at an isolated site. The open session carries on, and PIN unlocks keep working, until the workday sign-in ends. Only a brand-new full sign-in needs a connection again. The owner decided this, because techs locked out mid-job is the failure they most want to avoid. If the background check reaches the directory again and finds the account disabled, Toner still locks it at once.

**When Duo can't be reached.** If the directory answers but Duo doesn't, sign-in is refused. Duo's own default is to refuse, and skipping the second step would let anyone get past it by blocking one web address. *(my call)* The 6-digit code is Duo's own passcode, checked through Duo, so it needs Duo too.

## Locking the data

The vault already works this way: one data key, sealed by a key made from the master password (scrypt, AES-GCM, in `core/passvault.py`). Sign-in extends that pattern:

- **One data key per copy** encrypts everything Toner keeps on disk: every organization's database, the vault, config backups, session logs, saved reports, and the other files in the data folder. Logs keep no secrets, but are covered anyway.
- **The data key is sealed several times,** once for each way in:
  - **Local account:** sealed with a key made from that person's password.
  - **Directory or SSO account:** sealed with a key held by the computer's security chip and unlocked by their 6-digit PIN: the TPM on Windows and Linux, the Secure Enclave on Macs. It works the way Windows Hello does. The chip, not Toner, limits wrong guesses, so someone inside the tech's computer account can't copy the sealed key and try every PIN offline. The owner chose this over a longer software-only PIN, so that someone inside the tech's Windows account still can't get in without the PIN.
    - *(my call)* **A computer without a usable chip:** a TPM switched off, an old Mac, a Linux box without a TPM. There, the key is sealed by the operating system's protected store (DPAPI, the Keychain, Secret Service) plus a PIN of at least 8 characters, letters allowed, which is too many combinations to guess offline. The admin sees which kind each account on a copy has. With no protected store either (Linux without Secret Service, which `passvault.NoKeyring` already detects), it uses the 8-character PIN alone.
  - **Recovery key:** shown once when the copy is set up, kept by the admin. It opens the data and lets the admin reset any account. There is no other way back. If it's lost along with every password and PIN, the data on that copy is gone. The owner decided this.
- **What's covered.** Everything in the data folder, with three exceptions *(my call)*:
  - **The logs, `toner.log`, `toner-service.log` and `ssh-tunnel.log`:** written before anyone signs in, or by another program, and they keep no secrets. Also left plain are the public data Toner downloads: `oui.txt`, `ca-bundle.pem` and `updates/`.
  - **The Ansible playbook library:** WSL reads it straight from disk and people edit it in their own editor, so it should hold no secrets. Ansible's passwords come from the vault.
  - **The agent receiver's TLS key:** this one is encrypted like the rest, and unlocked when the receiver starts, which only happens while someone is signed in.
- **Locked versus signed out.**
  - **Locked:** the key stays in memory, so scheduled checks and backups keep running.
  - **Signed out, or Toner closed:** the key is wiped from memory and scheduled runs stop.
- **Repeated wrong guesses** slow down and then lock the account for a while. This covers passwords, PINs and codes. Local passwords must be long and are checked against a list of common and leaked ones.

How the databases get encrypted is left to the builder. SQLCipher is one way, and encrypting each file with the data key is another. See "Left to the builder".

## Roles and permissions

There are three starting roles *(my call)*. An admin can tick each permission on or off for each role:

- **Admin:** everything, including accounts, sign-in and directory settings, roles, and the recovery key.
- **Engineer:** everything except managing accounts, roles and sign-in settings.
- **Tech:** runs checks and uses the tools the admin leaves on. Can't push changes to devices, can't see config backups unmasked, and can't change settings except Appearance and Terminal.

The permissions an admin can switch, per role:

- **Push changes to devices.** This covers every path that writes to a device: config push and restore, Ansible runs, bulk changes, factory reset, firmware upgrades, and commands that change things.
- **See config backups with the secrets showing.**
- **Each tool on its own:** each Tools page, the API Tester, SSH and the terminal, RDP, file transfer and the others.
- **The AI assistant.**
- **Each Settings page,** open or locked. A locked page still shows its settings but can't be changed. The pages: General, Thresholds, Checks, Scanning, Maintenance, Connections, Proxy, Credentials, Agents, Demarc, Notifications, Reports, Config backups, Ansible, AI, Appearance, Terminal, Security, Audit log, Data and logs, Organizations.

A switched-off feature is hidden or disabled with a short reason. It doesn't fail when clicked.

**An honest limit.** Each tech's copy runs on their own laptop and holds the data key once they've signed in. So permissions stop mistakes and casual misuse, not someone set on taking the app apart. Two things narrow that gap:

- *(my call)* The role and permission rules are signed by the admin. That catches anyone editing the rules by hand, but not someone who replaces the rules, the signature and the checking key all together. Nothing on a laptop the tech controls can stop that until the server exists.
- *(my call)* Unmasked config backups are encrypted with a second key that's only sealed for roles allowed to see them. A tech's copy really can't show them.

Real enforcement comes with the central server.

## Setting up a copy

- **The first start.** On a new copy, or on an existing copy after the upgrade, Toner asks whoever opens it to create the first admin account, which is local. It then shows the recovery key and asks them to confirm they've saved it.
  - On copies already in use, that's usually the tech. The owner chose this: the tech sets it up and holds the recovery key.
  - *(my call)* An admin can later take the copy over: add their own admin account, make a new recovery key (which retires the old one), and change the tech's account to a Tech.
- **An existing copy.** On upgrade, Toner asks for the old master password once. It moves the vault's passwords in, then encrypts the existing data. *(my call: an existing install that doesn't remember its master password still asks for it. If it's forgotten, the vault starts empty, as Forgot it? does today. The rest of the data is kept.)*
- **The admin adds the rest:**
  - local accounts,
  - AD and LDAP connections (server, base DN, LDAPS certificate checking, service account, group-to-role map, second step on or off, and Duo settings),
  - SSO providers (presets for Entra, Okta, Google Workspace and Duo SSO, plus a generic OpenID Connect option, each with a group-to-role map),
  - role permissions,
  - and lock times.

  *(my call: these live under a new Settings page, "Accounts and sign-in", that only Admins can open.)*
- **Portable copies.** A portable copy moved to another computer opens for local accounts and with the recovery key. Directory and SSO users need an admin's approval there and set their PIN again, because the security chip doesn't travel. *(my call)*
- **Google Workspace groups.** Google doesn't send group membership with a sign-in. Mapping its groups to roles needs extra setup through a Google admin service account. Without that, Google users get the role an admin assigns them on that copy. *(my call)*

## Around the edges

- **Audit log.** It records sign-in, sign-out, lock, unlock, failed attempts, account and role changes, and use of the recovery key. Every audit entry names the signed-in Toner user instead of the Windows user name it uses today (`core/audit.py`).
- **The command line and the service** (`cli.py`, `core/service.py`). These run without a window today, through Task Scheduler.
  - *(my call)* `service` and other scheduled command-line runs stop working until centralization, matching "no runs while signed out". They say why when started.
  - *(my call)* Interactive commands such as `toner check` and `toner status` ask for a sign-in at the terminal.
  - This is a visible change for anyone using the service today, and the release notes must say so.
- **Wording.** All the text on the mockups is a draft. The owner checks the wording before it's built, as with every change to Toner.

## Constraints

- Windows, Linux and macOS ship together under one version number. Sign-in must work on all three.
- New dependencies need the owner's approval before they're installed. This work likely needs:
  - an LDAP client (ldap3),
  - an OpenID Connect or JWT library (authlib, or msal for Entra only),
  - Duo's Auth API, which is HTTPS and can be called directly,
  - possibly SQLCipher,
  - access to the security chip on each platform: Windows' TPM key storage, the Secure Enclave on macOS, and TPM 2.0 on Linux. Each may be reachable through what the system already provides, or may need a small library.

  Toner already has `cryptography` and `keyring`.
- Toner never decrypts other apps' stored passwords. Masked inspection only. Imported passwords go to Toner's vault.
- The existing test suite keeps running headless. Tests need a way to start Toner signed in.

## Left to the builder

- How the databases and other files are encrypted (SQLCipher or file-level). This includes how many database connections behave, plus the performance work already done for large inventories (40 organizations, 2000 devices).
- The key derivation settings (scrypt, the existing choice, or Argon2), the token storage, and the session format.
- How Toner tells the account types apart when names clash, within the rule that admins can map domains by hand.
- How each switched-off feature is hidden or disabled, and how the permission checks are wired through the code.
- How the second step and the background re-check work against each provider.
- How each platform's security chip is reached, and how a computer without one is detected.
