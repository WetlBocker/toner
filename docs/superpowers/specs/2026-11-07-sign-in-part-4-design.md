# Sign-in part 4: SSO, sign-in without approval, and directory admins approving

Date: 2026-11-07. Status: approved by the owner, 2026-11-07.

This builds on `2026-11-04-user-sign-in-design.md` (the sign-in design) and on what parts 1 to 3 and External Identities built. Where
this document and the sign-in design disagree, this document wins: the owner changed two things on 2026-11-07, marked **(changed)**.

Notes in *italics marked "(my call)"* are decisions made while writing this up, not the owner's. Everything else is what the owner said.

## Why

Techs already sign in with AD or LDAP. Most of the owner's people also have a Microsoft (Entra) account, and other teams use other
single-sign-on providers. Part 4 lets them sign in with that account, through the provider's own page and MFA.

The owner also wants a copy of Toner to accept anyone in a mapped group without an admin standing at the laptop the first time, but
without opening Toner's data to anything that gets into the tech's Windows session.

## Goals

1. **Single sign-on through OpenID Connect, provider-agnostic.** One connection type that works with any OpenID Connect provider.
   Entra must work; Okta, Google Workspace, Duo SSO and others work through the same type.
2. **SSO users get everything directory users have.** A role from group membership, the Toner PIN, the 12-hour session, idle locks
   that ask for the PIN, background re-checks, and the offline rules. All as in the sign-in design, "SSO in part 4".
3. **(changed) Sign-in without approval, as a switch.** "Let group members sign in without approval", per copy, Admin only, **off by
   default**. It covers AD, LDAP and SSO groups alike.
4. **A helper service** that makes the switch safe against anything running inside the tech's Windows session.
5. **Directory and SSO admins approve.** While the switch is off, anyone whose Admin role comes from a directory or SSO group can
   approve a first sign-in, in person at the tech's laptop, with their own account.

## Non-goals

- Approving from a distance (from the admin's own Toner). It needs the central server.
- The central server itself, and sharing accounts or data across laptops.
- SAML. OpenID Connect only.
- Reading Google Workspace groups. Google sends none with a sign-in; Google users get the role an admin assigns on that copy, as the
  sign-in design already says.

## Anti-goals: a failure even if it works

- **A spare key that anything in the tech's Windows session can use.** This is why the helper service exists. With the switch on,
  getting into the tech's Windows account must still not be enough to open Toner's data.
- **Quiet reuse of a browser that is already signed in.** Malware must not be able to finish an SSO sign-in on its own because the
  browser still holds the person's Microsoft session.
- **More sign-ins in a day than now.** SSO keeps the one full sign-in per session and the PIN for idle locks.
- **Toner's data readable on disk.** Unchanged: data on disk is always encrypted, and only unlocked in memory.

## SSO connections

**Adding one.** External Identities > Add > **SSO (OpenID Connect)**. Its first step picks a provider: **Entra, Okta, Google
Workspace, Duo SSO, Other**. A preset only fills in that provider's usual settings and shows its own setup notes; **Other** takes
anything that speaks OpenID Connect.

Toner needs from the provider:

- the provider's address (the issuer). Toner finds everything else from it: the sign-in and token addresses, and the keys that sign
  its answers. For Entra, the tenant ID is enough.
- an app ID (client ID) that the provider's admin creates for Toner, as a desktop app.
- where the provider lists a person's groups: the claim name, filled in by the preset.

**Groups.** The External Identities group mapping works as it does for AD and LDAP (each group maps to a role, with the search box for
large directories).

- **Entra** sends group IDs, not names. To show names and search them, the admin signs in once during setup with their own Entra
  admin account. Toner uses that sign-in only to list and search groups, and stores nothing but the chosen groups' IDs and names.
- When someone is in so many Entra groups that Entra sends a pointer instead of the list, Toner asks Microsoft for the list.
- **Okta and Duo SSO** send group names once their admin turns that on.
- **Google Workspace** sends no groups (see Non-goals).

**Signing in.** The sign-in design's flow, filled in:

1. "Username or email", then Next. An email domain matched to an SSO connection picks it (as the sign-in design describes).
2. Toner opens the provider's page in the system browser: the authorization code flow with PKCE and a loopback redirect, plus a
   one-time value (nonce) Toner checks in the answer. **The provider is asked for a fresh sign-in every time** (the person types their
   password and does MFA even when the browser is already signed in), and Toner checks the answer says so.
3. Toner checks the provider's signed answer: its signature against the provider's published keys, the issuer, that it is meant for
   Toner's app ID, the nonce, the time, and the groups.
4. First sign-in on this copy: approval (switch off) or the helper (switch on), then the person sets their PIN. Later sign-ins: the
   PIN.

**Background re-checks.** About every 15 minutes while online, using the provider's refresh token kept in the vault. If the account
is disabled or no longer in a mapped group, Toner locks, as it does for directory accounts. The offline rules are the same as for
directory accounts.

## The switch: sign in without approval

- Lives on the Admin's sign-in settings. Off by default.
- **Turning it on** shows a warning first. The admin has to confirm it. The warning says, in words the owner approves: the computer
  keeps a spare copy of Toner's key, held by Toner's helper service, so anyone in a mapped group can sign in here for the first time
  without an admin, and an admin of this computer could reach that spare copy. *(my call on the content; the wording is the owner's to
  approve)*
- **Turning it off** deletes the spare copy at once. First sign-ins need an approval again.
- **Off:** a person's first sign-in on a copy needs an admin's approval, as today.
- **On:** being in a mapped group is the approval. The person signs in (with Duo, when it is on for that directory), sets their
  PIN, and Toner opens.
- *(my call)* The same approval cases the sign-in design lists (a forgotten PIN, a different computer, a group change into a role
  that can see unmasked backups) also go through the helper while the switch is on.
- *(my call)* The switch is greyed out, with a reason, on a portable copy, and for another user on a computer whose helper serves
  someone else. Turning it on where the helper isn't installed installs it (see the helper service); where it is installed but not
  running, the switch says so and stays off.

## The helper service

One per computer, running as a system service: a Windows service, or a systemd service on Linux. *(my call)* macOS gets its launchd
daemon when the macOS app joins the shared release; there is no macOS app build yet. Toner talks to it locally.

- **It holds the spare key** in a store that only the system service can read: the machine's protected store or the security chip,
  under the service's own system account. Ordinary programs running as the tech can't reach it.
- **It never takes Toner's word.** It hands the key over, sealed for the new person's own key, only after it has checked the sign-in
  itself:
  - **SSO:** it checks the provider's signed answer as Toner does (signature, issuer, app ID, a nonce the helper issued for this
    sign-in, a fresh password-and-MFA sign-in, the time, and membership in a mapped group).
  - **AD and LDAP:** it checks the password against the directory itself over LDAPS or StartTLS, then Duo when it is on, then group
    membership.
- **It reads its rules** (which connections and groups are trusted) only from the admin-signed rules that part 2 introduced, so
  editing the rules file doesn't widen who gets in. *(my call)* It pins the rules key's fingerprint when the switch is turned on. If
  the rules key is replaced later (a repair after a recovery-key sign-in replaces it), the switch turns itself off, the spare copy is
  deleted, and an admin turns it on again, warning and all.
- **What it holds.** *(my call)* The data key and the rules key, so the person it lets in is recorded with their mapped role, as an
  approval does today; someone in an Admin group is a full Admin at once. **Not** the unmasked-backups key: a person whose role can see
  unmasked backups gets that key the first time an Admin who holds it signs in on that copy, and sees masked backups until then.
- **Fresh sign-in, the provider's MFA.** *(my call)* The helper and Toner require the provider to confirm a fresh sign-in (asked for
  with `prompt=login` and `max_age=0`, checked through `auth_time`). MFA is the provider's own policy (Entra's Conditional Access, for
  example): Toner doesn't demand proof of it in the answer, because Entra doesn't send that by default and passwordless sign-ins have no
  password step.
- **What it guards against:** anything running as the tech, including malware and someone at an unlocked laptop. **What it doesn't:**
  someone with admin rights on the computer. The warning says so.
- **Installed when the switch is turned on** (the owner, 2026-11-07). Toner keeps its install without admin rights. Turning the switch
  on installs the helper with one admin prompt (Windows' UAC, a password prompt on Linux). An update asks for admin rights only when it
  changes the helper; otherwise updates stay silent. The helper and Toner share the one version number; *(my call)* a Toner that finds an
  older helper keeps working with it while their protocol version matches, and asks to update it when it doesn't.
- **One copy per computer.** The helper serves the copy of the Windows (or Linux) user who turned the switch on. *(my call)* Another
  user on the same computer sees the switch greyed out, with a reason.
- *(my call)* If the helper isn't running, a first sign-in falls back to asking for an approval, with a short reason. The person's
  own PIN unlock never depends on the helper.
- **Audit.** The copy's audit log records each sign-in the helper allowed, and turning the switch on and off.

## Directory and SSO admins approving

While the switch is off, the approval page accepts, besides the existing local admin and recovery key:

- anyone whose **Admin** role comes from a directory or SSO group, signing in with their own account at that laptop: password and
  Duo for AD and LDAP; the provider's page with a fresh sign-in for SSO.

**The approver must already have signed in on that copy** (the owner, 2026-11-07). They sign in with their own account, then type
their own Toner PIN: that is what opens the copy's keys for the approval, so "off" keeps meaning there is no spare key on the laptop.
An admin who has never used that laptop can't approve there; the local admin or the recovery key can, or the switch can be on.
Approving from a distance is a non-goal.

## Constraints

- Windows, Linux and macOS ship together under one version. The helper exists on all three.
- Every user-facing string is approved by the owner before it is built: the SSO step texts, the provider notes, the switch, its
  warning, and every message from the helper.
- New dependencies need the owner's approval before they're installed. Likely:
  - a JWT library to check the provider's signed answers (PyJWT, which builds on the `cryptography` Toner already has, or authlib);
  - on Windows, running the helper as a service (pywin32, or a small service host).
- Installing the helper needs admin rights. Today Toner installs per user without asking for them (`packaging/toner.iss`,
  `PrivilegesRequired=lowest`), updates itself silently, and keeps its data per Windows user.
- No secret in logs, the audit or exceptions: tokens, refresh tokens, the spare key, passwords and codes.
- The test suite keeps running headless, on all three platforms, with a pretend OpenID Connect provider and a pretend helper. Entra is
  checked live by the owner.
- The sign-in design's rules stay: no way back without the recovery key; the security chip and PIN for each person's own key.

## Left to the builder

- How Toner and the helper talk (a named pipe or a local socket that only Toner's user can open), and how the helper knows the request
  comes from Toner.
- How the helper's spare key is stored on each platform, and how a running helper is detected.
- How the Linux AppImage and the macOS app install and remove the service.
- The refresh-token storage and the re-check timing details.
- How the Entra group-list sign-in during setup asks for its permission, and the pointer-instead-of-groups case.
- Which provider settings each preset fills in.
