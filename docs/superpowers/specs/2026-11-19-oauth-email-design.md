# OAuth 2.0 for email: design

**Status:** draft for the owner's approval (2026-11-19). No code is written from this until it is approved, including the wording in section 5.

**Request (Adjustments 2026-11-19, item 6):** "Due to increased security requirements, OAuth2.0 needs to be supported to be able to configure email notifications and to email reports. Please ensure Toner can be configured with OAuth as required by both Exchange and Gmail. This is an addition to standard SMTP not a replacement."

**Basis:** the code on branch `adjustments/2026-11-19` and the vendor pages listed at the end, read on 2026-11-19. Nothing was run. Points that could not be confirmed from a vendor page are marked.

## 1. What each provider requires today

| | Microsoft 365 / Exchange Online | Google Workspace / Gmail |
|---|---|---|
| Password sign-in | Works until the end of December 2026, then off by default for existing tenants (admins can re-enable it) and unavailable for new ones. Final removal date to be announced in the second half of 2027 [M3]. | Password-only SMTP was scheduled off for all accounts on 14 March 2025; app passwords still work [G8]. |
| OAuth over SMTP | SASL XOAUTH2 [M1]. | The same, with the scope `https://mail.google.com/` [G1]. |
| A person signs in once | Authorization-code flow with the scopes `https://outlook.office.com/SMTP.Send` and `offline_access` [M1]; redirect `http://localhost`, any port [M8]. | Desktop-app client, loopback redirect, PKCE [G2]. |
| No person | Client credentials: the application permission `SMTP.SendAsApp`, admin consent, and two Exchange PowerShell commands (`New-ServicePrincipal`, `Add-MailboxPermission`) [M1]. Needs a client secret or certificate; there is no refresh token [M9]. | A service account with domain-wide delegation, set by a super admin [G7]. Not confirmed: that Gmail's SMTP accepts such a token. |
| Traps | Authenticated SMTP must be on for the mailbox; it is off under security defaults [M2]. The refresh token lasts 90 days, is renewed on each use, and is revoked by a password change or an admin reset [M5]. | `mail.google.com` is a restricted scope [G4] unless the app is Internal to the organisation [G6]. For an External app in Testing the refresh token dies after 7 days [G3][G5]. It also dies after 6 months unused or a password change [G3]. |
| HTTP API instead of SMTP | Graph `sendMail` with `Mail.Send` [M6]; app-only means "send as any user" unless scoped in Exchange [M7]. | `users.messages.send` with `gmail.send`, a sensitive rather than restricted scope [G4][G9]. Size limits not confirmed. |

## 2. Options

**A. SMTP with XOAUTH2; a person signs in once.**
- The customer registers an app (an Entra public client, or a Google Desktop client in a project set to Internal) and turns on authenticated SMTP for the mailbox.
- Toner reuses its existing browser sign-in, keeps a refresh token in the vault, and adds one call when it sends.
- A windowless Toner sends with the stored token; it cannot sign in.
- If the token is revoked or expires, mail fails until someone signs in again at the window.

**B. SMTP with XOAUTH2; app only, no person.**
- Microsoft: admin consent and two PowerShell commands. Google: a super admin delegates `mail.google.com`, which covers every mailbox in the domain.
- Toner makes one token call per mail (Microsoft); for Google it would need a signed token and a private key in the vault.
- Fully unattended. An expired secret or withdrawn consent shows as "refused the app".

**C. The vendors' HTTP mail APIs (Graph, Gmail API).**
- Narrower permissions and no SMTP switch on the customer's side.
- Two new ways of sending beside SMTP, on top of A's or B's token handling; they would not use Toner's proxy, and attachment limits are unconfirmed.

## 3. Recommended: A for both providers, plus B for Microsoft

OAuth becomes a choice on the existing Email channel, so alerts and the scheduled reports work unchanged (`core/notify.py:337`, `:342`).

**The channel's form** (`core/notify.py:35`, `ui/settings_pages/notifications.py:46`)
- A new choice, "Sign in with": Password (today's behaviour, the default), Microsoft 365 account, Microsoft 365 app (no person), Google account.
- New plain settings: tenant ID, client ID. New secret: client secret, kept in the vault like the password (`core/notify.py:80-99`); required for app-only, optional for Google.
- Username is the mailbox Toner sends from. Security "None" is refused with OAuth.
- The form shows only the chosen method's fields, a Sign in button and who is signed in.

**Reusing the single sign-on code**
- The browser sign-in and the refresh call already exist (`core/oidc.py:267`, `:324`; presets in `core/ssopresets.py:23`).
- Two small changes there: the token call takes the client secret as an argument (today it reads only the system store, `core/oidc.py:211`), and the browser sign-in gets a switch to drop the "sign in again now" demands mail does not need (`core/oidc.py:285`, `:321`).

**Where the sign-in is kept**
- The refresh token goes in the vault under a name of its own for the channel, with the time it was last renewed, as single sign-on stores its own (`core/dirsignin.py:865`). It is never a form field and never leaves in an export.

**Sending** (`core/notify.py:274`)
- Get an access token, then authenticate the SMTP session with it. One token call per mail; nothing is cached.
- The token is scrubbed from every error text the way passwords already are (`core/notify.py:189`).

**Which process renews the sign-in**
- Whichever sends: the window, `cli run`, or the daemon. Only the window can sign in.
- Two processes renewing at once is harmless for Microsoft, which does not revoke the old refresh token [M5]. For any provider that does, Toner re-reads the vault once after a refusal and retries if the token changed.
- So a quiet period cannot let the sign-in lapse, Toner renews any sign-in older than 7 days at the start of a run (`core/notify.py:363`).
- When a provider refuses the sign-in for good: the token is removed, the audit log says so, and the other channels are told once.

**Send test** uses the same path. It moves off the window's thread, where it blocks today (`ui/settings_pages/notifications.py:110`).

**Audit log:** "email sign-in" (channel, provider, account), "email sign-in removed", "email sign-in refused". Never a token, a secret or a URL.

**Export, import, backup**
- Settings export already leaves channels out (`core/db.py:155`).
- The password export carries the client secret, never the sign-in; an import can never plant a sign-in (`core/vault.py:81`).
- A copied data folder carries the sealed vault; if the provider refuses the old sign-in, the channel asks for a new one.

## 4. What is left out

- Google service accounts (delegation exposes every mailbox, and SMTP acceptance is unconfirmed).
- The HTTP mail APIs (revisit when Microsoft announces the end date for authenticated SMTP [M3]).
- Consumer Gmail and Outlook.com accounts: not claimed as supported.
- An app registration owned by Toner: Google's restricted scope would need verification, and Toner ships as source so it cannot keep a secret.

## 5. Wording to approve

`{provider}` is "Microsoft 365" or "Google".

**Form**
- "Sign in with": "Password", "Microsoft 365 account", "Microsoft 365 app (no person)", "Google account"
- "Tenant ID", "Client ID", "Client secret"; placeholder "leave blank if the app has none"
- Buttons "Sign in", "Sign in again"
- "Not signed in." / "Signed in as {account}."

**Help under the form**
- Microsoft 365 account: "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect URI http://localhost and the delegated permission SMTP.Send. Turn on authenticated SMTP for the mailbox, then sign in here as that mailbox."
- Microsoft 365 app: "Register an app with the application permission SMTP.SendAsApp, admin consent and a client secret. Register it in Exchange Online and give it access to the mailbox. Nobody signs in."
- Google account: "In Google Cloud, create an OAuth client of type Desktop app in a project set to Internal, then sign in here as the mailbox."
- The channel's help becomes: "Sent through your mail server. Passwords and sign-ins are kept in Toner's vault."
- The remove prompt becomes: "Its saved webhook URL, password or sign-in is deleted too."

**Checks when saving**
- "Signing in with Microsoft 365 or Google needs STARTTLS or SSL/TLS."
- "Username is required: the mailbox Toner sends from."
- "Sign in first."

**Errors**
- "Toner isn't signed in to {provider} for this channel. Edit the channel and choose Sign in."
- "{provider} no longer accepts this sign-in. Edit the channel and choose Sign in again."
- "{provider} can't be reached, so the email wasn't sent."
- "{provider} refused the app. Check the tenant ID, client ID and client secret."
- "{provider} didn't give Toner a sign-in it can keep. Check the app's setup, then sign in again."
- "The mail server refused the sign-in. Check the username, that the app may send from this mailbox, and that authenticated SMTP is on for it."

**Notice on the other channels:** "{channel} needs a new sign-in. Edit it in Settings > Notifications and choose Sign in again."

## 6. Tests

**With fakes**
- A fake token endpoint: a renewal stores the new token; a refused sign-in gives the message, removes the token and sends one notice; a server error keeps the token; the app-only call carries the scope and the secret.
- A fake SMTP server that checks the exact XOAUTH2 string, the refusal path, and that authentication is refused before TLS.
- No token or secret in any error detail, log or audit line.
- A report with an attachment through an OAuth channel; password channels unchanged.
- The form follows the choice; Sign in runs off the window's thread and can be cancelled; Remove deletes the sign-in.
- Two processes renewing against a fake that rotates tokens; an export or import never carries a sign-in; the 7-day renewal fires.

**Only the owner can check**
- Microsoft 365: an account with multi-factor sign-in, a shared mailbox, authenticated SMTP off then on, security defaults on, the app-only setup, revoked sessions, a password reset.
- Google Workspace: an Internal client with and without a secret, a password change.
- Both: a large report, `cli run`, and the browser sign-in on macOS and Linux.

## 7. Decisions for the owner

1. **Microsoft app-only in the first version?** Recommended: yes. One token call, no stored sign-in, nothing to expire silently.
2. **Google service account?** Recommended: no (section 4).
3. **HTTP mail APIs?** Recommended: not now.
4. **Token calls do not go through Toner's proxy** (an existing rule for single sign-on, `core/oidc.py:24`); the mail itself still does. Recommended: accept and document it.
5. **Deleting an organization leaves its channels' vault entries behind** (`core/orgs.py:458`). Recommended: fix it in this change.
6. **Not confirmed from vendor pages, to be settled by your real-tenant tests:** whether Google's token exchange needs the desktop client's secret; whether Microsoft's security defaults also block OAuth SMTP; how Conditional Access affects refresh tokens.

## Sources

- [M1] https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
- [M2] https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
- [M3] https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835
- [M5] https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens
- [M6] https://learn.microsoft.com/en-us/graph/api/user-sendmail
- [M7] https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac
- [M8] https://learn.microsoft.com/en-us/entra/identity-platform/reply-url
- [M9] https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
- [G1] https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- [G2] https://developers.google.com/identity/protocols/oauth2/native-app
- [G3] https://developers.google.com/identity/protocols/oauth2
- [G4] https://developers.google.com/workspace/gmail/api/auth/scopes
- [G5] https://support.google.com/cloud/answer/15549945
- [G6] https://support.google.com/cloud/answer/13464323
- [G7] https://developers.google.com/identity/protocols/oauth2/service-account
- [G8] https://knowledge.workspace.google.com/admin/sync/transition-from-less-secure-apps-to-oauth
- [G9] https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send
