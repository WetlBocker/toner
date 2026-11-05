# Toner: sign-in

Toner now asks people to sign in. Every copy's data is encrypted and opens only when someone signs in, or uses the recovery key.

## What changes

- **Upgrading:** Toner moves your saved passwords into the new account, then encrypts the data. If Toner didn't remember the
  master password, it asks for it once.
- **First start:** the first person to open the upgraded Toner creates the admin account and gets the recovery key. Save it
  somewhere safe. Toner shows it only once.
- **Keep `netcheck.keys` with Toner's data.** Without it the recovery key can't open anything.
  netcheck.db is useless without netcheck.keys. Copy both.
- **The lock:** Toner locks after 15 minutes without use (change it in **Settings > Accounts and sign-in**), or at once with Ctrl+Shift+L.
- **Gone:** the vault's master password, **Change master password...** and **Remember on this computer**.
- **Command line:** `cli run`, `cli backup` and the other commands ask for a username and password at the terminal.
  On Windows, run commands with TonerCli.exe.

## What stops working

- There's no going back to versions before sign-in: they can't open the encrypted data.
- `Toner.exe cli service` (and `toner cli service` on Linux) is refused while sign-in is set up, until data is centralized.
  Scheduled checks and backups run while someone is signed in to Toner's window.
- Scheduled command-line runs stop working for the same reason: with no terminal to ask, they exit with code 3.
- Database backups now ask for a password. The backup holds devices, history and settings, encrypted with the password you choose.
  Saved passwords stay in Toner's vault and aren't included.

## Not in this release

Only local accounts are available. Other kinds of sign-in come later.
