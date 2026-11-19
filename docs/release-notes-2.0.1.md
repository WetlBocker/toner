# Toner 2.0.1

Three fixes for 2.0.0. If you are updating from 1.14.1 or earlier, read the
[2.0.0 notes](https://github.com/WetlBocker/toner/releases/tag/v2.0.0) first: that upgrade can't be undone.

## The lock screen

- **Charts are hidden while Toner is locked.** A chart could stay visible on a locked window. Every chart is now blanked until you
  unlock.
- **The lock stays in Toner's window.** It could appear on a different monitor from the window it was locking. It is now part of
  the window, so it is always where Toner is.
- **A locked Toner can be minimised, resized and closed.** The window's buttons did nothing while it was locked. If a dialog was
  open when Toner locked, they stay off until you unlock.

## Schedules

- **Signing out no longer leaves the old schedules running.** After signing out and back in without closing Toner, the earlier
  window's schedules stayed armed. Toner showed an error at the next scheduled time, and another organization's checks or backups
  could start twice.

## Charts

- The total in the middle of a ring is centred. On the vulnerability rings it sat low and to the right.

**Full changelog:** https://github.com/WetlBocker/toner/compare/v2.0.0...v2.0.1
