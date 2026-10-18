"""Copy Files on Linux and macOS: rsync, with the same options and calls as core/xcopy.py on Windows (the window picks one).

The contents of the source folder are copied into the destination folder (rsync's 'source/' form), as xcopy does. A pattern such
as /srv/tftp/*.cfg is expanded here, since rsync is run with an argument list and no shell. rsync always carries on after a
file it can't copy and checks every file it writes, so xcopy's 'keep going' and 'verify' have nothing to switch here.
--stats ends the output with the count of files copied (or, in a preview, that would be)."""
import glob
import os
import re
import shutil

from core.xcopy import NEWER, REPLACE, check_paths, clean  # noqa: F401  (the same choices and path checks)

EXIT = {0: "Copied.", 1: "rsync could not start: an option or path is not valid.", 11: "A disk read or write error stopped the copy.",
        20: "Stopped by the user.", 23: "Some files could not be copied (see above).", 24: "Some files vanished while they were being copied."}


def find():
    return shutil.which("rsync")


def build_args(source, dest, subfolders=True, existing=REPLACE, hidden=False, keep_readonly=False, keep_going=True,
               verify=False, preview=False):
    """rsync's argument list (keep_going and verify are always so with rsync)."""
    source, dest = check_paths(source, dest)
    args = ["-a", "--stats"]                       # archive: times, links, sub-folders; and the closing counts
    if not subfolders:
        args.append("--exclude=*/")                # the files in the folder, not the folders inside it
    if existing == NEWER:
        args.append("--update")
    else:
        args.append("--ignore-times")              # replace what is there, even when it looks the same
    if not hidden:
        args.append("--exclude=.*")                # hidden files are the ones whose names start with a dot
    if not keep_readonly:
        args.append("--no-perms")                  # new files get this computer's usual permissions
    if preview:
        args += ["--dry-run", "--itemize-changes"]
    if any(c in source for c in "*?["):
        found = sorted(glob.glob(source))
        if not found:
            raise ValueError(f"Nothing matches {source}.")
        sources = found
    else:
        sources = [source.rstrip("/") + "/" if os.path.isdir(source) else source]   # a folder: its contents, as xcopy copies
    return args + sources + [dest.rstrip("/") + "/"]


def count_copied(output):
    """The number of files copied (or, in a preview, that would be), from --stats; None when it isn't there."""
    m = re.findall(r"Number of regular files transferred:\s*([\d,]+)", output or "") or \
        re.findall(r"Number of files transferred:\s*([\d,]+)", output or "")          # older rsync, macOS
    return int(m[-1].replace(",", "")) if m else None


def describe_exit(code, output=""):
    n = count_copied(output)
    base = EXIT.get(code, f"rsync stopped with exit code {code}.")
    if code != 0 or n is None:
        return base
    return "Nothing needed copying (0 files)." if n == 0 else f"Done: {n} file(s)."
