"""Windows xcopy: copy folders and files on this computer or to a network share (for example to move what the TFTP and
SFTP servers received, or to copy configuration backups to a file server). Runs xcopy.exe with an argument list, so
nothing is passed through a shell."""
import os
import re
import shutil

REPLACE, NEWER = "replace", "newer"
EXIT = {0: "Copied.", 1: "No files were found to copy.", 2: "Stopped by the user.",
        4: "xcopy could not start: not enough memory or disk space, or an option or path is not valid.",
        5: "A disk write error stopped the copy."}


def find_xcopy():
    return shutil.which("xcopy")


def clean(path):
    """A path without the trailing backslash that would escape the closing quote on the command line."""
    p = (path or "").strip().strip('"')
    return p if len(p) <= 3 else p.rstrip("\\/")


def check_paths(source, dest):
    source, dest = clean(source), clean(dest)
    if not source:
        raise ValueError("Choose the folder or files to copy.")
    if not dest:
        raise ValueError("Choose where to copy them to.")
    wild = any(c in source for c in "*?")
    probe = os.path.dirname(source) if wild else source
    if not os.path.exists(probe or "."):
        raise ValueError(f"{source} does not exist.")
    if any(c in source + dest for c in '<>|"\x00'):
        raise ValueError("The path contains a character that is not allowed.")
    if os.path.normcase(os.path.abspath(source)) == os.path.normcase(os.path.abspath(dest)):
        raise ValueError("The source and the destination are the same.")
    return source, dest


def build_args(source, dest, subfolders=True, existing=REPLACE, hidden=False, keep_readonly=False, keep_going=True,
               verify=False, preview=False):
    """xcopy's argument list. /I makes the destination a folder, so copying never stops to ask 'file or directory?';
    /Y is always present, because xcopy would otherwise wait for an answer nobody can type."""
    source, dest = check_paths(source, dest)
    args = [source, dest, "/I", "/Y"]
    if subfolders:
        args.append("/E")
    if existing == NEWER:
        args.append("/D")
    if hidden:
        args.append("/H")
    if keep_readonly:
        args.append("/K")
    if keep_going:
        args.append("/C")
    if verify:
        args.append("/V")
    if preview:
        args += ["/L", "/F"]
    return args


def count_copied(output):
    """The number from xcopy's closing line ('12 File(s) copied' / '12 File(s)' for a preview), or None."""
    m = re.findall(r"(\d+)\s+File\(s\)", output or "")
    return int(m[-1]) if m else None


def describe_exit(code, output=""):
    n = count_copied(output)
    base = EXIT.get(code, f"xcopy stopped with exit code {code}.")
    if code != 0 or n is None:
        return base
    return "Nothing needed copying (0 files)." if n == 0 else f"Done: {n} file(s)."
