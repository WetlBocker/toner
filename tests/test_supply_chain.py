# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
# What keeps a build honest without a code-signing certificate: every package pinned by SHA-256 and installed with the hashes
# checked, GitHub Actions pinned to commits, Dependabot watching both, and a SHA256SUMS.txt in every release.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import os, re, sys
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def read(*parts):
    return open(os.path.join(root, *parts), encoding="utf-8").read()

print("== requirements.lock")
lock = read("requirements.lock")
entries = re.findall(r"^([A-Za-z0-9_.\-]+==[^ \\\n]+(?: ; [^\\\n]+?)?)\s*((?:\\\n\s*--hash=sha256:[0-9a-f]{64}\s*)+)$", lock, flags=re.M)   # "; marker": the Linux-only packages
pins = re.findall(r"^[A-Za-z0-9_.\-]+==", lock, flags=re.M)
check("every pinned package carries at least one SHA-256", len(entries) == len(pins) >= 50, (len(entries), len(pins)))
check("the ones Toner's graphs need are among them", any(e[0].startswith("pyqtgraph==") for e in entries) and any(e[0].startswith("numpy==") for e in entries))
check("nothing is left unpinned (no ranges, no bare names)", not re.search(r"^[A-Za-z0-9_.\-]+(>=|<|~=|$)", lock.split("\n", 3)[3], flags=re.M))
direct = [l.split(">=")[0].split("<")[0].strip() for l in read("requirements.txt").splitlines() if l and not l.startswith("#")]
names = {e[0].split("==")[0].lower().replace("_", "-") for e in entries}
check("every direct dependency in requirements.txt is in the lock", all(d.lower().replace("_", "-") in names for d in direct), [d for d in direct if d.lower().replace("_", "-") not in names])

print("== CI and the builds")
tests_yml, release_yml = read(".github", "workflows", "tests.yml"), read(".github", "workflows", "release.yml")
for name, wf in (("tests.yml", tests_yml), ("release.yml", release_yml)):
    check(f"{name} installs with the hashes checked, wheels only", "pip install --require-hashes --only-binary=:all: -r requirements.lock" in wf
          and "pip install -r requirements.lock" not in wf)
    uses = re.findall(r"uses: (\S+)", wf)
    check(f"{name} pins every action to a commit, with its version in a comment",
          uses and all(re.fullmatch(r"[\w.\-]+/[\w.\-]+@[0-9a-f]{40}", u) for u in uses)
          and all(re.search(rf"uses: {re.escape(u)}\s+# v\d+\.\d+\.\d+", wf) for u in uses), uses)
check("Dependabot watches the packages and the actions, weekly", os.path.exists(os.path.join(root, ".github", "dependabot.yml"))
      and all(s in read(".github", "dependabot.yml") for s in ("package-ecosystem: pip", "package-ecosystem: github-actions", "interval: weekly")))

print("== every release lists its files' SHA-256")
check("the Linux job, which runs last, writes SHA256SUMS.txt for both files and adds it to the release",
      "sha256sum \"Toner-Setup-$v.exe\" \"Toner-$v-x86_64.AppImage\" > SHA256SUMS.txt" in release_yml
      and "gh release upload \"${{ github.ref_name }}\" SHA256SUMS.txt" in release_yml)
check("it fetches the installer the Windows job published, so the sums are of what people download", 'gh release download "${{ github.ref_name }}"' in release_yml)
check("the README says so, in the agreed words", "Each release includes `SHA256SUMS.txt` with the SHA-256 of every file." in read("README.md"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
