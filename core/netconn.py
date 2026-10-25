"""Opening netmiko sessions, with Toner's adjustments for particular devices.

Cisco ASA: netmiko's ASA set-up types "show curpriv" the moment the SSH sign-in is done and waits 10 seconds for it to be
echoed. Two things on a real ASA stop that echo: a sign-in banner longer than a screen stops at '<--- More --->', which
takes the first letters typed as a key press (the ASA then sees only "curpriv"); and an ASA that authorises the shell over
TACACS+ or RADIUS drops what is typed before its prompt. Either way netmiko fails with "ReadTimeout: Pattern not detected:
'show\\ curpriv'". An interactive SSH client pages through the banner and waits for the prompt; so does this.
"""
import re
import time

from netmiko import ConnectHandler
from netmiko.cisco.cisco_asa_ssh import CiscoAsaSSH
from netmiko.exceptions import ReadTimeout

PROMPT = re.compile(r"\S[>#]\s?$")
MORE = re.compile(r"<-+\s*More\s*-+>|--\s*More\s*--", re.IGNORECASE)


def is_prompt(text):
    """Does the output end with a prompt such as 'fw1>' or 'fw1/ctx#'? A prompt is the last line, with no newline after it."""
    last = text.replace("\r", "").split("\n")[-1]
    return bool(PROMPT.search(last)) and not MORE.search(last)        # '<--- More --->' ends in '>' too


def at_more(text):
    """Is the output stopped at a pager ('<--- More --->'), waiting for a key? Only spaces or backspaces may follow it."""
    tail = text[-120:]
    marks = list(MORE.finditer(tail))
    return bool(marks) and not tail[marks[-1].end():].strip(" \x08\r\t")


class AsaSSH(CiscoAsaSSH):
    """CiscoAsaSSH that waits for the prompt before netmiko's first command."""

    prompt_wait = 30

    def session_preparation(self) -> None:
        self.wait_for_prompt(self.prompt_wait)
        super().session_preparation()

    def enable(self, *args, **kw):
        """A refused enable password leaves netmiko's ASA enable waiting for '#' until it times out; say what happened instead."""
        try:
            return super().enable(*args, **kw)
        except ReadTimeout as e:
            raise ValueError("Failed to enter enable mode: the enable password was refused.") from e

    def wait_for_prompt(self, seconds):
        """Read until something that looks like 'name>' or 'name#' ends the output. A sign-in banner longer than a screen
        stops at '<--- More --->': press Space for the next page (Enter would show only one more line, and what netmiko
        types next would be eaten by the pager). Press Enter after a quiet couple of seconds otherwise, as a person would.
        Returns what was read; on a time-out netmiko's own step runs anyway and reports what it finds."""
        seen, end, nudged, pages, quiet_since = "", time.time() + seconds, 0, 0, time.time()
        while time.time() < end:
            new = self.read_channel()
            if new:
                seen += new
                quiet_since = time.time()
                if is_prompt(seen) and not at_more(seen):
                    return seen
                if at_more(seen) and pages < 50:
                    self.write_channel(" ")
                    pages += 1
            elif at_more(seen) and pages < 50 and time.time() - quiet_since > 2:
                self.write_channel(" ")                        # a page key that got lost
                pages += 1
                quiet_since = time.time()
            elif time.time() - quiet_since > 2 and nudged < 5:
                self.write_channel(self.RETURN)
                nudged += 1
                quiet_since = time.time()
            time.sleep(0.1)
        return seen


def any_mode(conn):
    """A pattern for this device's prompt in any mode, for send_command's expect_string. netmiko otherwise waits for the
    exact prompt it saw before the command, and a command that changes mode ('conf t', 'object-group ...', Juniper or
    Palo Alto 'configure', HPE 'system-view', FortiOS 'config ...') changes it: 'fw1#' becomes 'fw1(config)#', and the
    command fails with ReadTimeout after the full wait. The device's name (its first 16 characters, as netmiko itself uses
    for config mode, since some devices shorten a long name there), then anything, then a prompt character at the very end.
    None when the name is not known, which leaves netmiko's own pattern."""
    base = (getattr(conn, "base_prompt", "") or "").strip()
    if not base:
        return None
    return re.escape(base[:16]) + r"[^\r\n]*[>#\]$]\s*$"


SPECIAL = {"cisco_asa": AsaSSH}


def connect(**args):
    """ConnectHandler(**args), with Toner's class for the device types listed in SPECIAL, and the device's SSH host key checked the
    way Settings > Security says (core.nettools.netmiko_hostkey_args; what the caller passes wins)."""
    from core import nettools
    args = {**nettools.netmiko_hostkey_args(), **args}
    cls = SPECIAL.get(args.get("device_type"))
    return cls(**args) if cls else ConnectHandler(**args)
