"""Opening netmiko sessions, with Toner's adjustments for particular devices.

Cisco ASA: netmiko's ASA set-up types "show curpriv" the moment the SSH sign-in is done and waits 10 seconds for it to be
echoed. An ASA that authorises the shell over TACACS+ or RADIUS (domain accounts), or shows a banner first, throws away
what is typed before its prompt appears, so the echo never comes: "ReadTimeout: Pattern not detected: 'show\\ curpriv'".
An interactive SSH client waits for the prompt; so does this.
"""
import re
import time

from netmiko import ConnectHandler
from netmiko.cisco.cisco_asa_ssh import CiscoAsaSSH

PROMPT = re.compile(r"\S[>#]\s?$")


def is_prompt(text):
    """Does the output end with a prompt such as 'fw1>' or 'fw1/ctx#'? A prompt is the last line, with no newline after it."""
    last = text.replace("\r", "").split("\n")[-1]
    return bool(PROMPT.search(last))


class AsaSSH(CiscoAsaSSH):
    """CiscoAsaSSH that waits for the prompt before netmiko's first command."""

    prompt_wait = 30

    def session_preparation(self) -> None:
        self.wait_for_prompt(self.prompt_wait)
        super().session_preparation()

    def wait_for_prompt(self, seconds):
        """Read until something that looks like 'name>' or 'name#' ends the output. Press Enter after a quiet couple of
        seconds (once a few seconds apart), as a person would. Returns what was read; on a time-out netmiko's own step
        runs anyway and reports what it finds."""
        seen, end, nudged, quiet_since = "", time.time() + seconds, 0, time.time()
        while time.time() < end:
            new = self.read_channel()
            if new:
                seen += new
                quiet_since = time.time()
                if is_prompt(seen):
                    return seen
            elif time.time() - quiet_since > 2 and nudged < 5:
                self.write_channel(self.RETURN)
                nudged += 1
                quiet_since = time.time()
            time.sleep(0.1)
        return seen


SPECIAL = {"cisco_asa": AsaSSH}


def connect(**args):
    """ConnectHandler(**args), with Toner's class for the device types listed in SPECIAL."""
    cls = SPECIAL.get(args.get("device_type"))
    return cls(**args) if cls else ConnectHandler(**args)
