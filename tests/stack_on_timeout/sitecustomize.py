"""Loaded at start-up in each test file's process (run_all.py puts this folder on PYTHONPATH): shortly before run_all's time
limit, write every thread's stack to stderr, so a file that hangs says where it was waiting."""
import faulthandler
import os

after = os.environ.pop("TONER_STACK_AFTER", None)        # popped: the processes a test starts are not timed
if after:
    faulthandler.dump_traceback_later(float(after))
