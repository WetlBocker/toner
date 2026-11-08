"""Toner's helper service: a separate program running as LocalSystem/root that keeps a spare copy of Toner's data key and rules
key and hands them to the enrolled user's Toner only for a sign-in it checked itself. protocol: the messages; store: the spare
copy on disk; server: the checks. The Windows service and the Linux socket around them live apart."""
