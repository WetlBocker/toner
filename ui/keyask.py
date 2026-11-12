"""Asking a security key for a window (ui/signinwindow.py, ui/lockscreen.py). A Job's thread calls key, present or register: they
tell the window (touching, then on Linux and macOS pin_wanted) and wait on the key there, never on the window's thread. The key's
own PIN is typed in the window and handed over with give_pin; Windows asks for it in its own dialog over the window.

Each Job that may ask gets its own Wait from arm(), on the window's thread before the Job starts. cancel() ends that wait and any
ask that comes after it (Cancel, closing the window, Use a different account): the key call then ends with fidokey.NotTouched."""
import sys
import threading

from PySide6.QtCore import QObject, Signal

from core import fidokey


class Wait:
    def __init__(self):
        self.cancel, self.asked = threading.Event(), False      # asked: the key was asked, so the password or PIN was right


class KeyAsk(QObject):
    touching = Signal()
    pin_wanted = Signal()

    def __init__(self, window):
        super().__init__(window)
        self.window = None                                      # the native handle Windows' dialog sits over, read at arm()
        self._mutex = threading.Lock()
        self._wait, self._given, self._pin = Wait(), threading.Event(), None

    def arm(self):
        if sys.platform == "win32" and self.window is None:
            self.window = int(self.parent().winId())            # (on the window's thread, once it is shown: not at build time)
        with self._mutex:
            self._wait = Wait()
            return self._wait

    def cancel(self):
        with self._mutex:
            self._wait.cancel.set()
            self._pin = None
            self._given.set()

    def give_pin(self, text):
        """The key's PIN as typed, or None to cancel."""
        with self._mutex:
            self._pin = text
            self._given.set()

    # ---------------------------------------------------------------- on the Job's thread
    def _start(self):
        with self._mutex:
            w = self._wait
            w.asked = True
        if w.cancel.is_set():
            raise fidokey.NotTouched()
        self.touching.emit()
        return w

    def _ask_pin(self, w):
        with self._mutex:
            if w.cancel.is_set():
                return None
            self._given.clear()
        self.pin_wanted.emit()
        self._given.wait()
        with self._mutex:
            pin, self._pin = self._pin, None                    # not kept once handed to the key
        return None if w.cancel.is_set() else pin

    def _with_pin(self, call):
        w = self._start()
        while True:
            try:
                return call(ask_pin=lambda: self._ask_pin(w), cancel=w.cancel, window=self.window)
            except fidokey.WrongKeyPin:
                pass                                            # asked again; the key itself stops it after three (KeyPinRetry)

    def key(self, creds):
        return self._with_pin(lambda **kw: fidokey.value(creds, **kw))

    def register(self, label, salt):
        return self._with_pin(lambda **kw: fidokey.register(label, salt, **kw))

    def present(self, creds):
        w = self._start()
        return fidokey.present(creds, cancel=w.cancel, window=self.window)
