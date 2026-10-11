"""Serial console: a connection thread with the same shape as the SSH and Telnet ones (data / closed signals, send,
resize, stop) for a COM port, or a serial server reached over the network (socket://host:port, rfc2217://host:port)."""
import threading

from PySide6.QtCore import QThread, Signal
from core import quiet

try:
    import serial
    from serial.tools import list_ports
except ImportError:                                   # pyserial is in requirements.txt; a clear message beats a crash
    serial = list_ports = None


def available():
    return serial is not None


def ports():
    """[(device, description)] for the serial ports Windows knows about, e.g. ('COM3', 'USB Serial Port (COM3)')."""
    if list_ports is None:
        return []
    return sorted(((p.device, p.description or p.device) for p in list_ports.comports()),
                  key=lambda x: (len(x[0]), x[0]))


def friendly(port, e):
    text = str(e)
    low = text.lower()
    if "permission" in low or "access is denied" in low or "13" in low and "denied" in low:
        return f"{port} is in use by another program (a terminal, a flashing tool, another Toner tab). Close it and reconnect."
    if "could not open port" in low and ("file" in low and "find" in low or "2," in low or "no such" in low):
        return f"{port} does not exist. Is the cable plugged in? Check the port list in the session settings."
    if "could not open port" in low:
        return f"Could not open {port}: {text.split(':', 1)[-1].strip()[:120]}"
    return f"The serial port stopped working: {text[:140]}"


class SerialSession(QThread):
    data = Signal(bytes)
    closed = Signal(str)

    def __init__(self, port, baud=9600, bytesize=8, parity="N", stopbits=1, flow="none"):
        super().__init__()
        self.host = port                               # shown in the status line like a host name
        self.port, self.baud, self.bytesize, self.parity, self.stopbits, self.flow = port, int(baud), int(bytesize), parity, stopbits, flow
        self.ser = None
        self._stop = False
        self._lock = threading.Lock()

    def send(self, data: bytes):
        try:
            with self._lock:
                if self.ser and self.ser.is_open:
                    self.ser.write(data)
        except (OSError, ValueError, getattr(serial, "SerialException", OSError)):
            pass

    def send_break(self, seconds=0.5):
        """A break signal, which routers read as 'interrupt the boot' (ROMMON)."""
        try:
            with self._lock:
                if self.ser and self.ser.is_open:
                    self.ser.send_break(seconds)
        except (OSError, ValueError, getattr(serial, "SerialException", OSError)):
            pass

    def resize(self, cols, rows):
        pass                                           # a serial line has no idea how big the window is

    def stop(self):
        self._stop = True

    def run(self):
        reason = "Disconnected by user."
        if serial is None:
            self.closed.emit("Serial support is missing: install pyserial (pip install pyserial).")
            return
        try:
            self.ser = serial.serial_for_url(self.port, baudrate=self.baud, bytesize=self.bytesize, parity=self.parity,
                                             stopbits=self.stopbits, xonxoff=self.flow == "xonxoff",
                                             rtscts=self.flow == "rtscts", timeout=0.2)
        except (serial.SerialException, ValueError, OSError) as e:
            self.closed.emit(friendly(self.port, e))
            return
        try:
            while not self._stop:
                n = self.ser.in_waiting
                chunk = self.ser.read(n or 1)
                if chunk:
                    self.data.emit(chunk)
        except (serial.SerialException, OSError) as e:
            if not self._stop:
                reason = friendly(self.port, e) if "disconnect" not in str(e).lower() else \
                    f"{self.port} was disconnected (the cable or adapter was unplugged)."
        finally:
            try:
                self.ser.close()
            except Exception:
                quiet.ignored()
            self.closed.emit(reason)
