"""Right-click on a selected IP address, anywhere in the window: the menu gains "Ping 10.0.2.251" and "WHOIS Lookup 10.0.2.251".
Text boxes, output boxes and labels get the actions added to their usual menu by the filter installed on the application; widgets
that draw their own menu (the terminal, lists with a menu of their own) call add_ip_actions() themselves."""
import re

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QAbstractItemView, QApplication, QLabel, QLineEdit, QMenu, QPlainTextEdit, QTextEdit

_IPV4 = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
_IPV6 = r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
_RX = re.compile(f"{_IPV4}|{_IPV6}")


def ip_in(text):
    """The first IP address in a piece of selected text, or ''. A bare address, or one inside a line ('ip: 10.0.2.251 255.255.255.0')."""
    import ipaddress
    for m in _RX.finditer(text or ""):
        cand = m.group(0).strip(":")
        try:
            ipaddress.ip_address(cand)
            return cand
        except ValueError:
            continue
    return ""


def selected_text(w):
    """What is selected in a widget, for the kinds that have a selection."""
    try:
        if isinstance(w, QLineEdit):
            return w.selectedText()
        if isinstance(w, (QPlainTextEdit, QTextEdit)):
            return w.textCursor().selectedText().replace(" ", "\n")
        if isinstance(w, QLabel):
            return w.selectedText()
        if hasattr(w, "selected_text"):                             # the terminal
            return w.selected_text() or ""
        if isinstance(w, QAbstractItemView):
            idx = w.currentIndex()
            return str(idx.data() or "") if idx.isValid() and idx in w.selectedIndexes() else ""
    except Exception:
        return ""
    return ""


def add_ip_actions(menu, text, parent):
    """Append the two actions to a menu when `text` holds an address. Returns the address, or ''."""
    ip = ip_in(text)
    if not ip:
        return ""
    if menu.actions():
        menu.addSeparator()
    menu.addAction(f"Ping {ip}", lambda: _ping(parent, ip))
    menu.addAction(f"WHOIS Lookup {ip}", lambda: _whois(parent, ip))
    return ip


def _ping(parent, ip):
    from ui.pingpop import ping_popup
    ping_popup(parent.window() if parent else None, ip, ip)


def _whois(parent, ip):
    from ui.whois import whois_popup
    whois_popup(parent.window() if parent else None, ip)


class IpMenuFilter(QObject):
    """Installed on the application: a right-click in a text box, output box or label with an address selected shows the widget's own
    menu with Ping and WHOIS Lookup added."""

    def eventFilter(self, obj, event):
        if event.type() != QEvent.Type.ContextMenu or not isinstance(obj, (QLineEdit, QPlainTextEdit, QTextEdit, QLabel)):
            return False
        ip = ip_in(selected_text(obj))
        if not ip:
            return False
        if isinstance(obj, QLabel):
            menu = QMenu(obj)
            menu.addAction("Copy", lambda: QApplication.clipboard().setText(obj.selectedText()))
        else:
            menu = obj.createStandardContextMenu()
        add_ip_actions(menu, ip, obj)
        menu.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        menu.exec(event.globalPos())
        return True


_filter = None


def install(app):
    """Once, on the application."""
    global _filter
    if _filter is None:
        _filter = IpMenuFilter(app)
        app.installEventFilter(_filter)
    return _filter
