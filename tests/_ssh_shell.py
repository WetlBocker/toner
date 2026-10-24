"""A tiny SSH server with an interactive shell, for the tests: it prints a banner and a prompt, echoes what you type,
and answers 'show ...' commands. It records every line it received."""
import socket
import threading
import time

import paramiko


class ShellServer:
    def __init__(self, user="u", password="pw", banner="Welcome to R1\r\n", prompt="router# ", sftp_root=None, exec_handler=None):
        """sftp_root: a folder on this computer served as the device's file system over SFTP (None: no SFTP subsystem, as on
        a switch). self.slow: seconds to sleep per SFTP write, so a transfer takes long enough to be cancelled.
        exec_handler(command) -> (output bytes, exit status): answers a one-off command (SSH exec); None refuses them."""
        self.user, self.password, self.banner, self.prompt = user, password, banner, prompt
        self.sftp_root, self.slow, self.exec_handler = sftp_root, 0.0, exec_handler
        self.execs = []
        self.key = paramiko.RSAKey.generate(2048)
        self.lines, self.sizes, self.logins = [], [], []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, c):
        srv = self

        class If(paramiko.ServerInterface):
            def get_allowed_auths(self, u):
                return "password"

            def check_auth_password(self, u, p):
                srv.logins.append((u, p))
                return paramiko.AUTH_SUCCESSFUL if (u, p) == (srv.user, srv.password) else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, cid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_pty_request(self, ch, term, w, h, pw, ph, modes):
                srv.sizes.append((w, h))
                return True

            def check_channel_window_change_request(self, ch, w, h, pw, ph):
                srv.sizes.append((w, h))
                return True

            def check_channel_exec_request(self, ch, command):
                if srv.exec_handler is None:
                    return False
                cmd = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
                srv.execs.append(cmd)

                def answer():
                    time.sleep(0.05)                      # (after the exec request is confirmed)
                    out, status = srv.exec_handler(cmd)
                    try:
                        ch.sendall(out)
                        ch.send_exit_status(status)
                        ch.close()
                    except Exception:
                        pass
                threading.Thread(target=answer, daemon=True).start()
                return True

            def check_channel_shell_request(self, ch):
                threading.Thread(target=srv._shell, args=(ch,), daemon=True).start()
                return True

        try:
            t = paramiko.Transport(c)
            t.add_server_key(self.key)
            if self.sftp_root:
                from _sftp_stub import attach
                attach(t, self.sftp_root, lambda: srv.slow)
            t.start_server(server=If())
            keep = t.accept(30)                           # hold the channel: a dropped one is closed
            while t.is_active():
                time.sleep(0.2)
        except Exception:
            pass

    def _shell(self, ch):
        try:
            ch.send(self.banner + self.prompt)
            buf = b""
            while True:
                d = ch.recv(1024)
                if not d:
                    break
                for b in d:
                    if b in (13, 10):
                        if buf:
                            line = buf.decode(errors="replace")
                            self.lines.append(line)
                            buf = b""
                            ch.send("\r\n")
                            if line == "exit":
                                ch.close()
                                return
                            ch.send((f"output of {line}\r\n" if line.startswith("show") else "% Unknown command\r\n") if line.strip() else "")
                            ch.send(self.prompt)
                    else:
                        buf += bytes([b])
                        ch.send(bytes([b]))                 # the device echoes what is typed
        except (OSError, EOFError):
            pass

    def stop(self):
        self.sock.close()
