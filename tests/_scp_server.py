"""A small SCP server for the tests: it plays the device's side of the scp protocol over SSH."""
import os, shlex, socket, threading, time
import paramiko


def recv_exact(ch, n):
    out = b""
    while len(out) < n:
        c = ch.recv(n - len(out))
        if not c: raise EOFError
        out += c
    return out

def read_line(ch):
    out = b""
    while True:
        c = ch.recv(1)
        if not c: return None
        if c == b"\n": return out
        out += c

class ScpServer:
    def __init__(self, root, pubkey=None, deny_exec=False, evil_name=None, slow=False):
        self.root, self.pubkey, self.deny_exec, self.evil_name, self.slow = os.path.realpath(root), pubkey, deny_exec, evil_name, slow
        self.key = paramiko.RSAKey.generate(2048); self.commands = []
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(8); self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
    def _accept(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()
    def _conn(self, c):
        srv = self
        class If(paramiko.ServerInterface):
            def get_allowed_auths(self, u): return "password,publickey"
            def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u, p) == ("u", "pw") else paramiko.AUTH_FAILED
            def check_auth_publickey(self, u, key): return paramiko.AUTH_SUCCESSFUL if srv.pubkey and key.asbytes() == srv.pubkey.asbytes() else paramiko.AUTH_FAILED
            def check_channel_request(self, kind, cid): return paramiko.OPEN_SUCCEEDED
            def check_channel_exec_request(self, ch, command):
                srv.commands.append(command.decode())
                if srv.deny_exec: return False
                threading.Thread(target=srv.run, args=(ch, command.decode()), daemon=True).start(); return True
        try:
            t = paramiko.Transport(c); t.add_server_key(self.key); t.start_server(server=If()); keep = t.accept(30)
            while t.is_active(): time.sleep(0.2)
        except Exception: pass
    def real(self, p):
        r = os.path.realpath(os.path.join(self.root, p.lstrip("/\\")))
        assert r == self.root or r.startswith(self.root + os.sep), "outside"
        return r
    def run(self, ch, cmd):
        try:
            tokens = shlex.split(cmd); flags, path = set(), None
            for t in tokens[1:]:
                if t == "--": continue
                if t.startswith("-"): flags |= set(t[1:])
                else: path = t
            (self.sink if "t" in flags else self.source)(ch, path, flags)
            ch.send_exit_status(0)
        except (EOFError, OSError): pass
        finally:
            try: ch.close()
            except Exception: pass
    def sink(self, ch, path, flags):
        target = self.real(path); ch.sendall(b"\0"); stack, cur, mt = [], (target if os.path.isdir(target) else None), None
        while True:
            line = read_line(ch)
            if line is None: break
            c = line[:1]
            if c == b"T": mt = (int(line[1:].split()[2]), int(line[1:].split()[0])); ch.sendall(b"\0")
            elif c == b"D":
                _, _, name = line[1:].decode().split(" ", 2); p = os.path.join(cur or os.path.dirname(target), name); os.makedirs(p, exist_ok=True); stack.append(cur); cur = p; ch.sendall(b"\0")
            elif c == b"E": cur = stack.pop(); ch.sendall(b"\0")
            elif c == b"C":
                _, size, name = line[1:].decode().split(" ", 2); ch.sendall(b"\0"); data = recv_exact(ch, int(size)); recv_exact(ch, 1)
                out = os.path.join(cur, name) if cur else target
                open(out, "wb").write(data)
                if mt: os.utime(out, mt); mt = None
                ch.sendall(b"\0")
    def source(self, ch, path, flags):
        recv_exact(ch, 1); p = self.real(path)
        if not os.path.exists(p): ch.sendall(f"\x01scp: {path}: No such file or directory\n".encode()); return
        def send(p):
            name = self.evil_name or os.path.basename(p)
            if "p" in flags:
                st = os.stat(p); ch.sendall(f"T{int(st.st_mtime)} 0 {int(st.st_atime)} 0\n".encode()); recv_exact(ch, 1)
            if os.path.isdir(p):
                ch.sendall(f"D0755 0 {name}\n".encode()); recv_exact(ch, 1)
                for n in sorted(os.listdir(p)): send(os.path.join(p, n))
                ch.sendall(b"E\n"); recv_exact(ch, 1)
            else:
                data = open(p, "rb").read(); ch.sendall(f"C0644 {len(data)} {name}\n".encode()); recv_exact(ch, 1)
                if self.slow:                                   # a slow link, so a test can press Stop part-way
                    for i in range(0, len(data), 65536):
                        ch.sendall(data[i:i + 65536]); time.sleep(0.03)
                    ch.sendall(b"\0")
                else:
                    ch.sendall(data + b"\0")
                recv_exact(ch, 1)
        if os.path.isdir(p) and "r" not in flags: ch.sendall(f"\x01scp: {path}: not a regular file\n".encode()); return
        send(p)
    def stop(self): self.sock.close()

