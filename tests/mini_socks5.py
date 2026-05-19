#!/usr/bin/env python3
"""
Minimal SOCKS5 server for local testing of rustytorrent's --socks5 flag.
Supports CONNECT to IPv4 targets with no-auth or USER/PASS auth. Used purely
to validate the SOCKS5 client and proxy plumbing — not production-grade.

Usage: mini_socks5.py LISTEN_PORT [USERNAME PASSWORD]
"""
import socket
import socketserver
import struct
import sys
import threading

USERNAME = None
PASSWORD = None


class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        # Greeting.
        head = c.recv(2)
        if len(head) < 2 or head[0] != 5:
            return
        n = head[1]
        methods = c.recv(n)
        if USERNAME and 2 in methods:
            c.sendall(b"\x05\x02")
            # USER/PASS subnegotiation.
            sub_head = c.recv(2)
            if len(sub_head) < 2 or sub_head[0] != 1:
                return
            ulen = sub_head[1]
            u = c.recv(ulen).decode()
            plen = c.recv(1)[0]
            p = c.recv(plen).decode()
            if u != USERNAME or p != PASSWORD:
                c.sendall(b"\x01\x01")
                return
            c.sendall(b"\x01\x00")
        elif 0 in methods:
            c.sendall(b"\x05\x00")
        else:
            c.sendall(b"\x05\xFF")
            return
        # CONNECT request.
        req_head = c.recv(4)
        if len(req_head) < 4 or req_head[0] != 5 or req_head[1] != 1:
            return
        atyp = req_head[3]
        if atyp == 1:
            ip = ".".join(str(b) for b in c.recv(4))
            port = struct.unpack("!H", c.recv(2))[0]
            host = ip
        elif atyp == 3:
            dlen = c.recv(1)[0]
            host = c.recv(dlen).decode()
            port = struct.unpack("!H", c.recv(2))[0]
        else:
            c.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        try:
            up = socket.create_connection((host, port), timeout=10)
        except OSError:
            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        # Bidirectional pipe.
        def pump(src, dst):
            try:
                while True:
                    buf = src.recv(4096)
                    if not buf:
                        break
                    dst.sendall(buf)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t1 = threading.Thread(target=pump, args=(c, up))
        t2 = threading.Thread(target=pump, args=(up, c))
        t1.start(); t2.start()
        t1.join(); t2.join()
        up.close()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global USERNAME, PASSWORD
    port = int(sys.argv[1])
    if len(sys.argv) == 4:
        USERNAME = sys.argv[2]
        PASSWORD = sys.argv[3]
    with ThreadedTCPServer(("127.0.0.1", port), Socks5Handler) as srv:
        print(f"mini SOCKS5 listening on 127.0.0.1:{port}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
