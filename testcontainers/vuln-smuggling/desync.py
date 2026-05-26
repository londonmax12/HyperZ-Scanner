"""
vuln-smuggling: a two-process HTTP rig that demonstrates a classic
CL.TE desynchronization.

Front-end (port 80): parses ONLY Content-Length, ignores
Transfer-Encoding. Forwards the request line + headers + exactly CL
bytes of body to the back-end and proxies the response back to the
client.

Back-end (port 8083, loopback): parses ONLY Transfer-Encoding when
present. Reads chunked body until the terminating 0\\r\\n\\r\\n.

The CL.TE probe hyperz sends carries a body of "1\\r\\nA\\r\\nX" with
CL=4. The front-end forwards "1\\r\\nA" (4 bytes); the back-end's TE
parser reads chunk size 1, reads "A", then blocks waiting for the
"\\r\\n" chunk terminator that the front-end never forwarded. Both
sides hang, the scanner's probe crosses the 5s threshold on two
attempts, and request-smuggling fires.

The same primitive triggers a TE.CL hang in the opposite direction
too, so request-smuggling reports the first variant whose timing
oracle confirms - both halves of the desync are reachable here.
"""

import socket
import threading

BACKEND_HOST, BACKEND_PORT = "127.0.0.1", 8083
FRONT_PORT = 80


def recv_until(sock, terminator, cap=64 << 10):
    buf = b""
    while terminator not in buf and len(buf) < cap:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_headers(raw_headers):
    lines = raw_headers.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        k, _, v = line.partition(b":")
        headers[k.strip().lower()] = v.strip()
    return lines[0], headers


# --- backend ---------------------------------------------------------------
def backend_serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACKEND_PORT))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=backend_handle, args=(conn,), daemon=True).start()


def backend_handle(conn):
    try:
        head = recv_until(conn, b"\r\n\r\n")
        if not head:
            return
        head_part, _, body_start = head.partition(b"\r\n\r\n")
        request_line, headers = parse_headers(head_part)
        te = headers.get(b"transfer-encoding", b"").lower()
        cl = headers.get(b"content-length", b"")
        body_buf = body_start
        if b"chunked" in te:
            # back-end TE parser: read until terminating 0\r\n\r\n.
            while b"\r\n0\r\n\r\n" not in body_buf and b"0\r\n\r\n" not in body_buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body_buf += chunk
        elif cl:
            need = int(cl)
            while len(body_buf) < need:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body_buf += chunk
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --- frontend (CL-only) ----------------------------------------------------
def frontend_serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", FRONT_PORT))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=frontend_handle, args=(conn,), daemon=True).start()


def frontend_handle(client):
    try:
        head = recv_until(client, b"\r\n\r\n")
        if not head:
            return
        head_part, _, body_start = head.partition(b"\r\n\r\n")
        request_line, headers = parse_headers(head_part)

        method = request_line.split(b" ", 1)[0]
        cl = headers.get(b"content-length", b"0")

        # CL-only parsing: read exactly CL bytes of body, ignore TE.
        try:
            need = int(cl)
        except ValueError:
            need = 0
        body = body_start
        while len(body) < need:
            chunk = client.recv(4096)
            if not chunk:
                break
            body += chunk
        body = body[:need]

        # If it's a benign GET with no body, still forward and respond
        # quickly so the host root looks alive to the crawler.
        if method == b"GET" and need == 0:
            backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=5)
            backend.sendall(head_part + b"\r\n\r\n")
            backend.shutdown(socket.SHUT_WR)
            resp = b""
            while True:
                chunk = backend.recv(4096)
                if not chunk:
                    break
                resp += chunk
            backend.close()
            if not resp:
                resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                        b"Content-Length: 13\r\n\r\nvuln-smuggling")
            client.sendall(resp)
            return

        backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=20)
        backend.sendall(head_part + b"\r\n\r\n" + body)

        # Proxy response back. If the back-end hangs (the desync
        # signal), this read blocks until the client (the scanner)
        # times out, which IS the timing-oracle signal that confirms.
        try:
            backend.settimeout(15)
            while True:
                chunk = backend.recv(4096)
                if not chunk:
                    break
                client.sendall(chunk)
        except socket.timeout:
            pass
        backend.close()
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    t = threading.Thread(target=backend_serve, daemon=True)
    t.start()
    frontend_serve()


if __name__ == "__main__":
    main()
