#!/usr/bin/env python3
"""Tiny internal status service. Sits behind the nginx TLS reverse proxy and
answers /status by round-tripping a value through Redis. Reads its Redis
connection settings from /opt/webapp/webapp.conf so operators can rotate the
cache credentials without editing code."""
import http.server
import json
import socket
import configparser

CONF_PATH = "/opt/webapp/webapp.conf"


def load_conf():
    cp = configparser.ConfigParser()
    cp.read(CONF_PATH)
    r = cp["redis"]
    return (
        r.get("host", "127.0.0.1"),
        int(r.get("port", "6379")),
        r.get("password", "").strip(),
    )


def redis_cmd(sock_file, *args):
    """Minimal RESP client: send one command, return the raw first reply line."""
    out = ["*%d\r\n" % len(args)]
    for a in args:
        a = str(a)
        out.append("$%d\r\n%s\r\n" % (len(a.encode()), a))
    sock_file.write("".join(out).encode())
    sock_file.flush()
    return sock_file.readline().decode(errors="replace").strip()


def redis_roundtrip():
    host, port, password = load_conf()
    s = socket.create_connection((host, port), timeout=3)
    f = s.makefile("rwb")
    try:
        if password:
            reply = redis_cmd(f, "AUTH", password)
            if not reply.startswith("+OK"):
                raise RuntimeError("redis auth failed: %s" % reply)
        redis_cmd(f, "SET", "status:probe", "healthy")
        # GET returns a bulk string: header line then the payload line.
        header = redis_cmd(f, "GET", "status:probe")
        if header.startswith("$") and header != "$-1":
            payload = f.readline().decode(errors="replace").strip()
            return payload
        raise RuntimeError("unexpected GET reply: %s" % header)
    finally:
        f.close()
        s.close()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip("/") == "/status":
            try:
                value = redis_roundtrip()
                body = json.dumps({"service": "status", "cache": value}).encode()
                self.send_response(200)
            except Exception as exc:  # noqa: BLE001
                body = json.dumps({"service": "status", "error": str(exc)}).encode()
                self.send_response(502)
        else:
            body = json.dumps({"error": "not found"}).encode()
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the container logs quiet
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
