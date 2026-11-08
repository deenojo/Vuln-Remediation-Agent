"""Second demo service: a tiny stdlib HTTP server with deliberately outdated dependencies.

Reachable on purpose: pyjwt (decode without verification), lxml (parses request XML), urllib3.
Never imported: cryptography, sqlparse (should rank lower in triage).
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import urllib3
from lxml import etree

http = urllib3.PoolManager()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        if self.path.startswith("/whoami"):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            claims = jwt.decode(token, verify=False)  # intentionally unsafe for the demo
            return self._send(200, claims)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/parse":
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            root = etree.fromstring(body)  # untrusted XML: the reachable lxml path
            return self._send(200, {"tag": root.tag})
        if self.path == "/proxy":
            url = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            r = http.request("GET", url, timeout=5.0)
            return self._send(200, {"status": r.status})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer((os.environ.get("HOST", "127.0.0.1"), 5000), Handler).serve_forever()
