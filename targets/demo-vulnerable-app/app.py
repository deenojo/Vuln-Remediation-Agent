"""Tiny demo service with deliberately outdated dependencies.

Which packages are actually *used* matters: the Week 2 triage agent checks reachability,
so pyyaml/requests (used below) should rank higher than pillow (installed, never imported).
"""

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    # yaml.load without SafeLoader on user input: the reachable path for the PyYAML CVE.
    data = yaml.load(request.data)  # noqa: S506 (intentionally unsafe for the demo)
    return jsonify(data)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    return requests.get(url, timeout=5).text[:200]


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
