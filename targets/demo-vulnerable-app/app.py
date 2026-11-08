"""Demo service 1, after its platform upgrade (Python 3.12, Flask 3).

The upgrade fixed the code, not just the versions: yaml.safe_load replaces yaml.load,
which closes the unsafe-deserialization path behind the old PyYAML advisory.
"""

import os

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    # safe_load only builds plain data types (no arbitrary Python objects from user input).
    data = yaml.safe_load(request.data)
    return jsonify(data)


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    return requests.get(url, timeout=5).text[:200]


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000)
