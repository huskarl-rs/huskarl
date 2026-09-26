#!/usr/bin/env python3
"""Compile the tutorial's program and run it against local integration Keycloak."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TUTORIAL = ROOT / "huskarl/docs/tutorial/first_token.md"
BASE_URL = "http://127.0.0.1:8080"


def block(document, language):
    matches = re.findall(r"^```" + re.escape(language) + r"\n(.*?)^```", document, re.M | re.S)
    if len(matches) != 1:
        raise ValueError(f"Expected one {language} block in {TUTORIAL}, found {len(matches)}")
    return matches[0]


def request(base_url, path, *, method="GET", data=None, headers=None):
    req = urllib.request.Request(base_url + path, method=method, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read()


def admin_token(base_url):
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": os.environ.get("KEYCLOAK_ADMIN", "admin"),
        "password": os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
    }).encode()
    deadline = time.monotonic() + 60
    while True:
        try:
            return json.loads(request(
                base_url, "/realms/master/protocol/openid-connect/token", method="POST", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ))["access_token"]
        except (urllib.error.URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true", help="Do not contact Keycloak")
    parser.add_argument("--base-url", default=BASE_URL,
                        help="Local Keycloak origin; substitutes the tutorial origin when testing")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    document = TUTORIAL.read_text()
    realm = json.loads(block(document, "json"))
    source = block(document, "rust,no_run").replace(BASE_URL, base_url)

    with tempfile.TemporaryDirectory(prefix="huskarl-tutorial-") as directory:
        project = Path(directory)
        (project / "src").mkdir()
        (project / "src/main.rs").write_text(source)
        (project / "Cargo.toml").write_text(f'''[package]
name = "huskarl-tutorial-smoke"
version = "0.0.0"
edition = "2024"

[dependencies]
huskarl = {{ path = {json.dumps(str(ROOT / "huskarl"))} }}
huskarl-reqwest = {{ path = {json.dumps(str(ROOT / "huskarl-reqwest"))}, features = ["rustls-tls"] }}
tokio = {{ version = "1", features = ["full"] }}
''')
        # Reuse workspace dependency versions and compiled artifacts while leaving
        # its manifest and lockfile untouched. Cargo adds only this temporary root.
        (project / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        target = ROOT / "target"
        subprocess.run([
            "cargo", "build", "--manifest-path", str(project / "Cargo.toml"),
            "--target-dir", str(target),
        ], check=True)
        if args.compile_only:
            print("Tutorial program compiled.")
            return

        headers = {"Authorization": f"Bearer {admin_token(base_url)}", "Content-Type": "application/json"}
        # Refuse an existing realm; never modify or remove a developer's realm.
        request(base_url, "/admin/realms", method="POST", data=json.dumps(realm).encode(), headers=headers)
        try:
            client = realm["clients"][0]
            result = subprocess.run(
                [str(target / "debug/huskarl-tutorial-smoke")],
                env={**os.environ, "CLIENT_SECRET": client["secret"]},
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Tutorial failed: {result.stderr}")
            if not re.search(r"^Access token: \S+$", result.stdout, re.M):
                raise RuntimeError("Tutorial did not print an access token")
            print("Tutorial obtained an access token from its documented realm.")
        finally:
            request(base_url, "/admin/realms/" + urllib.parse.quote(realm["realm"], safe=""),
                    method="DELETE", headers=headers)


if __name__ == "__main__":
    main()
