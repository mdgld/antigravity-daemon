#!/usr/bin/env python3
"""
antigravity-daemon: Makes CodexBar's Antigravity provider work without the app open.

How it works:
- CodexBar detects the Antigravity language server via `ps aux | grep language_server_macos`
- It extracts --extension_server_port and --csrf_token from the process args
- It probes the local language server port over TLS and then calls Antigravity endpoints
- This daemon mimics those endpoints and proxies quota data from cloudcode-pa.googleapis.com
"""

import argparse
import base64
import http.server
import json
import os
import re
import sqlite3
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Constants
VSCDB = os.path.expanduser(
    "~/Library/Application Support/Antigravity/User/globalStorage/state.vscdb"
)
QUOTA_URL = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
TOKEN_URL = "https://oauth2.googleapis.com/token"
CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
CLIENT_SECRET = "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"
CSRF_TOKEN = "antigravity-daemon-csrf-fixed-token"
PROTO_KEY = "antigravityUnifiedStateSync.oauthToken"

TLS_CERT_PATH = "/tmp/antigravity-daemon-cert.pem"
TLS_KEY_PATH = "/tmp/antigravity-daemon-key.pem"

USER_STATUS_PATH = "/exa.language_server_pb.LanguageServerService/GetUserStatus"
MODEL_CONFIGS_PATH = "/exa.language_server_pb.LanguageServerService/GetCommandModelConfigs"
UNLEASH_PATH = "/exa.language_server_pb.LanguageServerService/GetUnleashData"
LEGACY_QUOTA_PATH = "/v1internal:retrieveUserQuota"
CODEXBAR_CONFIG_PATH = os.path.expanduser("~/.codexbar/config.json")
PLAN_LABEL_FALLBACK = "Antigravity"

_plan_label_cache = None
_plan_label_source = None
_plan_label_first_request_logged = False
_plan_label_config_error_logged = False


# Token extraction from vscdb protobuf

def _parse_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def _parse_pb(data):
    """Minimal protobuf parser; yields (field_num, wire_type, value)."""
    pos = 0
    while pos < len(data):
        try:
            tag_wire, pos = _parse_varint(data, pos)
            fn, wt = tag_wire >> 3, tag_wire & 0x7
            if wt == 0:
                v, pos = _parse_varint(data, pos)
                yield fn, wt, v
            elif wt == 2:
                length, pos = _parse_varint(data, pos)
                yield fn, wt, data[pos : pos + length]
                pos += length
            else:
                return
        except Exception:
            return


def extract_refresh_token():
    """Read the refresh token from Antigravity's globalStorage SQLite DB."""
    if not os.path.exists(VSCDB):
        raise FileNotFoundError(f"globalStorage not found: {VSCDB}")
    conn = sqlite3.connect(VSCDB)
    row = conn.execute("SELECT value FROM ItemTable WHERE key=?", (PROTO_KEY,)).fetchone()
    conn.close()
    if not row or not row[0]:
        raise ValueError("oauthToken not found in globalStorage")

    raw = base64.b64decode(row[0] + "==")
    for fn, wt, val in _parse_pb(raw):
        if fn == 1 and wt == 2:
            inner = val
            break
    else:
        raise ValueError("Could not parse outer protobuf wrapper")

    fields = list(_parse_pb(inner))
    b64_content = None
    for fn, wt, val in fields:
        if fn == 2 and wt == 2:
            b64_content = val
            break
    if b64_content is None:
        raise ValueError("Could not find field 2 in inner protobuf")

    try:
        decoded_inner = base64.b64decode(b64_content[2:] + b"==")
    except Exception:
        decoded_inner = b64_content[2:]

    text = decoded_inner.decode("latin-1")
    match = re.search(r"1//[A-Za-z0-9_\-]+", text)
    if not match:
        raise ValueError("Refresh token (1//...) not found in decoded protobuf")
    return match.group(0)


# OAuth

_cached_token = None
_token_expiry = 0.0


def get_access_token():
    """Return a valid access token, refreshing if needed."""
    global _cached_token, _token_expiry
    import time

    if _cached_token and time.time() < _token_expiry - 60:
        return _cached_token

    refresh_token = extract_refresh_token()
    data = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
    ).encode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        token_data = json.load(resp)

    if "access_token" not in token_data:
        raise ValueError(
            "Token refresh failed: "
            f"{token_data.get('error')}: {token_data.get('error_description')}"
        )

    _cached_token = token_data["access_token"]
    _token_expiry = time.time() + token_data.get("expires_in", 3600)
    return _cached_token


# Transport + response helpers

def _log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{ts} {msg}", flush=True)


def resolve_plan_label():
    global _plan_label_cache, _plan_label_source, _plan_label_config_error_logged
    if _plan_label_cache is not None:
        return _plan_label_cache, _plan_label_source

    label = PLAN_LABEL_FALLBACK
    source = "fallback"

    try:
        with open(CODEXBAR_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
        providers = config.get("providers", [])
        if isinstance(providers, list):
            for provider in providers:
                if not isinstance(provider, dict):
                    continue
                if provider.get("id") != "antigravity":
                    continue
                override = provider.get("planLabelOverride")
                if isinstance(override, str) and override.strip():
                    label = override.strip()
                    source = "override"
                break
    except Exception as e:
        if not _plan_label_config_error_logged:
            _log(f"plan_label event=config_error error={e}")
            _plan_label_config_error_logged = True

    _plan_label_cache = label
    _plan_label_source = source
    return label, source


def log_plan_label(event):
    label, source = resolve_plan_label()
    _log(f"plan_label event={event} source={source} label={label}")


def ensure_tls_material():
    if os.path.exists(TLS_CERT_PATH) and os.path.exists(TLS_KEY_PATH):
        return

    primary_cmd = [
        "/usr/bin/openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "3650",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:antigravity.local",
        "-keyout",
        TLS_KEY_PATH,
        "-out",
        TLS_CERT_PATH,
    ]
    fallback_cmd = [
        "/usr/bin/openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "3650",
        "-subj",
        "/CN=localhost",
        "-keyout",
        TLS_KEY_PATH,
        "-out",
        TLS_CERT_PATH,
    ]

    try:
        subprocess.run(primary_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        subprocess.run(fallback_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fetch_quota_payload():
    token = get_access_token()
    req = urllib.request.Request(
        QUOTA_URL,
        data=b"{}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    parsed = json.loads(body.decode("utf-8"))
    return parsed, body


def build_user_status(quota):
    models = build_model_entries(quota)
    label, _ = resolve_plan_label()
    plan_info = {
        "planName": label,
        "planDisplayName": label,
        "displayName": label,
        "productName": "Antigravity",
        "planShortName": label,
        "string": label,
    }
    return {
        "userStatus": {
            "email": "matthewgold",
            "planStatus": {"planInfo": plan_info},
            "planInfo": plan_info,
            "cascadeModelConfigData": {"clientModelConfigs": models},
        }
    }


def build_model_entries(quota):
    models = []
    for bucket in quota.get("buckets", []):
        model_id = bucket.get("modelId")
        remaining = bucket.get("remainingFraction", 0)
        reset_time = bucket.get("resetTime")
        models.append(
            {
                "label": model_id,
                "modelOrAlias": {"model": model_id, "string": model_id},
                "quotaInfo": {
                    "remainingFraction": remaining,
                    "resetTime": reset_time,
                },
            }
        )
    return models


def build_model_configs(quota):
    models = build_model_entries(quota)

    return {
        "cascadeModelConfigData": {"clientModelConfigs": models},
        "clientModelConfigs": models,
    }


def build_unleash_data():
    return {"flags": {}, "source": "antigravity-daemon"}


def json_bytes(payload):
    return json.dumps(payload).encode("utf-8")


# HTTPS server

def make_handler(csrf_token):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _send_json(self, status, payload_bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload_bytes)))
            self.end_headers()
            self.wfile.write(payload_bytes)

        def _request_body(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _log_request(self, body):
            body_preview = ""
            if body:
                try:
                    body_preview = body.decode("utf-8", errors="replace")
                except Exception:
                    body_preview = "<non-utf8>"
            if len(body_preview) > 400:
                body_preview = body_preview[:400] + "...<truncated>"
            _log(
                "request "
                f"method={self.command} "
                f"path={self.path} "
                f"length={len(body)} "
                f"content_type={self.headers.get('Content-Type', '')} "
                f"connect_proto={self.headers.get('Connect-Protocol-Version', '')} "
                f"csrf_present={bool(self.headers.get('x-codeium-csrf-token', ''))} "
                f"body={body_preview}"
            )

        def do_GET(self):
            if self.path.rstrip("/") in ("", "/healthz"):
                self._send_json(200, json_bytes({"ok": True}))
            else:
                self._send_json(404, json_bytes({"error": "not found", "path": self.path}))

        def do_POST(self):
            global _plan_label_first_request_logged
            body = self._request_body()
            self._log_request(body)
            if not _plan_label_first_request_logged:
                log_plan_label("first_request")
                _plan_label_first_request_logged = True

            incoming_csrf = self.headers.get("x-codeium-csrf-token", "")
            if incoming_csrf != csrf_token:
                self._send_json(403, json_bytes({"error": "Invalid CSRF token"}))
                return

            normalized = self.path.rstrip("/")

            try:
                quota_json, quota_raw = fetch_quota_payload()

                if normalized.endswith("retrieveUserQuota"):
                    self._send_json(200, quota_raw)
                    return

                if normalized.endswith("GetUserStatus"):
                    self._send_json(200, json_bytes(build_user_status(quota_json)))
                    return

                if normalized.endswith("GetCommandModelConfigs"):
                    self._send_json(200, json_bytes(build_model_configs(quota_json)))
                    return

                if normalized.endswith("GetUnleashData"):
                    self._send_json(200, json_bytes(build_unleash_data()))
                    return

                self._send_json(404, json_bytes({"error": "unknown endpoint", "path": self.path}))
            except Exception as e:
                _log(f"handler_error path={self.path} error={e}")
                self._send_json(500, json_bytes({"error": str(e)}))

        def log_message(self, fmt, *args):
            _log(fmt % args)

    return Handler


# Main

def main():
    parser = argparse.ArgumentParser(description="Antigravity CodexBar proxy daemon")
    parser.add_argument("--port", type=int, default=54399, help="Port to listen on (default: 54399)")
    parser.add_argument(
        "--extension_server_port",
        type=int,
        default=None,
        help="(Used by CodexBar detection - set automatically)",
    )
    parser.add_argument(
        "--csrf_token",
        type=str,
        default=None,
        help="(Used by CodexBar detection - set automatically)",
    )
    args = parser.parse_args()

    if args.extension_server_port is None or args.csrf_token is None:
        os.execv(
            sys.executable,
            [
                sys.executable,
                __file__,
                "--port",
                str(args.port),
                "--extension_server_port",
                str(args.port),
                "--csrf_token",
                CSRF_TOKEN,
            ],
        )

    port = args.port
    csrf_token = args.csrf_token
    log_plan_label("startup")

    try:
        tok = get_access_token()
        _log(f"startup_token_ok prefix={tok[:20]}...")
    except Exception as e:
        _log(f"startup_token_warning error={e}")

    listen_fd = os.environ.get("LISTEN_FD")
    if listen_fd is not None:
        import socket as _socket

        inherited = _socket.fromfd(int(listen_fd), _socket.AF_INET, _socket.SOCK_STREAM)
        inherited.setblocking(True)
        server = http.server.HTTPServer(("127.0.0.1", port), make_handler(csrf_token), bind_and_activate=False)
        server.socket.close()
        server.socket = inherited
    else:
        server = http.server.HTTPServer(("127.0.0.1", port), make_handler(csrf_token))

    ensure_tls_material()
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)

    _log(f"antigravity-daemon tls_listening port={port} csrf={csrf_token}")
    server.serve_forever()


if __name__ == "__main__":
    main()
