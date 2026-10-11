#!/usr/bin/env python3
"""
CoolApk API client — token captured from rooted phone via mitmproxy + iptables.

Usage:
    python3 coolapk_api.py capture
    python3 coolapk_api.py profile <uid>
    python3 coolapk_api.py feed <uid> [page]
    python3 coolapk_api.py search <keyword> [page]
    python3 coolapk_api.py detail <feed_id>
    python3 coolapk_api.py capture-and-query <action> <uid_or_keyword>

Configuration (env vars override config file):
    COOLAPK_DEVICE_MODEL   — ADB device model (default: RMX3461)
    COOLAPK_HOST_IP        — Host machine IP (default: auto-detect)
    COOLAPK_MITM_VENV      — mitmproxy venv path (default: /tmp/mitmproxy-venv)
    COOLAPK_MITM_PORT      — mitmproxy port (default: 8080)
    COOLAPK_TOKEN_FILE     — Token file path (default: .coolapk_token.json next to script)

Config file: ./coolapk-api.json or ~/.config/coolapk-api/config.json
"""

import json, os, sys, time, re, subprocess, signal, socket, urllib.request, urllib.error
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

def _detect_host_ip():
    """Detect the local IP address (the one the phone's proxy will reach)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _load_config():
    """Load config: env vars > config file > defaults."""
    defaults = {
        "device_model": "RMX3461",
        "host_ip": None,  # None means auto-detect
        "mitm_venv": "/tmp/mitmproxy-venv",
        "mitm_port": 8080,
        "token_file": str(Path(__file__).parent / ".coolapk_token.json"),
    }
    # Try config files
    for path in [
        Path.cwd() / "coolapk-api.json",
        Path.home() / ".config" / "coolapk-api" / "config.json",
    ]:
        if path.exists():
            try:
                user_cfg = json.loads(path.read_text())
                defaults.update(user_cfg)
            except (json.JSONDecodeError, OSError):
                pass
            break
    # Env vars override (COOLAPK_<KEY>)
    for key in list(defaults):
        env_key = f"COOLAPK_{key.upper()}"
        if env_key in os.environ:
            val = os.environ[env_key]
            defaults[key] = int(val) if key == "mitm_port" else val
    # Auto-detect host IP if not set
    if not defaults["host_ip"]:
        defaults["host_ip"] = _detect_host_ip()
    return defaults

_config = _load_config()

TOKEN_FILE = Path(_config["token_file"])
MITM_VENV = Path(_config["mitm_venv"])
MITM_PORT = _config["mitm_port"]
HOST_IP = _config["host_ip"]
DEVICE_MODEL = _config["device_model"]

# ── ADB helpers ──────────────────────────────────────────────────────────────

def adb_device():
    """Find the connected ADB device matching configured model."""
    out = subprocess.check_output(["adb", "devices", "-l"], text=True)
    for line in out.strip().split("\n")[1:]:
        if DEVICE_MODEL in line and "device" in line:
            return line.split()[0]
    raise RuntimeError(
        f"{DEVICE_MODEL} not connected via ADB. "
        f"Set COOLAPK_DEVICE_MODEL env var if using a different device."
    )

def adb_shell(dev, cmd, su=False):
    """Run a shell command on the phone."""
    if su:
        cmd = f"su -c '{cmd}'"
    return subprocess.check_output(
        ["adb", "-s", dev, "shell", cmd], text=True, timeout=15
    ).strip()

# ── Token capture ────────────────────────────────────────────────────────────

CAPTURE_SCRIPT = '''
import json, sys

captured = []

class CoolApkCapture:
    def response(self, flow):
        if "api.coolapk.com" in flow.request.pretty_host:
            entry = {"url": flow.request.url, "headers": dict(flow.request.headers)}
            captured.append(entry)
            with open("/tmp/coolapk_api_capture.json", "w") as f:
                json.dump(captured, f, indent=2)

addons = [CoolApkCapture()]
'''

def capture_token():
    """Capture a fresh X-App-Token from the phone's CoolApk app."""
    dev = adb_device()
    print(f"[1/6] ADB device: {dev}")

    # Write capture script
    script_path = "/tmp/coolapk_capture_addon.py"
    with open(script_path, "w") as f:
        f.write(CAPTURE_SCRIPT)

    # Start mitmdump
    print("[2/6] Starting mitmdump...")
    mitmdump = subprocess.Popen(
        [str(MITM_VENV / "bin" / "mitmdump"),
         "-s", script_path, "-p", str(MITM_PORT),
         "--set", "flow_detail=0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    try:
        # Set proxy
        print("[3/6] Setting phone proxy...")
        adb_shell(dev, f"settings put global http_proxy {HOST_IP}:{MITM_PORT}")

        # Get CoolApk UID and set iptables redirect
        print("[4/6] Setting up iptables redirect...")
        uid_line = adb_shell(dev, "cat /data/system/packages.list | grep com.coolapk.market", su=True)
        uid = uid_line.split()[1]
        adb_shell(dev, f"iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner {uid} -j DNAT --to-destination {HOST_IP}:{MITM_PORT}", su=True)
        adb_shell(dev, f"iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner {uid} -j DNAT --to-destination {HOST_IP}:{MITM_PORT}", su=True)

        # Force-relaunch CoolApk
        print("[5/6] Relaunching CoolApk...")
        adb_shell(dev, "am force-stop com.coolapk.market")
        time.sleep(1)
        adb_shell(dev, "monkey -p com.coolapk.market -c android.intent.category.LAUNCHER 1")

        # Wait for capture
        capture_file = Path("/tmp/coolapk_api_capture.json")
        capture_file.unlink(missing_ok=True)
        for i in range(20):
            time.sleep(1)
            if capture_file.exists():
                data = json.loads(capture_file.read_text())
                if data:
                    break
        else:
            raise RuntimeError("Timeout waiting for CoolApk API request")

        # Save token
        headers = data[0]["headers"]
        token_data = {
            "captured_at": time.time(),
            "headers": {k: v for k, v in headers.items()
                        if k.startswith("X-") or k == "User-Agent"},
        }
        TOKEN_FILE.write_text(json.dumps(token_data, indent=2))
        print(f"[6/6] Token captured! ({len(headers)} headers)")
        print(f"  X-App-Token: {headers.get('X-App-Token', '?')[:60]}...")
        print(f"  X-App-Version: {headers.get('X-App-Version', '?')}")
        print(f"  Saved to: {TOKEN_FILE}")
        return token_data

    finally:
        # Cleanup
        print("Cleaning up...")
        adb_shell(dev, f"iptables -t nat -D OUTPUT -p tcp --dport 443 -m owner --uid-owner {uid} -j DNAT --to-destination {HOST_IP}:{MITM_PORT}", su=True)
        adb_shell(dev, f"iptables -t nat -D OUTPUT -p tcp --dport 80 -m owner --uid-owner {uid} -j DNAT --to-destination {HOST_IP}:{MITM_PORT}", su=True)
        adb_shell(dev, "settings put global http_proxy :0")
        mitmdump.terminate()
        mitmdump.wait(timeout=5)

# ── API client ───────────────────────────────────────────────────────────────

def load_token():
    """Load the most recently captured token."""
    if not TOKEN_FILE.exists():
        raise RuntimeError("No captured token. Run: python3 coolapk_api.py capture")
    data = json.loads(TOKEN_FILE.read_text())
    age = time.time() - data["captured_at"]
    if age > 3600:
        print(f"Warning: token is {age/60:.0f} min old, may have expired. Re-capture if needed.")
    return data["headers"]

def api_get(path, headers=None):
    """Make a GET request to the CoolApk API."""
    if headers is None:
        headers = load_token()
    url = f"https://api.coolapk.com{path}"
    req = urllib.request.Request(url)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            msg = body.get("message", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            msg = e.reason
        raise RuntimeError(f"API error {e.code}: {msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}") from e

# ── High-level API ───────────────────────────────────────────────────────────

def get_user_profile(uid):
    """Get user profile by UID."""
    return api_get(f"/v6/user/profile?uid={uid}")["data"]

def get_user_feeds(uid, page=1):
    """Get user's feed list."""
    return api_get(f"/v6/user/feedList?uid={uid}&page={page}")["data"]

def get_feed_detail(feed_id):
    """Get detail of a specific feed."""
    return api_get(f"/v6/feed/detail?id={feed_id}")["data"]

def search_feeds(keyword, page=1):
    """Search feeds by keyword."""
    return api_get(f"/v6/search?type=feed&keyword={keyword}&page={page}")["data"]

# ── CLI ──────────────────────────────────────────────────────────────────────

def strip_html(text):
    if not text: return ""
    return re.sub(r'<[^>]+>', '', text)

def cmd_profile(uid):
    p = get_user_profile(uid)
    print(f"=== {p['username']} (UID: {p['uid']}) ===")
    print(f"等级: {p.get('level','?')} | 动态: {p.get('feed','?')} | 关注: {p.get('follow','?')} | 粉丝: {p.get('fans','?')}")
    bio = strip_html(p.get('userBio', ''))
    if bio: print(f"简介: {bio}")

def cmd_feeds(uid, page=1):
    feeds = get_user_feeds(uid, page)
    print(f"=== 第 {page} 页，共 {len(feeds)} 条 ===\n")
    for item in feeds:
        title = item.get('title', '') or ''
        msg = strip_html(item.get('message', item.get('summary', '')) or '')
        if len(msg) > 120: msg = msg[:120] + '...'
        t = item.get('dateline', '')
        if isinstance(t, (int, float)):
            t = time.strftime('%Y-%m-%d %H:%M', time.localtime(t))
        etype = item.get('entityType', item.get('type', ''))
        print(f"[{t}] ({etype}) {title}")
        if msg: print(f"  {msg}")
        print()

def cmd_search(keyword, page=1):
    """CLI: search feeds by keyword."""
    results = search_feeds(keyword, page)
    print(f"=== 搜索: '{keyword}'，第 {page} 页，共 {len(results)} 条 ===\n")
    for item in results:
        title = item.get('title', '') or ''
        msg = strip_html(item.get('message', item.get('summary', '')) or '')
        if len(msg) > 120: msg = msg[:120] + '...'
        user = item.get('username', item.get('uid', '?'))
        print(f"[{user}] {title}")
        if msg: print(f"  {msg}")
        print()

def cmd_detail(feed_id):
    """CLI: show detail of a specific feed."""
    detail = get_feed_detail(feed_id)
    user = detail.get('username', '?')
    title = detail.get('title', '') or ''
    msg = strip_html(detail.get('message', '') or '')
    t = detail.get('dateline', '')
    if isinstance(t, (int, float)):
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(t))
    print(f"=== {title} ===")
    print(f"By: {user} | {t}")
    if msg:
        print(f"\n{msg}")

def cmd_capture_and_query(action, *args):
    capture_token()
    if action == "profile":
        cmd_profile(int(args[0]))
    elif action == "feed":
        cmd_feeds(int(args[0]))
    elif action == "search":
        cmd_search(args[0])
    elif action == "detail":
        cmd_detail(int(args[0]))

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "capture":
        capture_token()
    elif cmd == "profile" and len(sys.argv) >= 3:
        cmd_profile(int(sys.argv[2]))
    elif cmd == "feed" and len(sys.argv) >= 3:
        page = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        cmd_feeds(int(sys.argv[2]), page)
    elif cmd == "search" and len(sys.argv) >= 3:
        page = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        cmd_search(sys.argv[2], page)
    elif cmd == "detail" and len(sys.argv) >= 3:
        cmd_detail(int(sys.argv[2]))
    elif cmd == "capture-and-query" and len(sys.argv) >= 4:
        cmd_capture_and_query(sys.argv[2], *sys.argv[3:])
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
