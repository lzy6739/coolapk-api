# CoolApk API Client

[中文](#中文说明) | English

Capture CoolApk app's API authentication tokens from a rooted Android phone via mitmproxy, then query the CoolApk API from your desktop — user profiles, feeds, search, and more. Pure Python, zero runtime dependencies.

The key insight: CoolApk has no web login portal, and its Token V3 signature is dynamically generated and hard to reverse. This tool bypasses the problem entirely by intercepting real API requests from the phone and replaying them on desktop.

## Requirements

- **Rooted Android phone** (any model — configure via `COOLAPK_DEVICE_MODEL`)
- **Magisk module `mitm_certs`** with mitmproxy CA certificate installed as system cert ([setup guide](#magisk-module-setup))
- **ADB** connected to the phone (USB or WiFi)
- **Python 3.10+**
- CoolApk app logged in on the phone (guest tokens work but some endpoints are restricted)

## Installation

```bash
# From source
git clone https://github.com/lzy6739/coolapk-api.git
cd coolapk-api
pip install .

# Or use directly without installing
python3 coolapk_api.py
```

After `pip install`, the `coolapk-api` command is available globally.

## Quick Start

### 1. Install mitmproxy

```bash
python3 -m venv /tmp/mitmproxy-venv
/tmp/mitmproxy-venv/bin/pip install mitmproxy
```

> `/tmp` is cleared on reboot. For a persistent location, adjust `COOLAPK_MITM_VENV`.

### 2. Capture a token

```bash
coolapk-api capture
# or
python3 coolapk_api.py capture
```

The script automatically:
1. Starts mitmdump on port 8080
2. Sets the phone's proxy to point at your computer
3. Creates iptables rules to redirect only CoolApk's traffic (UID-based)
4. Relaunches the CoolApk app to trigger fresh API requests
5. Captures the complete request headers including `X-App-Token`
6. Cleans up iptables, proxy settings, and stops mitmdump

The token is saved to `.coolapk_token.json` (valid for ~1 hour).

### 3. Query the API

```bash
# User profile
coolapk-api profile 3420373

# User's feed list (paginated)
coolapk-api feed 3420373
coolapk-api feed 3420373 2    # page 2

# Search feeds by keyword
coolapk-api search "酷安"
coolapk-api search "酷安" 2   # page 2

# Feed detail
coolapk-api detail 12345678

# Capture then query in one step
coolapk-api capture-and-query feed 3420373
```

## Command Reference

| Command | Description |
|---|---|
| `capture` | Capture a fresh token from the phone |
| `profile <uid>` | View user profile (name, level, followers, bio) |
| `feed <uid> [page]` | View user's feed list |
| `search <keyword> [page]` | Search feeds by keyword |
| `detail <feed_id>` | View detail of a specific feed |
| `capture-and-query <action> <arg>` | Capture token then run a query |

## Configuration

Config priority: **environment variables** > **config file** > **defaults**

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `COOLAPK_DEVICE_MODEL` | ADB device model string | `RMX3461` |
| `COOLAPK_HOST_IP` | Host machine IP (phone must reach this) | auto-detect |
| `COOLAPK_MITM_VENV` | Path to mitmproxy virtualenv | `/tmp/mitmproxy-venv` |
| `COOLAPK_MITM_PORT` | mitmdump listen port | `8080` |
| `COOLAPK_TOKEN_FILE` | Token file path | `.coolapk_token.json` (next to script) |

### Config File

Place a `coolapk-api.json` in the project directory or `~/.config/coolapk-api/config.json`:

```json
{
  "device_model": "RMX3461",
  "host_ip": "192.168.1.100",
  "mitm_venv": "/tmp/mitmproxy-venv",
  "mitm_port": 8080,
  "token_file": ".coolapk_token.json"
}
```

See `config.example.json` for a template.

## Python Library

```python
from coolapk_api import (
    get_user_profile, get_user_feeds,
    get_feed_detail, search_feeds,
    load_token, api_get,
)

# User profile
profile = get_user_profile(3420373)
print(profile['username'], profile['level'])

# User's feeds
feeds = get_user_feeds(3420373, page=1)
for item in feeds:
    print(item.get('message', '')[:80])

# Feed detail
detail = get_feed_detail(12345678)
print(detail.get('title'), detail.get('message'))

# Search
results = search_feeds("酷安", page=1)
for item in results:
    print(item.get('username'), item.get('title'))

# Custom API call
headers = load_token()
data = api_get("/v6/user/profile?uid=3420373", headers)
```

## Known API Endpoints

| Endpoint | Description |
|---|---|
| `/v6/user/profile?uid=<uid>` | User profile |
| `/v6/user/feedList?uid=<uid>&page=<n>` | User feed list |
| `/v6/feed/detail?id=<feed_id>` | Feed detail |
| `/v6/search?type=feed&keyword=<kw>&page=<n>` | Search feeds |

All endpoints require the full set of `X-App-*` request headers (captured automatically).

## Current Request Headers (2026-10-11)

```
X-App-Id: com.coolapk.market
X-App-Version: 16.4.0
X-App-Code: 2607021
X-App-Mode: community
X-App-Channel: xiaomi
X-Api-Version: 16
X-App-Supported: 2607021
X-Sdk-Int: 31
X-Sdk-Locale: zh-CN
X-Dark-Mode: 0
X-Requested-With: XMLHttpRequest
```

These may change after CoolApk updates. Just re-run `capture` to get fresh values.

---

## Developer Docs

### Architecture

```
coolapk_api.py
├── _load_config()       # Configuration: env > file > defaults
├── capture_token()      # Token capture: mitmdump + iptables + ADB
├── api_get()            # HTTP GET with auth headers
├── get_user_profile()   # High-level API
├── get_user_feeds()
├── get_feed_detail()
├── search_feeds()
└── main()               # CLI entry point
```

### Token V3 Signature Analysis

Reverse-engineered from [coolapk-desktop](https://github.com/daimiaopeng/coolapk-desktop):

1. Select 128-byte fragment from `auth_blob` (hardcoded lookup table) by timestamp
2. Combine: `APP_ID & fragment & device_md5 & timestamp & APP_CODE`
3. MD5 of base64(plain) → password
4. Generate bcrypt salt (cost=4), compute bcrypt hash
5. Base64-encode result, prepend `v3`

**Unresolved issue:** Python `bcrypt` (4.x/5.x) and Rust `bcrypt` crate handle trailing salt bits differently. Offline-generated tokens return "request verification error" instead of 403, but don't authenticate successfully.

**Current workaround:** Capture live tokens from the phone. Valid for ~1 hour.

### Capture Flow

```
┌──────────┐    HTTPS     ┌──────────────┐
│  CoolApk │─────────────>│ api.coolapk  │
│  (app)   │              │     .com     │
└────┬─────┘              └──────────────┘
     │                         ▲
     │ iptables DNAT           │
     │ (uid-based)             │ mitmdump
     ▼                         │ TLS intercept
┌──────────┐    HTTP(S)  ┌─────┴──────┐
│  host    │────────────>│ mitmdump   │
│  IP:port │             │ :8080      │
└──────────┘             └────────────┘
```

1. **iptables transparent proxy**: match CoolApk's UID, DNAT ports 443/80 to mitmdump
2. **CA certificate**: mitmproxy CA installed as system cert via Magisk module
3. **Traffic capture**: mitmdump addon filters `api.coolapk.com` requests, extracts full headers

### Magisk Module Setup

One-time setup to install mitmproxy's CA certificate as a system-trusted cert:

```
/data/adb/modules/mitm_certs/
├── module.prop
└── system/etc/security/cacerts/
    └── c8750f0d.0    ← mitmproxy CA cert
```

```bash
# Generate cert filename from subject hash
openssl x509 -subject_hash_old -noout -in ~/.mitmproxy/mitmproxy-ca-cert.pem
# e.g. output: c8750f0d

# Push cert to phone
adb shell su -c 'mkdir -p /data/adb/modules/mitm_certs/system/etc/security/cacerts'
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /data/local/tmp/c8750f0d.0
adb shell su -c 'cp /data/local/tmp/c8750f0d.0 /data/adb/modules/mitm_certs/system/etc/security/cacerts/'
adb shell su -c 'chmod 644 /data/adb/modules/mitm_certs/system/etc/security/cacerts/c8750f0d.0'

# Write module.prop
adb shell su -c 'printf "id=mitm_certs\nname=MITM CA Certs\nversion=1.0\nversionCode=1\nauthor=coolapk-api\ndescription=Install mitmproxy CA cert as system cert" > /data/adb/modules/mitm_certs/module.prop'

# Reboot to activate
adb reboot
```

---

## 中文说明

通过 root 手机抓包获取酷安 app 的 API 签名 token，然后在电脑上直接调用酷安 API。纯 Python 标准库，零运行时依赖。

### 快速开始

```bash
# 安装 mitmproxy
python3 -m venv /tmp/mitmproxy-venv
/tmp/mitmproxy-venv/bin/pip install mitmproxy

# 抓取 token
python3 coolapk_api.py capture

# 查询
python3 coolapk_api.py profile 3420373
python3 coolapk_api.py feed 3420373
python3 coolapk_api.py search "酷安"
python3 coolapk_api.py detail 12345678
```

### 前置条件

- 已 root 的安卓手机（任意型号，通过 `COOLAPK_DEVICE_MODEL` 配置）
- Magisk 模块 `mitm_certs` 已安装 mitmproxy CA 证书（一次性操作，见上方 [Magisk Module Setup](#magisk-module-setup)）
- ADB 已连接手机
- Python 3.10+

### 配置

支持环境变量和配置文件两种方式，环境变量优先级更高。详见上方 [Configuration](#configuration) 章节。
