# antigravity-daemon

A daemon that enables CodexBar's Antigravity provider to work without the Antigravity app running.

## Overview

CodexBar detects the Antigravity language server by looking for `language_server_macos` processes. This daemon mimics the language server endpoints that CodexBar expects, allowing you to use Antigravity's AI capabilities through CodexBar even when the Antigravity app is not open.

## How It Works

1. **Token Extraction**: Reads the OAuth refresh token from Antigravity's SQLite database (`~/Library/Application Support/Antigravity/User/globalStorage/state.vscdb`)
2. **OAuth Refresh**: Uses the refresh token to obtain valid access tokens from Google's OAuth service
3. **Quota Proxy**: Proxies requests to `cloudcode-pa.googleapis.com` to fetch your quota and model information
4. **Endpoint Mimicry**: Provides the endpoints CodexBar expects:
   - `/exa.language_server_pb.LanguageServerService/GetUserStatus`
   - `/exa.language_server_pb.LanguageServerService/GetCommandModelConfigs`
   - `/exa.language_server_pb.LanguageServerService/GetUnleashData`
   - `/v1internal:retrieveUserQuota`

## Requirements

- Python 3.7+
- macOS
- CodexBar installed
- Antigravity app installed (for initial token extraction)

## Installation

```bash
# Clone the repository
git clone https://github.com/mdgld/antigravity-daemon.git
cd antigravity-daemon
```

## Usage

### Running the Daemon

```bash
python3 language_server_macos_arm.py [--port PORT]
```

The default port is `54399`. The daemon will:
1. Automatically generate TLS certificates
2. Extract your refresh token from Antigravity's database
3. Start listening for CodexBar connections

### Running as a LaunchAgent (Recommended)

To run automatically on login:

```bash
# Create the LaunchAgent directory if it doesn't exist
mkdir -p ~/Library/LaunchAgents

# Create the plist file
cat > ~/Library/LaunchAgents/com.user.antigravity-daemon.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.antigravity-daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/matthewgold/code/antigravity/language_server_macos_arm.py</string>
        <string>--port</string>
        <string>54399</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/antigravity-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/antigravity-daemon.log</string>
</dict>
</plist>
EOF

# Load the LaunchAgent
launchctl load ~/Library/LaunchAgents/com.user.antigravity-daemon.plist
```

### CodexBar Configuration

Ensure your `~/.codexbar/config.json` has the Antigravity provider configured. The daemon will automatically pick up any `planLabelOverride` setting from your provider config.

## Configuration

### Plan Label Override

You can customize the plan name displayed in CodexBar by adding a `planLabelOverride` to your CodexBar provider configuration:

```json
{
  "providers": [
    {
      "id": "antigravity",
      "planLabelOverride": "My Custom Plan"
    }
  ]
}
```

### Custom Port

If you need to use a different port:

```bash
python3 language_server_macos_arm.py --port 54398
```

## Logs

Logs are written to stdout. When running as a LaunchAgent, check:

```bash
tail -f /tmp/antigravity-daemon.log
```

## Troubleshooting

### Token Not Found

If you see "oauthToken not found in globalStorage", make sure:
1. Antigravity app has been launched at least once
2. You are logged into Antigravity

### GlobalStorage Not Found

Ensure the path exists:
```bash
ls ~/Library/Application\ Support/Antigravity/User/globalStorage/
```

### Port Already in Use

Find and kill the existing process:
```bash
lsof -i :54399
kill <PID>
```

## Security

- TLS certificates are generated locally and stored in `/tmp/`
- Refresh tokens are read from Antigravity's local database
- No credentials are stored by this daemon (tokens are cached in memory only)

## License

MIT License
