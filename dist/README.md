# Speed Monitor

Monitor your internet speed and aggregate results across your organization.

## Quick Start

### For Users (macOS)

```bash
# Install via Homebrew
brew tap kishore/speed-monitor
brew install speed-monitor

# Configure
speed-monitor setup

# Start automatic monitoring
speed-monitor start
```

### Commands

| Command | Description |
|---------|-------------|
| `speed-monitor setup` | Configure your name and server URL |
| `speed-monitor run` | Run a speed test now |
| `speed-monitor start` | Enable automatic monitoring (every 10 min) |
| `speed-monitor stop` | Disable automatic monitoring |
| `speed-monitor status` | Show current status and recent results |
| `speed-monitor dashboard` | Open local dashboard |
| `speed-monitor logs` | View recent logs |

### SwiftBar Integration (Optional)

Copy the plugin to show speeds in your menu bar:

```bash
cp /usr/local/share/speed-monitor/swiftbar-speed.5m.sh \
   ~/Library/Application\ Support/SwiftBar/Plugins/
```

---

## For Administrators

### Deploy Central Server

1. Clone the repo:
   ```bash
   git clone https://github.com/kishore/speed-monitor.git
   cd speed-monitor/server
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start server:
   ```bash
   npm start
   ```

4. Deploy to Render (recommended):
   - Connect your GitHub repo
   - Render auto-detects Node.js
   - Set `PORT` environment variable if needed

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `DB_PATH` | ./speed_monitor.db | SQLite database path |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/results` | Submit speed test result |
| GET | `/api/results` | Get all results (paginated) |
| GET | `/api/results/:user_id` | Get user's results |
| GET | `/api/stats` | Get aggregated statistics |
| GET | `/health` | Health check |

### Data Schema

```json
{
  "user_id": "John Doe",
  "hostname": "johns-macbook",
  "timestamp": "2025-01-12 10:30:00",
  "download_mbps": 95.5,
  "upload_mbps": 45.2,
  "ping_ms": 12.5,
  "network_ssid": "Office-5G",
  "external_ip": "203.0.113.1",
  "status": "success"
}
```

---

## Project Structure

```
dist/
├── bin/
│   └── speed-monitor      # Main CLI
├── lib/
│   └── swiftbar-speed.5m.sh  # SwiftBar plugin
├── server/
│   ├── index.js           # API server
│   ├── package.json
│   └── public/
│       └── dashboard.html # Aggregated dashboard
└── Formula/
    └── speed-monitor.rb   # Homebrew formula
```

## Requirements

- macOS 10.15+
- speedtest-cli (`brew install speedtest-cli`)
- Node.js 18+ (for server)

## License

MIT
