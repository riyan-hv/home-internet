const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');

const APP_VERSION = '3.1.38';

// AP name mapping based on BSSID prefix (first 5 bytes) to handle multiple virtual APs
const AP_PREFIX_MAP = {
  'a8:ba:25:ce:a4:d': '2F-AP_1', 'a8:ba:25:6a:4d': '2F-AP_1',   // 2F-AP_1
  'a8:ba:25:ce:a1:a': '2F-AP_2', 'a8:ba:25:6a:1a': '2F-AP_2',   // 2F-AP_2
  'a8:ba:25:ce:a1:2': '2F-AP_3', 'a8:ba:25:6a:12': '2F-AP_3',   // 2F-AP_3
  'a8:ba:25:ce:a2:3': '2F-AP_4', 'a8:ba:25:6a:23': '2F-AP_4',   // 2F-AP_4
  'a8:ba:25:ce:a3:e': '2F-AP_5', 'a8:ba:25:6a:3e': '2F-AP_5',   // 2F-AP_5
  'a8:ba:25:ce:a1:c': '3F-AP_5', 'a8:ba:25:6a:1c': '3F-AP_5',   // 3F-AP_5
  'a8:ba:25:ce:9f:5': '3F-AP-1', 'a8:ba:25:69:f5': '3F-AP-1',   // 3F-AP-1
  'a8:ba:25:ce:9f:0': '3F-AP-2', 'a8:ba:25:69:f0': '3F-AP-2',   // 3F-AP-2
  'a8:ba:25:ce:a4:6': '3F-AP-3', 'a8:ba:25:6a:46': '3F-AP-3',   // 3F-AP-3
  'a8:ba:25:ce:a4:e': '3F-AP-4', 'a8:ba:25:6a:4e': '3F-AP-4'    // 3F-AP-4
};

// Lookup AP name by BSSID prefix
function lookupAPName(bssid) {
  if (!bssid) return null;
  const lower = bssid.toLowerCase();
  // Try prefix match (first 14 chars = "aa:bb:cc:dd:ee")
  const prefix14 = lower.substring(0, 14);
  if (AP_PREFIX_MAP[prefix14]) return AP_PREFIX_MAP[prefix14];
  // Try shorter prefix (first 13 chars)
  const prefix13 = lower.substring(0, 13);
  for (const [key, name] of Object.entries(AP_PREFIX_MAP)) {
    if (key.startsWith(prefix13) || prefix13.startsWith(key)) {
      return name;
    }
  }
  return null;
}

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy headers (required for Render and other cloud providers)
// This fixes express-rate-limit X-Forwarded-For validation errors
app.set('trust proxy', 1);

// Rate limiting - increased for 300+ device fleet behind corporate NAT
// Use custom key generator to properly extract client IP from X-Forwarded-For
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // limit each IP to 500 requests per windowMs (supports 300 devices behind NAT)
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => {
    // Extract client IP from X-Forwarded-For header (first IP is the original client)
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0]; // Return the original client IP
    }
    return req.ip || req.connection.remoteAddress || 'unknown';
  },
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', limiter);

// Initialize PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

console.log(`PostgreSQL connection configured`);

// Initialize database schema
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS speed_results (
        id SERIAL PRIMARY KEY,

        -- Identity
        device_id TEXT NOT NULL,
        user_id TEXT,
        user_email TEXT,
        hostname TEXT,

        -- Metadata
        timestamp_utc TIMESTAMP NOT NULL,
        os_version TEXT,
        app_version TEXT,
        timezone TEXT,

        -- Network interface
        interface TEXT,
        local_ip TEXT,
        public_ip TEXT,

        -- WiFi details
        ssid TEXT,
        bssid TEXT,
        band TEXT,
        channel INTEGER DEFAULT 0,
        width_mhz INTEGER DEFAULT 0,
        rssi_dbm INTEGER DEFAULT 0,
        noise_dbm INTEGER DEFAULT 0,
        snr_db INTEGER DEFAULT 0,
        tx_rate_mbps REAL DEFAULT 0,

        -- v2.1: Link quality metrics
        mcs_index INTEGER DEFAULT -1,
        spatial_streams INTEGER DEFAULT 0,

        -- Performance metrics
        latency_ms REAL DEFAULT 0,
        jitter_ms REAL DEFAULT 0,
        jitter_p50 REAL DEFAULT 0,
        jitter_p95 REAL DEFAULT 0,
        packet_loss_pct REAL DEFAULT 0,
        download_mbps REAL DEFAULT 0,
        upload_mbps REAL DEFAULT 0,

        -- VPN status
        vpn_status TEXT DEFAULT 'disconnected',
        vpn_name TEXT DEFAULT 'none',

        -- v2.1: Interface error metrics
        input_errors BIGINT DEFAULT 0,
        output_errors BIGINT DEFAULT 0,
        input_error_rate REAL DEFAULT 0,
        output_error_rate REAL DEFAULT 0,
        tcp_retransmits BIGINT DEFAULT 0,

        -- v2.1: BSSID tracking (roaming detection)
        bssid_changed INTEGER DEFAULT 0,
        roam_count INTEGER DEFAULT 0,

        -- Status and errors
        status TEXT DEFAULT 'success',
        errors TEXT,

        -- Raw data
        raw_payload TEXT,

        -- Timestamps
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Indexes for common queries
      CREATE INDEX IF NOT EXISTS idx_device_id ON speed_results(device_id);
      CREATE INDEX IF NOT EXISTS idx_timestamp ON speed_results(timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_ssid ON speed_results(ssid);
      CREATE INDEX IF NOT EXISTS idx_bssid ON speed_results(bssid);
      CREATE INDEX IF NOT EXISTS idx_vpn_status ON speed_results(vpn_status);
      CREATE INDEX IF NOT EXISTS idx_status ON speed_results(status);

      -- Composite index for time-series queries
      CREATE INDEX IF NOT EXISTS idx_device_time ON speed_results(device_id, timestamp_utc);

      -- v3.0 Tables

      -- Alert configurations
      CREATE TABLE IF NOT EXISTS alert_configs (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        webhook_url TEXT NOT NULL,
        channel_name TEXT,
        threshold_download_mbps REAL,
        threshold_jitter_ms REAL,
        threshold_packet_loss_pct REAL,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Alert history
      CREATE TABLE IF NOT EXISTS alert_history (
        id SERIAL PRIMARY KEY,
        alert_config_id INTEGER,
        device_id TEXT,
        alert_type TEXT,
        message TEXT,
        severity TEXT DEFAULT 'warning',
        triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id)
      );

      -- ISP lookup cache
      CREATE TABLE IF NOT EXISTS isp_cache (
        public_ip TEXT PRIMARY KEY,
        isp_name TEXT,
        isp_org TEXT,
        city TEXT,
        region TEXT,
        country TEXT,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Daily aggregates for historical trends
      CREATE TABLE IF NOT EXISTS daily_aggregates (
        id SERIAL PRIMARY KEY,
        date TEXT NOT NULL,
        device_id TEXT,
        avg_download REAL,
        avg_upload REAL,
        avg_latency REAL,
        avg_jitter REAL,
        avg_packet_loss REAL,
        test_count INTEGER,
        vpn_on_count INTEGER DEFAULT 0,
        vpn_off_count INTEGER DEFAULT 0,
        UNIQUE(date, device_id)
      );

      -- Anomaly baselines per device
      CREATE TABLE IF NOT EXISTS device_baselines (
        device_id TEXT PRIMARY KEY,
        baseline_download REAL,
        baseline_upload REAL,
        baseline_jitter REAL,
        stddev_download REAL,
        stddev_upload REAL,
        stddev_jitter REAL,
        sample_count INTEGER DEFAULT 0,
        last_updated TIMESTAMP
      );

      -- Indexes for new tables
      CREATE INDEX IF NOT EXISTS idx_alert_history_device ON alert_history(device_id);
      CREATE INDEX IF NOT EXISTS idx_alert_history_time ON alert_history(triggered_at);
      CREATE INDEX IF NOT EXISTS idx_daily_aggregates_date ON daily_aggregates(date);
      CREATE INDEX IF NOT EXISTS idx_isp_cache_time ON isp_cache(cached_at);

      -- v2.1: Connection events table (for tracking disconnects/roaming)
      CREATE TABLE IF NOT EXISTS connection_events (
        id SERIAL PRIMARY KEY,
        device_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        timestamp_utc TIMESTAMP NOT NULL,
        ssid TEXT,
        bssid TEXT,
        prev_bssid TEXT,
        channel INTEGER,
        band TEXT,
        rssi_dbm INTEGER,
        association_duration_sec INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_conn_events_device ON connection_events(device_id, timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_conn_events_type ON connection_events(event_type);

      -- v3.1: User feedback table
      CREATE TABLE IF NOT EXISTS user_feedback (
        id SERIAL PRIMARY KEY,
        email TEXT,
        message TEXT NOT NULL,
        terminal_output TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- v3.1.08: Device diagnostics table (for remote troubleshooting)
      CREATE TABLE IF NOT EXISTS device_diagnostics (
        id SERIAL PRIMARY KEY,
        device_id TEXT NOT NULL,
        user_email TEXT,
        hostname TEXT,

        -- Versions
        app_version TEXT,
        script_version TEXT,
        os_version TEXT,

        -- Status checks
        launchd_status TEXT,
        speedtest_installed INTEGER DEFAULT 0,
        speedtest_path TEXT,

        -- Logs
        error_log TEXT,
        last_test_result TEXT,

        -- Network info
        network_interfaces TEXT,
        wifi_info TEXT,

        -- Timestamps
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_diagnostics_device ON device_diagnostics(device_id, submitted_at);
      CREATE INDEX IF NOT EXISTS idx_diagnostics_email ON device_diagnostics(user_email);
    `);
    console.log('Database schema initialized');
  } catch (err) {
    console.error('Error initializing database:', err);
    throw err;
  } finally {
    client.release();
  }
}

// Initialize database on startup
initDatabase().catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

// Helper: Parse and validate numeric field
const parseNum = (val, defaultVal = 0) => {
  if (val === null || val === undefined || val === '') return defaultVal;
  const num = parseFloat(val);
  return isNaN(num) ? defaultVal : num;
};

// API: Submit speed test result (v2.1 - added WiFi debugging fields)
app.post('/api/results', async (req, res) => {
  const data = req.body;

  if (!data.device_id) {
    return res.status(400).json({ error: 'device_id is required' });
  }

  // Validate and sanitize numeric fields to prevent type errors in aggregations
  data.channel = parseNum(data.channel, 0);
  data.width_mhz = parseNum(data.width_mhz, 0);
  data.rssi_dbm = parseNum(data.rssi_dbm, 0);
  data.noise_dbm = parseNum(data.noise_dbm, 0);
  data.snr_db = parseNum(data.snr_db, 0);
  data.tx_rate_mbps = parseNum(data.tx_rate_mbps, 0);
  data.mcs_index = parseNum(data.mcs_index, -1);
  data.spatial_streams = parseNum(data.spatial_streams, 0);
  data.latency_ms = parseNum(data.latency_ms, 0);
  data.jitter_ms = parseNum(data.jitter_ms, 0);
  data.jitter_p50 = parseNum(data.jitter_p50, 0);
  data.jitter_p95 = parseNum(data.jitter_p95, 0);
  data.packet_loss_pct = parseNum(data.packet_loss_pct, 0);
  data.download_mbps = parseNum(data.download_mbps, 0);
  data.upload_mbps = parseNum(data.upload_mbps, 0);
  data.input_errors = parseNum(data.input_errors, 0);
  data.output_errors = parseNum(data.output_errors, 0);
  data.input_error_rate = parseNum(data.input_error_rate, 0);
  data.output_error_rate = parseNum(data.output_error_rate, 0);
  data.tcp_retransmits = parseNum(data.tcp_retransmits, 0);
  data.bssid_changed = parseNum(data.bssid_changed, 0);
  data.roam_count = parseNum(data.roam_count, 0);

  try {
    const result = await pool.query(`
      INSERT INTO speed_results (
        device_id, user_id, user_email, hostname, timestamp_utc, os_version, app_version, timezone,
        interface, local_ip, public_ip,
        ssid, bssid, band, channel, width_mhz, rssi_dbm, noise_dbm, snr_db, tx_rate_mbps,
        mcs_index, spatial_streams,
        latency_ms, jitter_ms, jitter_p50, jitter_p95, packet_loss_pct, download_mbps, upload_mbps,
        vpn_status, vpn_name,
        input_errors, output_errors, input_error_rate, output_error_rate, tcp_retransmits,
        bssid_changed, roam_count,
        status, errors, raw_payload
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8,
        $9, $10, $11,
        $12, $13, $14, $15, $16, $17, $18, $19, $20,
        $21, $22,
        $23, $24, $25, $26, $27, $28, $29,
        $30, $31,
        $32, $33, $34, $35, $36,
        $37, $38,
        $39, $40, $41
      ) RETURNING id
    `, [
      data.device_id,
      data.user_id || data.device_id,
      data.user_email || null,
      data.hostname || null,
      data.timestamp_utc || new Date().toISOString(),
      data.os_version || null,
      data.app_version || null,
      data.timezone || null,
      data.interface || null,
      data.local_ip || null,
      data.public_ip || null,
      data.ssid || null,
      data.bssid || null,
      data.band || null,
      data.channel || 0,
      data.width_mhz || 0,
      data.rssi_dbm || 0,
      data.noise_dbm || 0,
      data.snr_db || 0,
      data.tx_rate_mbps || 0,
      data.mcs_index ?? -1,
      data.spatial_streams || 0,
      data.latency_ms || 0,
      data.jitter_ms || 0,
      data.jitter_p50 || 0,
      data.jitter_p95 || 0,
      data.packet_loss_pct || 0,
      data.download_mbps || 0,
      data.upload_mbps || 0,
      data.vpn_status || 'disconnected',
      data.vpn_name || 'none',
      data.input_errors || 0,
      data.output_errors || 0,
      data.input_error_rate || 0,
      data.output_error_rate || 0,
      data.tcp_retransmits || 0,
      data.bssid_changed || 0,
      data.roam_count || 0,
      data.status || 'success',
      data.errors || null,
      typeof data === 'object' ? JSON.stringify(data) : null
    ]);

    // v2.1: Record BSSID change as connection event
    if (data.bssid_changed === 1 || data.bssid_changed === true) {
      await pool.query(`
        INSERT INTO connection_events (device_id, event_type, timestamp_utc, ssid, bssid, channel, band, rssi_dbm)
        VALUES ($1, 'roam', $2, $3, $4, $5, $6, $7)
      `, [data.device_id, data.timestamp_utc || new Date().toISOString(),
          data.ssid, data.bssid, data.channel || 0, data.band, data.rssi_dbm || 0]);
    }

    // v3.0: Check alerts and anomalies asynchronously
    checkAlerts(data).catch(err => console.error('Alert check error:', err));

    // Update device baseline periodically (every 10th test)
    const testCount = await pool.query('SELECT COUNT(*) as count FROM speed_results WHERE device_id = $1', [data.device_id]);
    if (parseInt(testCount.rows[0].count) % 10 === 0) {
      updateBaseline(data.device_id);
    }

    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error inserting result:', err);
    res.status(500).json({ error: 'Failed to save result' });
  }
});

// API: Get version info
app.get('/api/version', (req, res) => {
  res.json({
    version: APP_VERSION,
    components: {
      server: APP_VERSION,
      min_client: '3.0.0'
    }
  });
});

// Serve installer .command file (opens Terminal on macOS when clicked)
app.get('/install.command', (req, res) => {
  const script = `#!/bin/bash
# Speed Monitor Installer
# This file opens Terminal and runs the installer

clear
echo "==========================================="
echo "   Speed Monitor - One-Click Installer"
echo "==========================================="
echo ""

# Run the actual installer
curl -fsSL https://raw.githubusercontent.com/hyperkishore/home-internet/main/dist/install.sh | bash

echo ""
echo "==========================================="
echo "   Installation complete!"
echo "   You can close this window."
echo "==========================================="
read -p "Press Enter to close..."
`;

  res.setHeader('Content-Type', 'application/x-sh');
  res.setHeader('Content-Disposition', 'attachment; filename="SpeedMonitor-Install.command"');
  res.send(script);
});

// API: Get all results (with pagination)
app.get('/api/results', async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 1000);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const device_id = req.query.device_id;
  const ssid = req.query.ssid;
  const vpn_status = req.query.vpn_status;

  try {
    let query = 'SELECT * FROM speed_results WHERE 1=1';
    let params = [];
    let paramIndex = 1;

    if (device_id) {
      query += ` AND device_id = $${paramIndex++}`;
      params.push(device_id);
    }
    if (ssid) {
      query += ` AND ssid = $${paramIndex++}`;
      params.push(ssid);
    }
    if (vpn_status) {
      query += ` AND vpn_status = $${paramIndex++}`;
      params.push(vpn_status);
    }

    query += ` ORDER BY timestamp_utc DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(limit, offset);

    const results = await pool.query(query, params);
    res.json(results.rows);
  } catch (err) {
    console.error('Error fetching results:', err);
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

// API: Get aggregated stats
app.get('/api/stats', async (req, res) => {
  try {
    // Overall stats
    const overall = await pool.query(`
      SELECT
        COUNT(*) as total_tests,
        COUNT(DISTINCT device_id) as total_devices,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(packet_loss_pct)::numeric, 2) as avg_packet_loss,
        ROUND(MIN(download_mbps)::numeric, 2) as min_download,
        ROUND(MAX(download_mbps)::numeric, 2) as max_download
      FROM speed_results
      WHERE status LIKE 'success%'
    `);

    // Per-device stats
    const perDevice = await pool.query(`
      SELECT
        device_id,
        MAX(user_email) as user_email,
        MAX(hostname) as hostname,
        MAX(os_version) as os_version,
        MAX(app_version) as app_version,
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        MAX(timestamp_utc) as last_test,
        MAX(vpn_status) as vpn_status,
        MAX(vpn_name) as vpn_name
      FROM speed_results
      WHERE status LIKE 'success%'
      GROUP BY device_id
      ORDER BY last_test DESC
    `);

    // Hourly trends (last 24 hours)
    const hourly = await pool.query(`
      SELECT
        to_char(timestamp_utc, 'YYYY-MM-DD HH24:00') as hour,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        COUNT(*) as test_count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '24 hours'
      GROUP BY hour
      ORDER BY hour
    `);

    res.json({ overall: overall.rows[0], perDevice: perDevice.rows, hourly: hourly.rows });
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// API: WiFi/Access Point statistics
app.get('/api/stats/wifi', async (req, res) => {
  try {
    // Stats by access point (BSSID)
    const byAccessPoint = await pool.query(`
      SELECT
        bssid,
        MAX(ssid) as ssid,
        MAX(band) as band,
        MAX(channel) as channel,
        COUNT(*) as test_count,
        COUNT(DISTINCT device_id) as device_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(packet_loss_pct)::numeric, 2) as avg_packet_loss
      FROM speed_results
      WHERE status LIKE 'success%' AND bssid IS NOT NULL AND bssid != 'none'
      GROUP BY bssid
      ORDER BY test_count DESC
    `);

    // Stats by SSID
    const bySSID = await pool.query(`
      SELECT
        ssid,
        COUNT(*) as test_count,
        COUNT(DISTINCT device_id) as device_count,
        COUNT(DISTINCT bssid) as ap_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi
      FROM speed_results
      WHERE status LIKE 'success%' AND ssid IS NOT NULL
      GROUP BY ssid
      ORDER BY test_count DESC
    `);

    // Band distribution
    const bandDistribution = await pool.query(`
      SELECT
        band,
        COUNT(*) as count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download
      FROM speed_results
      WHERE status LIKE 'success%' AND band IS NOT NULL AND band != 'none'
      GROUP BY band
    `);

    // Add AP names to the byAccessPoint results using prefix matching
    const byAccessPointWithNames = byAccessPoint.rows.map(ap => ({
      ...ap,
      ap_name: lookupAPName(ap.bssid)
    }));

    res.json({ byAccessPoint: byAccessPointWithNames, bySSID: bySSID.rows, bandDistribution: bandDistribution.rows });
  } catch (err) {
    console.error('Error fetching WiFi stats:', err);
    res.status(500).json({ error: 'Failed to fetch WiFi stats' });
  }
});

// API: VPN statistics
app.get('/api/stats/vpn', async (req, res) => {
  try {
    // VPN usage distribution
    const distribution = await pool.query(`
      SELECT
        vpn_status,
        vpn_name,
        COUNT(*) as count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter
      FROM speed_results
      WHERE status LIKE 'success%'
      GROUP BY vpn_status, vpn_name
      ORDER BY count DESC
    `);

    // VPN vs non-VPN comparison
    const comparison = await pool.query(`
      SELECT
        CASE WHEN vpn_status = 'connected' THEN 'VPN On' ELSE 'VPN Off' END as mode,
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(packet_loss_pct)::numeric, 2) as avg_packet_loss
      FROM speed_results
      WHERE status LIKE 'success%'
      GROUP BY mode
    `);

    res.json({ distribution: distribution.rows, comparison: comparison.rows });
  } catch (err) {
    console.error('Error fetching VPN stats:', err);
    res.status(500).json({ error: 'Failed to fetch VPN stats' });
  }
});

// API: Jitter distribution
app.get('/api/stats/jitter', async (req, res) => {
  try {
    const distribution = await pool.query(`
      SELECT
        CASE
          WHEN jitter_ms < 5 THEN '< 5ms'
          WHEN jitter_ms < 10 THEN '5-10ms'
          WHEN jitter_ms < 20 THEN '10-20ms'
          WHEN jitter_ms < 50 THEN '20-50ms'
          ELSE '> 50ms'
        END as jitter_range,
        COUNT(*) as count
      FROM speed_results
      WHERE status LIKE 'success%' AND jitter_ms IS NOT NULL
      GROUP BY jitter_range
      ORDER BY MIN(jitter_ms)
    `);

    // Devices with high jitter
    const problemDevices = await pool.query(`
      SELECT
        device_id,
        MAX(hostname) as hostname,
        MAX(user_email) as user_email,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        COUNT(*) as test_count
      FROM speed_results
      WHERE status LIKE 'success%'
      GROUP BY device_id
      HAVING AVG(jitter_ms) > 20
      ORDER BY avg_jitter DESC
      LIMIT 10
    `);

    // Calculate median jitter
    const medianResult = await pool.query(`
      SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY jitter_ms) as median_jitter
      FROM speed_results
      WHERE status LIKE 'success%' AND jitter_ms IS NOT NULL
    `);

    res.json({
      distribution: distribution.rows,
      problemDevices: problemDevices.rows,
      median_jitter: medianResult.rows[0]?.median_jitter || 0
    });
  } catch (err) {
    console.error('Error fetching jitter stats:', err);
    res.status(500).json({ error: 'Failed to fetch jitter stats' });
  }
});

// API: Speed timeline (for charts)
app.get('/api/stats/timeline', async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours) || 24, 168);

  try {
    const timeline = await pool.query(`
      SELECT
        to_char(timestamp_utc, 'YYYY-MM-DD HH24:00') as hour,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        COUNT(*) as test_count,
        COUNT(DISTINCT device_id) as device_count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '1 hour' * $1
      GROUP BY hour
      ORDER BY hour
    `, [hours]);

    res.json(timeline.rows);
  } catch (err) {
    console.error('Error fetching timeline:', err);
    res.status(500).json({ error: 'Failed to fetch timeline' });
  }
});

// API: Get device health (for employee self-service)
app.get('/api/devices/:device_id/health', async (req, res) => {
  const { device_id } = req.params;

  try {
    // Get recent stats
    const stats = await pool.query(`
      SELECT
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(packet_loss_pct)::numeric, 2) as avg_packet_loss,
        MAX(timestamp_utc) as last_test,
        MAX(ssid) as ssid,
        MAX(vpn_status) as vpn_status
      FROM speed_results
      WHERE device_id = $1
        AND timestamp_utc > NOW() - INTERVAL '24 hours'
    `, [device_id]);

    // Get recent tests
    const recentTests = await pool.query(`
      SELECT *
      FROM speed_results
      WHERE device_id = $1
      ORDER BY timestamp_utc DESC
      LIMIT 10
    `, [device_id]);

    // Calculate health score
    const s = stats.rows[0];
    let healthScore = 100;
    if (s.avg_download < 10) healthScore -= 30;
    else if (s.avg_download < 25) healthScore -= 15;
    if (s.avg_jitter > 50) healthScore -= 30;
    else if (s.avg_jitter > 20) healthScore -= 15;
    if (s.avg_packet_loss > 2) healthScore -= 20;
    else if (s.avg_packet_loss > 0.5) healthScore -= 10;

    res.json({
      stats: s,
      recentTests: recentTests.rows,
      healthScore: Math.max(0, healthScore)
    });
  } catch (err) {
    console.error('Error fetching device health:', err);
    res.status(500).json({ error: 'Failed to fetch device health' });
  }
});

// API: ISP lookup
async function lookupISP(publicIp) {
  if (!publicIp) return null;

  try {
    // Check cache first
    const cached = await pool.query(
      'SELECT * FROM isp_cache WHERE public_ip = $1',
      [publicIp]
    );

    if (cached.rows.length > 0) {
      return cached.rows[0];
    }

    // Fetch from ip-api.com (free tier: 45 req/min)
    const https = require('https');
    return new Promise((resolve) => {
      https.get(`https://ip-api.com/json/${publicIp}`, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', async () => {
          try {
            const json = JSON.parse(data);
            if (json.status === 'success') {
              // Cache the result
              await pool.query(`
                INSERT INTO isp_cache (public_ip, isp_name, isp_org, city, region, country, cached_at)
                VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
                ON CONFLICT (public_ip) DO UPDATE SET
                  isp_name = EXCLUDED.isp_name,
                  isp_org = EXCLUDED.isp_org,
                  city = EXCLUDED.city,
                  region = EXCLUDED.region,
                  country = EXCLUDED.country,
                  cached_at = CURRENT_TIMESTAMP
              `, [publicIp, json.isp, json.org, json.city, json.regionName, json.country]);

              resolve({
                isp_name: json.isp,
                isp_org: json.org,
                city: json.city,
                region: json.regionName,
                country: json.country
              });
            } else {
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
      }).on('error', () => resolve(null));
    });
  } catch (err) {
    console.error('ISP lookup error:', err);
    return null;
  }
}

// Update device baseline for anomaly detection
async function updateBaseline(deviceId) {
  try {
    const stats = await pool.query(`
      SELECT
        AVG(download_mbps) as avg_download,
        AVG(upload_mbps) as avg_upload,
        AVG(jitter_ms) as avg_jitter,
        STDDEV(download_mbps) as stddev_download,
        STDDEV(upload_mbps) as stddev_upload,
        STDDEV(jitter_ms) as stddev_jitter,
        COUNT(*) as sample_count
      FROM speed_results
      WHERE device_id = $1
        AND status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '7 days'
    `, [deviceId]);

    const s = stats.rows[0];
    if (s && s.sample_count >= 5) {
      await pool.query(`
        INSERT INTO device_baselines (device_id, baseline_download, baseline_upload, baseline_jitter,
          stddev_download, stddev_upload, stddev_jitter, sample_count, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
        ON CONFLICT (device_id) DO UPDATE SET
          baseline_download = EXCLUDED.baseline_download,
          baseline_upload = EXCLUDED.baseline_upload,
          baseline_jitter = EXCLUDED.baseline_jitter,
          stddev_download = EXCLUDED.stddev_download,
          stddev_upload = EXCLUDED.stddev_upload,
          stddev_jitter = EXCLUDED.stddev_jitter,
          sample_count = EXCLUDED.sample_count,
          last_updated = CURRENT_TIMESTAMP
      `, [deviceId, s.avg_download, s.avg_upload, s.avg_jitter,
          s.stddev_download || 0, s.stddev_upload || 0, s.stddev_jitter || 0, s.sample_count]);
    }
  } catch (err) {
    console.error('Error updating baseline:', err);
  }
}

// Check for alerts and anomalies
async function checkAlerts(data) {
  try {
    // Get alert configs
    const configs = await pool.query(
      'SELECT * FROM alert_configs WHERE enabled = 1'
    );

    for (const config of configs.rows) {
      let triggered = false;
      let message = '';

      if (config.threshold_download_mbps && data.download_mbps < config.threshold_download_mbps) {
        triggered = true;
        message = `Low download speed: ${data.download_mbps} Mbps (threshold: ${config.threshold_download_mbps} Mbps)`;
      }
      if (config.threshold_jitter_ms && data.jitter_ms > config.threshold_jitter_ms) {
        triggered = true;
        message += (message ? '; ' : '') + `High jitter: ${data.jitter_ms} ms (threshold: ${config.threshold_jitter_ms} ms)`;
      }
      if (config.threshold_packet_loss_pct && data.packet_loss_pct > config.threshold_packet_loss_pct) {
        triggered = true;
        message += (message ? '; ' : '') + `High packet loss: ${data.packet_loss_pct}% (threshold: ${config.threshold_packet_loss_pct}%)`;
      }

      if (triggered) {
        // Log alert
        await pool.query(`
          INSERT INTO alert_history (alert_config_id, device_id, alert_type, message, severity)
          VALUES ($1, $2, 'Threshold Exceeded', $3, 'warning')
        `, [config.id, data.device_id, message]);

        // Send webhook if configured
        if (config.webhook_url) {
          sendWebhook(config, data, message);
        }
      }
    }

    // Check for anomalies using z-score
    const baseline = await pool.query(
      'SELECT * FROM device_baselines WHERE device_id = $1',
      [data.device_id]
    );

    if (baseline.rows.length > 0) {
      const b = baseline.rows[0];
      const downloadZScore = b.stddev_download > 0
        ? (b.baseline_download - data.download_mbps) / b.stddev_download
        : 0;

      if (downloadZScore > 2) {
        await pool.query(`
          INSERT INTO alert_history (device_id, alert_type, message, severity)
          VALUES ($1, 'Anomaly Detected', $2, 'info')
        `, [data.device_id, `Download speed anomaly: ${data.download_mbps} Mbps (baseline: ${b.baseline_download?.toFixed(1)} Mbps, z-score: ${downloadZScore.toFixed(2)})`]);
      }
    }
  } catch (err) {
    console.error('Alert check error:', err);
  }
}

// Send webhook notification
function sendWebhook(config, data, message) {
  const https = require('https');
  const url = new URL(config.webhook_url);

  let payload;
  if (config.type === 'slack') {
    payload = JSON.stringify({
      text: `Speed Monitor Alert`,
      blocks: [
        { type: 'header', text: { type: 'plain_text', text: 'Speed Monitor Alert' } },
        { type: 'section', text: { type: 'mrkdwn', text: `*Device:* ${data.device_id}\n*Message:* ${message}` } }
      ]
    });
  } else {
    payload = JSON.stringify({ text: `Speed Monitor Alert: ${message} (Device: ${data.device_id})` });
  }

  const options = {
    hostname: url.hostname,
    port: 443,
    path: url.pathname + url.search,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
  };

  const req = https.request(options);
  req.on('error', err => console.error('Webhook error:', err));
  req.write(payload);
  req.end();
}

// API: Get employee dashboard data
app.get('/api/my/:email', async (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase();

  try {
    // Find devices for this email
    const devices = await pool.query(`
      SELECT DISTINCT device_id, MAX(hostname) as hostname, MAX(timestamp_utc) as last_seen
      FROM speed_results
      WHERE LOWER(user_email) = $1
      GROUP BY device_id
      ORDER BY last_seen DESC
    `, [email]);

    if (devices.rows.length === 0) {
      return res.json({ found: false, email });
    }

    const deviceIds = devices.rows.map(d => d.device_id);

    // Get recent stats
    const stats = await pool.query(`
      SELECT
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(packet_loss_pct)::numeric, 2) as avg_packet_loss,
        MAX(timestamp_utc) as last_test
      FROM speed_results
      WHERE device_id = ANY($1)
        AND timestamp_utc > NOW() - INTERVAL '24 hours'
    `, [deviceIds]);

    // Get timeline for chart
    const timeline = await pool.query(`
      SELECT
        to_char(timestamp_utc, 'YYYY-MM-DD HH24:00') as hour,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        COUNT(*) as test_count
      FROM speed_results
      WHERE device_id = ANY($1)
        AND timestamp_utc > NOW() - INTERVAL '24 hours'
      GROUP BY hour
      ORDER BY hour
    `, [deviceIds]);

    // Get recent tests
    const recentTests = await pool.query(`
      SELECT * FROM speed_results
      WHERE device_id = ANY($1)
      ORDER BY timestamp_utc DESC
      LIMIT 10
    `, [deviceIds]);

    // Calculate health score
    const s = stats.rows[0];
    let healthScore = 100;
    let issues = [];

    if (parseFloat(s.avg_download) < 10) {
      healthScore -= 30;
      issues.push('Very slow download speed');
    } else if (parseFloat(s.avg_download) < 25) {
      healthScore -= 15;
      issues.push('Below average download speed');
    }
    if (parseFloat(s.avg_jitter) > 50) {
      healthScore -= 30;
      issues.push('Very high jitter - video calls may be affected');
    } else if (parseFloat(s.avg_jitter) > 20) {
      healthScore -= 15;
      issues.push('High jitter');
    }
    if (parseFloat(s.avg_packet_loss) > 2) {
      healthScore -= 20;
      issues.push('High packet loss');
    }

    // Generate recommendations
    const recommendations = [];
    if (parseFloat(s.avg_download) < 25) {
      recommendations.push('Try moving closer to your WiFi router');
      recommendations.push('Check if others are using bandwidth-heavy applications');
    }
    if (parseFloat(s.avg_jitter) > 20) {
      recommendations.push('Restart your router');
      recommendations.push('Try using 5GHz WiFi instead of 2.4GHz');
    }

    res.json({
      found: true,
      email,
      devices: devices.rows,
      stats: s,
      timeline: timeline.rows,
      recentTests: recentTests.rows,
      healthScore: Math.max(0, healthScore),
      issues,
      recommendations
    });
  } catch (err) {
    console.error('Error fetching employee data:', err);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

// API: Alert configuration
app.post('/api/alerts/config', async (req, res) => {
  const { name, type, webhook_url, channel_name, threshold_download_mbps, threshold_jitter_ms, threshold_packet_loss_pct } = req.body;

  if (!name || !type || !webhook_url) {
    return res.status(400).json({ error: 'name, type, and webhook_url are required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO alert_configs (name, type, webhook_url, channel_name, threshold_download_mbps, threshold_jitter_ms, threshold_packet_loss_pct)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `, [name, type, webhook_url, channel_name, threshold_download_mbps, threshold_jitter_ms, threshold_packet_loss_pct]);

    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error creating alert config:', err);
    res.status(500).json({ error: 'Failed to create alert config' });
  }
});

app.get('/api/alerts/config', async (req, res) => {
  try {
    const configs = await pool.query('SELECT * FROM alert_configs ORDER BY created_at DESC');
    res.json(configs.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alert configs' });
  }
});

app.get('/api/alerts/history', async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  try {
    const history = await pool.query(`
      SELECT * FROM alert_history
      WHERE triggered_at > NOW() - INTERVAL '1 hour' * $1
      ORDER BY triggered_at DESC
      LIMIT 100
    `, [hours]);
    res.json(history.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alert history' });
  }
});

// API: User feedback
app.post('/api/feedback', async (req, res) => {
  const { email, message, terminal_output } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'message is required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO user_feedback (email, message, terminal_output, user_agent)
      VALUES ($1, $2, $3, $4)
      RETURNING id
    `, [email || null, message, terminal_output || null, req.get('user-agent')]);

    console.log(`Feedback received: id=${result.rows[0].id}, email=${email || 'anonymous'}`);
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error saving feedback:', err);
    res.status(500).json({ error: 'Failed to save feedback' });
  }
});

// API: Device diagnostics
app.post('/api/diagnostics', async (req, res) => {
  const data = req.body;

  if (!data.device_id) {
    return res.status(400).json({ error: 'device_id is required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO device_diagnostics (
        device_id, user_email, hostname, app_version, script_version, os_version,
        launchd_status, speedtest_installed, speedtest_path, error_log, last_test_result,
        network_interfaces, wifi_info
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id
    `, [
      data.device_id, data.user_email, data.hostname, data.app_version, data.script_version,
      data.os_version, data.launchd_status, data.speedtest_installed ? 1 : 0, data.speedtest_path,
      data.error_log, data.last_test_result, data.network_interfaces, data.wifi_info
    ]);

    console.log(`Diagnostics received: device=${data.device_id}, id=${result.rows[0].id}`);
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error saving diagnostics:', err);
    res.status(500).json({ error: 'Failed to save diagnostics' });
  }
});

app.get('/api/diagnostics/:device_id', async (req, res) => {
  const { device_id } = req.params;

  try {
    const diagnostics = await pool.query(`
      SELECT * FROM device_diagnostics
      WHERE device_id = $1
      ORDER BY submitted_at DESC
      LIMIT 10
    `, [device_id]);

    res.json(diagnostics.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch diagnostics' });
  }
});

// API: ISP statistics
app.get('/api/stats/isp', async (req, res) => {
  try {
    const ispStats = await pool.query(`
      SELECT
        c.isp_name,
        c.city,
        COUNT(DISTINCT r.device_id) as device_count,
        COUNT(*) as test_count,
        ROUND(AVG(r.download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(r.upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(r.latency_ms)::numeric, 2) as avg_latency
      FROM speed_results r
      JOIN isp_cache c ON r.public_ip = c.public_ip
      WHERE r.status LIKE 'success%'
        AND r.timestamp_utc > NOW() - INTERVAL '7 days'
      GROUP BY c.isp_name, c.city
      ORDER BY test_count DESC
    `);

    res.json(ispStats.rows);
  } catch (err) {
    console.error('Error fetching ISP stats:', err);
    res.status(500).json({ error: 'Failed to fetch ISP stats' });
  }
});

// API: Time of day analysis
app.get('/api/stats/timeofday', async (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 90);

  try {
    const hourlyStats = await pool.query(`
      SELECT
        EXTRACT(HOUR FROM timestamp_utc)::integer as hour,
        EXTRACT(DOW FROM timestamp_utc)::integer as day_of_week,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        COUNT(*) as test_count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '1 day' * $1
      GROUP BY hour, day_of_week
      ORDER BY day_of_week, hour
    `, [days]);

    res.json(hourlyStats.rows);
  } catch (err) {
    console.error('Error fetching time of day stats:', err);
    res.status(500).json({ error: 'Failed to fetch time of day stats' });
  }
});

// API: Historical trends
app.get('/api/stats/trends', async (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 90);

  try {
    const dailyTrends = await pool.query(`
      SELECT
        DATE(timestamp_utc) as date,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        COUNT(*) as test_count,
        COUNT(DISTINCT device_id) as device_count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '1 day' * $1
      GROUP BY DATE(timestamp_utc)
      ORDER BY date
    `, [days]);

    res.json(dailyTrends.rows);
  } catch (err) {
    console.error('Error fetching trends:', err);
    res.status(500).json({ error: 'Failed to fetch trends' });
  }
});

// API: WiFi recommendations
app.get('/api/recommendations/wifi', async (req, res) => {
  try {
    // Get AP performance comparison
    const apPerformance = await pool.query(`
      SELECT
        bssid,
        MAX(ssid) as ssid,
        MAX(band) as band,
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi
      FROM speed_results
      WHERE status LIKE 'success%'
        AND bssid IS NOT NULL
        AND bssid != 'none'
        AND timestamp_utc > NOW() - INTERVAL '7 days'
      GROUP BY bssid
      HAVING COUNT(*) >= 5
      ORDER BY avg_download DESC
    `);

    // Get channel congestion
    const channelStats = await pool.query(`
      SELECT
        channel,
        band,
        COUNT(DISTINCT bssid) as ap_count,
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download
      FROM speed_results
      WHERE status LIKE 'success%'
        AND channel > 0
        AND timestamp_utc > NOW() - INTERVAL '7 days'
      GROUP BY channel, band
      ORDER BY band, channel
    `);

    // Generate recommendations
    const recommendations = [];

    // Check for 2.4GHz vs 5GHz performance
    const bandPerf = await pool.query(`
      SELECT
        band,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        COUNT(*) as test_count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND band IS NOT NULL
        AND band != 'none'
        AND timestamp_utc > NOW() - INTERVAL '7 days'
      GROUP BY band
    `);

    const band5 = bandPerf.rows.find(b => b.band === '5GHz');
    const band24 = bandPerf.rows.find(b => b.band === '2.4GHz');

    if (band5 && band24 && parseFloat(band5.avg_download) > parseFloat(band24.avg_download) * 1.5) {
      recommendations.push({
        type: 'band_switch',
        priority: 'high',
        message: `5GHz WiFi is ${((parseFloat(band5.avg_download) / parseFloat(band24.avg_download) - 1) * 100).toFixed(0)}% faster. Encourage users to connect to 5GHz networks.`
      });
    }

    res.json({
      apPerformance: apPerformance.rows.map(ap => ({ ...ap, ap_name: lookupAPName(ap.bssid) })),
      channelStats: channelStats.rows,
      bandPerformance: bandPerf.rows,
      recommendations
    });
  } catch (err) {
    console.error('Error generating WiFi recommendations:', err);
    res.status(500).json({ error: 'Failed to generate recommendations' });
  }
});

// API: Device troubleshooting
app.get('/api/devices/:device_id/troubleshoot', async (req, res) => {
  const { device_id } = req.params;

  try {
    // Get recent device stats
    const stats = await pool.query(`
      SELECT
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi,
        MAX(vpn_status) as vpn_status,
        MAX(band) as band,
        COUNT(*) as test_count
      FROM speed_results
      WHERE device_id = $1
        AND timestamp_utc > NOW() - INTERVAL '24 hours'
    `, [device_id]);

    const s = stats.rows[0];
    const issues = [];
    const recommendations = [];

    // Analyze issues
    if (parseFloat(s.avg_download) < 10) {
      issues.push({ severity: 'high', message: 'Very slow download speed' });
      recommendations.push('Check if multiple devices are using the network');
      recommendations.push('Try restarting your router');
    }

    if (parseFloat(s.avg_rssi) < -70) {
      issues.push({ severity: 'medium', message: 'Weak WiFi signal' });
      recommendations.push('Move closer to the WiFi router');
      recommendations.push('Check for physical obstructions between your device and the router');
    }

    if (parseFloat(s.avg_jitter) > 30) {
      issues.push({ severity: 'medium', message: 'High jitter affecting call quality' });
      recommendations.push('Try using a wired Ethernet connection for important calls');
    }

    if (s.band === '2.4GHz') {
      recommendations.push('Consider switching to 5GHz WiFi for better performance');
    }

    if (s.vpn_status !== 'connected') {
      recommendations.push('Connect to VPN for secure access to company resources');
    }

    res.json({
      stats: s,
      issues,
      recommendations,
      overallHealth: issues.filter(i => i.severity === 'high').length === 0 ? 'good' : 'needs_attention'
    });
  } catch (err) {
    console.error('Error generating troubleshooting:', err);
    res.status(500).json({ error: 'Failed to generate troubleshooting' });
  }
});

// Device Data Export (CSV)
app.get('/api/devices/:device_id/export', async (req, res) => {
  const { device_id } = req.params;
  const days = Math.min(parseInt(req.query.days) || 30, 90);

  try {
    const results = await pool.query(`
      SELECT * FROM speed_results
      WHERE device_id = $1
        AND timestamp_utc > NOW() - INTERVAL '1 day' * $2
      ORDER BY timestamp_utc DESC
    `, [device_id, days]);

    if (results.rows.length === 0) {
      return res.status(404).json({ error: 'No data found for device' });
    }

    // Generate CSV
    const headers = Object.keys(results.rows[0]).join(',');
    const rows = results.rows.map(r => Object.values(r).map(v =>
      typeof v === 'string' && v.includes(',') ? `"${v}"` : v
    ).join(','));

    const csv = [headers, ...rows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=speed_monitor_${device_id.substring(0, 8)}_${days}d.csv`);
    res.send(csv);
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// Anomaly Detection Status
app.get('/api/anomalies', async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;

  try {
    const recentAlerts = await pool.query(`
      SELECT * FROM alert_history
      WHERE alert_type = 'Anomaly Detected'
        AND triggered_at > NOW() - INTERVAL '1 hour' * $1
      ORDER BY triggered_at DESC
    `, [hours]);

    const baselines = await pool.query(`
      SELECT * FROM device_baselines
      ORDER BY last_updated DESC
      LIMIT 50
    `);

    res.json({ recentAnomalies: recentAlerts.rows, baselines: baselines.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch anomaly data' });
  }
});

// Cloudflare status API - Filter for significant outages only
app.get('/api/cloudflare-status', async (req, res) => {
  const https = require('https');

  const fetchWithTimeout = (url, timeout = 5000) => {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timeout')), timeout);
      https.get(url, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => {
          clearTimeout(timer);
          resolve(data);
        });
      }).on('error', err => {
        clearTimeout(timer);
        reject(err);
      });
    });
  };

  try {
    const data = await fetchWithTimeout('https://www.cloudflarestatus.com/api/v2/summary.json');
    const status = JSON.parse(data);

    // Filter components for significant outages only
    const significantStatuses = ['major_outage', 'partial_outage'];
    const affectedComponents = status.components
      .filter(c => significantStatuses.includes(c.status))
      .map(c => ({ name: c.name, status: c.status }));

    // Only include incidents that are actually impacting services
    const activeIncidents = (status.incidents || [])
      .filter(i => i.status !== 'resolved' && i.impact !== 'none')
      .map(i => ({
        name: i.name,
        status: i.status,
        impact: i.impact,
        created_at: i.created_at
      }));

    res.json({
      status: affectedComponents.length > 0 ? 'degraded' : 'operational',
      affectedComponents,
      activeIncidents,
      lastUpdated: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch Cloudflare status' });
  }
});

// Employee self-service portal landing page
app.get('/my', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'my.html'));
});

// Employee self-service portal by email
app.get('/my/:email', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'my-employee.html'));
});

// Self-service portal route (by device ID - for IT admins)
app.get('/device/:device_id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'my-device.html'));
});

// Serve setup/installation guide
app.get('/setup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Health check
app.get('/health', async (req, res) => {
  try {
    const count = await pool.query('SELECT COUNT(*) as count FROM speed_results');
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: APP_VERSION,
      database: 'postgresql',
      features: ['wifi_debugging', 'mcs_tracking', 'error_rates', 'roaming_detection'],
      total_results: parseInt(count.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  console.error('Stack:', err.stack);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// Handle uncaught promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.listen(PORT, () => {
  console.log(`Speed Monitor Server v${APP_VERSION} running on port ${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`API: http://localhost:${PORT}/api`);
});
