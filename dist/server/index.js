const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pgSession = require('connect-pg-simple')(session);

const APP_VERSION = "3.1.45";

// Admin authentication configuration
// Credentials stored securely in environment variables (never hardcode!)
// To generate password hash: node -e "console.log(require('crypto').createHash('sha256').update('YOUR_PASSWORD').digest('hex'))"
const ADMIN_CONFIG = {
  username: process.env.ADMIN_USERNAME,
  passwordHash: process.env.ADMIN_PASSWORD_HASH  // Pre-computed SHA-256 hash
};

// Validate admin credentials are configured at startup
if (!ADMIN_CONFIG.username || !ADMIN_CONFIG.passwordHash) {
  console.warn('⚠️  WARNING: Admin credentials not configured');
  console.warn('   Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH environment variables');
  console.warn('   Generate hash: node -e "console.log(require(\'crypto\').createHash(\'sha256\').update(\'password\').digest(\'hex\'))"');
}

// Google OAuth configuration
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || 'hyperverge.co';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const GOOGLE_AUTH_ENABLED = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;

if (!GOOGLE_AUTH_ENABLED) {
  console.warn('⚠️  WARNING: Google OAuth not configured');
  console.warn('   Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and SESSION_SECRET');
  console.warn('   Dashboard will be publicly accessible until OAuth is configured');
}

// Generate a secure session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Verify admin session (database-backed for persistence across restarts)
async function verifyAdminSession(token) {
  if (!token) return false;
  try {
    const result = await pool.query(
      'SELECT username FROM admin_sessions WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (err) {
    console.error('Error verifying admin session:', err);
    return null;
  }
}

// Clean up expired sessions periodically
async function cleanupExpiredSessions() {
  try {
    await pool.query('DELETE FROM admin_sessions WHERE expires_at < NOW()');
  } catch (err) {
    console.error('Error cleaning up sessions:', err);
  }
}
setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Clean up every hour

// Middleware to require admin authentication
async function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '');

  const session = await verifyAdminSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  req.adminUser = session.username;
  next();
}

// AP name mapping based on BSSID prefix (first 5 bytes) to handle multiple virtual APs
const AP_PREFIX_MAP = {
  // Old APs (a8:ba:25 prefix)
  'a8:ba:25:ce:a4:d': '2F-AP_1', 'a8:ba:25:6a:4d': '2F-AP_1',   // 2F-AP_1
  'a8:ba:25:ce:a1:a': '2F-AP_2', 'a8:ba:25:6a:1a': '2F-AP_2',   // 2F-AP_2
  'a8:ba:25:ce:a1:2': '2F-AP_3', 'a8:ba:25:6a:12': '2F-AP_3',   // 2F-AP_3
  'a8:ba:25:ce:a2:3': '2F-AP_4', 'a8:ba:25:6a:23': '2F-AP_4',   // 2F-AP_4
  'a8:ba:25:ce:a3:e': '2F-AP_5', 'a8:ba:25:6a:3e': '2F-AP_5',   // 2F-AP_5
  'a8:ba:25:ce:a1:c': '3F-AP_5', 'a8:ba:25:6a:1c': '3F-AP_5',   // 3F-AP_5
  'a8:ba:25:ce:9f:5': '3F-AP-1', 'a8:ba:25:69:f5': '3F-AP-1',   // 3F-AP-1
  'a8:ba:25:ce:9f:0': '3F-AP-2', 'a8:ba:25:69:f0': '3F-AP-2',   // 3F-AP-2
  'a8:ba:25:ce:a4:6': '3F-AP-3', 'a8:ba:25:6a:46': '3F-AP-3',   // 3F-AP-3
  'a8:ba:25:ce:a4:e': '3F-AP-4', 'a8:ba:25:6a:4e': '3F-AP-4',   // 3F-AP-4

  // New APs (f0:61:c0 prefix) - HypervergeHQ / Hyperverge-Guest
  'f0:61:c0:bf:0d': 'CNP5K9T0L4',   // CNP5K9T0L4
  'f0:61:c0:be:d5': 'CNP5K9T0YP',   // CNP5K9T0YP
  'f0:61:c0:be:f1': 'CNP5K9T1XH',   // CNP5K9T1XH
  'f0:61:c0:c0:06': 'CNP5K9T2TP',   // CNP5K9T2TP
  'f0:61:c0:bf:c2': 'CNP5K9T3J7',   // CNP5K9T3J7

  // New APs (dc:b7:ac prefix) - HypervergeHQ / Hyperverge-Guest
  'dc:b7:ac:fc:d8': 'CNPWK9T1KL',   // CNPWK9T1KL
  'dc:b7:ac:fb:f2': 'CNPWK9T1M6',   // CNPWK9T1M6
  'dc:b7:ac:00:88': 'CNPYK9T3W2',   // CNPYK9T3W2
  'dc:b7:ac:01:03': 'CNPYK9T3X4',   // CNPYK9T3X4
  'dc:b7:ac:00:bd': 'CNPYK9T3XJ',   // CNPYK9T3XJ

  // AP21 devices (54:f0:b1 prefix) - HypervergeHQ / Hyperverge-Guest
  '54:f0:b1:07:c2': '2F AP-3',      // 2F AP-3 (2.4G: c0, 5G: d0)
  '54:f0:b1:02:98': '2F-AP-1',      // 2F-AP-1 (2.4G: 20, 5G: 30)
  '54:f0:b1:02:79': '3F AP-2',      // 3F AP-2 (2.4G: a0, 5G: b0)
  '54:f0:b1:02:53': 'VNTTM1K0DX'    // VNTTM1K0DX (2.4G: c0, 5G: d0)
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
    // Skip rate limiting for health checks and debug endpoints
    return req.path === '/health' || req.path.startsWith('/api/debug/');
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use('/api/', limiter);

// Note: Static files will be served after auth middleware is set up

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

// =============================================================================
// SESSION & GOOGLE OAUTH CONFIGURATION
// =============================================================================

// Session middleware (uses PostgreSQL for storage)
app.use(session({
  store: new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Google OAuth strategy (only if credentials are provided)
if (GOOGLE_AUTH_ENABLED) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback'
    },
    (accessToken, refreshToken, profile, done) => {
      const email = (profile.emails?.[0]?.value || '').toLowerCase();

      // Check domain restriction
      if (!email.endsWith(`@${ALLOWED_DOMAIN}`)) {
        return done(null, false, { message: 'Domain not allowed' });
      }

      // Check if user is admin (whitelisted for commands)
      const isAdmin = ADMIN_EMAILS.includes(email);

      return done(null, {
        id: profile.id,
        email,
        name: profile.displayName,
        picture: profile.photos?.[0]?.value,
        isAdmin
      });
    }
  ));

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  console.log(`Google OAuth configured for @${ALLOWED_DOMAIN} domain`);
  console.log(`Admin emails: ${ADMIN_EMAILS.length > 0 ? ADMIN_EMAILS.join(', ') : '(none configured)'}`);
}

// Middleware to require Google authentication
function requireGoogleAuth(req, res, next) {
  // Skip auth if Google OAuth is not configured
  if (!GOOGLE_AUTH_ENABLED) {
    return next();
  }

  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/google');
}

// Middleware to require admin (whitelisted Google users only)
function requireGoogleAdmin(req, res, next) {
  // Fall back to token-based auth if Google OAuth is not configured
  if (!GOOGLE_AUTH_ENABLED) {
    return requireAdmin(req, res, next);
  }

  if (req.isAuthenticated() && req.user.isAdmin) {
    return next();
  }
  res.status(403).json({ error: 'Admin access required. Contact IT to be added to the admin list.' });
}

// Serve static files (after auth middleware is configured)
app.use(express.static(path.join(__dirname, 'public')));

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

      -- Remote commands queue for push-based device control
      CREATE TABLE IF NOT EXISTS device_commands (
        id SERIAL PRIMARY KEY,
        device_id TEXT NOT NULL,           -- Target device (or 'all' for broadcast)
        command TEXT NOT NULL,             -- Command type: force_update, force_speedtest, restart_service
        payload TEXT,                      -- Optional JSON payload for command parameters
        status TEXT DEFAULT 'pending',     -- pending, acknowledged, executed, expired, failed
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        acknowledged_at TIMESTAMP,
        executed_at TIMESTAMP,
        result TEXT,                       -- Execution result or error message
        created_by TEXT                    -- Who issued the command (email/admin)
      );

      CREATE INDEX IF NOT EXISTS idx_commands_device_status ON device_commands(device_id, status);
      CREATE INDEX IF NOT EXISTS idx_commands_created ON device_commands(created_at);

      -- v3.1.43: Command execution logs for real-time progress tracking
      CREATE TABLE IF NOT EXISTS command_logs (
        id SERIAL PRIMARY KEY,
        command_id INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        level TEXT DEFAULT 'info',      -- info, warning, error, success
        message TEXT NOT NULL,
        metadata JSONB,
        FOREIGN KEY (command_id) REFERENCES device_commands(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_command_logs_command_id ON command_logs(command_id);
      CREATE INDEX IF NOT EXISTS idx_command_logs_timestamp ON command_logs(timestamp);

      -- v3.1.46: Admin sessions (persistent across server restarts)
      CREATE TABLE IF NOT EXISTS admin_sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

      -- Google OAuth user sessions (connect-pg-simple format)
      CREATE TABLE IF NOT EXISTS user_sessions (
        sid VARCHAR NOT NULL PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP(6) NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_user_sessions_expire ON user_sessions(expire);
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

// =============================================================================
// GOOGLE OAUTH ROUTES
// =============================================================================

// Start Google OAuth flow
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_AUTH_ENABLED) {
    return res.status(503).send('Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// Google OAuth callback
app.get('/auth/google/callback',
  (req, res, next) => {
    if (!GOOGLE_AUTH_ENABLED) {
      return res.redirect('/');
    }
    passport.authenticate('google', { failureRedirect: '/auth/denied' })(req, res, next);
  },
  (req, res) => res.redirect('/')
);

// Access denied page (wrong domain)
app.get('/auth/denied', (req, res) => {
  res.status(403).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Access Denied</title>
      <style>
        body { font-family: system-ui, -apple-system, sans-serif; padding: 40px; text-align: center; background: #0a0a0a; color: #fff; }
        h1 { color: #ef4444; }
        a { color: #3b82f6; }
      </style>
    </head>
    <body>
      <h1>Access Denied</h1>
      <p>Only @${ALLOWED_DOMAIN} email addresses can access this dashboard.</p>
      <p><a href="/auth/google">Try again with a different account</a></p>
    </body>
    </html>
  `);
});

// Logout
app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy((err) => {
      res.redirect('/auth/google');
    });
  });
});

// Get current authenticated user
app.get('/api/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      user: {
        email: req.user.email,
        name: req.user.name,
        picture: req.user.picture,
        isAdmin: req.user.isAdmin
      }
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
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

// ============================================================================
// ADMIN AUTHENTICATION API
// ============================================================================

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

  if (username === ADMIN_CONFIG.username && passwordHash === ADMIN_CONFIG.passwordHash) {
    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    try {
      await pool.query(
        'INSERT INTO admin_sessions (token, username, expires_at) VALUES ($1, $2, $3)',
        [token, username, expiresAt]
      );

      return res.json({
        success: true,
        token,
        username,
        expiresIn: '24h'
      });
    } catch (err) {
      console.error('Error creating session:', err);
      return res.status(500).json({ error: 'Failed to create session' });
    }
  }

  return res.status(401).json({ error: 'Invalid username or password' });
});

// Admin logout
app.post('/api/admin/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '');

  if (token) {
    try {
      await pool.query('DELETE FROM admin_sessions WHERE token = $1', [token]);
    } catch (err) {
      console.error('Error deleting session:', err);
    }
  }

  res.json({ success: true });
});

// Check admin session validity
app.get('/api/admin/session', async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '');

  const session = await verifyAdminSession(token);
  if (session) {
    return res.json({ valid: true, username: session.username });
  }

  return res.json({ valid: false });
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

    // Per-device stats with latest test values (VPN status, BSSID) using subquery
    // MAX(vpn_status) is wrong because alphabetically "disconnected" > "connected"
    // So we join with the latest test to get accurate VPN status and BSSID for AP name lookup
    const perDevice = await pool.query(`
      WITH device_stats AS (
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
          MAX(timestamp_utc) as last_test
        FROM speed_results
        WHERE status LIKE 'success%'
        GROUP BY device_id
      ),
      latest_tests AS (
        SELECT DISTINCT ON (device_id)
          device_id,
          download_mbps as latest_download,
          upload_mbps as latest_upload,
          latency_ms as latest_latency,
          jitter_ms as latest_jitter,
          packet_loss_pct as latest_packet_loss,
          vpn_status,
          vpn_name,
          bssid,
          ssid,
          band,
          channel,
          rssi_dbm,
          noise_dbm,
          snr_db,
          tx_rate_mbps,
          mcs_index,
          roam_count,
          input_error_rate,
          output_error_rate,
          tcp_retransmits,
          packet_loss_pct,
          public_ip,
          local_ip
        FROM speed_results
        WHERE status LIKE 'success%'
        ORDER BY device_id, timestamp_utc DESC
      )
      SELECT
        ds.*,
        lt.latest_download,
        lt.latest_upload,
        lt.latest_latency,
        lt.latest_jitter,
        lt.latest_packet_loss,
        lt.vpn_status,
        lt.vpn_name,
        lt.bssid,
        lt.ssid,
        lt.band,
        lt.channel,
        lt.rssi_dbm,
        lt.noise_dbm,
        lt.snr_db,
        lt.tx_rate_mbps,
        lt.mcs_index,
        lt.roam_count,
        lt.input_error_rate,
        lt.output_error_rate,
        lt.tcp_retransmits,
        lt.packet_loss_pct,
        lt.public_ip,
        lt.local_ip
      FROM device_stats ds
      LEFT JOIN latest_tests lt ON ds.device_id = lt.device_id
      ORDER BY ds.last_test DESC
    `);

    // Add AP names to perDevice results
    const perDeviceWithAPNames = perDevice.rows.map(device => ({
      ...device,
      ap_name: lookupAPName(device.bssid)
    }));

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

    res.json({ overall: overall.rows[0], perDevice: perDeviceWithAPNames, hourly: hourly.rows });
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
    const { days = 30 } = req.query;

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
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY vpn_status, vpn_name
      ORDER BY count DESC
    `);

    // VPN vs non-VPN comparison with averages
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
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY mode
    `);

    // Detailed percentile statistics for VPN analysis
    const percentiles = await pool.query(`
      SELECT
        vpn_status,
        COUNT(*) as sample_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as median_download,
        ROUND(PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as p25_download,
        ROUND(PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as p75_download,
        ROUND(PERCENTILE_CONT(0.1) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as p10_download,
        ROUND(PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as p90_download,
        ROUND(STDDEV(download_mbps)::numeric, 2) as stddev_download,
        ROUND(MIN(download_mbps)::numeric, 2) as min_download,
        ROUND(MAX(download_mbps)::numeric, 2) as max_download,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY upload_mbps)::numeric, 2) as median_upload,
        ROUND(PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY upload_mbps)::numeric, 2) as p25_upload,
        ROUND(PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY upload_mbps)::numeric, 2) as p75_upload,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latency_ms)::numeric, 2) as median_latency,
        ROUND(PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY latency_ms)::numeric, 2) as p25_latency,
        ROUND(PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY latency_ms)::numeric, 2) as p75_latency,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY jitter_ms)::numeric, 2) as median_jitter
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY vpn_status
    `);

    // Speed distribution buckets for comparison
    const speedBuckets = await pool.query(`
      SELECT
        vpn_status,
        CASE
          WHEN download_mbps < 10 THEN '< 10 Mbps'
          WHEN download_mbps < 25 THEN '10-25 Mbps'
          WHEN download_mbps < 50 THEN '25-50 Mbps'
          WHEN download_mbps < 100 THEN '50-100 Mbps'
          ELSE '> 100 Mbps'
        END as speed_bucket,
        COUNT(*) as count
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY vpn_status, speed_bucket
      ORDER BY vpn_status, MIN(download_mbps)
    `);

    // Time-of-day analysis for VPN
    const timeOfDay = await pool.query(`
      SELECT
        vpn_status,
        EXTRACT(HOUR FROM timestamp_utc) as hour,
        COUNT(*) as test_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY vpn_status, hour
      ORDER BY vpn_status, hour
    `);

    res.json({
      distribution: distribution.rows,
      comparison: comparison.rows,
      percentiles: percentiles.rows,
      speedBuckets: speedBuckets.rows,
      timeOfDay: timeOfDay.rows
    });
  } catch (err) {
    console.error('Error fetching VPN stats:', err);
    res.status(500).json({ error: 'Failed to fetch VPN stats' });
  }
});

// API: Combined Analytics with cross-dimensional filtering
app.get('/api/stats/analytics', async (req, res) => {
  try {
    const { days = 30, ssid, band, vpn, channel, ap, device } = req.query;

    // Build WHERE conditions
    let whereConditions = ["status LIKE 'success%'", `timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'`];
    if (ssid && ssid !== 'all') whereConditions.push(`ssid = '${ssid.replace(/'/g, "''")}'`);
    if (band && band !== 'all') whereConditions.push(`band = '${band.replace(/'/g, "''")}'`);
    if (vpn && vpn !== 'all') whereConditions.push(`vpn_status = '${vpn.replace(/'/g, "''")}'`);
    if (channel && channel !== 'all') whereConditions.push(`channel = ${parseInt(channel)}`);
    if (ap && ap !== 'all') whereConditions.push(`bssid = '${ap.replace(/'/g, "''")}'`);
    if (device && device !== 'all') whereConditions.push(`device_id = '${device.replace(/'/g, "''")}'`);

    const whereClause = whereConditions.join(' AND ');

    // Run all analytics queries with the combined filter
    const [overview, bySSID, byAP, byChannel, vpnComparison, trends, bandDistribution] = await Promise.all([
      // Overview stats
      pool.query(`
        SELECT
          COUNT(*) as test_count,
          COUNT(DISTINCT device_id) as device_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
          ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
          ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
          ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as median_download
        FROM speed_results
        WHERE ${whereClause}
      `),

      // By SSID
      pool.query(`
        SELECT
          ssid,
          COUNT(*) as test_count,
          COUNT(DISTINCT device_id) as device_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
          ROUND(AVG(latency_ms)::numeric, 2) as avg_latency
        FROM speed_results
        WHERE ${whereClause} AND ssid IS NOT NULL
        GROUP BY ssid
        ORDER BY test_count DESC
      `),

      // By AP (BSSID)
      pool.query(`
        SELECT
          bssid,
          MAX(ssid) as ssid,
          COUNT(*) as test_count,
          COUNT(DISTINCT device_id) as device_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
          ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi
        FROM speed_results
        WHERE ${whereClause} AND bssid IS NOT NULL
        GROUP BY bssid
        ORDER BY test_count DESC
      `),

      // By Channel
      pool.query(`
        SELECT
          channel,
          band,
          COUNT(*) as test_count,
          COUNT(DISTINCT device_id) as device_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
          ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi
        FROM speed_results
        WHERE ${whereClause} AND channel IS NOT NULL
        GROUP BY channel, band
        ORDER BY channel
      `),

      // VPN comparison
      pool.query(`
        SELECT
          vpn_status,
          COUNT(*) as test_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
          ROUND(AVG(latency_ms)::numeric, 2) as avg_latency
        FROM speed_results
        WHERE ${whereClause}
        GROUP BY vpn_status
      `),

      // Daily trends
      pool.query(`
        SELECT
          DATE(timestamp_utc) as date,
          COUNT(*) as test_count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
          ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload
        FROM speed_results
        WHERE ${whereClause}
        GROUP BY date
        ORDER BY date
      `),

      // Band distribution (filtered)
      pool.query(`
        SELECT
          band,
          COUNT(*) as count,
          ROUND(AVG(download_mbps)::numeric, 2) as avg_download
        FROM speed_results
        WHERE ${whereClause} AND band IS NOT NULL AND band != 'none'
        GROUP BY band
      `)
    ]);

    // Get unique filter values for populating dropdowns
    const filterValues = await pool.query(`
      SELECT
        ARRAY_AGG(DISTINCT ssid) FILTER (WHERE ssid IS NOT NULL) as ssids,
        ARRAY_AGG(DISTINCT band) FILTER (WHERE band IS NOT NULL) as bands,
        ARRAY_AGG(DISTINCT channel::text) FILTER (WHERE channel IS NOT NULL) as channels,
        ARRAY_AGG(DISTINCT bssid) FILTER (WHERE bssid IS NOT NULL) as aps,
        ARRAY_AGG(DISTINCT device_id) as devices
      FROM speed_results
      WHERE status LIKE 'success%'
        AND timestamp_utc > NOW() - INTERVAL '${parseInt(days)} days'
    `);

    res.json({
      overview: overview.rows[0],
      bySSID: bySSID.rows,
      byAP: byAP.rows,
      byChannel: byChannel.rows,
      vpnComparison: vpnComparison.rows,
      trends: trends.rows,
      bandDistribution: bandDistribution.rows,
      filterValues: filterValues.rows[0]
    });
  } catch (err) {
    console.error('Error fetching combined analytics:', err);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// API: Channel statistics
app.get('/api/stats/channels', async (req, res) => {
  try {
    const channels = await pool.query(`
      SELECT
        channel,
        band,
        COUNT(*) as test_count,
        COUNT(DISTINCT device_id) as device_count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(rssi_dbm)::numeric, 0) as avg_rssi,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter
      FROM speed_results
      WHERE status LIKE 'success%' AND channel IS NOT NULL
      GROUP BY channel, band
      ORDER BY channel
    `);

    res.json(channels.rows);
  } catch (err) {
    console.error('Error fetching channel stats:', err);
    res.status(500).json({ error: 'Failed to fetch channel stats' });
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

// API: Speed timeline (for charts) with optional filters
app.get('/api/stats/timeline', async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours) || 24, 168);
  const { ssid, band, vpn, device_id, ap } = req.query;

  try {
    // Build WHERE clause with parameterized values
    let whereConditions = ["status LIKE 'success%'", "timestamp_utc > NOW() - INTERVAL '1 hour' * $1"];
    let params = [hours];
    let paramIndex = 2;

    if (ssid && ssid !== 'all') {
      whereConditions.push(`ssid = $${paramIndex}`);
      params.push(ssid);
      paramIndex++;
    }
    if (band && band !== 'all') {
      whereConditions.push(`band = $${paramIndex}`);
      params.push(band);
      paramIndex++;
    }
    if (vpn && vpn !== 'all') {
      whereConditions.push(`vpn_status = $${paramIndex}`);
      params.push(vpn);
      paramIndex++;
    }
    if (device_id && device_id !== 'all') {
      whereConditions.push(`device_id = $${paramIndex}`);
      params.push(device_id);
      paramIndex++;
    }
    if (ap && ap !== 'all') {
      whereConditions.push(`bssid = $${paramIndex}`);
      params.push(ap);
      paramIndex++;
    }

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
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY hour
      ORDER BY hour
    `, params);

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
      recentTests: recentTests.rows.map(test => ({
        ...test,
        ap_name: lookupAPName(test.bssid)
      })),
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
      devices: devices.rows.map(d => ({ ...d, ap_name: lookupAPName(d.bssid) })),
      stats: s,
      timeline: timeline.rows,
      recentTests: recentTests.rows.map(test => ({
        ...test,
        ap_name: lookupAPName(test.bssid)
      })),
      healthScore: Math.max(0, healthScore),
      issues,
      recommendations
    });
  } catch (err) {
    console.error('Error fetching employee data:', err);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

// API: Full historical data for employee dashboard
app.get('/api/my/:email/history', async (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase();
  const { page = 1, limit = 50, sort = 'timestamp_utc', order = 'desc', search = '' } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  try {
    // Find devices for this email
    const devices = await pool.query(`
      SELECT DISTINCT device_id
      FROM speed_results
      WHERE LOWER(user_email) = $1
    `, [email]);

    if (devices.rows.length === 0) {
      return res.json({ found: false, email, data: [], total: 0 });
    }

    const deviceIds = devices.rows.map(d => d.device_id);

    // Build search condition
    let searchCondition = '';
    const params = [deviceIds];
    if (search) {
      searchCondition = `AND (ssid ILIKE $2 OR band ILIKE $2 OR vpn_status ILIKE $2 OR hostname ILIKE $2)`;
      params.push(`%${search}%`);
    }

    // Validate sort column to prevent SQL injection
    const validSortColumns = ['timestamp_utc', 'download_mbps', 'upload_mbps', 'latency_ms', 'jitter_ms', 'rssi_dbm', 'ssid', 'band', 'channel', 'vpn_status'];
    const sortColumn = validSortColumns.includes(sort) ? sort : 'timestamp_utc';
    const sortOrder = order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    // Get total count
    const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM speed_results
      WHERE device_id = ANY($1) ${searchCondition}
    `, params);

    // Get paginated data
    const dataQuery = `
      SELECT
        id,
        timestamp_utc,
        device_id,
        hostname,
        download_mbps,
        upload_mbps,
        latency_ms,
        jitter_ms,
        packet_loss_pct,
        ssid,
        bssid,
        band,
        channel,
        rssi_dbm,
        vpn_status,
        vpn_name,
        status
      FROM speed_results
      WHERE device_id = ANY($1) ${searchCondition}
      ORDER BY ${sortColumn} ${sortOrder}
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;

    const data = await pool.query(dataQuery, [...params, parseInt(limit), offset]);

    // Get summary stats for all data
    const statsResult = await pool.query(`
      SELECT
        COUNT(*) as total_tests,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY download_mbps)::numeric, 2) as median_download,
        MIN(timestamp_utc) as first_test,
        MAX(timestamp_utc) as last_test
      FROM speed_results
      WHERE device_id = ANY($1)
    `, [deviceIds]);

    res.json({
      found: true,
      email,
      data: data.rows,
      total: parseInt(countResult.rows[0].total),
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(parseInt(countResult.rows[0].total) / parseInt(limit)),
      stats: statsResult.rows[0]
    });
  } catch (err) {
    console.error('Error fetching employee history:', err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// API: Export employee data as CSV
app.get('/api/my/:email/export', async (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase();

  try {
    const devices = await pool.query(`
      SELECT DISTINCT device_id
      FROM speed_results
      WHERE LOWER(user_email) = $1
    `, [email]);

    if (devices.rows.length === 0) {
      return res.status(404).json({ error: 'No data found' });
    }

    const deviceIds = devices.rows.map(d => d.device_id);

    const data = await pool.query(`
      SELECT
        timestamp_utc,
        hostname,
        download_mbps,
        upload_mbps,
        latency_ms,
        jitter_ms,
        packet_loss_pct,
        ssid,
        band,
        channel,
        rssi_dbm,
        vpn_status,
        vpn_name,
        status
      FROM speed_results
      WHERE device_id = ANY($1)
      ORDER BY timestamp_utc DESC
    `, [deviceIds]);

    // Generate CSV
    const headers = ['Timestamp', 'Hostname', 'Download (Mbps)', 'Upload (Mbps)', 'Latency (ms)', 'Jitter (ms)', 'Packet Loss (%)', 'SSID', 'Band', 'Channel', 'RSSI (dBm)', 'VPN Status', 'VPN Name', 'Status'];
    const csvRows = [headers.join(',')];

    data.rows.forEach(row => {
      const values = [
        row.timestamp_utc,
        row.hostname || '',
        row.download_mbps || '',
        row.upload_mbps || '',
        row.latency_ms || '',
        row.jitter_ms || '',
        row.packet_loss_pct || '',
        `"${(row.ssid || '').replace(/"/g, '""')}"`,
        row.band || '',
        row.channel || '',
        row.rssi_dbm || '',
        row.vpn_status || '',
        row.vpn_name || '',
        row.status || ''
      ];
      csvRows.push(values.join(','));
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=speed_monitor_${email.replace(/[^a-z0-9]/gi, '_')}_${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csvRows.join('\n'));
  } catch (err) {
    console.error('Error exporting employee data:', err);
    res.status(500).json({ error: 'Failed to export data' });
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

// Serve dashboard (protected by Google OAuth if configured)
app.get('/', requireGoogleAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Debug: Check speedtest strategy distribution
app.get('/api/debug/status-distribution', async (req, res) => {
  try {
    const distribution = await pool.query(`
      SELECT
        status,
        COUNT(*) as count,
        ROUND(AVG(download_mbps)::numeric, 2) as avg_download,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency,
        ROUND(AVG(jitter_ms)::numeric, 2) as avg_jitter
      FROM speed_results
      GROUP BY status
      ORDER BY count DESC
    `);

    const byDevice = await pool.query(`
      SELECT
        COALESCE(user_email, device_id) as device,
        status,
        COUNT(*) as count,
        ROUND(AVG(upload_mbps)::numeric, 2) as avg_upload,
        ROUND(AVG(latency_ms)::numeric, 2) as avg_latency
      FROM speed_results
      WHERE timestamp_utc > NOW() - INTERVAL '24 hours'
      GROUP BY device, status
      ORDER BY device, count DESC
    `);

    res.json({
      overall: distribution.rows,
      byDeviceLast24h: byDevice.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
      features: ['wifi_debugging', 'mcs_tracking', 'error_rates', 'roaming_detection', 'remote_commands'],
      total_results: parseInt(count.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ============================================================================
// REMOTE COMMANDS API - Push commands to devices
// ============================================================================

// Create a command for a device (or all devices) - ADMIN ONLY
// POST /api/commands
// Body: { device_id: "xxx" or "all", command: "force_update|force_speedtest|restart_service", payload?: {}, created_by?: "admin" }
// Requires: Google OAuth admin (whitelisted email) or Bearer token auth
app.post('/api/commands', requireGoogleAdmin, async (req, res) => {
  try {
    const { device_id, command, payload, created_by } = req.body;

    if (!device_id || !command) {
      return res.status(400).json({ error: 'device_id and command are required' });
    }

    const validCommands = ['force_update', 'force_speedtest', 'restart_service', 'collect_diagnostics'];
    if (!validCommands.includes(command)) {
      return res.status(400).json({ error: `Invalid command. Valid commands: ${validCommands.join(', ')}` });
    }

    // If device_id is 'all', create commands for all active devices (seen in last 24h)
    if (device_id === 'all') {
      const activeDevices = await pool.query(`
        SELECT DISTINCT device_id FROM speed_results
        WHERE timestamp_utc > NOW() - INTERVAL '24 hours'
      `);

      const results = [];
      for (const row of activeDevices.rows) {
        const result = await pool.query(`
          INSERT INTO device_commands (device_id, command, payload, created_by)
          VALUES ($1, $2, $3, $4)
          RETURNING id, device_id, command, status, created_at
        `, [row.device_id, command, payload ? JSON.stringify(payload) : null, created_by || 'dashboard']);
        results.push(result.rows[0]);
      }

      res.json({
        success: true,
        message: `Command '${command}' queued for ${results.length} active devices`,
        commands: results
      });
    } else {
      // Single device command - normalize device_id to lowercase for consistent matching
      const normalizedDeviceId = device_id.toLowerCase();
      const result = await pool.query(`
        INSERT INTO device_commands (device_id, command, payload, created_by)
        VALUES ($1, $2, $3, $4)
        RETURNING id, device_id, command, status, created_at
      `, [normalizedDeviceId, command, payload ? JSON.stringify(payload) : null, created_by || 'dashboard']);

      res.json({ success: true, command: result.rows[0] });
    }
  } catch (err) {
    console.error('Error creating command:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get pending commands for a device (called by client after each speedtest)
// GET /api/commands/:device_id
app.get('/api/commands/:device_id', async (req, res) => {
  try {
    const { device_id } = req.params;
    // Normalize to lowercase for case-insensitive matching
    const normalizedDeviceId = device_id.toLowerCase();

    // Get pending commands for this device, mark them as acknowledged
    const commands = await pool.query(`
      UPDATE device_commands
      SET status = 'acknowledged', acknowledged_at = NOW()
      WHERE LOWER(device_id) = $1 AND status = 'pending'
      RETURNING id, command, payload, created_at
    `, [normalizedDeviceId]);

    // Also expire old pending commands (older than 1 hour)
    await pool.query(`
      UPDATE device_commands
      SET status = 'expired'
      WHERE status = 'pending' AND created_at < NOW() - INTERVAL '1 hour'
    `);

    res.json({ commands: commands.rows });
  } catch (err) {
    console.error('Error fetching commands:', err);
    res.status(500).json({ error: err.message });
  }
});

// Report command execution result (called by client after executing command)
// POST /api/commands/:id/result
app.post('/api/commands/:id/result', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, result } = req.body;

    const validStatuses = ['executed', 'failed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Valid: ${validStatuses.join(', ')}` });
    }

    await pool.query(`
      UPDATE device_commands
      SET status = $1, executed_at = NOW(), result = $2
      WHERE id = $3
    `, [status, result || null, id]);

    // Add final log entry
    const level = status === 'executed' ? 'success' : 'error';
    const message = status === 'executed' ? 'Command completed successfully' : `Command failed: ${result || 'Unknown error'}`;
    await pool.query(`
      INSERT INTO command_logs (command_id, level, message, metadata)
      VALUES ($1, $2, $3, $4)
    `, [id, level, message, JSON.stringify({ status, result })]);

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating command result:', err);
    res.status(500).json({ error: err.message });
  }
});

// Report command progress (called by client during command execution)
// POST /api/commands/:id/progress
app.post('/api/commands/:id/progress', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, message, timestamp, level } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'message is required' });
    }

    // Update command status if provided
    if (status) {
      const validStatuses = ['pending', 'acknowledged', 'running', 'executed', 'failed'];
      if (validStatuses.includes(status)) {
        await pool.query(`
          UPDATE device_commands SET status = $1 WHERE id = $2
        `, [status, id]);
      }
    }

    // Add log entry
    await pool.query(`
      INSERT INTO command_logs (command_id, level, message, metadata)
      VALUES ($1, $2, $3, $4)
    `, [id, level || 'info', message, JSON.stringify({ status, client_timestamp: timestamp })]);

    res.json({ success: true });
  } catch (err) {
    console.error('Error reporting progress:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get logs for a specific command
// GET /api/commands/:id/logs
app.get('/api/commands/:id/logs', async (req, res) => {
  try {
    const { id } = req.params;

    const command = await pool.query(`
      SELECT c.*,
        (SELECT hostname FROM speed_results WHERE device_id = c.device_id ORDER BY timestamp_utc DESC LIMIT 1) as hostname,
        (SELECT user_email FROM speed_results WHERE device_id = c.device_id ORDER BY timestamp_utc DESC LIMIT 1) as user_email
      FROM device_commands c
      WHERE c.id = $1
    `, [id]);

    if (command.rows.length === 0) {
      return res.status(404).json({ error: 'Command not found' });
    }

    const logs = await pool.query(`
      SELECT * FROM command_logs WHERE command_id = $1 ORDER BY timestamp ASC
    `, [id]);

    res.json({
      command: command.rows[0],
      logs: logs.rows
    });
  } catch (err) {
    console.error('Error fetching command logs:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get all command logs (for dedicated logs page)
// GET /api/logs?device_id=xxx&command=force_update&status=executed&limit=100&offset=0
app.get('/api/logs', async (req, res) => {
  try {
    const { device_id, command, status, limit = 100, offset = 0 } = req.query;

    let whereConditions = [];
    let params = [];
    let paramIndex = 1;

    if (device_id) {
      whereConditions.push(`LOWER(dc.device_id) = $${paramIndex++}`);
      params.push(device_id.toLowerCase());
    }
    if (command) {
      whereConditions.push(`dc.command = $${paramIndex++}`);
      params.push(command);
    }
    if (status) {
      whereConditions.push(`dc.status = $${paramIndex++}`);
      params.push(status);
    }

    const whereClause = whereConditions.length > 0
      ? 'WHERE ' + whereConditions.join(' AND ')
      : '';

    const result = await pool.query(`
      SELECT
        dc.*,
        (SELECT hostname FROM speed_results WHERE device_id = dc.device_id ORDER BY timestamp_utc DESC LIMIT 1) as hostname,
        (SELECT user_email FROM speed_results WHERE device_id = dc.device_id ORDER BY timestamp_utc DESC LIMIT 1) as user_email,
        (SELECT json_agg(cl ORDER BY cl.timestamp)
         FROM command_logs cl
         WHERE cl.command_id = dc.id) as logs
      FROM device_commands dc
      ${whereClause}
      ORDER BY dc.created_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `, [...params, parseInt(limit), parseInt(offset)]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).json({ error: err.message });
  }
});

// List all commands (for dashboard)
// GET /api/commands?status=pending&limit=100
app.get('/api/commands', async (req, res) => {
  try {
    const { status, device_id, limit = 100 } = req.query;

    let query = `
      SELECT c.*,
        (SELECT hostname FROM speed_results WHERE device_id = c.device_id ORDER BY timestamp_utc DESC LIMIT 1) as hostname,
        (SELECT user_email FROM speed_results WHERE device_id = c.device_id ORDER BY timestamp_utc DESC LIMIT 1) as user_email
      FROM device_commands c
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      params.push(status);
      query += ` AND c.status = $${params.length}`;
    }

    if (device_id) {
      params.push(device_id);
      query += ` AND c.device_id = $${params.length}`;
    }

    params.push(parseInt(limit));
    query += ` ORDER BY c.created_at DESC LIMIT $${params.length}`;

    const result = await pool.query(query, params);
    res.json({ commands: result.rows });
  } catch (err) {
    console.error('Error listing commands:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a pending command
// DELETE /api/commands/:id
app.delete('/api/commands/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      DELETE FROM device_commands WHERE id = $1 AND status = 'pending'
      RETURNING id
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Command not found or already processed' });
    }

    res.json({ success: true, deleted: id });
  } catch (err) {
    console.error('Error deleting command:', err);
    res.status(500).json({ error: err.message });
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
