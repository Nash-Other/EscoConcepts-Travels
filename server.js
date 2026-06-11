const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Resend } = require('resend');
const sanitizeHtml = require('sanitize-html');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 11037;
const isProduction = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);
app.disable('x-powered-by');

// Helmet with relaxed CSP to allow external images and Quill CDN
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "https://*.unsplash.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
    },
  },
}));

const configuredOrigins = (process.env.CORS_ORIGIN || process.env.APP_URL || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !isProduction || configuredOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Serve uploads without forcing attachment
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    res.set('X-Content-Type-Options', 'nosniff');
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.send('EscoConcepts Travels API is running');
});

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (isProduction) {
    throw new Error('JWT_SECRET is required in production.');
  }
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET not set. Using a temporary development secret.');
}

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL not set. Database routes will fail until it is configured.');
}

const APP_URL = process.env.APP_URL || `http://localhost:${port}`;

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';
const AUTH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;
const ADMIN_COOKIE_MAX_AGE = 2 * 60 * 60 * 1000;
const RICH_TEXT_SANITIZE_OPTIONS = {
  allowedTags: [
    ...sanitizeHtml.defaults.allowedTags,
    'img',
    'h1',
    'h2',
    'span',
    'div',
    'figure',
    'figcaption',
    'pre',
    'code',
    'hr'
  ],
  allowedAttributes: {
    ...sanitizeHtml.defaults.allowedAttributes,
    a: ['href', 'name', 'target', 'rel'],
    img: ['src', 'alt', 'title', 'width', 'height', 'loading']
  },
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  transformTags: {
    a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer' }, true)
  }
};

// ==========================================
// DATABASE POOL (original working SSL config)
// ==========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }
});

// ==========================================
// RATE LIMITER (database backed)
// ==========================================
function createRateLimiter({ windowMs, max }) {
  return async function rateLimiterMiddleware(req, res, next) {
    const key = `${req.ip}:${req.path}`;
    const now = new Date();
    const windowEnd = new Date(now.getTime() + windowMs);

    let client;
    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const existing = await client.query(
        `SELECT count, window_start, window_end FROM rate_limits WHERE key = $1 FOR UPDATE`,
        [key]
      );

      if (existing.rows.length === 0) {
        await client.query(
          `INSERT INTO rate_limits (key, count, window_start, window_end)
           VALUES ($1, $2, $3, $4)`,
          [key, 1, now, windowEnd]
        );
        await client.query('COMMIT');
        return next();
      }

      const row = existing.rows[0];
      const windowEndDB = new Date(row.window_end);

      if (now > windowEndDB) {
        await client.query(
          `UPDATE rate_limits
           SET count = $1, window_start = $2, window_end = $3
           WHERE key = $4`,
          [1, now, windowEnd, key]
        );
        await client.query('COMMIT');
        return next();
      }

      const newCount = row.count + 1;
      if (newCount > max) {
        await client.query('ROLLBACK');
        return res.status(429).json({
          success: false,
          message: 'Too many requests. Please try again later.'
        });
      }

      await client.query(
        `UPDATE rate_limits SET count = $1 WHERE key = $2`,
        [newCount, key]
      );
      await client.query('COMMIT');
      next();
    } catch (err) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackErr) {
          console.error('Rate limiter rollback error:', rollbackErr);
        }
      }
      console.error('Rate limiter error:', err);
      next();
    } finally {
      if (client) client.release();
    }
  };
}

// ==========================================
// DATABASE INITIALIZATION (idempotent)
// ==========================================
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        key TEXT NOT NULL UNIQUE,
        count INT NOT NULL DEFAULT 1,
        window_start TIMESTAMP NOT NULL,
        window_end TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_rate_limits_window_end ON rate_limits(window_end)`);

    await client.query(`CREATE TABLE IF NOT EXISTS users (
      user_id SERIAL PRIMARY KEY,
      first_name VARCHAR(50) NOT NULL,
      last_name VARCHAR(50) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      phone VARCHAR(20),
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(20) DEFAULT 'customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      reset_token_hash VARCHAR(255),
      reset_token_expiry TIMESTAMP,
      is_guest BOOLEAN DEFAULT FALSE
    )`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash VARCHAR(255)`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_guest BOOLEAN DEFAULT FALSE`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_reset_token_hash ON users(reset_token_hash)`);

    await client.query(`CREATE TABLE IF NOT EXISTS services (
      service_id SERIAL PRIMARY KEY,
      service_category VARCHAR(50),
      title VARCHAR(150) NOT NULL,
      destination VARCHAR(100),
      description TEXT,
      base_price NUMERIC(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'KES',
      max_pax INTEGER DEFAULT 1 NOT NULL,
      image_url VARCHAR(255),
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      itinerary TEXT,
      gallery TEXT[] DEFAULT '{}'
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS bookings (
      booking_id SERIAL PRIMARY KEY,
      booking_reference VARCHAR(20) UNIQUE NOT NULL,
      user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
      service_id INTEGER REFERENCES services(service_id) ON DELETE RESTRICT,
      travel_date DATE NOT NULL,
      return_date DATE,
      pax INTEGER DEFAULT 1 NOT NULL,
      total_amount NUMERIC(10,2) NOT NULL,
      status VARCHAR(20) DEFAULT 'Pending',
      booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      special_requests TEXT,
      guest_first_name VARCHAR(50),
      guest_last_name VARCHAR(50),
      guest_email VARCHAR(100),
      guest_phone VARCHAR(20)
    )`);

    await client.query(`ALTER TABLE bookings DROP CONSTRAINT IF EXISTS bookings_status_check`);
    await client.query(`ALTER TABLE bookings ADD CONSTRAINT bookings_status_check CHECK (status IN ('Pending', 'Confirmed', 'Cancelled', 'Completed'))`);

    await client.query(`
      ALTER TABLE bookings DROP CONSTRAINT IF EXISTS bookings_return_date_check;
      ALTER TABLE bookings ADD CONSTRAINT bookings_return_date_check 
      CHECK (return_date IS NULL OR return_date >= travel_date);
    `);

    await client.query(`CREATE TABLE IF NOT EXISTS payments (
      payment_id SERIAL PRIMARY KEY,
      booking_id INTEGER REFERENCES bookings(booking_id) ON DELETE CASCADE,
      payment_method VARCHAR(50) NOT NULL,
      amount NUMERIC(10,2) NOT NULL,
      transaction_reference VARCHAR(100) UNIQUE,
      payment_status VARCHAR(20) DEFAULT 'Pending',
      payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      payment_phone VARCHAR(20)
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS blogs (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      slug VARCHAR(255) UNIQUE NOT NULL,
      author VARCHAR(100),
      content TEXT NOT NULL,
      image_url VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS contactmessages (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      subject VARCHAR(255),
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        review_id SERIAL PRIMARY KEY,
        service_id INTEGER NOT NULL REFERENCES services(service_id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(service_id, user_id)
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_reviews_service_id ON reviews(service_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_reviews_user_id ON reviews(user_id)`);

    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const adminHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await client.query(`
        INSERT INTO users (first_name, last_name, email, phone, password_hash, role)
        VALUES ($1, $2, $3, $4, $5, 'admin')
        ON CONFLICT (email) DO NOTHING
      `, [
        process.env.ADMIN_FIRST_NAME || 'Esco',
        process.env.ADMIN_LAST_NAME || 'Admin',
        process.env.ADMIN_EMAIL,
        process.env.ADMIN_PHONE || null,
        adminHash
      ]);
    } else {
      console.warn('ADMIN_EMAIL and ADMIN_PASSWORD not set. Skipping admin bootstrap.');
    }

    console.log('Database ready.');
  } catch (err) {
    console.error('DB init error:', err);
    throw err;
  } finally {
    client.release();
  }
}

// ==========================================
// HELPER FUNCTIONS
// ==========================================
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(normalizeEmail(email));
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');
  return scheme === 'Bearer' && token ? token : null;
}

function parsePositiveInteger(value, fallback = null) {
  if (Number.isInteger(value) && value > 0) return value;
  const text = String(value ?? '').trim();
  if (!/^[1-9]\d*$/.test(text)) return fallback;
  const parsed = Number(text);
  return Number.isSafeInteger(parsed) ? parsed : fallback;
}

function parsePositiveNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function parseRouteId(value) {
  return parsePositiveInteger(value);
}

function parseBoolean(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }
  return fallback;
}

function isValidIsoDateString(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ''))) return false;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day;
}

function cleanOptionalUrl(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  try {
    const url = new URL(text, APP_URL);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return text.startsWith('/') ? `${url.pathname}${url.search}${url.hash}` : url.href;
  } catch (err) {
    return null;
  }
}

function cleanGallery(value) {
  if (!Array.isArray(value)) return [];
  return value.map(cleanOptionalUrl).filter(Boolean).slice(0, 25);
}

function sanitizeRichText(value) {
  return sanitizeHtml(String(value || ''), RICH_TEXT_SANITIZE_OPTIONS).trim();
}

function getAuthCookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge
  };
}

function getPagination(query, defaultLimit = 10, maxLimit = 50) {
  const page = parsePositiveInteger(query.page, 1);
  const requestedLimit = parsePositiveInteger(query.limit, defaultLimit);
  const limit = Math.min(requestedLimit, maxLimit);
  return { page, limit, offset: (page - 1) * limit };
}

async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.log('RESEND_API_KEY not set. Email not sent.');
    return;
  }
  try {
    const { data, error } = await resend.emails.send({
      from: FROM_EMAIL,
      to: [to],
      subject: subject,
      html: html,
    });
    if (error) {
      console.error('Email send error:', error);
    } else {
      console.log(`Email sent to ${to} (${subject})`);
    }
  } catch (err) {
    console.error('Email send failed:', err);
  }
}

async function generateUniqueSlug(baseTitle, currentId = null) {
  let slug = baseTitle.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
  let unique = slug;
  let counter = 1;
  let exists = true;
  while (exists) {
    const query = currentId 
      ? 'SELECT id FROM blogs WHERE slug = $1 AND id != $2'
      : 'SELECT id FROM blogs WHERE slug = $1';
    const params = currentId ? [unique, currentId] : [unique];
    const res = await pool.query(query, params);
    if (res.rows.length === 0) {
      exists = false;
    } else {
      unique = `${slug}-${counter++}`;
    }
  }
  return unique;
}

// ==========================================
// CSRF PROTECTION (double-submit cookie)
// ==========================================
function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashResetToken(token) {
  return crypto.createHmac('sha256', JWT_SECRET).update(String(token)).digest('hex');
}

function setCsrfCookie(res, token) {
  res.cookie('csrf_token', token, {
    httpOnly: false,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });
}

function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return next();
  }
  const csrfCookie = req.cookies.csrf_token;
  const csrfHeader = req.headers['x-csrf-token'];
  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return res.status(403).json({ success: false, message: 'Invalid CSRF token.' });
  }
  next();
}

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
function authenticateCustomer(req, res, next) {
  let token = req.cookies.token;
  if (!token) {
    token = getBearerToken(req);
  }
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token.' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token.' });
    }
    req.user = user;
    req.authSource = req.cookies.token ? 'cookie' : 'header';
    next();
  });
}

function authenticateAdmin(req, res, next) {
  let token = req.cookies.token;
  if (!token) {
    token = getBearerToken(req);
  }
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token.' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token.' });
    }
    if (user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin only.' });
    }
    req.user = user;
    next();
  });
}

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ==========================================
// MULTER SETUP
// ==========================================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomUUID();
    const ext = path.extname(file.originalname);
    cb(null, 'blog-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedExts = new Set(['.jpeg', '.jpg', '.png', '.gif', '.webp']);
  const allowedMimes = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
  const ext = allowedExts.has(path.extname(file.originalname).toLowerCase());
  const mime = allowedMimes.has(file.mimetype);
  if (ext && mime) cb(null, true);
  else cb(new Error('Only images allowed'));
};

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });

// ==========================================
// RATE LIMITER INSTANCES
// ==========================================
const authRateLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
const adminRateLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const contactRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 5 });
const checkoutRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 10 });
const uploadRateLimit = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 10 });

// ==========================================
// ROUTES
// ==========================================

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', getAuthCookieOptions(0));
  res.clearCookie('csrf_token', { secure: isProduction, sameSite: 'strict' });
  res.json({ success: true, message: 'Logged out' });
});

// Password reset routes (unchanged but we keep them compact for space)
app.post('/api/auth/forgot-password', authRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) return res.status(400).json({ success: false, message: 'Email is required.' });
  if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  const user = await pool.query('SELECT user_id, first_name FROM users WHERE email = $1', [email]);
  if (user.rows.length === 0) {
    return res.json({ success: true, message: 'If that email is registered, you will receive a reset link.' });
  }
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = hashResetToken(resetToken);
  const expiry = new Date();
  expiry.setHours(expiry.getHours() + 1);
  await pool.query('UPDATE users SET reset_token_hash = $1, reset_token_expiry = $2 WHERE email = $3', [hashedToken, expiry, email]);
  const resetLink = `${APP_URL}/reset-password.html?token=${resetToken}`;
  const html = `<h2>Password Reset Request</h2><p>Hello ${escapeHtml(user.rows[0].first_name || 'there')},</p><p>Click the link below to set a new password (expires in 1 hour).</p><p><a href="${resetLink}">${resetLink}</a></p><p>If you did not request this, ignore this email.</p><p>- EscoConcepts Travels</p>`;
  await sendEmail(email, 'Reset Your Password', html);
  res.json({ success: true, message: 'If that email is registered, you will receive a reset link.' });
}));

app.post('/api/auth/reset-password', authRateLimit, asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ success: false, message: 'Token and new password required.' });
  if (newPassword.length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  if (!/[a-zA-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
    return res.status(400).json({ success: false, message: 'Password must contain at least one letter and one number.' });
  }
  const hashedToken = hashResetToken(token);
  const user = await pool.query(
    'SELECT user_id FROM users WHERE reset_token_hash = $1 AND reset_token_expiry > CURRENT_TIMESTAMP',
    [hashedToken]
  );
  if (user.rows.length === 0) return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(newPassword, salt);
  await pool.query('UPDATE users SET password_hash = $1, reset_token_hash = NULL, reset_token_expiry = NULL WHERE user_id = $2', [hashedPassword, user.rows[0].user_id]);
  res.json({ success: true, message: 'Password reset successful. You can now log in.' });
}));

// Customer auth
app.post('/api/auth/signup', authRateLimit, asyncHandler(async (req, res) => {
  const firstName = String(req.body.firstName || '').trim();
  const lastName = String(req.body.lastName || '').trim();
  const email = normalizeEmail(req.body.email);
  const phone = String(req.body.phone || '').trim();
  const { password } = req.body;
  if (!firstName || !lastName || !email || !password) return res.status(400).json({ success: false, message: 'Missing required fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  if (firstName.length > 50 || lastName.length > 50 || phone.length > 20) return res.status(400).json({ success: false, message: 'Profile details are too long.' });
  if (password.length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) return res.status(400).json({ success: false, message: 'Password must contain at least one letter and one number.' });
  const existing = await pool.query('SELECT user_id, is_guest FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    const user = existing.rows[0];
    if (user.is_guest) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await pool.query(`UPDATE users SET password_hash = $1, is_guest = FALSE, first_name = $2, last_name = $3, phone = $4 WHERE user_id = $5`, [hashedPassword, firstName, lastName, phone || null, user.user_id]);
      const token = jwt.sign({ userId: user.user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
      const csrfToken = generateCsrfToken();
      setCsrfCookie(res, csrfToken);
      return res.status(200).json({ success: true, message: 'Account claimed successfully!', token });
    } else {
      return res.status(400).json({ success: false, message: 'Email already registered. Please log in or reset password.' });
    }
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const result = await pool.query(`INSERT INTO users (first_name, last_name, email, phone, password_hash, role, is_guest) VALUES ($1,$2,$3,$4,$5,'customer',FALSE) RETURNING user_id`, [firstName, lastName, email, phone || null, hashedPassword]);
  const token = jwt.sign({ userId: result.rows[0].user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
  const csrfToken = generateCsrfToken();
  setCsrfCookie(res, csrfToken);
  res.status(201).json({ success: true, message: 'Signup successful', token });
}));

app.post('/api/auth/login', authRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required.' });
  const result = await pool.query('SELECT user_id, first_name, last_name, email, password_hash, role FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  const token = jwt.sign({ userId: user.user_id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
  const csrfToken = generateCsrfToken();
  setCsrfCookie(res, csrfToken);
  res.json({ success: true, message: 'Login successful', token, role: user.role });
}));

app.get('/api/auth/me', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT user_id, first_name, last_name, email, phone, role FROM users WHERE user_id = $1', [req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'User not found.' });
  res.json({ success: true, user: result.rows[0] });
}));

app.put('/api/auth/profile', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const firstName = String(req.body.firstName || '').trim();
  const lastName = String(req.body.lastName || '').trim();
  const phone = String(req.body.phone || '').trim();
  const email = normalizeEmail(req.body.email);
  const userId = req.user.userId;
  if (!firstName || !lastName || !email) return res.status(400).json({ success: false, message: 'First name, last name, and email are required.' });
  if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  if (firstName.length > 50 || lastName.length > 50 || phone.length > 20) return res.status(400).json({ success: false, message: 'Profile details are too long.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (email !== req.user.email) {
      const emailCheck = await client.query('SELECT user_id FROM users WHERE email = $1 AND user_id != $2', [email, userId]);
      if (emailCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, message: 'Email already in use by another account.' });
      }
    }
    const result = await client.query(`UPDATE users SET first_name=$1, last_name=$2, phone=$3, email=$4 WHERE user_id=$5 RETURNING user_id, first_name, last_name, email, phone, role`, [firstName, lastName, phone || null, email, userId]);
    await client.query('COMMIT');
    const updatedUser = result.rows[0];
    const newToken = jwt.sign({ userId: updatedUser.user_id, email: updatedUser.email, role: updatedUser.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', newToken, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
    res.json({ success: true, message: 'Profile updated successfully.', user: updatedUser, token: newToken });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

// My bookings
app.get('/api/bookings/my-bookings', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query(`SELECT b.booking_id, b.booking_reference, s.title AS package_name, s.service_id, b.travel_date, b.return_date, b.pax, b.total_amount, b.status, b.booking_date, b.special_requests, b.guest_first_name, b.guest_last_name, b.guest_email, b.guest_phone FROM bookings b JOIN services s ON b.service_id = s.service_id WHERE b.user_id = $1 ORDER BY b.booking_date DESC`, [req.user.userId]);
  res.json({ success: true, data: result.rows });
}));

app.put('/api/bookings/cancel/:id', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid booking ID.' });
  const client = await pool.connect();
  try {
    const booking = await client.query(`SELECT b.status, b.user_id, b.booking_reference, s.title as package_title FROM bookings b JOIN services s ON b.service_id = s.service_id WHERE b.booking_id = $1`, [id]);
    if (booking.rows.length === 0) return res.status(404).json({ success: false, message: 'Booking not found.' });
    if (booking.rows[0].user_id !== req.user.userId) return res.status(403).json({ success: false, message: 'Unauthorised.' });
    if (booking.rows[0].status !== 'Pending') return res.status(400).json({ success: false, message: 'Only pending bookings can be cancelled.' });
    await client.query('BEGIN');
    await client.query(`UPDATE bookings SET status = 'Cancelled' WHERE booking_id = $1`, [id]);
    await client.query(`UPDATE payments SET payment_status = 'Failed' WHERE booking_id = $1`, [id]);
    await client.query('COMMIT');
    const customer = await client.query('SELECT email, first_name FROM users WHERE user_id = $1', [req.user.userId]);
    if (customer.rows.length) {
      const html = `<h2>Booking Cancelled</h2><p>Hello ${escapeHtml(customer.rows[0].first_name)},</p><p>Your booking <strong>${escapeHtml(booking.rows[0].booking_reference)}</strong> for <strong>${escapeHtml(booking.rows[0].package_title)}</strong> has been cancelled.</p><p>- EscoConcepts Travels</p>`;
      await sendEmail(customer.rows[0].email, `Booking Cancelled - ${booking.rows[0].booking_reference}`, html);
    }
    res.json({ success: true, message: 'Booking cancelled.' });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

app.post('/api/bookings/receipt/:id', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid booking ID.' });
  const result = await pool.query(`SELECT b.booking_reference, b.travel_date, b.return_date, b.pax, b.total_amount, b.status, b.booking_date, b.special_requests, b.guest_first_name, b.guest_last_name, b.guest_email, b.guest_phone, s.title as package_title, s.destination, u.first_name as owner_first_name, u.last_name as owner_last_name, u.email as owner_email FROM bookings b JOIN services s ON b.service_id = s.service_id JOIN users u ON b.user_id = u.user_id WHERE b.booking_id = $1 AND b.user_id = $2`, [id, req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Booking not found.' });
  const booking = result.rows[0];
  const guestName = `${booking.guest_first_name || ''} ${booking.guest_last_name || ''}`.trim() || 'Not provided';
  const guestEmail = booking.guest_email || 'Not provided';
  const guestPhone = booking.guest_phone || 'Not provided';
  const specialRequests = booking.special_requests || 'None';
  const ownerName = `${booking.owner_first_name} ${booking.owner_last_name}`;
  const html = `<h2>Your Booking Receipt</h2><p><strong>Booking Reference:</strong> ${escapeHtml(booking.booking_reference)}</p><p><strong>Package:</strong> ${escapeHtml(booking.package_title)}</p><p><strong>Destination:</strong> ${escapeHtml(booking.destination)}</p><p><strong>Travel Date:</strong> ${new Date(booking.travel_date).toLocaleDateString()}</p><p><strong>Return Date:</strong> ${booking.return_date ? new Date(booking.return_date).toLocaleDateString() : '-'}</p><p><strong>Guests:</strong> ${booking.pax}</p><p><strong>Total:</strong> KES ${Number(booking.total_amount).toLocaleString()}</p><p><strong>Status:</strong> ${booking.status}</p><p><strong>Booked On:</strong> ${new Date(booking.booking_date).toLocaleString()}</p><hr><h3>Traveler Details</h3><p><strong>Name:</strong> ${escapeHtml(guestName)}</p><p><strong>Email:</strong> ${escapeHtml(guestEmail)}</p><p><strong>Phone:</strong> ${escapeHtml(guestPhone)}</p><p><strong>Special Requests:</strong> ${escapeHtml(specialRequests)}</p><hr><p><strong>Booked by:</strong> ${escapeHtml(ownerName)} (${escapeHtml(booking.owner_email)})</p><p>Thank you for choosing EscoConcepts Travels.</p>`;
  await sendEmail(booking.owner_email, `Your Booking Receipt - ${booking.booking_reference}`, html);
  res.json({ success: true, message: 'Receipt sent to your email.' });
}));

// Search services
app.get('/api/services/search', asyncHandler(async (req, res) => {
  const { location, minPrice, maxPrice, guests } = req.query;
  let query = 'SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE';
  const params = [];
  let idx = 1;
  if (location && location.trim()) { query += ` AND (LOWER(title) LIKE $${idx} OR LOWER(destination) LIKE $${idx})`; params.push(`%${location.toLowerCase()}%`); idx++; }
  const min = minPrice ? parsePositiveNumber(minPrice) : null;
  const max = maxPrice ? parsePositiveNumber(maxPrice) : null;
  const guestCount = guests ? parsePositiveInteger(guests) : null;
  if (min !== null) { query += ` AND base_price >= $${idx}`; params.push(min); idx++; }
  if (max !== null) { query += ` AND base_price <= $${idx}`; params.push(max); idx++; }
  if (guestCount !== null) { query += ` AND max_pax >= $${idx}`; params.push(guestCount); idx++; }
  query += ' ORDER BY base_price ASC';
  const result = await pool.query(query, params);
  res.json({ success: true, data: result.rows });
}));

// Admin login
app.post('/api/admin/login', adminRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required.' });
  const result = await pool.query('SELECT user_id, password_hash, role FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
  if (result.rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  const token = jwt.sign({ userId: user.user_id, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
  res.cookie('token', token, getAuthCookieOptions(ADMIN_COOKIE_MAX_AGE));
  const csrfToken = generateCsrfToken();
  setCsrfCookie(res, csrfToken);
  res.json({ success: true, token });
}));

// Upload
app.post('/api/upload', authenticateAdmin, csrfProtection, uploadRateLimit, (req, res) => {
  upload.single('image')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || 'Upload failed.' });
    if (!req.file) return res.status(400).json({ success: false, message: 'No file.' });
    const protocol = isProduction ? 'https' : (req.protocol === 'https' ? 'https' : 'http');
    const url = `${protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.json({ success: true, url });
  });
});

// Admin bookings
app.get('/api/bookings', authenticateAdmin, asyncHandler(async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const status = req.query.status;
  const dateFrom = req.query.dateFrom;
  const dateTo = req.query.dateTo;
  let baseQuery = `SELECT b.booking_id, b.booking_reference, b.guest_first_name || ' ' || b.guest_last_name AS guest_name, b.guest_email, b.guest_phone, b.special_requests, CONCAT(u.first_name, ' ', u.last_name, ' (', u.email, ')') AS booked_by, s.title AS package_booked, b.travel_date, b.return_date, b.pax AS total_guests, p.payment_method, b.total_amount, b.booking_date, b.status FROM bookings b JOIN services s ON b.service_id = s.service_id JOIN payments p ON b.booking_id = p.booking_id JOIN users u ON b.user_id = u.user_id`;
  let countQuery = `SELECT COUNT(*) FROM bookings b JOIN services s ON b.service_id = s.service_id JOIN payments p ON b.booking_id = p.booking_id JOIN users u ON b.user_id = u.user_id`;
  let where = '';
  let params = [];
  let idx = 1;
  if (search) { where += ` WHERE (LOWER(b.booking_reference) LIKE $${idx} OR LOWER(b.guest_first_name) LIKE $${idx} OR LOWER(b.guest_last_name) LIKE $${idx} OR LOWER(b.guest_email) LIKE $${idx} OR LOWER(s.title) LIKE $${idx} OR LOWER(u.first_name) LIKE $${idx} OR LOWER(u.last_name) LIKE $${idx})`; params.push(search); idx++; }
  else { where += ` WHERE 1=1`; }
  if (status) { where += ` AND b.status = $${idx}`; params.push(status); idx++; }
  if (dateFrom) { where += ` AND b.travel_date >= $${idx}`; params.push(dateFrom); idx++; }
  if (dateTo) { where += ` AND b.travel_date <= $${idx}`; params.push(dateTo); idx++; }
  const countRes = await pool.query(countQuery + where, params);
  const total = parseInt(countRes.rows[0].count);
  const dataRes = await pool.query(baseQuery + where + ` ORDER BY b.booking_date DESC LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]);
  res.json({ success: true, data: dataRes.rows, pagination: { currentPage: page, totalPages: Math.ceil(total / limit), totalItems: total, limit: limit } });
}));

app.put('/api/bookings/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid booking ID.' });
  const { status } = req.body;
  const allowedStatuses = ['Pending', 'Confirmed', 'Cancelled', 'Completed'];
  if (!allowedStatuses.includes(status)) return res.status(400).json({ success: false, message: 'Invalid status.' });
  let paymentStatus = 'Pending';
  if (status === 'Confirmed') paymentStatus = 'Completed';
  if (status === 'Cancelled') paymentStatus = 'Failed';
  if (status === 'Completed') paymentStatus = 'Completed';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query(`SELECT b.status as old_status, b.guest_email AS email, b.guest_first_name AS first_name, b.guest_last_name AS last_name, b.booking_reference, s.title as package_title FROM bookings b JOIN services s ON b.service_id = s.service_id WHERE b.booking_id = $1`, [id]);
    if (current.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Booking not found.' });
    }
    const oldStatus = current.rows[0].old_status;
    const customerEmail = current.rows[0].email;
    const customerName = `${current.rows[0].first_name} ${current.rows[0].last_name}`;
    const bookingRef = current.rows[0].booking_reference;
    const packageTitle = current.rows[0].package_title;
    await client.query(`UPDATE bookings SET status = $1 WHERE booking_id = $2`, [status, id]);
    await client.query(`UPDATE payments SET payment_status = $1 WHERE booking_id = $2`, [paymentStatus, id]);
    await client.query('COMMIT');
    if (oldStatus !== status) {
      const statusText = status === 'Confirmed' ? 'confirmed' : (status === 'Cancelled' ? 'cancelled' : (status === 'Completed' ? 'completed' : 'pending'));
      const subject = `Booking ${statusText} - ${bookingRef}`;
      const html = `<h2>Hello ${escapeHtml(customerName)},</h2><p>Your booking <strong>${escapeHtml(bookingRef)}</strong> for <strong>${escapeHtml(packageTitle)}</strong> has been <strong>${escapeHtml(statusText)}</strong>.</p><p>Thank you for choosing EscoConcepts Travels.</p>`;
      await sendEmail(customerEmail, subject, html);
    }
    res.json({ success: true, message: `Booking status updated to ${status}${oldStatus !== status ? ' and email sent' : ''}.` });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

// Admin services
app.get('/api/admin/services', authenticateAdmin, asyncHandler(async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const isActive = req.query.is_active;
  let baseQuery = 'SELECT service_id, service_category, title, destination, description, base_price, currency, max_pax, image_url, is_active, created_at, itinerary, gallery FROM services';
  let countQuery = 'SELECT COUNT(*) FROM services';
  let where = '';
  let params = [];
  let idx = 1;
  if (search) { where += ` WHERE (LOWER(title) LIKE $${idx} OR LOWER(destination) LIKE $${idx} OR LOWER(description) LIKE $${idx})`; params.push(search); idx++; }
  else { where += ` WHERE 1=1`; }
  if (isActive !== undefined && isActive !== '') { where += ` AND is_active = $${idx}`; params.push(isActive === 'true'); idx++; }
  const countRes = await pool.query(countQuery + where, params);
  const total = parseInt(countRes.rows[0].count);
  const dataRes = await pool.query(baseQuery + where + ` ORDER BY service_id ASC LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]);
  res.json({ success: true, data: dataRes.rows, pagination: { currentPage: page, totalPages: Math.ceil(total / limit), totalItems: total, limit: limit } });
}));

app.get('/api/admin/services/:id', authenticateAdmin, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  const result = await pool.query('SELECT * FROM services WHERE service_id = $1', [id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Destination not found.' });
  res.json({ success: true, data: result.rows[0] });
}));

app.post('/api/admin/services', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  let { title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery } = req.body;
  title = String(title || '').trim();
  destination = String(destination || '').trim();
  const price = parsePositiveNumber(base_price);
  const paxLimit = parsePositiveInteger(max_pax);
  if (!title || !destination || price === null || paxLimit === null) return res.status(400).json({ success: false, message: 'Title, destination, valid price, and valid max pax are required.' });
  if (title.length > 150 || destination.length > 100) return res.status(400).json({ success: false, message: 'Destination details are too long.' });
  description = description ? sanitizeRichText(description) : null;
  itinerary = itinerary ? sanitizeRichText(itinerary) : null;
  const result = await pool.query(`INSERT INTO services (title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`, [title, destination, price, paxLimit, cleanOptionalUrl(image_url), parseBoolean(is_active, true), description, itinerary, cleanGallery(gallery)]);
  res.status(201).json({ success: true, message: 'Destination added!', data: result.rows[0] });
}));

app.put('/api/admin/services/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  let { title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery } = req.body;
  title = String(title || '').trim();
  destination = String(destination || '').trim();
  const price = parsePositiveNumber(base_price);
  const paxLimit = parsePositiveInteger(max_pax);
  if (!title || !destination || price === null || paxLimit === null) return res.status(400).json({ success: false, message: 'Title, destination, valid price, and valid max pax are required.' });
  if (title.length > 150 || destination.length > 100) return res.status(400).json({ success: false, message: 'Destination details are too long.' });
  description = description ? sanitizeRichText(description) : null;
  itinerary = itinerary ? sanitizeRichText(itinerary) : null;
  const result = await pool.query(`UPDATE services SET title=$1, destination=$2, base_price=$3, max_pax=$4, image_url=$5, is_active=$6, description=$7, itinerary=$8, gallery=$9 WHERE service_id=$10 RETURNING *`, [title, destination, price, paxLimit, cleanOptionalUrl(image_url), parseBoolean(is_active, true), description, itinerary, cleanGallery(gallery), id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, message: 'Updated!', data: result.rows[0] });
}));

app.delete('/api/admin/services/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  const check = await pool.query('SELECT COUNT(*) FROM bookings WHERE service_id = $1', [id]);
  if (parseInt(check.rows[0].count) > 0) return res.status(400).json({ success: false, message: 'Cannot delete: has bookings. Deactivate instead.' });
  const result = await pool.query('DELETE FROM services WHERE service_id = $1 RETURNING *', [id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, message: 'Deleted!' });
}));

// Contact messages
app.post('/api/contact', contactRateLimit, asyncHandler(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const subject = String(req.body.subject || '').trim();
  const message = String(req.body.message || '').trim();
  if (!name || !email || !message) return res.status(400).json({ success: false, message: 'Name, email, and message are required.' });
  if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  if (name.length > 255 || email.length > 255 || subject.length > 255 || message.length > 5000) return res.status(400).json({ success: false, message: 'Message details are too long.' });
  await pool.query('INSERT INTO contactmessages (name, email, subject, message) VALUES ($1, $2, $3, $4)', [name, email, subject || null, message]);
  if (process.env.CONTACT_NOTIFICATION_EMAIL) {
    await sendEmail(process.env.CONTACT_NOTIFICATION_EMAIL, `New contact message${subject ? `: ${subject}` : ''}`, `<h2>New Contact Message</h2><p><strong>Name:</strong> ${escapeHtml(name)}</p><p><strong>Email:</strong> ${escapeHtml(email)}</p><p><strong>Subject:</strong> ${escapeHtml(subject || 'No subject')}</p><p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>`);
  }
  res.status(201).json({ success: true, message: 'Message received.' });
}));

app.get('/api/contact', authenticateAdmin, asyncHandler(async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const dateFrom = req.query.dateFrom;
  const dateTo = req.query.dateTo;
  let baseQuery = 'SELECT id, name, email, subject, message, created_at FROM contactmessages';
  let countQuery = 'SELECT COUNT(*) FROM contactmessages';
  let where = '';
  let params = [];
  let idx = 1;
  if (search) { where += ` WHERE (LOWER(name) LIKE $${idx} OR LOWER(email) LIKE $${idx} OR LOWER(subject) LIKE $${idx} OR LOWER(message) LIKE $${idx})`; params.push(search); idx++; }
  else { where += ` WHERE 1=1`; }
  if (dateFrom) { where += ` AND created_at >= $${idx}`; params.push(dateFrom); idx++; }
  if (dateTo) { where += ` AND created_at <= $${idx}`; params.push(dateTo); idx++; }
  const countRes = await pool.query(countQuery + where, params);
  const total = parseInt(countRes.rows[0].count);
  const dataRes = await pool.query(baseQuery + where + ` ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]);
  res.json({ success: true, data: dataRes.rows, pagination: { currentPage: page, totalPages: Math.ceil(total / limit), totalItems: total, limit: limit } });
}));

// Blogs (public)
app.get('/api/blogs', asyncHandler(async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 6, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const author = req.query.author;
  let baseQuery = 'SELECT id, title, slug, author, content, image_url, created_at, updated_at FROM blogs';
  let countQuery = 'SELECT COUNT(*) FROM blogs';
  let where = '';
  let params = [];
  let idx = 1;
  if (search) { where += ` WHERE (LOWER(title) LIKE $${idx} OR LOWER(author) LIKE $${idx} OR LOWER(content) LIKE $${idx})`; params.push(search); idx++; }
  else { where += ` WHERE 1=1`; }
  if (author && author !== 'all') { where += ` AND author = $${idx}`; params.push(author); idx++; }
  const countRes = await pool.query(countQuery + where, params);
  const totalBlogs = parseInt(countRes.rows[0].count);
  const result = await pool.query(baseQuery + where + ` ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]);
  res.json({ blogs: result.rows, pagination: { currentPage: page, totalPages: Math.ceil(totalBlogs / limit), totalBlogs: totalBlogs, limit: limit } });
}));

app.get('/api/blogs/slug/:slug', asyncHandler(async (req, res) => {
  const { slug } = req.params;
  const result = await pool.query('SELECT id, title, slug, author, content, image_url, created_at, updated_at FROM blogs WHERE slug = $1', [slug]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, data: result.rows[0] });
}));

app.get('/api/blogs/:id', asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid blog ID.' });
  const result = await pool.query('SELECT id, title, slug, author, content, image_url, created_at, updated_at FROM blogs WHERE id = $1', [id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, data: result.rows[0] });
}));

// Admin blog operations (with CSRF)
app.post('/api/blogs', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  let { title, author, content, image_url } = req.body;
  title = String(title || '').trim();
  author = String(author || '').trim();
  if (!title || !content) return res.status(400).json({ success: false, message: 'Title and content are required.' });
  if (title.length > 255 || author.length > 100) return res.status(400).json({ success: false, message: 'Blog details are too long.' });
  content = sanitizeRichText(content);
  if (!content) return res.status(400).json({ success: false, message: 'Content is required.' });
  const slug = await generateUniqueSlug(title);
  const result = await pool.query(`INSERT INTO blogs (title, slug, author, content, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [title, slug, author || null, content, cleanOptionalUrl(image_url)]);
  res.status(201).json({ success: true, message: 'Published!', data: result.rows[0] });
}));

app.put('/api/blogs/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid blog ID.' });
  let { title, author, content, image_url } = req.body;
  title = String(title || '').trim();
  author = String(author || '').trim();
  if (!title || !content) return res.status(400).json({ success: false, message: 'Title and content are required.' });
  if (title.length > 255 || author.length > 100) return res.status(400).json({ success: false, message: 'Blog details are too long.' });
  content = sanitizeRichText(content);
  if (!content) return res.status(400).json({ success: false, message: 'Content is required.' });
  const slug = await generateUniqueSlug(title, id);
  const result = await pool.query(`UPDATE blogs SET title=$1, slug=$2, author=$3, content=$4, image_url=$5, updated_at=CURRENT_TIMESTAMP WHERE id=$6 RETURNING *`, [title, slug, author || null, content, cleanOptionalUrl(image_url), id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, message: 'Updated!', data: result.rows[0] });
}));

app.delete('/api/blogs/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  if (id === null) return res.status(400).json({ success: false, message: 'Invalid blog ID.' });
  const result = await pool.query('DELETE FROM blogs WHERE id=$1 RETURNING *', [id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, message: 'Deleted!' });
}));

// Reviews
app.get('/api/reviews/featured', asyncHandler(async (req, res) => {
  const reviewResult = await pool.query(`SELECT r.review_id, r.rating, r.comment, r.created_at, r.service_id, r.user_id, u.first_name, u.last_name FROM reviews r JOIN users u ON r.user_id = u.user_id ORDER BY RANDOM() LIMIT 1`);
  if (reviewResult.rows.length === 0) return res.json({ success: true, review: null });
  const review = reviewResult.rows[0];
  const bookingCheck = await pool.query(`SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`, [review.user_id, review.service_id]);
  const verified = bookingCheck.rows.length > 0;
  const destResult = await pool.query(`SELECT title FROM services WHERE service_id = $1`, [review.service_id]);
  const destination = destResult.rows[0]?.title || 'Safari Package';
  res.json({ success: true, review: { id: review.review_id, rating: review.rating, comment: review.comment, created_at: review.created_at, first_name: review.first_name, last_name: review.last_name, verified, destination } });
}));

app.post('/api/reviews', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const serviceId = parsePositiveInteger(req.body.service_id);
  const rating = parsePositiveInteger(req.body.rating);
  const comment = String(req.body.comment || '').trim();
  if (serviceId === null || rating === null || rating < 1 || rating > 5) return res.status(400).json({ success: false, message: 'Service ID and rating (1-5) required.' });
  if (comment.length > 2000) return res.status(400).json({ success: false, message: 'Review comment is too long.' });
  const bookingCheck = await pool.query(`SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`, [req.user.userId, serviceId]);
  if (bookingCheck.rows.length === 0) return res.status(403).json({ success: false, message: 'You can only review services after your trip has ended.' });
  const existing = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [serviceId, req.user.userId]);
  if (existing.rows.length > 0) return res.status(400).json({ success: false, message: 'You have already reviewed this destination.' });
  await pool.query('INSERT INTO reviews (service_id, user_id, rating, comment) VALUES ($1, $2, $3, $4)', [serviceId, req.user.userId, rating, comment || null]);
  res.status(201).json({ success: true, message: 'Review submitted.' });
}));

app.get('/api/reviews/:service_id', asyncHandler(async (req, res) => {
  const serviceId = parsePositiveInteger(req.params.service_id);
  if (serviceId === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  const reviews = await pool.query(`SELECT r.review_id, r.rating, r.comment, r.created_at, u.first_name, u.last_name, u.user_id FROM reviews r JOIN users u ON r.user_id = u.user_id WHERE r.service_id = $1 ORDER BY r.created_at DESC`, [serviceId]);
  const withVerified = await Promise.all(reviews.rows.map(async (r) => {
    const check = await pool.query(`SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`, [r.user_id, serviceId]);
    return { ...r, verified: check.rows.length > 0 };
  }));
  const avg = await pool.query('SELECT AVG(rating) as average FROM reviews WHERE service_id = $1', [serviceId]);
  const average = avg.rows[0].average ? parseFloat(avg.rows[0].average).toFixed(1) : null;
  res.json({ success: true, reviews: withVerified, average });
}));

app.get('/api/reviews/check/:service_id', authenticateCustomer, asyncHandler(async (req, res) => {
  const serviceId = parsePositiveInteger(req.params.service_id);
  if (serviceId === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  const result = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [serviceId, req.user.userId]);
  res.json({ success: true, reviewed: result.rows.length > 0 });
}));

app.get('/api/reviews/can-review/:service_id', authenticateCustomer, asyncHandler(async (req, res) => {
  const serviceId = parsePositiveInteger(req.params.service_id);
  if (serviceId === null) return res.status(400).json({ success: false, message: 'Invalid service ID.' });
  const bookingCheck = await pool.query(`SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`, [req.user.userId, serviceId]);
  const hasCompleted = bookingCheck.rows.length > 0;
  if (!hasCompleted) return res.json({ success: true, canReview: false, reason: 'No completed booking' });
  const reviewCheck = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [serviceId, req.user.userId]);
  const alreadyReviewed = reviewCheck.rows.length > 0;
  res.json({ success: true, canReview: !alreadyReviewed, alreadyReviewed });
}));

app.delete('/api/reviews/:review_id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const review_id = parseRouteId(req.params.review_id);
  if (review_id === null) return res.status(400).json({ success: false, message: 'Invalid review ID.' });
  await pool.query('DELETE FROM reviews WHERE review_id = $1', [review_id]);
  res.json({ success: true, message: 'Review deleted.' });
}));

app.get('/api/admin/reviews', authenticateAdmin, asyncHandler(async (req, res) => {
  const result = await pool.query(`SELECT r.review_id, r.rating, r.comment, r.created_at, s.title AS destination_title, u.first_name || ' ' || u.last_name AS user_name FROM reviews r JOIN services s ON r.service_id = s.service_id JOIN users u ON r.user_id = u.user_id ORDER BY r.created_at DESC`);
  res.json({ success: true, data: result.rows });
}));

// Checkout
async function generateBookingReference(client) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const ref = `ECT-${crypto.randomInt(100000, 1000000)}`;
    const existing = await client.query('SELECT booking_id FROM bookings WHERE booking_reference = $1', [ref]);
    if (existing.rows.length === 0) return ref;
  }
  throw new Error('Could not generate unique booking reference');
}

app.post('/api/checkout', checkoutRateLimit, asyncHandler(async (req, res) => {
  const { firstName, lastName, email, phone, travelDate, returnDate, pax, paymentMethod, service_id, specialRequests, mpesaPhone } = req.body;
  const cleanFirstName = String(firstName || '').trim();
  const cleanLastName = String(lastName || '').trim();
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanPhone = String(phone || '').trim();
  const cleanPaymentMethod = String(paymentMethod || '').trim();
  const paxCount = parsePositiveInteger(pax);
  const serviceId = parsePositiveInteger(service_id);
  const cleanSpecialRequests = String(specialRequests || '').trim() || null;
  const cleanTravelDate = travelDate ? String(travelDate).trim() : null;
  const cleanReturnDate = returnDate ? String(returnDate).trim() : null;
  const cleanMpesaPhone = mpesaPhone ? String(mpesaPhone).trim() : null;

  if (paxCount === null || serviceId === null) return res.status(400).json({ success: false, message: 'Invalid number of guests or package.' });
  if (!cleanFirstName || !cleanLastName || !cleanEmail || !cleanPhone || !cleanTravelDate || !cleanPaymentMethod) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  if (!isValidEmail(cleanEmail)) return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  if (cleanFirstName.length > 50 || cleanLastName.length > 50 || cleanPhone.length > 20 || (cleanSpecialRequests && cleanSpecialRequests.length > 5000)) {
    return res.status(400).json({ success: false, message: 'Booking details are too long.' });
  }
  if (!isValidIsoDateString(cleanTravelDate)) return res.status(400).json({ success: false, message: 'Invalid travel date.' });
  const today = new Date().toISOString().slice(0,10);
  if (cleanTravelDate < today) return res.status(400).json({ success: false, message: 'Travel date cannot be in the past.' });
  if (cleanReturnDate && !isValidIsoDateString(cleanReturnDate)) return res.status(400).json({ success: false, message: 'Invalid return date.' });
  if (cleanReturnDate && cleanReturnDate < cleanTravelDate) return res.status(400).json({ success: false, message: 'Return date cannot be before travel date.' });
  if (paxCount > 10) return res.status(400).json({ success: false, message: 'Please contact us for bookings above 10 guests.' });
  if (!['card', 'mpesa'].includes(cleanPaymentMethod)) return res.status(400).json({ success: false, message: 'Invalid payment method.' });
  if (cleanPaymentMethod === 'mpesa' && !cleanMpesaPhone) return res.status(400).json({ success: false, message: 'M-Pesa phone number is required.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let tokenUser = null;
    const token = req.cookies.token || getBearerToken(req);
    if (token) {
      try {
        tokenUser = jwt.verify(token, JWT_SECRET);
        const userCheck = await client.query('SELECT user_id FROM users WHERE user_id = $1', [tokenUser.userId]);
        if (userCheck.rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(401).json({ success: false, message: 'User no longer exists.' });
        }
      } catch (err) {
        await client.query('ROLLBACK');
        return res.status(403).json({ success: false, message: 'Invalid token.' });
      }
    }
    const service = await client.query('SELECT service_id, title, base_price, max_pax FROM services WHERE service_id = $1 AND is_active = TRUE', [serviceId]);
    if (service.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Selected package was not found.' });
    }
    const selectedService = service.rows[0];
    let maxPax = Number(selectedService.max_pax);
    if (isNaN(maxPax) || maxPax < 1) maxPax = 10;
    if (paxCount > maxPax) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: `This package allows up to ${maxPax} guests.` });
    }
    let finalUserId = tokenUser?.userId || null;
    if (!finalUserId) {
      const userCheck = await client.query('SELECT user_id FROM users WHERE email = $1', [cleanEmail]);
      if (userCheck.rows.length > 0) {
        finalUserId = userCheck.rows[0].user_id;
      } else {
        const guestPasswordHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
        const insertUser = await client.query(`INSERT INTO users (first_name, last_name, email, phone, password_hash, role, is_guest) VALUES ($1,$2,$3,$4,$5,'customer',TRUE) RETURNING user_id`, [cleanFirstName, cleanLastName, cleanEmail, cleanPhone, guestPasswordHash]);
        finalUserId = insertUser.rows[0].user_id;
      }
    }
    const totalAmount = Number(selectedService.base_price) * paxCount;
    const bookingRef = await generateBookingReference(client);
    const insertBooking = await client.query(`INSERT INTO bookings (booking_reference, user_id, service_id, travel_date, return_date, pax, total_amount, status, special_requests, guest_first_name, guest_last_name, guest_email, guest_phone) VALUES ($1,$2,$3,$4,$5,$6,$7,'Pending',$8,$9,$10,$11,$12) RETURNING booking_id`, [bookingRef, finalUserId, serviceId, cleanTravelDate, cleanReturnDate || null, paxCount, totalAmount, cleanSpecialRequests, cleanFirstName, cleanLastName, cleanEmail, cleanPhone]);
    const bookingId = insertBooking.rows[0].booking_id;
    await client.query(`INSERT INTO payments (booking_id, payment_method, amount, payment_status, payment_phone) VALUES ($1,$2,$3,'Pending',$4)`, [bookingId, cleanPaymentMethod, totalAmount, cleanMpesaPhone]);
    await client.query('COMMIT');
    res.status(201).json({ success: true, message: `Booking successful! Reference: ${bookingRef}`, bookingReference: bookingRef });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

// Public services
app.get('/api/services', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE ORDER BY service_id');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/services/summary', asyncHandler(async (req, res) => {
  const result = await pool.query(`SELECT service_id, title, destination, base_price, max_pax, image_url FROM services WHERE is_active = TRUE ORDER BY service_id`);
  res.json({ success: true, data: result.rows });
}));

app.get('/api/services/paginated', asyncHandler(async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 6, 50);
  const countResult = await pool.query('SELECT COUNT(*) FROM services WHERE is_active = TRUE');
  const totalDestinations = parseInt(countResult.rows[0].count);
  const totalPages = Math.ceil(totalDestinations / limit);
  const result = await pool.query('SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE ORDER BY service_id LIMIT $1 OFFSET $2', [limit, offset]);
  res.json({ success: true, data: result.rows, pagination: { currentPage: page, totalPages, totalItems: totalDestinations, limit } });
}));

// Cron endpoint (supports header secret)
app.get('/api/cron/complete-bookings', (req, res) => {
  const secret = req.headers['x-cron-secret'] || req.query.secret;
  const expectedSecret = process.env.CRON_SECRET;
  if (!expectedSecret || secret !== expectedSecret) return res.status(403).json({ success: false, message: 'Unauthorized' });
  (async () => {
    try {
      const result = await pool.query(`UPDATE bookings SET status = 'Completed' WHERE status = 'Confirmed' AND COALESCE(return_date, travel_date) <= CURRENT_DATE RETURNING booking_id, booking_reference`);
      console.log(`Cron: Marked ${result.rowCount} booking(s) as Completed.`);
      res.json({ success: true, message: 'Cron completed successfully.' });
    } catch (err) {
      console.error('Cron error:', err);
      res.status(500).json({ success: false, message: err.message });
    }
  })();
});

// Admin panel route
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  const statusCode = Number.isInteger(err.statusCode) ? err.statusCode : 500;
  res.status(statusCode).json({
    success: false,
    message: statusCode === 500 ? 'Internal server error' : err.message
  });
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    setInterval(async () => {
      try {
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
        await pool.query('DELETE FROM rate_limits WHERE window_end < $1', [cutoff]);
        console.log('Rate limit old entries cleaned');
      } catch (err) { console.error('Rate limit cleanup error:', err); }
    }, 60 * 60 * 1000);
    app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();