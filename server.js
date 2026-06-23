require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client } = require('@aws-sdk/client-s3');
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

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: [
        "'self'", 
        "data:", 
        "https://images.unsplash.com", 
        "https://*.unsplash.com",
        "https://*.r2.dev",
        "https://*.cloudflarestorage.com",
        process.env.R2_PUBLIC_URL ? process.env.R2_PUBLIC_URL : "https://*"
      ],
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
    'img', 'h1', 'h2', 'span', 'div', 'figure', 'figcaption', 'pre', 'code', 'hr'
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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }
});

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
        try { await client.query('ROLLBACK'); } catch (rollbackErr) {}
      }
      console.error('Rate limiter error:', err);
      next();
    } finally {
      if (client) client.release();
    }
  };
}

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
    }
    console.log('Database ready.');
  } catch (err) {
    console.error('DB init error:', err);
    throw err;
  } finally {
    client.release();
  }
}

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
  if (!process.env.RESEND_API_KEY || process.env.RESEND_API_KEY.startsWith('re_local')) return;
  try {
    await resend.emails.send({
      from: FROM_EMAIL,
      to: [to],
      subject: subject,
      html: html,
    });
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
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) return next();
  const csrfCookie = req.cookies.csrf_token;
  const csrfHeader = req.headers['x-csrf-token'];
  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return res.status(403).json({ success: false, message: 'Invalid CSRF token.' });
  }
  next();
}

function authenticateCustomer(req, res, next) {
  let token = req.cookies.token || getBearerToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

function authenticateAdmin(req, res, next) {
  let token = req.cookies.token || getBearerToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
    req.user = user;
    next();
  });
}

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

let s3;
if (process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY) {
  s3 = new S3Client({
    region: 'auto',
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: process.env.R2_ACCESS_KEY_ID,
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
  });
}

const fileFilter = (req, file, cb) => {
  const allowedExts = new Set(['.jpeg', '.jpg', '.png', '.gif', '.webp']);
  const allowedMimes = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
  const ext = allowedExts.has(path.extname(file.originalname).toLowerCase());
  const mime = allowedMimes.has(file.mimetype);
  if (ext && mime) cb(null, true);
  else cb(new Error('Only image files are allowed.'));
};

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = s3 ? multerS3({
  s3: s3,
  bucket: process.env.R2_BUCKET_NAME || 'escoconcepts-travels',
  contentType: multerS3.AUTO_CONTENT_TYPE,
  key: (req, file, cb) => {
    const uniqueSuffix = crypto.randomUUID();
    const ext = path.extname(file.originalname);
    cb(null, 'blog-' + uniqueSuffix + ext);
  }
}) : multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomUUID();
    const ext = path.extname(file.originalname);
    cb(null, 'blog-' + uniqueSuffix + ext);
  }
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });

const authRateLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
const adminRateLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const contactRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 5 });
const checkoutRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 10 });
const uploadRateLimit = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 10 });

// ==========================================
// AUTH & USER ROUTES
// ==========================================
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', getAuthCookieOptions(0));
  res.clearCookie('csrf_token', { secure: isProduction, sameSite: 'strict' });
  res.json({ success: true, message: 'Logged out' });
});

app.post('/api/auth/forgot-password', authRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email || !isValidEmail(email)) return res.status(400).json({ success: false, message: 'Valid email required.' });
  const user = await pool.query('SELECT user_id, first_name FROM users WHERE email = $1', [email]);
  if (user.rows.length === 0) return res.json({ success: true, message: 'If registered, you will receive a reset link.' });
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = hashResetToken(resetToken);
  const expiry = new Date(Date.now() + 60 * 60 * 1000);
  await pool.query('UPDATE users SET reset_token_hash = $1, reset_token_expiry = $2 WHERE email = $3', [hashedToken, expiry, email]);
  const resetLink = `${APP_URL}/reset-password.html?token=${resetToken}`;
  await sendEmail(email, 'Reset Your Password', `<p>Click to set a new password: <a href="${resetLink}">${resetLink}</a></p>`);
  res.json({ success: true, message: 'If registered, you will receive a reset link.' });
}));

app.post('/api/auth/reset-password', authRateLimit, asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 8) return res.status(400).json({ success: false, message: 'Invalid request.' });
  const hashedToken = hashResetToken(token);
  const user = await pool.query('SELECT user_id FROM users WHERE reset_token_hash = $1 AND reset_token_expiry > CURRENT_TIMESTAMP', [hashedToken]);
  if (user.rows.length === 0) return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(newPassword, salt);
  await pool.query('UPDATE users SET password_hash = $1, reset_token_hash = NULL, reset_token_expiry = NULL WHERE user_id = $2', [hashedPassword, user.rows[0].user_id]);
  res.json({ success: true, message: 'Password reset successful.' });
}));

app.post('/api/auth/signup', authRateLimit, asyncHandler(async (req, res) => {
  const { firstName, lastName, phone, password } = req.body;
  const email = normalizeEmail(req.body.email);
  if (!firstName || !lastName || !email || !password || password.length < 8) return res.status(400).json({ success: false, message: 'Invalid fields.' });
  const existing = await pool.query('SELECT user_id, is_guest FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    if (!existing.rows[0].is_guest) return res.status(400).json({ success: false, message: 'Email already registered.' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    await pool.query('UPDATE users SET password_hash=$1, is_guest=FALSE, first_name=$2, last_name=$3, phone=$4 WHERE user_id=$5', [hash, firstName, lastName, phone || null, existing.rows[0].user_id]);
    const token = jwt.sign({ userId: existing.rows[0].user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
    setCsrfCookie(res, generateCsrfToken());
    return res.json({ success: true, token });
  }
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  const result = await pool.query('INSERT INTO users (first_name, last_name, email, phone, password_hash, role, is_guest) VALUES ($1,$2,$3,$4,$5,\'customer\',FALSE) RETURNING user_id', [firstName, lastName, email, phone || null, hash]);
  const token = jwt.sign({ userId: result.rows[0].user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
  setCsrfCookie(res, generateCsrfToken());
  res.status(201).json({ success: true, token });
}));

app.post('/api/auth/login', authRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { password } = req.body;
  const result = await pool.query('SELECT user_id, email, password_hash, role FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0 || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  }
  const user = result.rows[0];
  const token = jwt.sign({ userId: user.user_id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, getAuthCookieOptions(AUTH_COOKIE_MAX_AGE));
  setCsrfCookie(res, generateCsrfToken());
  res.json({ success: true, token, role: user.role });
}));

app.get('/api/auth/me', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT user_id, first_name, last_name, email, phone, role FROM users WHERE user_id = $1', [req.user.userId]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'User not found.' });
  res.json({ success: true, user: result.rows[0] });
}));

app.put('/api/auth/profile', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const { firstName, lastName, phone } = req.body;
  const email = normalizeEmail(req.body.email);
  await pool.query('UPDATE users SET first_name=$1, last_name=$2, phone=$3, email=$4 WHERE user_id=$5', [firstName, lastName, phone || null, email, req.user.userId]);
  res.json({ success: true });
}));

app.get('/api/bookings/my-bookings', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT b.*, s.title AS package_name, s.destination FROM bookings b JOIN services s ON b.service_id = s.service_id WHERE b.user_id = $1 ORDER BY b.booking_date DESC', [req.user.userId]);
  res.json({ success: true, data: result.rows });
}));

app.put('/api/bookings/cancel/:id', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  await pool.query('UPDATE bookings SET status=\'Cancelled\' WHERE booking_id=$1 AND user_id=$2 AND status=\'Pending\'', [parseRouteId(req.params.id), req.user.userId]);
  res.json({ success: true });
}));

// ==========================================
// SECURED CUSTOMER REVIEW MANAGEMENT
// ==========================================

// 1. Check eligibility (Strict 'Completed' status check)
app.get('/api/reviews/can-review/:service_id', authenticateCustomer, asyncHandler(async (req, res) => {
  const serviceId = parseRouteId(req.params.service_id);
  const check = await pool.query(
    `SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed' LIMIT 1`,
    [req.user.userId, serviceId]
  );
  res.json({ success: true, canReview: check.rows.length > 0 });
}));

// 2. Fetch all existing reviews written by this specific customer
app.get('/api/reviews/my-reviews', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query(`
    SELECT r.*, s.title AS service_title, s.image_url 
    FROM reviews r 
    JOIN services s ON r.service_id = s.service_id 
    WHERE r.user_id = $1 
    ORDER BY r.created_at DESC
  `, [req.user.userId]);
  res.json({ success: true, reviews: result.rows });
}));

// 3. Create or Upsert Review (Backend Gatekeeper enforced)
app.post('/api/reviews', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const { service_id, rating, comment } = req.body;
  const parsedServiceId = parseRouteId(service_id);
  const parsedRating = parsePositiveInteger(rating);

  if (!parsedRating || parsedRating < 1 || parsedRating > 5) {
    return res.status(400).json({ success: false, message: 'Rating must be between 1 and 5.' });
  }

  // Gatekeeper: Reject if they haven't officially completed this trip
  const check = await pool.query(
    `SELECT booking_id FROM bookings WHERE user_id = $1 AND service_id = $2 AND status = 'Completed' LIMIT 1`,
    [req.user.userId, parsedServiceId]
  );
  if (check.rows.length === 0) {
    return res.status(403).json({ success: false, message: 'Reviews are reserved strictly for completed safaris.' });
  }

  const cleanComment = sanitizeHtml(comment || '', RICH_TEXT_SANITIZE_OPTIONS);

  const result = await pool.query(`
    INSERT INTO reviews (service_id, user_id, rating, comment) 
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (service_id, user_id) 
    DO UPDATE SET rating = EXCLUDED.rating, comment = EXCLUDED.comment, created_at = CURRENT_TIMESTAMP
    RETURNING *
  `, [parsedServiceId, req.user.userId, parsedRating, cleanComment]);

  res.json({ success: true, review: result.rows[0] });
}));

// 4. Secured PUT update for an existing review
app.put('/api/reviews/my-reviews/:review_id', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const { rating, comment } = req.body;
  const reviewId = parseRouteId(req.params.review_id);
  const parsedRating = parsePositiveInteger(rating);

  if (!parsedRating || parsedRating < 1 || parsedRating > 5) {
    return res.status(400).json({ success: false, message: 'Rating must be between 1 and 5.' });
  }

  const cleanComment = sanitizeHtml(comment || '', RICH_TEXT_SANITIZE_OPTIONS);

  const result = await pool.query(`
    UPDATE reviews 
    SET rating = $1, comment = $2, created_at = CURRENT_TIMESTAMP 
    WHERE review_id = $3 AND user_id = $4 
    RETURNING *
  `, [parsedRating, cleanComment, reviewId, req.user.userId]);

  if (result.rows.length === 0) {
    return res.status(404).json({ success: false, message: 'Review not found or unauthorized.' });
  }

  res.json({ success: true, review: result.rows[0] });
}));

// 5. Secured Customer-scoped Delete
app.delete('/api/reviews/my-reviews/:review_id', authenticateCustomer, csrfProtection, asyncHandler(async (req, res) => {
  const reviewId = parseRouteId(req.params.review_id);
  const result = await pool.query(
    `DELETE FROM reviews WHERE review_id = $1 AND user_id = $2 RETURNING review_id`,
    [reviewId, req.user.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ success: false, message: 'Review not found or unauthorized.' });
  }

  res.json({ success: true });
}));

// Public review helpers
app.get('/api/reviews/featured', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT r.*, u.first_name, u.last_name FROM reviews r JOIN users u ON r.user_id=u.user_id ORDER BY RANDOM() LIMIT 1');
  res.json({ success: true, review: result.rows[0] || null });
}));

app.get('/api/reviews/:service_id', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT r.*, u.first_name, u.last_name FROM reviews r JOIN users u ON r.user_id=u.user_id WHERE r.service_id=$1', [parseRouteId(req.params.service_id)]);
  res.json({ success: true, reviews: result.rows });
}));

app.get('/api/reviews/check/:service_id', authenticateCustomer, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT review_id FROM reviews WHERE service_id=$1 AND user_id=$2', [parseRouteId(req.params.service_id), req.user.userId]);
  res.json({ success: true, reviewed: result.rows.length > 0 });
}));

// ==========================================
// ADMIN & CORE ROUTES
// ==========================================
app.delete('/api/reviews/:review_id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM reviews WHERE review_id=$1', [parseRouteId(req.params.review_id)]);
  res.json({ success: true });
}));

app.get('/api/admin/reviews', authenticateAdmin, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM reviews');
  res.json({ success: true, data: result.rows });
}));

app.post('/api/admin/login', adminRateLimit, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const result = await pool.query('SELECT user_id, password_hash FROM users WHERE email = $1 AND role = \'admin\'', [email]);
  if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) {
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  }
  const token = jwt.sign({ userId: result.rows[0].user_id, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
  res.cookie('token', token, getAuthCookieOptions(ADMIN_COOKIE_MAX_AGE));
  setCsrfCookie(res, generateCsrfToken());
  res.json({ success: true, token });
}));

app.post('/api/upload', authenticateAdmin, csrfProtection, uploadRateLimit, (req, res) => {
  upload.single('image')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || 'Upload failed.' });
    if (!req.file) return res.status(400).json({ success: false, message: 'No file provided.' });

    let url;
    if (req.file.location) {
      const publicBaseUrl = (process.env.R2_PUBLIC_URL || '').replace(/\/$/, '');
      if (publicBaseUrl && req.file.key) {
        url = `${publicBaseUrl}/${req.file.key}`;
      } else {
        url = req.file.location;
      }
    } else {
      const protocol = isProduction ? 'https' : (req.protocol === 'https' ? 'https' : 'http');
      url = `${protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    }
    res.json({ success: true, url });
  });
});

app.get('/api/bookings', authenticateAdmin, asyncHandler(async (req, res) => {
  const { limit, offset } = getPagination(req.query, 15, 50);
  const result = await pool.query('SELECT b.*, s.title AS package_booked, u.email AS booked_by FROM bookings b JOIN services s ON b.service_id=s.service_id JOIN users u ON b.user_id=u.user_id ORDER BY b.booking_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
  res.json({ success: true, data: result.rows, pagination: { currentPage: 1, totalPages: 1 } });
}));

app.put('/api/bookings/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  await pool.query('UPDATE bookings SET status=$1 WHERE booking_id=$2', [req.body.status, parseRouteId(req.params.id)]);
  res.json({ success: true });
}));

app.get('/api/admin/services', authenticateAdmin, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM services ORDER BY service_id ASC');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/admin/services/:id', authenticateAdmin, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM services WHERE service_id = $1', [parseRouteId(req.params.id)]);
  res.json({ success: true, data: result.rows[0] });
}));

app.post('/api/admin/services', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const { title, destination, base_price, max_pax } = req.body;
  const result = await pool.query('INSERT INTO services (title, destination, base_price, max_pax) VALUES ($1,$2,$3,$4) RETURNING *', [title, destination, base_price, max_pax]);
  res.json({ success: true, data: result.rows[0] });
}));

app.put('/api/admin/services/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const { title, destination, base_price, max_pax } = req.body;
  const result = await pool.query('UPDATE services SET title=$1, destination=$2, base_price=$3, max_pax=$4 WHERE service_id=$5 RETURNING *', [title, destination, base_price, max_pax, parseRouteId(req.params.id)]);
  res.json({ success: true, data: result.rows[0] });
}));

app.delete('/api/admin/services/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM services WHERE service_id=$1', [parseRouteId(req.params.id)]);
  res.json({ success: true });
}));

app.post('/api/contact', contactRateLimit, asyncHandler(async (req, res) => {
  await pool.query('INSERT INTO contactmessages (name, email, subject, message) VALUES ($1,$2,$3,$4)', [req.body.name, req.body.email, req.body.subject, req.body.message]);
  res.json({ success: true });
}));

app.get('/api/contact', authenticateAdmin, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM contactmessages ORDER BY created_at DESC');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/blogs', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM blogs ORDER BY created_at DESC');
  res.json({ blogs: result.rows });
}));

app.get('/api/blogs/slug/:slug', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM blogs WHERE slug=$1', [req.params.slug]);
  res.json({ blog: result.rows[0] });
}));

app.get('/api/blogs/:id', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM blogs WHERE id=$1', [parseRouteId(req.params.id)]);
  res.json({ data: result.rows[0] });
}));

app.post('/api/blogs', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const slug = await generateUniqueSlug(req.body.title);
  const result = await pool.query('INSERT INTO blogs (title, slug, author, content, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING *', [req.body.title, slug, req.body.author, sanitizeRichText(req.body.content), cleanOptionalUrl(req.body.image_url)]);
  res.json({ success: true, data: result.rows[0] });
}));

app.put('/api/blogs/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  const id = parseRouteId(req.params.id);
  const slug = await generateUniqueSlug(req.body.title, id);
  const result = await pool.query('UPDATE blogs SET title=$1, slug=$2, author=$3, content=$4, image_url=$5 WHERE id=$6 RETURNING *', [req.body.title, slug, req.body.author, sanitizeRichText(req.body.content), cleanOptionalUrl(req.body.image_url), id]);
  res.json({ success: true, data: result.rows[0] });
}));

app.delete('/api/blogs/:id', authenticateAdmin, csrfProtection, asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM blogs WHERE id=$1', [parseRouteId(req.params.id)]);
  res.json({ success: true });
}));

app.post('/api/checkout', checkoutRateLimit, asyncHandler(async (req, res) => {
  const ref = `ECT-${crypto.randomInt(100000, 1000000)}`;
  const { firstName, lastName, email, phone, travelDate, pax, total_amount, service_id } = req.body;
  let finalUserId = req.cookies.token ? jwt.verify(req.cookies.token, JWT_SECRET).userId : null;
  if (!finalUserId) {
    const u = await pool.query('INSERT INTO users (first_name, last_name, email, password_hash, is_guest) VALUES ($1,$2,$3,\'guest\',TRUE) RETURNING user_id', [firstName, lastName, email]);
    finalUserId = u.rows[0].user_id;
  }
  const b = await pool.query('INSERT INTO bookings (booking_reference, user_id, service_id, travel_date, pax, total_amount) VALUES ($1,$2,$3,$4,$5,$6) RETURNING booking_id', [ref, finalUserId, service_id, travelDate, pax, total_amount || 1000]);
  await pool.query('INSERT INTO payments (booking_id, payment_method, amount) VALUES ($1,$2,$3)', [b.rows[0].booking_id, req.body.paymentMethod || 'card', total_amount || 1000]);
  res.json({ success: true, bookingReference: ref });
}));

app.get('/api/services', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM services WHERE is_active=TRUE ORDER BY service_id');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/services/summary', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT service_id, title, destination, base_price, max_pax, image_url FROM services WHERE is_active=TRUE ORDER BY service_id');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/services/paginated', asyncHandler(async (req, res) => {
  const { limit, offset } = getPagination(req.query, 6, 50);
  const result = await pool.query('SELECT * FROM services WHERE is_active=TRUE ORDER BY service_id LIMIT $1 OFFSET $2', [limit, offset]);
  res.json({ success: true, data: result.rows, pagination: { currentPage: 1, totalPages: 1 } });
}));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.statusCode || 500).json({ success: false, message: err.message || 'Server error' });
});

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
  } catch (err) {
    process.exit(1);
  }
}
startServer();