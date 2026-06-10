const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Resend } = require('resend');
const { exec } = require('child_process');

const app = express();
const port = process.env.PORT || 11037;
const isProduction = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);
app.disable('x-powered-by');

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
  }
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
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

function createRateLimiter({ windowMs, max }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const entry = hits.get(key) || { count: 0, resetAt: now + windowMs };
    if (entry.resetAt <= now) {
      entry.count = 0;
      entry.resetAt = now + windowMs;
    }
    entry.count += 1;
    hits.set(key, entry);
    if (entry.count > max) {
      return res.status(429).json({ success: false, message: 'Too many requests. Please try again later.' });
    }
    next();
  };
}

const authRateLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
const contactRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 5 });

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');
  return scheme === 'Bearer' && token ? token : null;
}

function parsePositiveInteger(value, fallback = null) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function getPagination(query, defaultLimit = 10, maxLimit = 50) {
  const page = parsePositiveInteger(query.page, 1);
  const requestedLimit = parsePositiveInteger(query.limit, defaultLimit);
  const limit = Math.min(requestedLimit, maxLimit);
  return { page, limit, offset: (page - 1) * limit };
}

async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.log('⚠️ RESEND_API_KEY not set. Email not sent.');
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
      console.log(`✅ Email sent to ${to} (${subject})`);
    }
  } catch (err) {
    console.error('Email send failed:', err);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }
});

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
// DATABASE INIT
// ==========================================
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      user_id SERIAL PRIMARY KEY,
      first_name VARCHAR(50) NOT NULL,
      last_name VARCHAR(50) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      phone VARCHAR(20),
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(20) DEFAULT 'customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      reset_token VARCHAR(255),
      reset_token_expiry TIMESTAMP
    )`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255)`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_guest BOOLEAN DEFAULT FALSE`);

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
      booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS special_requests TEXT`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS guest_first_name VARCHAR(50)`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS guest_last_name VARCHAR(50)`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS guest_email VARCHAR(100)`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS guest_phone VARCHAR(20)`);
    await client.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS return_date DATE`);

    await client.query(`CREATE TABLE IF NOT EXISTS payments (
      payment_id SERIAL PRIMARY KEY,
      booking_id INTEGER REFERENCES bookings(booking_id) ON DELETE CASCADE,
      payment_method VARCHAR(50) NOT NULL,
      amount NUMERIC(10,2) NOT NULL,
      transaction_reference VARCHAR(100) UNIQUE,
      payment_status VARCHAR(20) DEFAULT 'Pending',
      payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    await client.query(`ALTER TABLE bookings DROP CONSTRAINT IF EXISTS bookings_status_check`);
    await client.query(`ALTER TABLE bookings ADD CONSTRAINT bookings_status_check CHECK (status IN ('Pending', 'Confirmed', 'Cancelled', 'Completed'))`);

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

    console.log('✅ Database ready.');
  } catch (err) {
    console.error('DB init error:', err);
  } finally {
    client.release();
  }
}
initializeDatabase();

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

function authenticateAdmin(req, res, next) {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
    if (user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
    req.user = user;
    next();
  });
}

function authenticateCustomer(req, res, next) {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// ==========================================
// PASSWORD RESET
// ==========================================
app.post('/api/auth/forgot-password', authRateLimit, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email is required.' });
  try {
    const user = await pool.query('SELECT user_id, first_name FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.json({ success: true, message: 'If that email is registered, you will receive a reset link.' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + 1);
    await pool.query('UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3', [resetToken, expiry, email]);
    const resetLink = `${APP_URL}/reset-password.html?token=${resetToken}`;
    const html = `
      <h2>Password Reset Request</h2>
      <p>Hello ${escapeHtml(user.rows[0].first_name || 'there')},</p>
      <p>Click the link below to set a new password (expires in 1 hour).</p>
      <p><a href="${resetLink}">${resetLink}</a></p>
      <p>If you did not request this, ignore this email.</p>
      <p>— EscoConcepts Travels</p>
    `;
    await sendEmail(email, 'Reset Your Password', html);
    res.json({ success: true, message: 'If that email is registered, you will receive a reset link.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/reset-password', authRateLimit, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Token and new password required.' });
  }
  try {
    const user = await pool.query('SELECT user_id, reset_token_expiry FROM users WHERE reset_token = $1', [token]);
    if (user.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
    }
    const expiry = new Date(user.rows[0].reset_token_expiry);
    if (expiry < new Date()) {
      return res.status(400).json({ success: false, message: 'Token expired. Request a new reset link.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    await pool.query('UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = $2', [hashedPassword, user.rows[0].user_id]);
    res.json({ success: true, message: 'Password reset successful. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ==========================================
// CUSTOMER AUTH
// ==========================================
app.post('/api/auth/signup', authRateLimit, async (req, res) => {
  const { firstName, lastName, email, phone, password } = req.body;
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  try {
    const existing = await pool.query('SELECT user_id, is_guest FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      const user = existing.rows[0];
      if (user.is_guest) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        await pool.query(
          `UPDATE users SET password_hash = $1, is_guest = FALSE, first_name = $2, last_name = $3, phone = $4 WHERE user_id = $5`,
          [hashedPassword, firstName, lastName, phone || null, user.user_id]
        );
        const token = jwt.sign({ userId: user.user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
        return res.status(200).json({ success: true, message: 'Account claimed successfully!', token });
      } else {
        return res.status(400).json({ success: false, message: 'Email already registered. Please log in or reset password.' });
      }
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, role, is_guest)
       VALUES ($1, $2, $3, $4, $5, 'customer', FALSE) RETURNING user_id`,
      [firstName, lastName, email, phone || null, hashedPassword]
    );
    const token = jwt.sign({ userId: result.rows[0].user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ success: true, message: 'Signup successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required.' });
  }
  try {
    const result = await pool.query('SELECT user_id, first_name, last_name, email, password_hash, role FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
    const token = jwt.sign({ userId: user.user_id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, message: 'Login successful', token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/auth/me', authenticateCustomer, async (req, res) => {
  try {
    const result = await pool.query('SELECT user_id, first_name, last_name, email, phone, role FROM users WHERE user_id = $1', [req.user.userId]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.put('/api/auth/profile', authenticateCustomer, async (req, res) => {
  const { firstName, lastName, phone, email } = req.body;
  const userId = req.user.userId;
  if (!firstName || !lastName || !email) {
    return res.status(400).json({ success: false, message: 'First name, last name, and email are required.' });
  }
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
    const result = await client.query(
      `UPDATE users SET first_name = $1, last_name = $2, phone = $3, email = $4 WHERE user_id = $5 RETURNING user_id, first_name, last_name, email, phone, role`,
      [firstName, lastName, phone || null, email, userId]
    );
    await client.query('COMMIT');
    const updatedUser = result.rows[0];
    const newToken = jwt.sign({ userId: updatedUser.user_id, email: updatedUser.email, role: updatedUser.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, message: 'Profile updated successfully.', user: updatedUser, token: newToken });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Profile update error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally {
    client.release();
  }
});

// ==========================================
// MY BOOKINGS
// ==========================================
app.get('/api/bookings/my-bookings', authenticateCustomer, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.booking_id, b.booking_reference, s.title AS package_name, s.service_id,
             b.travel_date, b.return_date, b.pax, b.total_amount, b.status, b.booking_date,
             b.special_requests, b.guest_first_name, b.guest_last_name, b.guest_email, b.guest_phone
      FROM bookings b
      JOIN services s ON b.service_id = s.service_id
      WHERE b.user_id = $1
      ORDER BY b.booking_date DESC
    `, [req.user.userId]);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch bookings.' });
  }
});

app.put('/api/bookings/cancel/:id', authenticateCustomer, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    const booking = await client.query(
      `SELECT b.status, b.user_id, b.booking_reference, s.title as package_title
       FROM bookings b
       JOIN services s ON b.service_id = s.service_id
       WHERE b.booking_id = $1`,
      [id]
    );
    if (booking.rows.length === 0) return res.status(404).json({ success: false, message: 'Booking not found.' });
    if (booking.rows[0].user_id !== req.user.userId) return res.status(403).json({ success: false, message: 'Unauthorised.' });
    if (booking.rows[0].status !== 'Pending') return res.status(400).json({ success: false, message: 'Only pending bookings can be cancelled.' });

    await client.query('BEGIN');
    await client.query(`UPDATE bookings SET status = 'Cancelled' WHERE booking_id = $1`, [id]);
    await client.query(`UPDATE payments SET payment_status = 'Failed' WHERE booking_id = $1`, [id]);
    await client.query('COMMIT');

    const customer = await client.query('SELECT email, first_name FROM users WHERE user_id = $1', [req.user.userId]);
    if (customer.rows.length) {
      const html = `
        <h2>Booking Cancelled</h2>
        <p>Hello ${escapeHtml(customer.rows[0].first_name)},</p>
        <p>Your booking <strong>${escapeHtml(booking.rows[0].booking_reference)}</strong> for <strong>${escapeHtml(booking.rows[0].package_title)}</strong> has been cancelled.</p>
        <p>– EscoConcepts Travels</p>
      `;
      await sendEmail(customer.rows[0].email, `Booking Cancelled – ${booking.rows[0].booking_reference}`, html);
    }
    res.json({ success: true, message: 'Booking cancelled.' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to cancel.' });
  } finally {
    client.release();
  }
});

app.post('/api/bookings/receipt/:id', authenticateCustomer, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`
      SELECT b.booking_reference, b.travel_date, b.return_date, b.pax, b.total_amount, b.status, b.booking_date,
             b.special_requests, b.guest_first_name, b.guest_last_name, b.guest_email, b.guest_phone,
             s.title as package_title, s.destination,
             u.first_name as owner_first_name, u.last_name as owner_last_name, u.email as owner_email
      FROM bookings b
      JOIN services s ON b.service_id = s.service_id
      JOIN users u ON b.user_id = u.user_id
      WHERE b.booking_id = $1 AND b.user_id = $2
    `, [id, req.user.userId]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Booking not found.' });
    const booking = result.rows[0];
    const guestName = `${booking.guest_first_name || ''} ${booking.guest_last_name || ''}`.trim() || 'Not provided';
    const guestEmail = booking.guest_email || 'Not provided';
    const guestPhone = booking.guest_phone || 'Not provided';
    const specialRequests = booking.special_requests || 'None';
    const ownerName = `${booking.owner_first_name} ${booking.owner_last_name}`;
    const html = `
      <h2>Your Booking Receipt</h2>
      <p><strong>Booking Reference:</strong> ${escapeHtml(booking.booking_reference)}</p>
      <p><strong>Package:</strong> ${escapeHtml(booking.package_title)}</p>
      <p><strong>Destination:</strong> ${escapeHtml(booking.destination)}</p>
      <p><strong>Travel Date:</strong> ${new Date(booking.travel_date).toLocaleDateString()}</p>
      <p><strong>Return Date:</strong> ${booking.return_date ? new Date(booking.return_date).toLocaleDateString() : '—'}</p>
      <p><strong>Guests:</strong> ${booking.pax}</p>
      <p><strong>Total:</strong> KES ${Number(booking.total_amount).toLocaleString()}</p>
      <p><strong>Status:</strong> ${booking.status}</p>
      <p><strong>Booked On:</strong> ${new Date(booking.booking_date).toLocaleString()}</p>
      <hr>
      <h3>Traveler Details</h3>
      <p><strong>Name:</strong> ${escapeHtml(guestName)}</p>
      <p><strong>Email:</strong> ${escapeHtml(guestEmail)}</p>
      <p><strong>Phone:</strong> ${escapeHtml(guestPhone)}</p>
      <p><strong>Special Requests:</strong> ${escapeHtml(specialRequests)}</p>
      <hr>
      <p><strong>Booked by:</strong> ${escapeHtml(ownerName)} (${escapeHtml(booking.owner_email)})</p>
      <p>Thank you for choosing EscoConcepts Travels.</p>
    `;
    await sendEmail(booking.owner_email, `Your Booking Receipt – ${booking.booking_reference}`, html);
    res.json({ success: true, message: 'Receipt sent to your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to send receipt.' });
  }
});

// ==========================================
// SEARCH SERVICES
// ==========================================
app.get('/api/services/search', async (req, res) => {
  const { location, minPrice, maxPrice, guests } = req.query;
  let query = 'SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE';
  const params = [];
  let paramIndex = 1;
  if (location && location.trim() !== '') {
    query += ` AND (LOWER(title) LIKE $${paramIndex} OR LOWER(destination) LIKE $${paramIndex})`;
    params.push(`%${location.toLowerCase()}%`);
    paramIndex++;
  }
  if (minPrice && !isNaN(parseFloat(minPrice))) {
    query += ` AND base_price >= $${paramIndex}`;
    params.push(parseFloat(minPrice));
    paramIndex++;
  }
  if (maxPrice && !isNaN(parseFloat(maxPrice))) {
    query += ` AND base_price <= $${paramIndex}`;
    params.push(parseFloat(maxPrice));
    paramIndex++;
  }
  if (guests && !isNaN(parseInt(guests))) {
    query += ` AND max_pax >= $${paramIndex}`;
    params.push(parseInt(guests));
    paramIndex++;
  }
  query += ' ORDER BY base_price ASC';
  try {
    const result = await pool.query(query, params);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Search failed.' });
  }
});

app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ success: true, message: 'Database connected', time: result.rows[0].time });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// ADMIN LOGIN
// ==========================================
app.post('/api/admin/login', authRateLimit, async (req, res) => {
  const { email, password } = req.body;
  const HARDCODED_EMAIL = 'admin@escoconcepts.com';
  const HARDCODED_PASSWORD = 'admin123';
  if (email === HARDCODED_EMAIL && password === HARDCODED_PASSWORD) {
    const token = jwt.sign({ userId: 1, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
    return res.json({ success: true, token });
  }
  try {
    const result = await pool.query('SELECT user_id, password_hash FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
    if (result.rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const token = jwt.sign({ userId: user.user_id, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/upload', authenticateAdmin, (req, res) => {
  upload.single('image')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || 'Upload failed.' });
    if (!req.file) return res.status(400).json({ success: false, message: 'No file.' });
    const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.json({ success: true, url });
  });
});

// ==========================================
// BOOKINGS (admin)
// ==========================================
app.get('/api/bookings', authenticateAdmin, async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const status = req.query.status;
  const dateFrom = req.query.dateFrom;
  const dateTo = req.query.dateTo;

  let baseQuery = `
    SELECT 
      b.booking_id, 
      b.booking_reference,
      b.guest_first_name || ' ' || b.guest_last_name AS guest_name,
      b.guest_email,
      b.guest_phone,
      b.special_requests,
      CONCAT(u.first_name, ' ', u.last_name, ' (', u.email, ')') AS booked_by,
      s.title AS package_booked,
      b.travel_date,
      b.return_date,
      b.pax AS total_guests,
      p.payment_method,
      b.total_amount,
      b.booking_date,
      b.status
    FROM bookings b
    JOIN services s ON b.service_id = s.service_id
    JOIN payments p ON b.booking_id = p.booking_id
    JOIN users u ON b.user_id = u.user_id
  `;
  let countQuery = 'SELECT COUNT(*) FROM bookings b JOIN services s ON b.service_id = s.service_id JOIN payments p ON b.booking_id = p.booking_id JOIN users u ON b.user_id = u.user_id';
  let whereClause = '';
  let params = [];
  let paramIndex = 1;

  if (search) {
    whereClause += ` WHERE (LOWER(b.booking_reference) LIKE $${paramIndex} OR LOWER(b.guest_first_name) LIKE $${paramIndex} OR LOWER(b.guest_last_name) LIKE $${paramIndex} OR LOWER(b.guest_email) LIKE $${paramIndex} OR LOWER(s.title) LIKE $${paramIndex} OR LOWER(u.first_name) LIKE $${paramIndex} OR LOWER(u.last_name) LIKE $${paramIndex})`;
    params.push(search);
    paramIndex++;
  } else {
    whereClause += ` WHERE 1=1`;
  }

  if (status) {
    whereClause += ` AND b.status = $${paramIndex}`;
    params.push(status);
    paramIndex++;
  }
  if (dateFrom) {
    whereClause += ` AND b.travel_date >= $${paramIndex}`;
    params.push(dateFrom);
    paramIndex++;
  }
  if (dateTo) {
    whereClause += ` AND b.travel_date <= $${paramIndex}`;
    params.push(dateTo);
    paramIndex++;
  }

  try {
    const countRes = await pool.query(countQuery + whereClause, params);
    const total = parseInt(countRes.rows[0].count);
    const dataRes = await pool.query(
      baseQuery + whereClause + ` ORDER BY b.booking_date DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset]
    );
    res.json({
      success: true,
      data: dataRes.rows,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        limit: limit
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch bookings.' });
  }
});

app.put('/api/bookings/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
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
    const current = await client.query(`
      SELECT b.status as old_status, b.guest_email AS email, b.guest_first_name AS first_name, b.guest_last_name AS last_name, b.booking_reference, s.title as package_title
      FROM bookings b
      JOIN services s ON b.service_id = s.service_id
      WHERE b.booking_id = $1
    `, [id]);
    if (current.rows.length === 0) throw new Error('Booking not found');
    const oldStatus = current.rows[0].old_status;
    const customerEmail = current.rows[0].email;
    const customerName = `${current.rows[0].first_name} ${current.rows[0].last_name}`;
    const bookingRef = current.rows[0].booking_reference;
    const packageTitle = current.rows[0].package_title;

    await client.query(`UPDATE bookings SET status = $1 WHERE booking_id = $2`, [status, id]);
    await client.query(`UPDATE payments SET payment_status = $1 WHERE booking_id = $2`, [paymentStatus, id]);
    await client.query('COMMIT');

    if (oldStatus !== status) {
      const statusText = status === 'Confirmed' ? 'confirmed ✅' : (status === 'Cancelled' ? 'cancelled ❌' : (status === 'Completed' ? 'completed ✅' : 'pending ⏳'));
      const subject = `Booking ${statusText} – ${bookingRef}`;
      const html = `
        <h2>Hello ${escapeHtml(customerName)},</h2>
        <p>Your booking <strong>${escapeHtml(bookingRef)}</strong> for <strong>${escapeHtml(packageTitle)}</strong> has been <strong>${escapeHtml(statusText)}</strong>.</p>
        <p>Thank you for choosing EscoConcepts Travels.</p>
      `;
      await sendEmail(customerEmail, subject, html);
    }
    res.json({ success: true, message: `Booking status updated to ${status}${oldStatus !== status ? ' and email sent' : ''}.` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed.' });
  } finally {
    client.release();
  }
});

// ==========================================
// ADMIN SERVICES
// ==========================================
app.get('/api/admin/services', authenticateAdmin, async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const isActive = req.query.is_active;

  let baseQuery = 'SELECT service_id, service_category, title, destination, description, base_price, currency, max_pax, image_url, is_active, created_at, itinerary, gallery FROM services';
  let countQuery = 'SELECT COUNT(*) FROM services';
  let whereClause = '';
  let params = [];
  let paramIndex = 1;

  if (search) {
    whereClause += ` WHERE (LOWER(title) LIKE $${paramIndex} OR LOWER(destination) LIKE $${paramIndex} OR LOWER(description) LIKE $${paramIndex})`;
    params.push(search);
    paramIndex++;
  } else {
    whereClause += ` WHERE 1=1`;
  }

  if (isActive !== undefined && isActive !== '') {
    const activeBool = isActive === 'true';
    whereClause += ` AND is_active = $${paramIndex}`;
    params.push(activeBool);
    paramIndex++;
  }

  try {
    const countRes = await pool.query(countQuery + whereClause, params);
    const total = parseInt(countRes.rows[0].count);
    const dataRes = await pool.query(
      baseQuery + whereClause + ` ORDER BY service_id ASC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset]
    );
    res.json({
      success: true,
      data: dataRes.rows,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        limit: limit
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

app.get('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM services WHERE service_id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Destination not found.' });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch destination.' });
  }
});

app.post('/api/admin/services', authenticateAdmin, async (req, res) => {
  const { title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery } = req.body;
  if (!title || !destination || !base_price) return res.status(400).json({ success: false, message: 'Missing fields.' });
  const paxLimit = parsePositiveInteger(max_pax, 1);
  try {
    const result = await pool.query(
      `INSERT INTO services (title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [title, destination, base_price, paxLimit, image_url || null, is_active !== undefined ? is_active : true, description || null, itinerary || null, gallery || []]
    );
    res.status(201).json({ success: true, message: 'Destination added!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to add destination.' });
  }
});

app.put('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, destination, base_price, max_pax, image_url, is_active, description, itinerary, gallery } = req.body;
  if (!title || !destination || !base_price) return res.status(400).json({ success: false, message: 'Missing fields.' });
  const paxLimit = parsePositiveInteger(max_pax, 1);
  try {
    const result = await pool.query(
      `UPDATE services SET title=$1, destination=$2, base_price=$3, max_pax=$4, image_url=$5, is_active=$6,
       description=$7, itinerary=$8, gallery=$9 WHERE service_id=$10 RETURNING *`,
      [title, destination, base_price, paxLimit, image_url || null, is_active, description || null, itinerary || null, gallery || [], id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, message: 'Updated!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed.' });
  }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query('SELECT COUNT(*) FROM bookings WHERE service_id = $1', [id]);
    if (parseInt(check.rows[0].count) > 0) {
      return res.status(400).json({ success: false, message: 'Cannot delete: has bookings. Deactivate instead.' });
    }
    const result = await pool.query('DELETE FROM services WHERE service_id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, message: 'Deleted!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed.' });
  }
});

// ==========================================
// CONTACT MESSAGES
// ==========================================
app.post('/api/contact', contactRateLimit, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const subject = String(req.body.subject || '').trim();
  const message = String(req.body.message || '').trim();

  if (!name || !email || !message) {
    return res.status(400).json({ success: false, message: 'Name, email, and message are required.' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  }
  if (name.length > 255 || email.length > 255 || subject.length > 255 || message.length > 5000) {
    return res.status(400).json({ success: false, message: 'Message details are too long.' });
  }

  try {
    await pool.query('INSERT INTO contactmessages (name, email, subject, message) VALUES ($1, $2, $3, $4)', [name, email, subject || null, message]);
    if (process.env.CONTACT_NOTIFICATION_EMAIL) {
      await sendEmail(process.env.CONTACT_NOTIFICATION_EMAIL, `New contact message${subject ? `: ${subject}` : ''}`, `<h2>New Contact Message</h2><p><strong>Name:</strong> ${escapeHtml(name)}</p><p><strong>Email:</strong> ${escapeHtml(email)}</p><p><strong>Subject:</strong> ${escapeHtml(subject || 'No subject')}</p><p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>`);
    }
    res.status(201).json({ success: true, message: 'Message received.' });
  } catch (err) {
    console.error('Contact submit error:', err);
    res.status(500).json({ success: false, message: 'Failed to submit message.' });
  }
});

app.get('/api/contact', authenticateAdmin, async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 10, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const dateFrom = req.query.dateFrom;
  const dateTo = req.query.dateTo;

  let baseQuery = 'SELECT id, name, email, subject, message, created_at FROM contactmessages';
  let countQuery = 'SELECT COUNT(*) FROM contactmessages';
  let whereClause = '';
  let params = [];
  let paramIndex = 1;

  if (search) {
    whereClause += ` WHERE (LOWER(name) LIKE $${paramIndex} OR LOWER(email) LIKE $${paramIndex} OR LOWER(subject) LIKE $${paramIndex} OR LOWER(message) LIKE $${paramIndex})`;
    params.push(search);
    paramIndex++;
  } else {
    whereClause += ` WHERE 1=1`;
  }

  if (dateFrom) {
    whereClause += ` AND created_at >= $${paramIndex}`;
    params.push(dateFrom);
    paramIndex++;
  }
  if (dateTo) {
    whereClause += ` AND created_at <= $${paramIndex}`;
    params.push(dateTo);
    paramIndex++;
  }

  try {
    const countRes = await pool.query(countQuery + whereClause, params);
    const total = parseInt(countRes.rows[0].count);
    const dataRes = await pool.query(baseQuery + whereClause + ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`, [...params, limit, offset]);
    res.json({ success: true, data: dataRes.rows, pagination: { currentPage: page, totalPages: Math.ceil(total / limit), totalItems: total, limit: limit } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages.' });
  }
});

// ==========================================
// BLOGS
// ==========================================
app.get('/api/blogs/authors', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT DISTINCT author FROM blogs WHERE author IS NOT NULL ORDER BY author');
    res.json({ success: true, authors: result.rows.map(r => r.author) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch authors.' });
  }
});

app.get('/api/blogs', async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 6, 50);
  const search = req.query.search ? `%${req.query.search.toLowerCase()}%` : null;
  const author = req.query.author;

  let baseQuery = 'SELECT id, title, slug, author, content, image_url, created_at, updated_at FROM blogs';
  let countQuery = 'SELECT COUNT(*) FROM blogs';
  let whereClause = '';
  let params = [];
  let paramIndex = 1;

  if (search) {
    whereClause += ` WHERE (LOWER(title) LIKE $${paramIndex} OR LOWER(author) LIKE $${paramIndex} OR LOWER(content) LIKE $${paramIndex})`;
    params.push(search);
    paramIndex++;
  } else {
    whereClause += ` WHERE 1=1`;
  }

  if (author && author !== 'all') {
    whereClause += ` AND author = $${paramIndex}`;
    params.push(author);
    paramIndex++;
  }

  try {
    const countRes = await pool.query(countQuery + whereClause, params);
    const totalBlogs = parseInt(countRes.rows[0].count);
    const result = await pool.query(baseQuery + whereClause + ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`, [...params, limit, offset]);
    res.json({ blogs: result.rows, pagination: { currentPage: page, totalPages: Math.ceil(totalBlogs / limit), totalBlogs: totalBlogs, limit: limit } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch blogs.' });
  }
});

app.get('/api/blogs/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT id, title, slug, author, content, image_url, created_at, updated_at FROM blogs WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/blogs', authenticateAdmin, async (req, res) => {
  const { title, author, content, image_url } = req.body;
  if (!title || !content) return res.status(400).json({ success: false, message: 'Title and content are required.' });
  try {
    const slug = await generateUniqueSlug(title);
    const result = await pool.query(`INSERT INTO blogs (title, slug, author, content, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [title, slug, author, content, image_url]);
    res.status(201).json({ success: true, message: 'Published!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to publish.' });
  }
});

app.put('/api/blogs/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, author, content, image_url } = req.body;
  if (!title || !content) return res.status(400).json({ success: false, message: 'Title and content are required.' });
  try {
    const slug = await generateUniqueSlug(title, id);
    const result = await pool.query(`UPDATE blogs SET title=$1, slug=$2, author=$3, content=$4, image_url=$5, updated_at=CURRENT_TIMESTAMP WHERE id=$6 RETURNING *`, [title, slug, author, content, image_url, id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, message: 'Updated!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed.' });
  }
});

app.delete('/api/blogs/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM blogs WHERE id=$1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, message: 'Deleted!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed.' });
  }
});

// ==========================================
// REVIEWS (updated with verified flag and can-review endpoint)
// ==========================================
app.post('/api/reviews', authenticateCustomer, async (req, res) => {
  const { service_id, rating, comment } = req.body;
  if (!service_id || !rating || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: 'Service ID and rating (1-5) required.' });
  }
  try {
    const bookingCheck = await pool.query(
      `SELECT booking_id FROM bookings 
       WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`,
      [req.user.userId, service_id]
    );
    if (bookingCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: 'You can only review services after your trip has ended.' });
    }

    const existing = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [service_id, req.user.userId]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already reviewed this destination.' });
    }

    await pool.query('INSERT INTO reviews (service_id, user_id, rating, comment) VALUES ($1, $2, $3, $4)', [service_id, req.user.userId, rating, comment || null]);
    res.status(201).json({ success: true, message: 'Review submitted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to submit review.' });
  }
});

app.get('/api/reviews/:service_id', async (req, res) => {
  const { service_id } = req.params;
  try {
    const reviews = await pool.query(`
      SELECT r.review_id, r.rating, r.comment, r.created_at, u.first_name, u.last_name, u.user_id
      FROM reviews r
      JOIN users u ON r.user_id = u.user_id
      WHERE r.service_id = $1
      ORDER BY r.created_at DESC
    `, [service_id]);

    // For each review, check if the user has a completed booking for this service
    const reviewsWithVerified = await Promise.all(reviews.rows.map(async (review) => {
      const bookingCheck = await pool.query(
        `SELECT booking_id FROM bookings 
         WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`,
        [review.user_id, service_id]
      );
      return {
        ...review,
        verified: bookingCheck.rows.length > 0
      };
    }));

    const avgResult = await pool.query('SELECT AVG(rating) as average FROM reviews WHERE service_id = $1', [service_id]);
    const average = avgResult.rows[0].average ? parseFloat(avgResult.rows[0].average).toFixed(1) : null;
    res.json({ success: true, reviews: reviewsWithVerified, average: average });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch reviews.' });
  }
});

app.get('/api/reviews/check/:service_id', authenticateCustomer, async (req, res) => {
  const { service_id } = req.params;
  try {
    const result = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [service_id, req.user.userId]);
    res.json({ success: true, reviewed: result.rows.length > 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error checking review status.' });
  }
});

// New endpoint: check if user can write a review (has completed booking and not already reviewed)
app.get('/api/reviews/can-review/:service_id', authenticateCustomer, async (req, res) => {
  const { service_id } = req.params;
  try {
    const bookingCheck = await pool.query(
      `SELECT booking_id FROM bookings 
       WHERE user_id = $1 AND service_id = $2 AND status = 'Completed'`,
      [req.user.userId, service_id]
    );
    const hasCompleted = bookingCheck.rows.length > 0;
    if (!hasCompleted) {
      return res.json({ success: true, canReview: false, reason: 'No completed booking' });
    }
    const reviewCheck = await pool.query(
      'SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2',
      [service_id, req.user.userId]
    );
    const alreadyReviewed = reviewCheck.rows.length > 0;
    res.json({ success: true, canReview: !alreadyReviewed, alreadyReviewed });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/reviews/:review_id', authenticateAdmin, async (req, res) => {
  const { review_id } = req.params;
  try {
    await pool.query('DELETE FROM reviews WHERE review_id = $1', [review_id]);
    res.json({ success: true, message: 'Review deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed.' });
  }
});

app.get('/api/admin/reviews', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.review_id, r.rating, r.comment, r.created_at,
             s.title AS destination_title,
             u.first_name || ' ' || u.last_name AS user_name
      FROM reviews r
      JOIN services s ON r.service_id = s.service_id
      JOIN users u ON r.user_id = u.user_id
      ORDER BY r.created_at DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch reviews.' });
  }
});

// ==========================================
// CHECKOUT
// ==========================================
async function generateBookingReference(client) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const reference = `ECT-${crypto.randomInt(100000, 1000000)}`;
    const existing = await client.query('SELECT booking_id FROM bookings WHERE booking_reference = $1', [reference]);
    if (existing.rows.length === 0) return reference;
  }
  throw new Error('Could not generate a unique booking reference');
}

app.post('/api/checkout', async (req, res) => {
  const { firstName, lastName, email, phone, travelDate, returnDate, pax, paymentMethod, service_id, specialRequests } = req.body;
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

  if (!cleanFirstName || !cleanLastName || !cleanEmail || !cleanPhone || !cleanTravelDate || !paxCount || !cleanPaymentMethod || !serviceId) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  if (!isValidEmail(cleanEmail)) {
    return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(cleanTravelDate)) {
    return res.status(400).json({ success: false, message: 'Invalid travel date.' });
  }
  if (cleanReturnDate && !/^\d{4}-\d{2}-\d{2}$/.test(cleanReturnDate)) {
    return res.status(400).json({ success: false, message: 'Invalid return date.' });
  }
  if (cleanReturnDate && cleanReturnDate < cleanTravelDate) {
    return res.status(400).json({ success: false, message: 'Return date cannot be before travel date.' });
  }
  if (paxCount > 10) {
    return res.status(400).json({ success: false, message: 'Please contact us for bookings above 10 guests.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let tokenUser = null;
    const token = getBearerToken(req);
    if (token) {
      try {
        tokenUser = jwt.verify(token, JWT_SECRET);
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
        const insertUser = await client.query(
          `INSERT INTO users (first_name, last_name, email, phone, password_hash, role, is_guest)
           VALUES ($1, $2, $3, $4, $5, 'customer', TRUE) RETURNING user_id`,
          [cleanFirstName, cleanLastName, cleanEmail, cleanPhone, guestPasswordHash]
        );
        finalUserId = insertUser.rows[0].user_id;
      }
    }

    const totalAmount = Number(selectedService.base_price) * paxCount;
    const bookingRef = await generateBookingReference(client);
    const insertBooking = await client.query(
      `INSERT INTO bookings (booking_reference, user_id, service_id, travel_date, return_date, pax, total_amount, status, special_requests, guest_first_name, guest_last_name, guest_email, guest_phone)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'Pending', $8, $9, $10, $11, $12) RETURNING booking_id`,
      [bookingRef, finalUserId, serviceId, cleanTravelDate, cleanReturnDate || null, paxCount, totalAmount, cleanSpecialRequests, cleanFirstName, cleanLastName, cleanEmail, cleanPhone]
    );
    const bookingId = insertBooking.rows[0].booking_id;
    await client.query(`INSERT INTO payments (booking_id, payment_method, amount, payment_status) VALUES ($1, $2, $3, 'Pending')`, [bookingId, cleanPaymentMethod, totalAmount]);
    await client.query('COMMIT');
    res.status(201).json({ success: true, message: `Booking successful! Reference: ${bookingRef}`, bookingReference: bookingRef });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Checkout error:', err);
    res.status(500).json({ success: false, message: 'Failed to process booking.' });
  } finally {
    client.release();
  }
});

// ==========================================
// PUBLIC SERVICES
// ==========================================
app.get('/api/services', async (req, res) => {
  try {
    const result = await pool.query('SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE ORDER BY service_id');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

app.get('/api/services/paginated', async (req, res) => {
  const { page, limit, offset } = getPagination(req.query, 6, 50);
  try {
    const countResult = await pool.query('SELECT COUNT(*) FROM services WHERE is_active = TRUE');
    const totalDestinations = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalDestinations / limit);
    const result = await pool.query('SELECT service_id, title, destination, base_price, max_pax, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE ORDER BY service_id LIMIT $1 OFFSET $2', [limit, offset]);
    res.json({ success: true, data: result.rows, pagination: { currentPage: page, totalPages: totalPages, totalItems: totalDestinations, limit: limit } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch destinations.' });
  }
});

// ==========================================
// CRON ENDPOINT (for cron-job.org)
// ==========================================
app.get('/api/cron/complete-bookings', (req, res) => {
  const secret = req.query.secret;
  const expectedSecret = process.env.CRON_SECRET;
  if (!expectedSecret || secret !== expectedSecret) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }
  exec('node complete-bookings.js', (error, stdout, stderr) => {
    if (error) {
      console.error(`Cron error: ${error}`);
      return res.status(500).json({ success: false, error: stderr });
    }
    console.log(`Cron output: ${stdout}`);
    res.json({ success: true, output: stdout });
  });
});

// ==========================================
// ADMIN PANEL ROUTE
// ==========================================
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==========================================
// ERROR HANDLING MIDDLEWARE
// ==========================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ==========================================
// START SERVER
// ==========================================
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});