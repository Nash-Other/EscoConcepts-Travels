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

const app = express();
const port = process.env.PORT || 11037;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const JWT_SECRET = process.env.JWT_SECRET || 'esco_super_secret_key_2026';
const APP_URL = process.env.APP_URL || 'https://your-app.onrender.com';

// Email setup
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';

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

// Database connection
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
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'blog-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif|webp/;
  const ext = allowed.test(path.extname(file.originalname).toLowerCase());
  const mime = allowed.test(file.mimetype);
  if (ext && mime) cb(null, true);
  else cb(new Error('Only images allowed'));
};

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });

// ==========================================
// DATABASE INIT (creates all tables including reviews)
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

    // Reviews table
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

    // Ensure admin exists
    await client.query(`
      INSERT INTO users (first_name, last_name, email, phone, password_hash, role)
      VALUES ('Esco', 'Admin', 'admin@escoconcepts.com', '0000000000', '$2b$10$sEvVRz6qou8z8GFzfck3MuwTQmDRj7XAYmLOeyZHQhEKggcgciZSW', 'admin')
      ON CONFLICT (email) DO NOTHING
    `);

    console.log('✅ Database ready.');
  } catch (err) {
    console.error('DB init error:', err);
  } finally {
    client.release();
  }
}
initializeDatabase();

// ==========================================
// HELPER: generate unique slug for blogs
// ==========================================
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
// AUTH MIDDLEWARES
// ==========================================
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
    if (user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
    req.user = user;
    next();
  });
}

function authenticateCustomer(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
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
app.post('/api/auth/forgot-password', async (req, res) => {
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
      <p>Hello ${user.rows[0].first_name || 'there'},</p>
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

app.post('/api/auth/reset-password', async (req, res) => {
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
// CUSTOMER AUTH (signup, login, profile)
// ==========================================
app.post('/api/auth/signup', async (req, res) => {
  const { firstName, lastName, email, phone, password } = req.body;
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  try {
    const existing = await pool.query('SELECT user_id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, 'customer') RETURNING user_id`,
      [firstName, lastName, email, phone || null, hashedPassword]
    );
    const token = jwt.sign({ userId: result.rows[0].user_id, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ success: true, message: 'Signup successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
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
    const result = await pool.query(
      'SELECT user_id, first_name, last_name, email, phone, role FROM users WHERE user_id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
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
      `UPDATE users 
       SET first_name = $1, last_name = $2, phone = $3, email = $4 
       WHERE user_id = $5 
       RETURNING user_id, first_name, last_name, email, phone, role`,
      [firstName, lastName, phone || null, email, userId]
    );
    await client.query('COMMIT');
    const updatedUser = result.rows[0];
    const newToken = jwt.sign(
      { userId: updatedUser.user_id, email: updatedUser.email, role: updatedUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      success: true,
      message: 'Profile updated successfully.',
      user: updatedUser,
      token: newToken
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Profile update error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally {
    client.release();
  }
});

// ==========================================
// MY BOOKINGS (customer)
// ==========================================
app.get('/api/bookings/my-bookings', authenticateCustomer, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.booking_id, b.booking_reference, s.title AS package_name, b.travel_date, b.pax, b.total_amount, b.status, b.booking_date
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

// ==========================================
// CUSTOMER CANCEL BOOKING
// ==========================================
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
        <p>Hello ${customer.rows[0].first_name},</p>
        <p>Your booking <strong>${booking.rows[0].booking_reference}</strong> for <strong>${booking.rows[0].package_title}</strong> has been cancelled.</p>
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

// ==========================================
// SEND RECEIPT EMAIL
// ==========================================
app.post('/api/bookings/receipt/:id', authenticateCustomer, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`
      SELECT b.booking_reference, b.travel_date, b.pax, b.total_amount, b.status, b.booking_date,
             s.title as package_title, s.destination,
             u.first_name, u.last_name, u.email
      FROM bookings b
      JOIN services s ON b.service_id = s.service_id
      JOIN users u ON b.user_id = u.user_id
      WHERE b.booking_id = $1 AND b.user_id = $2
    `, [id, req.user.userId]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Booking not found.' });
    const booking = result.rows[0];
    const html = `
      <h2>Your Booking Receipt</h2>
      <p><strong>Reference:</strong> ${booking.booking_reference}</p>
      <p><strong>Package:</strong> ${booking.package_title}</p>
      <p><strong>Destination:</strong> ${booking.destination}</p>
      <p><strong>Travel Date:</strong> ${new Date(booking.travel_date).toLocaleDateString()}</p>
      <p><strong>Guests:</strong> ${booking.pax}</p>
      <p><strong>Total:</strong> KES ${Number(booking.total_amount).toLocaleString()}</p>
      <p><strong>Status:</strong> ${booking.status}</p>
      <p><strong>Booked On:</strong> ${new Date(booking.booking_date).toLocaleString()}</p>
      <p>Thank you for choosing EscoConcepts Travels.</p>
    `;
    await sendEmail(booking.email, `Your Booking Receipt – ${booking.booking_reference}`, html);
    res.json({ success: true, message: 'Receipt sent to your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to send receipt.' });
  }
});

// ==========================================
// SEARCH SERVICES (public)
// ==========================================
app.get('/api/services/search', async (req, res) => {
  const { location, minPrice, maxPrice, guests } = req.query;
  let query = 'SELECT service_id, title, destination, base_price, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE';
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

// ==========================================
// TEST DB
// ==========================================
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
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
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

// ==========================================
// IMAGE UPLOAD (admin only)
// ==========================================
app.post('/api/upload', authenticateAdmin, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'No file.' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ success: true, url });
});

// ==========================================
// BOOKINGS (admin)
// ==========================================
app.get('/api/bookings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.booking_id, b.booking_reference,
             u.first_name || ' ' || u.last_name AS customer_name,
             u.email, u.phone, s.title AS package_booked,
             b.travel_date, b.pax AS total_guests,
             p.payment_method, b.total_amount, b.booking_date, b.status
      FROM bookings b
      JOIN users u ON b.user_id = u.user_id
      JOIN services s ON b.service_id = s.service_id
      JOIN payments p ON b.booking_id = p.booking_id
      ORDER BY b.booking_date DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch bookings.' });
  }
});

app.put('/api/bookings/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const allowedStatuses = ['Pending', 'Confirmed', 'Cancelled'];
  if (!allowedStatuses.includes(status)) return res.status(400).json({ success: false, message: 'Invalid status.' });
  
  let paymentStatus = 'Pending';
  if (status === 'Confirmed') paymentStatus = 'Completed';
  if (status === 'Cancelled') paymentStatus = 'Failed';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query(`
      SELECT b.status as old_status, u.email, u.first_name, u.last_name, b.booking_reference, s.title as package_title
      FROM bookings b
      JOIN users u ON b.user_id = u.user_id
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
      const statusText = status === 'Confirmed' ? 'confirmed ✅' : (status === 'Cancelled' ? 'cancelled ❌' : 'pending ⏳');
      const subject = `Booking ${statusText} – ${bookingRef}`;
      const html = `
        <h2>Hello ${customerName},</h2>
        <p>Your booking <strong>${bookingRef}</strong> for <strong>${packageTitle}</strong> has been <strong>${statusText}</strong>.</p>
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
// CHECKOUT (guest or logged‑in user)
// ==========================================
app.post('/api/checkout', async (req, res) => {
  const { firstName, lastName, email, phone, travelDate, pax, totalAmount, paymentMethod, service_id, userId } = req.body;
  if (!firstName || !lastName || !email || !phone || !travelDate || !pax || !totalAmount || !paymentMethod || !service_id) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let finalUserId = userId;
    if (!finalUserId) {
      const userCheck = await client.query('SELECT user_id FROM users WHERE email = $1', [email]);
      if (userCheck.rows.length > 0) {
        finalUserId = userCheck.rows[0].user_id;
      } else {
        const insertUser = await client.query(
          `INSERT INTO users (first_name, last_name, email, phone, password_hash, role)
           VALUES ($1, $2, $3, $4, $5, 'customer') RETURNING user_id`,
          [firstName, lastName, email, phone, 'guest_checkout_no_password']
        );
        finalUserId = insertUser.rows[0].user_id;
      }
    }
    const bookingRef = 'ECT-' + Math.floor(100000 + Math.random() * 900000);
    const insertBooking = await client.query(
      `INSERT INTO bookings (booking_reference, user_id, service_id, travel_date, pax, total_amount, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'Pending') RETURNING booking_id`,
      [bookingRef, finalUserId, service_id, travelDate, pax, totalAmount]
    );
    const bookingId = insertBooking.rows[0].booking_id;
    await client.query(
      `INSERT INTO payments (booking_id, payment_method, amount, payment_status)
       VALUES ($1, $2, $3, 'Pending')`,
      [bookingId, paymentMethod, totalAmount]
    );
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
// PUBLIC SERVICES (no filters)
// ==========================================
app.get('/api/services', async (req, res) => {
  try {
    const result = await pool.query('SELECT service_id, title, destination, base_price, image_url, description, itinerary, gallery FROM services WHERE is_active = TRUE ORDER BY service_id');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

// ==========================================
// ADMIN SERVICES CRUD
// ==========================================
app.get('/api/admin/services', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM services ORDER BY service_id');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

app.post('/api/admin/services', authenticateAdmin, async (req, res) => {
  const { title, destination, base_price, image_url, is_active, description, itinerary, gallery } = req.body;
  if (!title || !destination || !base_price) return res.status(400).json({ success: false, message: 'Missing fields.' });
  try {
    const result = await pool.query(
      `INSERT INTO services (title, destination, base_price, image_url, is_active, description, itinerary, gallery)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [title, destination, base_price, image_url || null, is_active !== undefined ? is_active : true, description || null, itinerary || null, gallery || []]
    );
    res.status(201).json({ success: true, message: 'Destination added!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to add destination.' });
  }
});

app.put('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, destination, base_price, image_url, is_active, description, itinerary, gallery } = req.body;
  try {
    const result = await pool.query(
      `UPDATE services SET title=$1, destination=$2, base_price=$3, image_url=$4, is_active=$5,
       description=$6, itinerary=$7, gallery=$8 WHERE service_id=$9 RETURNING *`,
      [title, destination, base_price, image_url || null, is_active, description || null, itinerary || null, gallery || [], id]
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
// REVIEWS ENDPOINTS
// ==========================================
// 2.1 Submit a review (POST)
app.post('/api/reviews', authenticateCustomer, async (req, res) => {
  const { service_id, rating, comment } = req.body;
  if (!service_id || !rating || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: 'Service ID and rating (1-5) required.' });
  }
  try {
    const existing = await pool.query('SELECT review_id FROM reviews WHERE service_id = $1 AND user_id = $2', [service_id, req.user.userId]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already reviewed this destination.' });
    }
    await pool.query(
      'INSERT INTO reviews (service_id, user_id, rating, comment) VALUES ($1, $2, $3, $4)',
      [service_id, req.user.userId, rating, comment || null]
    );
    res.status(201).json({ success: true, message: 'Review submitted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to submit review.' });
  }
});

// 2.2 Get reviews for a destination (GET)
app.get('/api/reviews/:service_id', async (req, res) => {
  const { service_id } = req.params;
  try {
    const reviews = await pool.query(`
      SELECT r.rating, r.comment, r.created_at, u.first_name, u.last_name
      FROM reviews r
      JOIN users u ON r.user_id = u.user_id
      WHERE r.service_id = $1
      ORDER BY r.created_at DESC
    `, [service_id]);
    const avgResult = await pool.query('SELECT AVG(rating) as average FROM reviews WHERE service_id = $1', [service_id]);
    const average = avgResult.rows[0].average ? parseFloat(avgResult.rows[0].average).toFixed(1) : null;
    res.json({ success: true, reviews: reviews.rows, average: average });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch reviews.' });
  }
});

// Check if user has already reviewed a destination (used by frontend)
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

// 2.3 Delete a review (admin only)
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

// ==========================================
// ADMIN GET ALL REVIEWS (missing endpoint)
// ==========================================
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
// BLOG ENDPOINTS (pagination)
// ==========================================
app.get('/api/blogs', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 6;
  const offset = (page - 1) * limit;
  try {
    const result = await pool.query('SELECT * FROM blogs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const countResult = await pool.query('SELECT COUNT(*) FROM blogs');
    const totalBlogs = parseInt(countResult.rows[0].count);
    res.json({
      blogs: result.rows,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalBlogs / limit),
        totalBlogs: totalBlogs,
        limit: limit
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch blogs.' });
  }
});

app.get('/api/blogs/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM blogs WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Not found.' });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/blogs', authenticateAdmin, async (req, res) => {
  const { title, author, content, image_url } = req.body;
  try {
    const slug = await generateUniqueSlug(title);
    const result = await pool.query(
      `INSERT INTO blogs (title, slug, author, content, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [title, slug, author, content, image_url]
    );
    res.status(201).json({ success: true, message: 'Published!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to publish.' });
  }
});

app.put('/api/blogs/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, author, content, image_url } = req.body;
  try {
    const slug = await generateUniqueSlug(title, id);
    const result = await pool.query(
      `UPDATE blogs SET title=$1, slug=$2, author=$3, content=$4, image_url=$5, updated_at=CURRENT_TIMESTAMP WHERE id=$6 RETURNING *`,
      [title, slug, author, content, image_url, id]
    );
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
// CONTACT MESSAGES
// ==========================================
app.post('/api/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ success: false, message: 'Missing fields.' });
  try {
    await pool.query(`INSERT INTO contactmessages (name, email, subject, message) VALUES ($1,$2,$3,$4)`, [name, email, subject, message]);
    res.status(201).json({ success: true, message: 'Message received.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to send.' });
  }
});

app.get('/api/contact', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contactmessages ORDER BY created_at DESC');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages.' });
  }
});

// ==========================================
// START SERVER
// ==========================================
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});