const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 11037;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const JWT_SECRET = process.env.JWT_SECRET || 'esco_super_secret_key_2026';

// Database connection – uses DATABASE_URL from environment
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
// DATABASE INIT (creates tables if missing)
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS services (
      service_id SERIAL PRIMARY KEY,
      service_category VARCHAR(50) NOT NULL,
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
      payment_status VARCHAR(20) DEFAULT 'Completed',
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

    // Insert admin if missing (email matches your database)
    await client.query(`
      INSERT INTO users (first_name, last_name, email, phone, password_hash)
      VALUES ('Esco', 'Admin', 'admin@escoconcepts.com', '0000000000', '$2b$10$sEvVRz6qou8z8GFzfck3MuwTQmDRj7XAYmLOeyZHQhEKggcgciZSW')
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
// TEST DATABASE CONNECTION ENDPOINT
// ==========================================
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ success: true, message: 'Database connected', time: result.rows[0].time });
  } catch (err) {
    console.error('DB test error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// AUTHENTICATION
// ==========================================
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const token = jwt.sign({ role: 'admin', userId: user.user_id }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ==========================================
// IMAGE UPLOAD
// ==========================================
app.post('/api/upload', authenticateAdmin, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'No file.' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ success: true, url });
});

// ==========================================
// BOOKINGS (GET & UPDATE)
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
    const bookingResult = await client.query(`UPDATE bookings SET status = $1 WHERE booking_id = $2 RETURNING *`, [status, id]);
    if (bookingResult.rows.length === 0) throw new Error('Booking not found');
    await client.query(`UPDATE payments SET payment_status = $1 WHERE booking_id = $2`, [paymentStatus, id]);
    await client.query('COMMIT');
    res.json({ success: true, message: `Status updated to ${status}` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed.' });
  } finally {
    client.release();
  }
});

// ==========================================
// SERVICES (public)
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
// BLOG ENDPOINTS (with unique slug generator)
// ==========================================
app.get('/api/blogs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blogs ORDER BY created_at DESC');
    res.json(result.rows);
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
// CHECKOUT (placeholder)
// ==========================================
app.post('/api/checkout', async (req, res) => {
  res.status(200).json({ success: true, message: 'Checkout placeholder.' });
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});