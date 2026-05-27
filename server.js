const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Email is DISABLED for now to avoid certificate issues
// To enable email later, install nodemailer and uncomment the relevant sections

const app = express();
const port = process.env.PORT || 11037;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const JWT_SECRET = 'esco_super_secret_key_2026';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==========================================
// EMAIL DISABLED – Placeholder function
// ==========================================
async function sendBookingStatusEmail(customerEmail, customerName, bookingRef, newStatus, packageTitle) {
  // Email sending is disabled – just log the action
  console.log(`📧 [EMAIL DISABLED] Would send email to ${customerEmail} for booking ${bookingRef} status: ${newStatus}`);
  // Uncomment below and configure nodemailer when ready
  /*
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({ ... });
  await transporter.sendMail({ ... });
  */
}

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
// DATABASE INIT (with new columns for destinations)
// ==========================================
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS Users (user_id SERIAL PRIMARY KEY, first_name VARCHAR(100), last_name VARCHAR(100), email VARCHAR(255) UNIQUE NOT NULL, phone VARCHAR(20), password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS Services (service_id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, destination VARCHAR(255), base_price DECIMAL(10,2) NOT NULL, image_url TEXT, is_active BOOLEAN DEFAULT TRUE)`);
    await client.query(`CREATE TABLE IF NOT EXISTS Bookings (booking_id SERIAL PRIMARY KEY, booking_reference VARCHAR(50) UNIQUE NOT NULL, user_id INTEGER REFERENCES Users(user_id), service_id INTEGER REFERENCES Services(service_id), travel_date DATE NOT NULL, pax INTEGER NOT NULL, total_amount DECIMAL(10,2) NOT NULL, status VARCHAR(50) DEFAULT 'Pending', booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS Payments (payment_id SERIAL PRIMARY KEY, booking_id INTEGER REFERENCES Bookings(booking_id), payment_method VARCHAR(50), amount DECIMAL(10,2), payment_status VARCHAR(50) DEFAULT 'Pending', payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS blogs (id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, slug VARCHAR(255) UNIQUE, author VARCHAR(100), content TEXT, image_url TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`ALTER TABLE blogs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
    await client.query(`CREATE TABLE IF NOT EXISTS ContactMessages (id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, subject VARCHAR(255), message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

    // Add rich content columns to Services
    await client.query(`ALTER TABLE Services ADD COLUMN IF NOT EXISTS description TEXT`);
    await client.query(`ALTER TABLE Services ADD COLUMN IF NOT EXISTS itinerary TEXT`);
    await client.query(`ALTER TABLE Services ADD COLUMN IF NOT EXISTS gallery TEXT[] DEFAULT '{}'`);

    // Seed admin user
    const adminEmail = 'admin@escoconcepts.com';
    const adminCheck = await client.query('SELECT * FROM Users WHERE email = $1', [adminEmail]);
    if (adminCheck.rows.length === 0) {
      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash('admin123', salt);
      await client.query(`INSERT INTO Users (first_name, last_name, email, phone, password_hash) VALUES ($1,$2,$3,$4,$5)`, ['Esco', 'Admin', adminEmail, '0000000000', hashed]);
      console.log('✅ Admin seeded.');
    }

    // Fix NULL slugs in blogs
    await client.query(`UPDATE blogs SET slug = CONCAT(LOWER(REPLACE(title, ' ', '-')), '-', id) WHERE slug IS NULL`);

    // Seed sample destinations if empty (with description, itinerary, gallery)
    const servicesCheck = await client.query('SELECT * FROM Services LIMIT 1');
    if (servicesCheck.rows.length === 0) {
      await client.query(`INSERT INTO Services (title, destination, base_price, image_url, is_active, description, itinerary, gallery) VALUES
        ('Maasai Mara Safari', 'Maasai Mara', 45000, 'https://images.unsplash.com/photo-1516426122078-c23e76319801?w=600', TRUE, 
         '<p>Experience the greatest wildlife show on Earth. The Maasai Mara is renowned for the Great Migration, the Big Five, and breathtaking landscapes.</p>',
         '<h4>Day 1:</h4><p>Arrival and afternoon game drive.</p><h4>Day 2:</h4><p>Full day safari with picnic lunch.</p><h4>Day 3:</h4><p>Morning game drive then departure.</p>',
         ARRAY['https://images.unsplash.com/photo-1516426122078-c23e76319801?w=600','https://images.unsplash.com/photo-1547471080-7cb2ac6470b5?w=600']),
        ('Diani Beach Escape', 'Diani Beach', 35000, 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=600', TRUE,
         '<p>Crystal clear waters, white sand beaches, and vibrant coral reefs. Perfect for relaxation and water sports.</p>',
         '<h4>Day 1:</h4><p>Beach relaxation and welcome dinner.</p><h4>Day 2:</h4><p>Snorkeling and boat trip.</p><h4>Day 3:</h4><p>Leisure day or optional excursions.</p>',
         ARRAY['https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=600','https://images.unsplash.com/photo-1519046904884-53103b34b206?w=600']),
        ('Amboseli National Park', 'Amboseli', 40000, 'https://images.unsplash.com/photo-1493246507139-91e8fad9978e?w=600', TRUE,
         '<p>Famous for its large elephant herds and stunning views of Mount Kilimanjaro.</p>',
         '<h4>Day 1:</h4><p>Evening game drive.</p><h4>Day 2:</h4><p>Full day safari with visits to observation hill.</p><h4>Day 3:</h4><p>Morning game drive and departure.</p>',
         ARRAY['https://images.unsplash.com/photo-1493246507139-91e8fad9978e?w=600'])`);
      console.log('✅ Sample services with rich content inserted.');
    }
    console.log('✅ Database ready.');
  } catch (err) {
    console.error('DB init error:', err);
  } finally {
    client.release();
  }
}
initializeDatabase();

// ==========================================
// AUTH MIDDLEWARE
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

// ==========================================
// IMAGE UPLOAD
// ==========================================
app.post('/api/upload', authenticateAdmin, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'No file.' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ success: true, url });
});

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
// ADMIN LOGIN
// ==========================================
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM Users WHERE email = $1', [email]);
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
// CHECKOUT (placeholder – replace with actual logic)
// ==========================================
app.post('/api/checkout', async (req, res) => {
  res.status(200).json({ success: true, message: 'Checkout endpoint placeholder.' });
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
      FROM Bookings b
      JOIN Users u ON b.user_id = u.user_id
      JOIN Services s ON b.service_id = s.service_id
      JOIN Payments p ON b.booking_id = p.booking_id
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
  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status value.' });
  }
  let paymentStatus = 'Pending';
  if (status === 'Confirmed') paymentStatus = 'Completed';
  if (status === 'Cancelled') paymentStatus = 'Failed';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Get booking details for email (disabled, but we keep data)
    const currentBooking = await client.query(`
      SELECT b.booking_reference, b.status AS old_status, u.email, u.first_name, u.last_name, s.title AS package_title
      FROM Bookings b
      JOIN Users u ON b.user_id = u.user_id
      JOIN Services s ON b.service_id = s.service_id
      WHERE b.booking_id = $1
    `, [id]);
    if (currentBooking.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Booking not found.' });
    }
    const oldStatus = currentBooking.rows[0].old_status;
    const bookingRef = currentBooking.rows[0].booking_reference;
    const customerEmail = currentBooking.rows[0].email;
    const customerName = `${currentBooking.rows[0].first_name} ${currentBooking.rows[0].last_name}`;
    const packageTitle = currentBooking.rows[0].package_title;

    // Update booking
    const bookingResult = await client.query(
      `UPDATE Bookings SET status = $1 WHERE booking_id = $2 RETURNING *`,
      [status, id]
    );
    if (bookingResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Booking not found.' });
    }
    // Update payment
    await client.query(`UPDATE Payments SET payment_status = $1 WHERE booking_id = $2`, [paymentStatus, id]);
    await client.query('COMMIT');

    // Send email if status changed (disabled – just logs)
    if (oldStatus !== status) {
      await sendBookingStatusEmail(customerEmail, customerName, bookingRef, status, packageTitle);
    }

    res.json({ success: true, message: `Booking status updated to ${status}, payment status set to ${paymentStatus}.` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('PUT /api/bookings error:', err);
    res.status(500).json({ success: false, message: 'Failed to update booking status.' });
  } finally {
    client.release();
  }
});

// ==========================================
// PUBLIC SERVICES (for checkout & destinations page)
// ==========================================
app.get('/api/services', async (req, res) => {
  try {
    const result = await pool.query('SELECT service_id, title, destination, base_price, image_url, description, itinerary, gallery FROM Services WHERE is_active = TRUE ORDER BY service_id');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

// ==========================================
// ADMIN SERVICES CRUD (with rich fields)
// ==========================================
app.get('/api/admin/services', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM Services ORDER BY service_id');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch services.' });
  }
});

app.post('/api/admin/services', authenticateAdmin, async (req, res) => {
  const { title, destination, base_price, image_url, is_active, description, itinerary, gallery } = req.body;
  if (!title || !destination || !base_price) {
    return res.status(400).json({ success: false, message: 'Title, destination, and base price are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO Services (title, destination, base_price, image_url, is_active, description, itinerary, gallery)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
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
      `UPDATE Services SET title = $1, destination = $2, base_price = $3, image_url = $4, is_active = $5,
       description = $6, itinerary = $7, gallery = $8
       WHERE service_id = $9 RETURNING *`,
      [title, destination, base_price, image_url || null, is_active, description || null, itinerary || null, gallery || [], id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Destination not found.' });
    res.json({ success: true, message: 'Destination updated!', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to update destination.' });
  }
});

app.delete('/api/admin/services/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const checkBookings = await pool.query('SELECT COUNT(*) FROM Bookings WHERE service_id = $1', [id]);
    if (parseInt(checkBookings.rows[0].count) > 0) {
      return res.status(400).json({ success: false, message: 'Cannot delete: This destination has existing bookings. Deactivate it instead.' });
    }
    const result = await pool.query('DELETE FROM Services WHERE service_id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Destination not found.' });
    res.json({ success: true, message: 'Destination deleted!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to delete destination.' });
  }
});

// ==========================================
// BLOG ENDPOINTS (unchanged)
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
    console.error('POST /api/blogs error:', err);
    res.status(500).json({ success: false, message: 'Failed to publish. ' + err.message });
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
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Blog not found.' });
    res.json({ success: true, message: 'Updated!', data: result.rows[0] });
  } catch (err) {
    console.error('PUT /api/blogs error:', err);
    res.status(500).json({ success: false, message: 'Update failed: ' + err.message });
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
    await pool.query(`INSERT INTO ContactMessages (name, email, subject, message) VALUES ($1,$2,$3,$4)`, [name, email, subject, message]);
    res.status(201).json({ success: true, message: 'Message received.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to send.' });
  }
});

app.get('/api/contact', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM ContactMessages ORDER BY created_at DESC');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages.' });
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});