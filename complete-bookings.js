// complete-bookings.js
require('dotenv').config();  // Load variables from .env file

const { Pool } = require('pg');

// Use the same connection settings as in server.js
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }   // Required for Supabase
});

(async () => {
  try {
    const result = await pool.query(`
      UPDATE bookings 
      SET status = 'Completed' 
      WHERE status = 'Confirmed' 
        AND COALESCE(return_date, travel_date) <= CURRENT_DATE
      RETURNING booking_id, booking_reference
    `);
    console.log(`✅ Marked ${result.rowCount} booking(s) as Completed.`);
    if (result.rows.length > 0) {
      console.log('Updated references:', result.rows.map(r => r.booking_reference).join(', '));
    }
    process.exit(0);
  } catch (err) {
    console.error('❌ Error updating bookings:', err);
    process.exit(1);
  } finally {
    await pool.end(); // Close the connection pool
  }
})();