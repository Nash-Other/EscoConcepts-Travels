// complete-bookings.js
require('dotenv').config();

const { Pool } = require('pg');

const isProduction = process.env.NODE_ENV === 'production';
const poolConfig = {
  connectionString: process.env.DATABASE_URL
};

if (isProduction || process.env.DB_SSL === 'true') {
  poolConfig.ssl = {
    rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false' ? false : true
  };
}

const pool = new Pool(poolConfig);

(async () => {
  try {
    const result = await pool.query(`
      UPDATE bookings
      SET status = 'Completed'
      WHERE status = 'Confirmed'
        AND COALESCE(return_date, travel_date) <= CURRENT_DATE
      RETURNING booking_id, booking_reference
    `);
    console.log(`Marked ${result.rowCount} booking(s) as Completed.`);
    if (result.rows.length > 0) {
      console.log('Updated references:', result.rows.map(r => r.booking_reference).join(', '));
    }
    process.exit(0);
  } catch (err) {
    console.error('Error updating bookings:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
})();
