require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('CRITICAL: DATABASE_URL environment variable is not defined.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }
});

// Reconciled Safari Packages from site.ts (Converted USD -> KES at 130 exchange rate)
const packagesSeed = [
  {
    category: 'Safari Package',
    title: 'Maasai Mara Classic',
    destination: 'Maasai Mara',
    description: 'Game drives in the world-famous Maasai Mara reserve with luxury tented camp stays. Highlights: Big Five game drives, Mara River viewpoints, Sundowner experience.',
    base_price: 166400,
    currency: 'KES',
    max_pax: 10,
    image_url: '/images/lion.jpg',
    itinerary: 'Day 1: Nairobi to Maasai Mara\nDay 2-3: Full Day Mara Game Drives\nDay 4: Morning Drive & Return to Nairobi',
    gallery: ['/images/lion.jpg', '/images/migration.jpg']
  },
  {
    category: 'Safari Expedition',
    title: 'Great Migration Expedition',
    destination: 'Mara River',
    description: "Witness the wildebeest river crossings — one of nature's most dramatic spectacles. Highlights: River crossing front-row seats, Hot-air balloon optional, Bush breakfasts.",
    base_price: 383500,
    currency: 'KES',
    max_pax: 10,
    image_url: '/images/migration.jpg',
    itinerary: 'Day 1: Arrival & Mara North Conservancy\nDay 2-5: Mara River Crossings & Game Drives\nDay 6: Conservancy Night Drives\nDay 7: Bush Breakfast & Departure',
    gallery: ['/images/migration.jpg', '/images/balloon.jpg']
  },
  {
    category: 'Safari Package',
    title: 'Amboseli & Kilimanjaro',
    destination: 'Amboseli',
    description: "Elephant herds beneath Africa's highest peak with stays at iconic eco-lodges. Highlights: Elephant research center, Observation hill, Maasai village visit.",
    base_price: 214500,
    currency: 'KES',
    max_pax: 10,
    image_url: '/images/camp.jpg',
    itinerary: 'Day 1: Nairobi to Amboseli National Park\nDay 2-4: Elephant Tracking & Observation Hill Viewpoints\nDay 5: Morning Drive & Return to Nairobi',
    gallery: ['/images/camp.jpg', '/images/maasai.jpg']
  },
  {
    category: 'Honeymoon Safari',
    title: 'Honeymoon Bush & Beach',
    destination: 'Mara & Diani Beach',
    description: 'Romantic bush safari paired with white-sand beaches on the Indian Ocean coast. Highlights: Private candlelit dinners, Dhow sunset cruise, Spa & wellness.',
    base_price: 546000,
    currency: 'KES',
    max_pax: 2,
    image_url: '/images/beach.jpg',
    itinerary: 'Day 1-4: Luxury Tented Camp in Maasai Mara\nDay 5: Direct Bush Flight to Diani Beach\nDay 6-9: Indian Ocean Beach Resort & Spa\nDay 10: Return Flight to Nairobi',
    gallery: ['/images/beach.jpg', '/images/camp.jpg']
  },
  {
    category: 'Scenic Safari',
    title: 'Rift Valley Lakes',
    destination: 'Lake Nakuru & Naivasha',
    description: "Pink flamingos, rhinos and boat rides through Kenya's spectacular Rift Valley lakes. Highlights: Crescent Island walk, Rhino sanctuary, Hells Gate biking.",
    base_price: 115700,
    currency: 'KES',
    max_pax: 10,
    image_url: '/images/flamingo.jpg',
    itinerary: 'Day 1: Nairobi to Lake Nakuru Rhino Sanctuary\nDay 2: Lake Naivasha Boat Ride & Crescent Island Sanctuary Walk\nDay 3: Hells Gate Gorge Biking & Return',
    gallery: ['/images/flamingo.jpg']
  },
  {
    category: 'Mountain Trekking',
    title: 'Mt. Kenya Trek',
    destination: 'Mt. Kenya',
    description: "Summit Point Lenana on Africa's second-highest mountain — a true adventurer's reward. Highlights: Sirimon-Chogoria route, Alpine tarns, Expert porters.",
    base_price: 253500,
    currency: 'KES',
    max_pax: 8,
    image_url: '/images/mtkenya.jpg',
    itinerary: 'Day 1: Sirimon Gate to Old Moses Camp\nDay 2: Trek to Shiptons Camp\nDay 3: Acclimatization Tarns Walk\nDay 4: Summit Point Lenana & Descent to Mintos Camp\nDay 5-6: Chogoria Bamboo Forest Route Descent',
    gallery: ['/images/mtkenya.jpg']
  }
];

// Reconciled Safari Dispatches (Blog Posts) from site.ts
const postsSeed = [
  {
    title: 'When to visit Kenya: a month-by-month guide',
    slug: 'when-to-visit-kenya-month-by-month',
    author: 'EscoConcepts Safari Dispatch Team',
    excerpt: "From dry-season game viewing to lush green seasons, here's how to time your safari.",
    content: "<h2>Timing Your East African Expedition</h2><p>From dry-season game viewing to lush green seasons, timing your safari guarantees front-row access to Kenya's greatest wildlife spectacles.</p><h3>The Great Migration Window (July – October)</h3><p>During these peak months, over 1.5 million wildebeest cross the Mara River in search of green pastures. Bookings must be secured at least six months in advance.</p>",
    image_url: '/images/balloon.jpg',
    created_at: '2026-04-12T08:00:00Z'
  },
  {
    title: 'The honest safari packing list',
    slug: 'honest-safari-packing-list',
    author: 'EscoConcepts Field Guides',
    excerpt: 'Everything you actually need — and the gear you can leave at home.',
    content: "<h2>What to Actually Pack for Kenya</h2><p>Packing for safari doesn't mean buying head-to-toe tactical camouflage. Here is what our veteran guides recommend bringing to the bush:</p><ul><li>Lightweight neutral cotton layers (olive, khaki, brown)</li><li>Polarized sunglasses and wide-brimmed safari hat</li><li>High-grade binoculars (8x42 or 10x42)</li><li>High SPF sunscreen and insect repellent</li></ul>",
    image_url: '/images/camp.jpg',
    created_at: '2026-03-02T08:00:00Z'
  },
  {
    title: 'How we practice responsible travel',
    slug: 'how-we-practice-responsible-travel',
    author: 'EscoConcepts Conservation Mandate',
    excerpt: 'Our commitments to conservation, communities and low-impact journeys.',
    content: "<h2>Preserving Our Wilderness</h2><p>True eco-tourism means ensuring that every Kenyan Shilling invested in your safari directly preserves our ecosystems and uplifts local Maasai and Samburu communities.</p><p>All EscoConcepts game drive cruisers enforce a strict zero-single-use-plastic policy, utilizing stainless steel water stations throughout game drives.</p>",
    image_url: '/images/maasai.jpg',
    created_at: '2026-02-08T08:00:00Z'
  }
];

async function executeSeeding() {
  const client = await pool.connect();
  console.log('◇ Connected to Supabase PostgreSQL pooler...');

  try {
    await client.query('BEGIN');

    // Ensure excerpt column exists on blogs table
    await client.query(`ALTER TABLE blogs ADD COLUMN IF NOT EXISTS excerpt TEXT`);

    console.log('\n--- Seeding Safari Packages ---');
    for (const pkg of packagesSeed) {
      // Idempotency Gatekeeper: Check existence by title to prevent duplicates
      const check = await client.query(`SELECT service_id FROM services WHERE title = $1 LIMIT 1`, [pkg.title]);

      if (check.rows.length > 0) {
        const existingId = check.rows[0].service_id;
        await client.query(`
          UPDATE services 
          SET service_category = $1, destination = $2, description = $3, base_price = $4, currency = $5, max_pax = $6, image_url = $7, itinerary = $8, gallery = $9, is_active = true
          WHERE service_id = $10
        `, [pkg.category, pkg.destination, pkg.description, pkg.base_price, pkg.currency, pkg.max_pax, pkg.image_url, pkg.itinerary, pkg.gallery, existingId]);
        console.log(`✔ Updated existing Package: "${pkg.title}" [KES ${Number(pkg.base_price).toLocaleString()}]`);
      } else {
        await client.query(`
          INSERT INTO services (service_category, title, destination, description, base_price, currency, max_pax, image_url, itinerary, gallery, is_active)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
        `, [pkg.category, pkg.title, pkg.destination, pkg.description, pkg.base_price, pkg.currency, pkg.max_pax, pkg.image_url, pkg.itinerary, pkg.gallery]);
        console.log(`✔ Inserted Package: "${pkg.title}" [KES ${Number(pkg.base_price).toLocaleString()}]`);
      }
    }

    console.log('\n--- Seeding Safari Dispatches (Blogs) ---');
    for (const post of postsSeed) {
      await client.query(`
        INSERT INTO blogs (title, slug, author, excerpt, content, image_url, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (slug) DO UPDATE 
        SET title = EXCLUDED.title, author = EXCLUDED.author, excerpt = EXCLUDED.excerpt, content = EXCLUDED.content, image_url = EXCLUDED.image_url
      `, [post.title, post.slug, post.author, post.excerpt, post.content, post.image_url, post.created_at]);

      console.log(`✔ Upserted Dispatch: "${post.title}"`);
    }

    await client.query('COMMIT');
    console.log('\n★ Database seeding completed successfully.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('✖ Seeding transaction failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

executeSeeding();