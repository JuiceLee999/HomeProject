// Run from camp/ directory: node scripts/seed.js
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const fs   = require('fs');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ...(process.env.DATABASE_URL?.includes('localhost') || process.env.DATABASE_URL?.includes('127.0.0.1')
    ? {} : { ssl: { rejectUnauthorized: false } }),
});

const PASSWORD = 'Fill1+UP-w/P0rk';

const hosts = [
  { name: 'Ray Pines',     email: 'ray.pines@himpcamp.io',     site: { title: 'Pine Ridge Tent Site',       type: 'tent',     city: 'Gatlinburg',     state: 'TN', price: 35,  guests: 6,  desc: 'Tucked beneath towering pines on a quiet ridgeline, this secluded tent site offers a firepit, stargazing, and easy trail access into the Smokies.', amenities: ['Fire Pit','Water','Hiking','Shade','Picnic Table'] } },
  { name: 'Dana Bluesky',  email: 'dana.bluesky@himpcamp.io',  site: { title: 'Blue Sky RV Resort',         type: 'rv',       city: 'Sedona',         state: 'AZ', price: 65,  guests: 4,  desc: 'Full hookup RV sites with jaw-dropping red rock views. Pull-through spots, clean restrooms, and a community fire ring.', amenities: ['Electric Hookup','Water','Flush Toilets','Fire Pit','Accessible'] } },
  { name: 'Marcus Fern',   email: 'marcus.fern@himpcamp.io',   site: { title: 'Whispering Pines Cabin',     type: 'cabin',    city: 'Whitefish',      state: 'MT', price: 120, guests: 5,  desc: 'A cozy hand-built cabin on 40 acres of Montana wilderness. Wood stove, loft bed, front porch rocking chairs, and elk sightings most mornings.', amenities: ['Fire Pit','Water','Hiking','Shade','Fishing','Picnic Table'] } },
  { name: 'Lena Oaks',     email: 'lena.oaks@himpcamp.io',     site: { title: 'Sunset Glamping Retreat',    type: 'glamping', city: 'Paso Robles',    state: 'CA', price: 185, guests: 2,  desc: 'Safari tent on a working vineyard with a king bed, Persian rugs, string lights, and a private outdoor shower. Wine tasting included.', amenities: ['WiFi','Electric Hookup','Water','Flush Toilets','Picnic Table','Shade'] } },
  { name: 'Tom Acre',      email: 'tom.acre@himpcamp.io',      site: { title: 'Rolling Hills Farm Camp',    type: 'farm',     city: 'Stowe',          state: 'VT', price: 45,  guests: 8,  desc: 'Camp on a working dairy farm surrounded by Vermont hills. Wake up to cows, collect eggs, and enjoy the local farmers market on Saturday mornings.', amenities: ['Water','Fire Pit','Picnic Table','Pets OK','Hiking'] } },
  { name: 'Sierra Red',    email: 'sierra.red@himpcamp.io',    site: { title: 'Red Rock Canyon Camp',       type: 'tent',     city: 'Moab',           state: 'UT', price: 40,  guests: 4,  desc: 'Desert tent platform with sweeping canyon views, shade ramada, and access to over 30 miles of slickrock trails right from camp.', amenities: ['Shade','Picnic Table','Hiking','Fire Pit'] } },
  { name: 'Pat Lakeview',  email: 'pat.lakeview@himpcamp.io',  site: { title: 'Lakeside RV Park',           type: 'rv',       city: 'Sister Bay',     state: 'WI', price: 70,  guests: 6,  desc: 'Waterfront RV sites on a calm bay in Door County. Kayak and canoe rentals on site, bald eagle sightings, and sunset views every night.', amenities: ['Electric Hookup','Water','Flush Toilets','Fishing','Swimming','Picnic Table'] } },
  { name: 'Jade Moss',     email: 'jade.moss@himpcamp.io',     site: { title: 'Emerald Forest Cabin',       type: 'cabin',    city: 'Ashland',        state: 'OR', price: 110, guests: 4,  desc: 'Off-grid cedar cabin buried deep in old-growth forest. Solar power, composting toilet, wood-fired hot tub, and total silence.', amenities: ['Fire Pit','Hiking','Shade','Fishing','Pets OK'] } },
  { name: 'Rosa Dell',     email: 'rosa.dell@himpcamp.io',     site: { title: 'Desert Rose Glamping',       type: 'glamping', city: 'Taos',           state: 'NM', price: 160, guests: 2,  desc: 'Adobe-inspired canvas suite with heated floors, a clawfoot tub, and a private deck for sunrise coffee over the Sangre de Cristo mountains.', amenities: ['Electric Hookup','Water','WiFi','Flush Toilets','Fire Pit'] } },
  { name: 'Will Sunfield', email: 'will.sunfield@himpcamp.io', site: { title: 'Sunflower Farm Stay',        type: 'farm',     city: 'Lawrence',       state: 'KS', price: 30,  guests: 10, desc: 'Sprawling sunflower and wheat farm with designated tent areas, a communal fire pit, and farm-to-table breakfast available as an add-on.', amenities: ['Water','Fire Pit','Picnic Table','Pets OK','Accessible'] } },
  { name: 'Kim Smoke',     email: 'kim.smoke@himpcamp.io',     site: { title: 'Smoky Mountain Basecamp',    type: 'tent',     city: 'Cherokee',       state: 'NC', price: 38,  guests: 6,  desc: 'Primitive tent sites on the edge of Cherokee National Forest. A whitewater river runs along the property -- bring your kayak.', amenities: ['Water','Fire Pit','Fishing','Swimming','Hiking','Pets OK'] } },
  { name: 'Finn Gulf',     email: 'finn.gulf@himpcamp.io',     site: { title: 'Gulf Coast RV Escape',       type: 'rv',       city: 'Destin',         state: 'FL', price: 80,  guests: 4,  desc: 'Steps from the white sand beaches of the Emerald Coast. Full hookups, outdoor shower, palm tree shade, and a short walk to the Gulf.', amenities: ['Electric Hookup','Water','Flush Toilets','Accessible','Swimming'] } },
  { name: 'Bea Cedar',     email: 'bea.cedar@himpcamp.io',     site: { title: 'Cedar Creek Cabin',          type: 'cabin',    city: 'Eureka Springs', state: 'AR', price: 95,  guests: 4,  desc: 'Rustic cabin on a bluff above Cedar Creek. Hammock porch, creek swimming hole 200 yards away, and stars so bright they will keep you up.', amenities: ['Fire Pit','Fishing','Swimming','Shade','Hiking','Pets OK'] } },
  { name: 'Cole Prairie',  email: 'cole.prairie@himpcamp.io',  site: { title: 'Prairie Star Glamping',      type: 'glamping', city: 'Rapid City',     state: 'SD', price: 145, guests: 2,  desc: 'Luxury domed tent on the open prairie with a retractable skylight for stargazing from your bed. Near Badlands and Mount Rushmore.', amenities: ['Electric Hookup','WiFi','Fire Pit','Picnic Table','Hiking'] } },
  { name: 'Ann Ridge',     email: 'ann.ridge@himpcamp.io',     site: { title: 'Blue Ridge Farm Camp',       type: 'farm',     city: 'Floyd',          state: 'VA', price: 42,  guests: 8,  desc: 'Pasture camping on a 200-acre family farm in the Blue Ridge highlands. Apple orchards, friendly goats, and incredible fall foliage.', amenities: ['Water','Fire Pit','Picnic Table','Pets OK','Hiking','Shade'] } },
  { name: 'Owen Falls',    email: 'owen.falls@himpcamp.io',    site: { title: 'Cascade Falls Camp',         type: 'tent',     city: 'North Bend',     state: 'WA', price: 44,  guests: 4,  desc: 'Lush rainforest tent pad next to a roaring waterfall in the Cascades. Moss-draped old growth, constant mist, and unbeatable scenery.', amenities: ['Water','Hiking','Fishing','Shade','Fire Pit'] } },
  { name: 'Vera Shore',    email: 'vera.shore@himpcamp.io',    site: { title: 'Big Sur Cliffside Camp',     type: 'tent',     city: 'Big Sur',        state: 'CA', price: 85,  guests: 2,  desc: 'Private clifftop tent site with direct Pacific Ocean views. Sunset dinners with a 180-degree horizon, whale watching in season, total solitude.', amenities: ['Fire Pit','Shade','Picnic Table','Hiking'] } },
  { name: 'Eli Hollow',    email: 'eli.hollow@himpcamp.io',    site: { title: 'Ozark Hollow Cabin',         type: 'cabin',    city: 'Branson',        state: 'MO', price: 88,  guests: 6,  desc: 'Stone-floor cabin in a hidden hollow with a spring-fed creek, wraparound deck, hammock grove, and a fire ring under a canopy of hardwoods.', amenities: ['Fire Pit','Fishing','Hiking','Pets OK','Shade','Picnic Table'] } },
  { name: 'Nora Haven',    email: 'nora.haven@himpcamp.io',    site: { title: 'High Desert RV Haven',       type: 'rv',       city: 'Fallon',         state: 'NV', price: 50,  guests: 4,  desc: 'Remote desert RV park under the Milky Way. Power hookups, warm showers, and absolute silence -- the closest thing to off-grid with full amenities.', amenities: ['Electric Hookup','Water','Flush Toilets','Fire Pit'] } },
  { name: 'Duke Bayou',    email: 'duke.bayou@himpcamp.io',    site: { title: 'Bayou Backyard Camp',        type: 'tent',     city: 'Breaux Bridge',  state: 'LA', price: 28,  guests: 6,  desc: 'Primitive camp on the edge of the Atchafalaya Basin. Crawfish boils on weekends, alligator tours available, and fireflies at dusk year-round.', amenities: ['Water','Fire Pit','Fishing','Picnic Table','Pets OK'] } },
];

const explorers = [
  { name: 'Alex Rivera',  email: 'alex.rivera@explorer.io'  },
  { name: 'Sam Chen',     email: 'sam.chen@explorer.io'     },
  { name: 'Jordan Blake', email: 'jordan.blake@explorer.io' },
  { name: 'Casey Moore',  email: 'casey.moore@explorer.io'  },
  { name: 'Morgan Lee',   email: 'morgan.lee@explorer.io'   },
  { name: 'Taylor Kim',   email: 'taylor.kim@explorer.io'   },
  { name: 'Quinn Davis',  email: 'quinn.davis@explorer.io'  },
  { name: 'Avery White',  email: 'avery.white@explorer.io'  },
  { name: 'Drew Santos',  email: 'drew.santos@explorer.io'  },
  { name: 'Jamie Nguyen', email: 'jamie.nguyen@explorer.io' },
];

async function run() {
  const hash = await bcrypt.hash(PASSWORD, 10);
  const lines = [];

  lines.push('============================================================');
  lines.push('            HIMPCAMP — SEED ACCOUNT CREDENTIALS            ');
  lines.push('============================================================');
  lines.push(`Password (all accounts): ${PASSWORD}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');

  lines.push('--- HOSTS (20) ---');
  lines.push('  Name               Email                              Role    Listing');
  lines.push('  ' + '-'.repeat(90));

  for (const h of hosts) {
    const u = await pool.query(
      `INSERT INTO users (email, password_hash, role, display_name)
       VALUES ($1,$2,'host',$3)
       ON CONFLICT (email) DO UPDATE SET password_hash=$2, role='host', display_name=$3
       RETURNING id`,
      [h.email, hash, h.name]
    );
    const uid = u.rows[0].id;
    const s = h.site;
    await pool.query(
      `INSERT INTO listings
         (host_id, title, description, site_type, city, state, price_per_night,
          max_guests, amenities, is_published, check_in_time, check_out_time, min_nights, max_nights)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,'15:00','11:00',1,14)`,
      [uid, s.title, s.desc, s.type, s.city, s.state, s.price, s.guests, JSON.stringify(s.amenities)]
    );
    lines.push(`  ${h.name.padEnd(18)} ${h.email.padEnd(34)} host    ${s.title}`);
    process.stdout.write('.');
  }

  lines.push('');
  lines.push('--- EXPLORERS (10) ---');
  lines.push('  Name               Email                              Role');
  lines.push('  ' + '-'.repeat(60));

  for (const e of explorers) {
    await pool.query(
      `INSERT INTO users (email, password_hash, role, display_name)
       VALUES ($1,$2,'guest',$3)
       ON CONFLICT (email) DO UPDATE SET password_hash=$2, role='guest', display_name=$3`,
      [e.email, hash, e.name]
    );
    lines.push(`  ${e.name.padEnd(18)} ${e.email.padEnd(34)} guest`);
    process.stdout.write('.');
  }

  lines.push('');
  lines.push('============================================================');
  lines.push(`Total: ${hosts.length} hosts + ${explorers.length} explorers = ${hosts.length + explorers.length} accounts`);
  lines.push('============================================================');

  await pool.end();

  const outPath = path.join(__dirname, '..', 'himpcamp_accounts.txt');
  fs.writeFileSync(outPath, lines.join('\n') + '\n');
  console.log(`\nDone! Credentials saved to ${outPath}`);
}

run().catch(e => { console.error('\nError:', e.message); process.exit(1); });
