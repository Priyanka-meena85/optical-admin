const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

let DB_PATH = path.join(__dirname, 'sharma_optical.db');

// Vercel Serverless environment: /var/task is read-only, copy db to writable /tmp
if (process.env.VERCEL) {
  const tmpPath = path.join('/tmp', 'optical_hub.db');
  try {
    if (!fs.existsSync(tmpPath)) {
      if (fs.existsSync(DB_PATH)) {
        fs.copyFileSync(DB_PATH, tmpPath);
      }
    }
    DB_PATH = tmpPath;
  } catch (err) {
    console.warn('[Vercel] Warning copying SQLite to /tmp:', err.message);
  }
}

const db = new sqlite3.Database(DB_PATH);

// Helper for promise-based queries
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function initDB() {
  // Enforce foreign key constraints
  await run('PRAGMA foreign_keys = ON');

  // 1. Users Table (Auth, Roles, MFA)
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('owner', 'staff')) NOT NULL,
      full_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2. Frames Inventory Table
  await run(`
    CREATE TABLE IF NOT EXISTS frames (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sku TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      brand TEXT NOT NULL,
      category TEXT CHECK(category IN ('Gents', 'Ladies', 'Kids', 'Sunglasses')) NOT NULL,
      shape TEXT DEFAULT 'Modern',
      material TEXT DEFAULT 'Acetate',
      cost_price INTEGER NOT NULL,
      selling_price INTEGER NOT NULL,
      stock INTEGER NOT NULL DEFAULT 5,
      image_url TEXT,
      tag TEXT DEFAULT 'Trending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 3. Lens Stock Table
  await run(`
    CREATE TABLE IF NOT EXISTS lens_stock (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      lens_type TEXT UNIQUE NOT NULL,
      stock INTEGER NOT NULL DEFAULT 20,
      cost_price INTEGER NOT NULL,
      selling_price INTEGER NOT NULL
    )
  `);

  // 4. Customers Table
  await run(`
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      area TEXT DEFAULT 'Bhiwadi',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 5. Prescriptions Table (Sensitive Protected Health Information)
  await run(`
    CREATE TABLE IF NOT EXISTS prescriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      customer_phone TEXT NOT NULL,
      exam_date DATE NOT NULL,
      right_sph TEXT NOT NULL,
      right_cyl TEXT NOT NULL,
      right_axis TEXT NOT NULL,
      left_sph TEXT NOT NULL,
      left_cyl TEXT NOT NULL,
      left_axis TEXT NOT NULL,
      add_power TEXT DEFAULT '+0.00',
      pd TEXT DEFAULT '63mm',
      notes TEXT,
      doctor_name TEXT DEFAULT 'Dr. R. K. Sharma (B.Optom)',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
    )
  `);

  // 6. Eye Test Appointments
  await run(`
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_id TEXT UNIQUE NOT NULL,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      appointment_date DATE NOT NULL,
      time_slot TEXT NOT NULL,
      concern TEXT DEFAULT 'Routine Checkup',
      status TEXT CHECK(status IN ('Upcoming', 'Confirmed', 'Completed', 'Cancelled')) DEFAULT 'Upcoming',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 7. Orders & Billing
  await run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_number TEXT UNIQUE NOT NULL,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      frame_name TEXT NOT NULL,
      frame_price INTEGER NOT NULL,
      lens_type TEXT NOT NULL,
      lens_price INTEGER NOT NULL,
      coatings_json TEXT DEFAULT '[]',
      total_amount INTEGER NOT NULL,
      advance_paid INTEGER NOT NULL,
      pending_amount INTEGER NOT NULL,
      payment_status TEXT CHECK(payment_status IN ('Paid', 'Advance', 'Udhaar')) NOT NULL,
      order_status TEXT CHECK(order_status IN ('Order Taken', 'Fitting', 'Ready', 'Delivered')) DEFAULT 'Order Taken',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 8. Frame Repairs
  await run(`
    CREATE TABLE IF NOT EXISTS repairs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id TEXT UNIQUE NOT NULL,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      problem_type TEXT NOT NULL,
      photo_path TEXT,
      status TEXT CHECK(status IN ('Raised', 'Repairing', 'Ready', 'Delivered')) DEFAULT 'Raised',
      estimated_cost INTEGER DEFAULT 150,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 9. Security Audit Logs Table
  await run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      user_role TEXT NOT NULL,
      ip_address TEXT,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create fast lookup indexes
  await run('CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone)');
  await run('CREATE INDEX IF NOT EXISTS idx_prescriptions_phone ON prescriptions(customer_phone)');
  await run('CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(customer_phone)');
  await run('CREATE INDEX IF NOT EXISTS idx_bookings_date ON bookings(appointment_date)');

  // Seed default data if empty
  await seedInitialData();
}

async function seedInitialData() {
  const userCount = await get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    // Salt & hash passwords with bcrypt
    const saltRounds = 12;
    const ownerHash = bcrypt.hashSync('OpticalHub@Jaipur2026', saltRounds);
    const staffHash = bcrypt.hashSync('Staff@Optic2026', saltRounds);

    // Default Owner with MFA enabled (simulated secret)
    await run(
      'INSERT INTO users (username, password_hash, role, full_name, phone, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['owner', ownerHash, 'owner', 'Sunil Kumar (Store Owner)', '9876543210', 'MFA_OPTICAL_SECRET_KEY', 1]
    );

    // Default Counter Staff (Masked cost view)
    await run(
      'INSERT INTO users (username, password_hash, role, full_name, phone, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['staff', staffHash, 'staff', 'Ramesh Kumar', '9812345678', null, 0]
    );
  }

  const frameCount = await get('SELECT COUNT(*) as count FROM frames');
  if (frameCount.count === 0) {
    const defaultFrames = [
      ['SKU-1001', 'Imperial Wayfarer Bold', 'Ray-Lite', 'Gents', 'Wayfarer', 'Handcrafted Acetate', 850, 1899, 8, 'https://images.unsplash.com/photo-1591076482161-42ce6da69f67?auto=format&fit=crop&w=600&q=80', 'Italian Acetate'],
      ['SKU-1002', 'Vintage Round Wire', 'Titan Vista', 'Gents', 'Round', 'Feather-light Titanium', 1100, 2499, 2, 'https://images.unsplash.com/photo-1574258495973-f010dfbb5371?auto=format&fit=crop&w=600&q=80', 'Pure Titanium'],
      ['SKU-1003', 'Cat-Eye Elegance Gold', 'Vogue Star', 'Ladies', 'Cat-Eye', 'Rose Gold Alloy', 950, 2199, 2, 'https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=600&q=80', 'Bestseller'],
      ['SKU-1004', 'Executive Half-Rim Aviator', 'Hub Signature', 'Gents', 'Aviator', 'Monel Metal', 750, 1699, 7, 'https://images.unsplash.com/photo-1577803645773-f96470509666?auto=format&fit=crop&w=600&q=80', 'Formal Classic'],
      ['SKU-1005', 'Junior Flexi-Bend Blue', 'KidsSafe', 'Kids', 'Rectangle', 'Flexible Swiss TR90', 500, 1199, 2, 'https://images.unsplash.com/photo-1508296695146-257a814070b4?auto=format&fit=crop&w=600&q=80', 'Unbreakable TR90'],
      ['SKU-1006', 'Polarized Clubmaster', 'Fastrack Elite', 'Sunglasses', 'Clubmaster', 'Acetate & Metal', 1300, 2899, 6, 'https://images.unsplash.com/photo-1508296695146-257a814070b4?auto=format&fit=crop&w=600&q=80', 'UV400 Polarized'],
      ['SKU-1007', 'Minimalist Rimless Executive', 'Silhouette Style', 'Gents', 'Rimless', 'Beta Titanium', 1600, 3499, 1, 'https://images.unsplash.com/photo-1591076482161-42ce6da69f67?auto=format&fit=crop&w=600&q=80', 'Ultra Lightweight'],
      ['SKU-1008', 'Soft Pastel Butterfly', 'Vogue Star', 'Ladies', 'Butterfly', 'Crystal Acetate', 850, 1999, 5, 'https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=600&q=80', 'Trending']
    ];

    for (const f of defaultFrames) {
      await run(
        'INSERT INTO frames (sku, name, brand, category, shape, material, cost_price, selling_price, stock, image_url, tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        f
      );
    }
  }

  const lensCount = await get('SELECT COUNT(*) as count FROM lens_stock');
  if (lensCount.count === 0) {
    await run('INSERT INTO lens_stock (lens_type, stock, cost_price, selling_price) VALUES (?, ?, ?, ?)', ['Blue-Cut Digital', 20, 320, 800]);
    await run('INSERT INTO lens_stock (lens_type, stock, cost_price, selling_price) VALUES (?, ?, ?, ?)', ['Progressive Multifocal', 10, 650, 1500]);
    await run('INSERT INTO lens_stock (lens_type, stock, cost_price, selling_price) VALUES (?, ?, ?, ?)', ['Normal Anti-Glare', 50, 120, 0]);
    await run('INSERT INTO lens_stock (lens_type, stock, cost_price, selling_price) VALUES (?, ?, ?, ?)', ['Photochromic Transitions', 16, 420, 950]);
  }

  const custCount = await get('SELECT COUNT(*) as count FROM customers');
  if (custCount.count === 0) {
    // Seed Sunita Meena
    const r1 = await run('INSERT INTO customers (name, phone, area) VALUES (?, ?, ?)', ['Sunita Meena', '9812345678', 'Ashiana Angan, Bhiwadi']);
    const c1Id = r1.lastID;
    await run(
      'INSERT INTO prescriptions (customer_id, customer_phone, exam_date, right_sph, right_cyl, right_axis, left_sph, left_cyl, left_axis, add_power, pd, notes, doctor_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [c1Id, '9812345678', '2026-11-23', '-1.00', '-0.25', '90', '-1.00', '-0.25', '90', '+0.00', '62mm', 'Mild screen fatigue, prescribed Blue-Cut', 'Dr. R. K. Sharma (B.Optom)']
    );
    await run(
      'INSERT INTO prescriptions (customer_id, customer_phone, exam_date, right_sph, right_cyl, right_axis, left_sph, left_cyl, left_axis, add_power, pd, notes, doctor_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [c1Id, '9812345678', '2025-05-10', '-0.75', '0.00', '-', '-0.75', '0.00', '-', '+0.00', '62mm', 'Previous checkup', 'Dr. R. K. Sharma (B.Optom)']
    );
    await run(
      'INSERT INTO prescriptions (customer_id, customer_phone, exam_date, right_sph, right_cyl, right_axis, left_sph, left_cyl, left_axis, add_power, pd, notes, doctor_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [c1Id, '9812345678', '2024-02-15', '-0.50', '0.00', '-', '-0.50', '0.00', '-', '+0.00', '62mm', 'Initial baseline exam', 'Dr. R. K. Sharma (B.Optom)']
    );

    // Seed Rohit Khandelwal
    const r2 = await run('INSERT INTO customers (name, phone, area) VALUES (?, ?, ?)', ['Rohit Khandelwal', '9811223344', 'UIT Sector 2, Bhiwadi']);
    await run(
      'INSERT INTO prescriptions (customer_id, customer_phone, exam_date, right_sph, right_cyl, right_axis, left_sph, left_cyl, left_axis, add_power, pd, notes, doctor_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [r2.lastID, '9811223344', '2026-11-24', '-2.00', '-0.75', '100', '-1.75', '-0.50', '80', '+0.00', '64mm', 'Astigmatism corrected', 'Dr. R. K. Sharma (B.Optom)']
    );
  }

  const orderCount = await get('SELECT COUNT(*) as count FROM orders');
  if (orderCount.count === 0) {
    await run(
      'INSERT INTO orders (order_number, customer_name, customer_phone, frame_name, frame_price, lens_type, lens_price, coatings_json, total_amount, advance_paid, pending_amount, payment_status, order_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['SO/2026/089', 'Rohit Khandelwal', '9811223344', 'Imperial Wayfarer Bold', 1899, 'Blue-Cut Digital Protection Lens', 800, '["Diamond Hard Coat (+₹250)"]', 2949, 1500, 1449, 'Advance', 'Fitting']
    );
    await run(
      'INSERT INTO orders (order_number, customer_name, customer_phone, frame_name, frame_price, lens_type, lens_price, coatings_json, total_amount, advance_paid, pending_amount, payment_status, order_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['SO/2026/088', 'Anita Gupta', '9822334455', 'Cat-Eye Elegance Gold', 2199, 'Progressive Multifocal Lens', 1500, '["Hydrophobic Oleophobic (+₹400)", "Photochromic (+₹950)"]', 5049, 5049, 0, 'Paid', 'Ready']
    );
    await run(
      'INSERT INTO orders (order_number, customer_name, customer_phone, frame_name, frame_price, lens_type, lens_price, coatings_json, total_amount, advance_paid, pending_amount, payment_status, order_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['SO/2026/087', 'Deepak Chawla', '9833445566', 'Vintage Round Wire', 2499, 'Normal / Anti-Glare Lens', 0, '[]', 2499, 0, 2499, 'Udhaar', 'Delivered']
    );
    await run(
      'INSERT INTO orders (order_number, customer_name, customer_phone, frame_name, frame_price, lens_type, lens_price, coatings_json, total_amount, advance_paid, pending_amount, payment_status, order_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['SO/2026/086', 'Sanjay Yadav', '9899887766', 'Executive Half-Rim Aviator', 1699, 'Normal / Anti-Glare Lens', 0, '["Diamond Hard Coat (+₹250)"]', 1949, 1949, 0, 'Paid', 'Delivered']
    );
  }

  const bookingCount = await get('SELECT COUNT(*) as count FROM bookings');
  if (bookingCount.count === 0) {
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-101', 'Sunita Meena', '9812345678', '2026-11-24', '11:00 AM', 'Digital Eye Strain & Headache', 'Confirmed']
    );
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-102', 'Harish Verma', '9823456789', '2026-11-24', '04:00 PM', 'Regular Power Renewal', 'Upcoming']
    );
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-103', 'Vikram Yadav', '9899112233', '2026-11-23', '12:00 PM', 'Blurry Distance Vision', 'Completed']
    );
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-104', 'Kavita Rao', '9876543210', '2026-11-24', '05:00 PM', 'Digital Eye Strain', 'Upcoming']
    );
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-105', 'Rajesh Mehra', '9811447788', '2026-11-24', '12:00 PM', 'Reading Blur', 'Completed']
    );
    await run(
      'INSERT INTO bookings (token_id, customer_name, customer_phone, appointment_date, time_slot, concern, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['BK-106', 'Aakash Goyal', '9811556677', '2026-11-24', '11:00 AM', 'Routine Checkup', 'Completed']
    );
  }

  const repairCount = await get('SELECT COUNT(*) as count FROM repairs');
  if (repairCount.count === 0) {
    await run(
      'INSERT INTO repairs (ticket_id, customer_name, customer_phone, problem_type, status, estimated_cost, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['REP-1042', 'Kavita Rao', '9876543210', 'Broken Frame / Temple Hinge Repair', 'Repairing', 150, 'Left hinge screw sheared off, urgent delivery requested.']
    );
    await run(
      'INSERT INTO repairs (ticket_id, customer_name, customer_phone, problem_type, status, estimated_cost, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['REP-1041', 'Mahesh Sharma', '9871122334', 'Scratched Lens Replacement', 'Ready', 600, 'CR39 single vision replacement in existing frame.']
    );
    await run(
      'INSERT INTO repairs (ticket_id, customer_name, customer_phone, problem_type, status, estimated_cost, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['REP-1040', 'Dinesh Joshi', '9899334411', 'Loose or Missing Screw', 'Raised', 50, 'Nose pad screw loose.']
    );
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  initDB
};
