const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// ──────────────────────────────────────────────
//  DATABASE SETUP (Excel-compatible CSV files)
// ──────────────────────────────────────────────
const USERS_FILE = path.join(__dirname, 'users_database.csv');
const ADDRESSES_FILE = path.join(__dirname, 'addresses_database.csv');
const ORDERS_FILE = path.join(__dirname, 'orders_database.csv');

const USERS_HEADERS = ['id', 'name', 'email', 'phone', 'password', 'created'];
const ADDRESSES_HEADERS = ['id', 'user_id', 'label', 'full_name', 'phone', 'line1', 'line2', 'city', 'state', 'pincode', 'is_default', 'created'];
const ORDERS_HEADERS = ['id', 'date', 'user_email', 'items', 'total', 'address', 'status'];

// Helper to escape values for CSV
function escapeCSV(val) {
  if (val === null || val === undefined) return '';
  let str = String(val);
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    str = '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

// Helper to parse a CSV line, respecting quoted fields
function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

// Helper to read CSV rows
function readCSV(filepath, headers) {
  if (!fs.existsSync(filepath)) {
    try {
      fs.writeFileSync(filepath, headers.join(',') + '\n', 'utf8');
    } catch (err) {
      console.warn(`⚠️ Warning: Failed to initialize file ${filepath}.`, err.message);
    }
    return [];
  }
  const content = fs.readFileSync(filepath, 'utf8');
  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length <= 1) return [];

  const fileHeaders = parseCSVLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    const obj = {};
    fileHeaders.forEach((h, idx) => {
      obj[h] = values[idx] || '';
    });
    rows.push(obj);
  }
  return rows;
}

// Helper to write CSV rows
function writeCSV(filepath, headers, rows) {
  const headerLine = headers.join(',') + '\n';
  const dataLines = rows.map(row => {
    return headers.map(h => escapeCSV(row[h])).join(',');
  }).join('\n');
  try {
    fs.writeFileSync(filepath, headerLine + dataLines + '\n', 'utf8');
  } catch (err) {
    console.warn(`⚠️ Warning: Failed to write to file ${filepath}.`, err.message);
  }
}

// Initialize files if they don't exist
readCSV(USERS_FILE, USERS_HEADERS);
readCSV(ADDRESSES_FILE, ADDRESSES_HEADERS);
readCSV(ORDERS_FILE, ORDERS_HEADERS);

// ──────────────────────────────────────────────
//  MIDDLEWARE
// ──────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'inkora-kawaii-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,   // 7 days
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Serve all static files from project directory
app.use(express.static(__dirname));

// ──────────────────────────────────────────────
//  AUTH API ENDPOINTS
// ──────────────────────────────────────────────

// SIGN UP
app.post('/api/signup', (req, res) => {
  const { name, email, phone, password } = req.body;

  // Validate inputs
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (name.trim().length < 2) {
    return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!/^[\d\s\-+()]{7,15}$/.test(phone)) {
    return res.status(400).json({ error: 'Please enter a valid phone number.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  // Check if user already exists
  const users = readCSV(USERS_FILE, USERS_HEADERS);
  const normalizedEmail = email.toLowerCase().trim();
  const existing = users.find(u => u.email === normalizedEmail);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists.' });
  }

  // Hash password and insert
  const hash = bcrypt.hashSync(password, 10);
  const nextId = users.length > 0 ? Math.max(...users.map(u => parseInt(u.id) || 0)) + 1 : 1;

  const newUser = {
    id: nextId.toString(),
    name: name.trim(),
    email: normalizedEmail,
    phone: phone.trim(),
    password: hash,
    created: new Date().toISOString()
  };

  users.push(newUser);
  writeCSV(USERS_FILE, USERS_HEADERS, users);

  // Auto-login after signup
  req.session.userId = newUser.id;
  req.session.userName = newUser.name;
  req.session.userEmail = newUser.email;
  req.session.userPhone = newUser.phone;

  res.json({
    success: true,
    message: 'Account created successfully!',
    user: { id: newUser.id, name: newUser.name, email: newUser.email, phone: newUser.phone }
  });
});

// SIGN IN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const users = readCSV(USERS_FILE, USERS_HEADERS);
  const normalizedEmail = email.toLowerCase().trim();
  const user = users.find(u => u.email === normalizedEmail);
  if (!user) {
    return res.status(401).json({ error: 'No account found with this email.' });
  }

  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Incorrect password. Please try again.' });
  }

  // Set session
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.userEmail = user.email;
  req.session.userPhone = user.phone;

  res.json({
    success: true,
    message: 'Logged in successfully!',
    user: { id: user.id, name: user.name, email: user.email, phone: user.phone }
  });
});

// GET CURRENT USER (session check) — includes default address
app.get('/api/user', (req, res) => {
  if (req.session.userId) {
    const addresses = readCSV(ADDRESSES_FILE, ADDRESSES_HEADERS);
    const address = addresses.find(a => a.user_id === req.session.userId && a.is_default === '1');
    res.json({
      loggedIn: true,
      user: {
        id: req.session.userId,
        name: req.session.userName,
        email: req.session.userEmail,
        phone: req.session.userPhone || ''
      },
      address: address || null
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: 'Logged out.' });
  });
});

// ──────────────────────────────────────────────
//  ADDRESS API ENDPOINTS
// ──────────────────────────────────────────────

// SAVE / UPDATE address
app.post('/api/address', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }

  const { full_name, phone, line1, line2, city, state, pincode, label } = req.body;

  if (!full_name || !phone || !line1 || !city || !state || !pincode) {
    return res.status(400).json({ error: 'All address fields are required (except line 2).' });
  }

  let addresses = readCSV(ADDRESSES_FILE, ADDRESSES_HEADERS);

  // Set all existing addresses for this user to non-default
  addresses = addresses.map(a => {
    if (a.user_id === req.session.userId) {
      a.is_default = '0';
    }
    return a;
  });

  const nextId = addresses.length > 0 ? Math.max(...addresses.map(a => parseInt(a.id) || 0)) + 1 : 1;
  const newAddress = {
    id: nextId.toString(),
    user_id: req.session.userId,
    label: (label || 'Home').trim(),
    full_name: full_name.trim(),
    phone: phone.trim(),
    line1: line1.trim(),
    line2: (line2 || '').trim(),
    city: city.trim(),
    state: state.trim(),
    pincode: pincode.trim(),
    is_default: '1',
    created: new Date().toISOString()
  };

  addresses.push(newAddress);
  writeCSV(ADDRESSES_FILE, ADDRESSES_HEADERS, addresses);

  res.json({
    success: true,
    message: 'Address saved!',
    address: newAddress
  });
});

// GET all addresses for user
app.get('/api/addresses', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }
  const addresses = readCSV(ADDRESSES_FILE, ADDRESSES_HEADERS);
  const userAddresses = addresses.filter(a => a.user_id === req.session.userId);
  res.json({ addresses: userAddresses });
});

// DELETE an address
app.delete('/api/address/:id', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please sign in first.' });
  }
  let addresses = readCSV(ADDRESSES_FILE, ADDRESSES_HEADERS);
  addresses = addresses.filter(a => !(a.id === req.params.id && a.user_id === req.session.userId));
  writeCSV(ADDRESSES_FILE, ADDRESSES_HEADERS, addresses);
  res.json({ success: true });
});

// ──────────────────────────────────────────────
//  ORDER API ENDPOINTS
// ──────────────────────────────────────────────

// SAVE checkout order to CSV file database
app.post('/api/order', (req, res) => {
  const { id, date, items, total, address, status } = req.body;
  const userEmail = req.session.userEmail || 'guest@email.com';

  if (!id || !total || !items) {
    return res.status(400).json({ error: 'Order details missing.' });
  }

  const orders = readCSV(ORDERS_FILE, ORDERS_HEADERS);

  // Stringify items list & address for easy viewing in Excel
  const itemsStr = items.map(i => `${i.name} (${i.qty}x)`).join('; ');
  const addressStr = address ? `${address.line1}, ${address.city}, ${address.state} - ${address.pincode}` : '';

  const newOrder = {
    id: id,
    date: date || new Date().toISOString(),
    user_email: userEmail,
    items: itemsStr,
    total: total.toString(),
    address: addressStr,
    status: status || 'Processing'
  };

  orders.push(newOrder);
  writeCSV(ORDERS_FILE, ORDERS_HEADERS, orders);

  res.json({ success: true, message: 'Order saved in server CSV file.' });
});

// GET all orders for current logged-in user
app.get('/api/orders', (req, res) => {
  if (!req.session.userEmail) {
    return res.json({ orders: [] });
  }
  const orders = readCSV(ORDERS_FILE, ORDERS_HEADERS);
  const userOrders = orders.filter(o => o.user_email === req.session.userEmail);

  // Map to matching format
  const formattedOrders = userOrders.map(o => {
    // Parse items back
    const itemsList = o.items.split('; ').map(part => {
      const match = part.match(/(.*) \((\d+)x\)/);
      return match ? { name: match[1], qty: parseInt(match[2]), price: 0 } : { name: part, qty: 1, price: 0 };
    });

    const addrParts = o.address.split(', ');
    const line1 = addrParts[0] || '';
    const city = addrParts[1] || '';
    const stateParts = (addrParts[2] || '').split(' - ');
    const state = stateParts[0] || '';
    const pincode = stateParts[1] || '';

    return {
      id: o.id,
      date: o.date,
      items: itemsList,
      total: parseFloat(o.total) || 0,
      address: { line1, city, state, pincode },
      status: o.status
    };
  });

  res.json({ orders: formattedOrders });
});

// ──────────────────────────────────────────────
//  START SERVER
// ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ✨  Inkora server running at http://localhost:${PORT}\n`);
  console.log(`  📦  Users Excel file:     users_database.csv`);
  console.log(`  📦  Addresses Excel file: addresses_database.csv`);
  console.log(`  📦  Orders Excel file:    orders_database.csv`);
  console.log(`  🛍️   Shop:                 http://localhost:${PORT}/index.html`);
  console.log(`  🔐  Login:                http://localhost:${PORT}/login.html\n`);
});

module.exports = app;
