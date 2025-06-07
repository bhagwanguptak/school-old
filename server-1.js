// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const session = require('express-session');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Initialize SQLite database
const db = new sqlite3.Database('./school.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to the school database.');
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_name TEXT UNIQUE,
    setting_value TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS carousel_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_url TEXT NOT NULL,
    link TEXT,
    alt TEXT,
    display_order INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) return console.error("Error creating users table:", err.message);

    db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
      if (err) return console.error("Error checking admin user:", err.message);

      if (!row) {
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', 'password123'], (err) => {
          if (err) return console.error("Error inserting default admin:", err.message);
          console.log("Default admin user created: admin / password123");
        });
      } else {
        console.log("Admin user already exists");
      }
    });
  });
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/school.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/admin', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/school', (req, res) => res.sendFile(path.join(__dirname, 'public/school.html')));

// Auth
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) return res.status(500).send('Internal server error');
    if (row) {
      req.session.authenticated = true;
      res.redirect('/admin');
    } else {
      res.send('Invalid credentials');
    }
  });
});

function checkAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.redirect('/login');
}

// Users API
app.get('/user', (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) return res.status(500).send('Internal server error');
    res.json(rows);
  });
});

// Settings API
app.get('/api/settings', (req, res) => {
  db.all('SELECT setting_name, setting_value FROM settings', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const loadedSettings = {};
    rows.forEach(row => {
      try {
        // Attempt to parse if it looks like a JSON object or array
        if (row.setting_value && (row.setting_value.startsWith('{') || row.setting_value.startsWith('['))) {
          loadedSettings[row.setting_name] = JSON.parse(row.setting_value);
        } else {
          loadedSettings[row.setting_name] = row.setting_value;
        }
      } catch (e) {
        // If parsing fails, store as is (it was likely a plain string)
        loadedSettings[row.setting_name] = row.setting_value;
      }
    });
    res.json(loadedSettings);
  });
});

app.post('/api/settings', (req, res) => {
 const { settings } = req.body;
  if (!settings) {
    return res.status(400).json({ error: "Missing 'settings' object" });
  }
  const stmt = db.prepare('INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)');
  
  Object.entries(settings).forEach(([key, value]) => {
    let valueToStore = value;
    // Check if the value is an object (and not null)
    if (typeof value === 'object' && value !== null) {
      try {
        valueToStore = JSON.stringify(value); // Store complex objects as JSON strings
      } catch (e) {
        console.error(`Could not stringify setting ${key}:`, e);
        // Decide how to handle: skip, store as string, or error out
        valueToStore = '[object Object]'; // Fallback if stringify fails (shouldn't for simple objects)
      }
    }
    stmt.run(key, valueToStore);
  });

  stmt.finalize(err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Settings saved successfully' });
  });
});

// Carousel Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'public/uploads';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

app.use('/uploads', express.static('public/uploads'));

app.post('/api/upload-carousel-image', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const imageUrl = `/uploads/${req.file.filename}`;
  const link = req.body.link || null;
  const alt = req.body.alt || `Carousel Image`;

  const sql = `INSERT INTO carousel_images (image_url, link, alt, display_order)
               VALUES (?, ?, ?, (SELECT IFNULL(MAX(display_order), 0) + 1 FROM carousel_images))`;

  db.run(sql, [imageUrl, link, alt], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, image_url: imageUrl, link, alt });
  });
});

// Carousel API
app.get('/api/carousel', (req, res) => {
  db.all('SELECT id, image_url, link, alt, display_order FROM carousel_images ORDER BY display_order', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/carousel/:id', (req, res) => {
  const imageId = req.params.id;
  db.get('SELECT image_url FROM carousel_images WHERE id = ?', [imageId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Image not found' });

    const filePath = path.join(__dirname, 'public', row.image_url);
    fs.unlink(filePath, (err) => {
      if (err) console.warn("Image file couldn't be deleted:", err.message);

      db.run('DELETE FROM carousel_images WHERE id = ?', [imageId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Image deleted' });
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));