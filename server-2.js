// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // Node.js File System module
const session = require('express-session');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from 'public'
app.use(bodyParser.urlencoded({ extended: false }));

// Serve uploaded files statically from 'public/uploads'
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));


app.use(session({
  secret: 'your-secret-key', // Replace with a strong, random secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
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
  )`, (err) => { // Removed bcrypt for simplicity, add back if needed
    if (err) return console.error("Error creating users table:", err.message);

    // Check if admin user exists, if not, create one
    db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
      if (err) return console.error("Error checking admin user:", err.message);

      if (!row) {
        // For a real app, hash the password!
        // const hashedPassword = await bcrypt.hash('password123', 10);
        // db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', hashedPassword], ...
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', 'password123'], (err) => {
          if (err) return console.error("Error inserting default admin:", err.message);
          console.log("Default admin user created: admin / password123 (PLAIN TEXT - CHANGE THIS!)");
        });
      } else {
        console.log("Admin user already exists");
      }
    });
  });
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/school', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school.html')));

// Auth
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // IMPORTANT: In a real application, compare hashed passwords!
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error("Login DB error:", err);
      return res.status(500).send('Internal server error');
    }
    if (user && user.password === password) { // Plain text comparison (BAD for production)
      // For hashed passwords:
      // if (user && await bcrypt.compare(password, user.password)) {
      req.session.authenticated = true;
      req.session.username = user.username; // Store username in session if needed
      res.redirect('/admin');
    } else {
      res.send('Invalid credentials. <a href="/login">Try again</a>'); // Provide a link back
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/admin'); // Or an error page
    }
    res.clearCookie('connect.sid'); // Cookie name might vary based on session middleware
    res.redirect('/login');
  });
});


function checkAuth(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect('/login');
}

// Settings API
app.get('/api/settings', (req, res) => {
  db.all('SELECT setting_name, setting_value FROM settings', [], (err, rows) => {
    if (err) {
      console.error("GET /api/settings error:", err);
      return res.status(500).json({ error: err.message });
    }
    const loadedSettings = {};
    rows.forEach(row => {
      try {
        if (row.setting_value && (row.setting_value.startsWith('{') || row.setting_value.startsWith('['))) {
          loadedSettings[row.setting_name] = JSON.parse(row.setting_value);
        } else {
          loadedSettings[row.setting_name] = row.setting_value;
        }
      } catch (e) {
        console.warn(`Failed to parse setting '${row.setting_name}':`, e.message, "Storing as string.");
        loadedSettings[row.setting_name] = row.setting_value;
      }
    });
    res.json(loadedSettings);
  });
});

app.post('/api/settings', checkAuth, (req, res) => { // Added checkAuth
 const { settings } = req.body;
  if (!settings || typeof settings !== 'object') { // Check if settings is an object
    return res.status(400).json({ error: "Missing or invalid 'settings' object" });
  }

  // Use a transaction for multiple database operations
  db.serialize(() => {
    db.run("BEGIN TRANSACTION;");
    const stmt = db.prepare('INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)');
    
    let hadError = false;
    Object.entries(settings).forEach(([key, value]) => {
      if (hadError) return; // Don't proceed if an error occurred

      let valueToStore = value;
      if (typeof value === 'object' && value !== null) {
        try {
          valueToStore = JSON.stringify(value);
        } catch (e) {
          console.error(`Could not stringify setting ${key}:`, e);
          // Consider how to handle this error. For now, skip this key or store a placeholder
          // For simplicity, we'll skip it here and report an error later if any key failed.
          // In a real app, you might want more robust error handling per key.
          valueToStore = null; // Or some error string
        }
      }
      if (valueToStore !== null) { // Only run if value is valid
          stmt.run(key, valueToStore, function(err) {
              if (err) {
                  console.error(`Error saving setting ${key}:`, err);
                  hadError = true;
              }
          });
      }
    });

    stmt.finalize(err => {
      if (err && !hadError) { // Finalize error that wasn't caught per-run
          hadError = true;
          console.error("Error finalizing settings statement:", err);
      }

      if (hadError) {
        db.run("ROLLBACK;");
        return res.status(500).json({ error: "Failed to save one or more settings." });
      } else {
        db.run("COMMIT;");
        res.json({ message: 'Settings saved successfully' });
      }
    });
  });
});

// --- Multer Configuration (shared for logo and carousel) ---
const UPLOADS_DIR_PUBLIC = path.join(__dirname, 'public', 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR_PUBLIC)) {
  fs.mkdirSync(UPLOADS_DIR_PUBLIC, { recursive: true });
  console.log(`Created directory: ${UPLOADS_DIR_PUBLIC}`);
}

// Helper to ensure unique filenames to prevent overwriting
const generateFilename = (originalName) => {
  const timestamp = Date.now();
  const randomString = Math.random().toString(36).substring(2, 8);
  const ext = path.extname(originalName);
  const basename = path.basename(originalName, ext);
  // Sanitize basename to remove problematic characters for URLs/filenames
  const sanitizedBasename = basename.replace(/[^a-zA-Z0-9_.-]/g, '_');
  return `${sanitizedBasename}-${timestamp}-${randomString}${ext}`;
};


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR_PUBLIC); // Use the defined uploads directory
  },
  filename: (req, file, cb) => {
    cb(null, generateFilename(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => { // Optional: Basic file type filter
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // Optional: 5MB file size limit
});


// --- NEW: Logo Upload API Endpoint ---
// Expects a single file upload with the field name 'logo'
app.post('/api/upload-logo', checkAuth, upload.single('logo'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No logo file uploaded.' });
  }
  // The file is uploaded by multer. req.file contains file details.
  // The path to the file on the server is req.file.path
  // The URL to access it from the client is /uploads/filename
  const logoUrl = `/uploads/${req.file.filename}`;
  res.json({ message: 'Logo uploaded successfully', url: logoUrl });
}, (error, req, res, next) => { // Multer error handler
    if (error instanceof multer.MulterError) {
        // A Multer error occurred (e.g., file too large)
        return res.status(400).json({ message: error.message });
    } else if (error) {
        // An unknown error occurred (e.g., file type mismatch from fileFilter)
        return res.status(400).json({ message: error.message });
    }
    next();
});


// Carousel Upload (Existing - slightly adjusted to use shared UPLOADS_DIR_PUBLIC)
app.post('/api/upload-carousel-image', checkAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded for carousel' });

  const imageUrl = `/uploads/${req.file.filename}`;
  const link = req.body.link || null;
  const alt = req.body.alt || `Carousel Image`;

  const sql = `INSERT INTO carousel_images (image_url, link, alt, display_order)
               VALUES (?, ?, ?, (SELECT IFNULL(MAX(display_order), 0) + 1 FROM carousel_images))`;

  db.run(sql, [imageUrl, link, alt], function(err) {
    if (err) {
      console.error("Carousel image insert error:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Carousel image added', id: this.lastID, image_url: imageUrl, link, alt });
  });
}, (error, req, res, next) => { // Multer error handler for carousel
    if (error instanceof multer.MulterError) {
        return res.status(400).json({ message: error.message });
    } else if (error) {
        return res.status(400).json({ message: error.message });
    }
    next();
});


// Carousel API (Existing)
app.get('/api/carousel', (req, res) => {
  db.all('SELECT id, image_url, link, alt, display_order FROM carousel_images ORDER BY display_order', [], (err, rows) => {
    if (err) {
      console.error("GET /api/carousel error:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.delete('/api/carousel/:id', checkAuth, (req, res) => {
  const imageId = req.params.id;
  db.get('SELECT image_url FROM carousel_images WHERE id = ?', [imageId], (err, row) => {
    if (err) {
      console.error(`DELETE /api/carousel/${imageId} - DB select error:`, err);
      return res.status(500).json({ error: err.message });
    }
    if (!row) return res.status(404).json({ error: 'Image not found' });

    // Construct absolute path for fs.unlink
    const filePath = path.join(UPLOADS_DIR_PUBLIC, path.basename(row.image_url));
    
    fs.unlink(filePath, (unlinkErr) => {
      // Log unlink error but proceed to delete DB record even if file deletion fails
      if (unlinkErr) console.warn(`Image file ${filePath} couldn't be deleted:`, unlinkErr.message);

      db.run('DELETE FROM carousel_images WHERE id = ?', [imageId], function(dbErr) {
        if (dbErr) {
          console.error(`DELETE /api/carousel/${imageId} - DB delete error:`, dbErr);
          return res.status(500).json({ error: dbErr.message });
        }
        if (this.changes === 0) return res.status(404).json({ message: 'Image not found or already deleted from DB'});
        res.json({ message: 'Image deleted successfully' });
      });
    });
  });
});

const SERVER_PORT = process.env.PORT || 3000; // Renamed PORT to SERVER_PORT
app.listen(SERVER_PORT, () => console.log(`Server running on port ${SERVER_PORT}`));