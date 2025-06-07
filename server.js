// server.js
// server.js - at the very top
const dotenv = require('dotenv');
const path = require('path'); // You'll likely need 'path' for joining directory paths

// Load variables from 'variables.env' in the current directory
const envConfig = dotenv.config({ path: path.resolve(__dirname, 'variables.env') });

if (envConfig.error) {
  // This error should never happen if the file is present
  console.warn('Warning: Could not load variables.env file. Using default fallbacks or environment variables already set.', envConfig.error);
} else if (Object.keys(envConfig.parsed || {}).length === 0) {
  console.warn('Warning: variables.env file was found but is empty or contains no valid variables.');
} else {
  console.log('Successfully loaded variables from variables.env');
}
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
// const path = require('path');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session); 
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer'); 

const saltRounds = 10; // Cost factor for bcrypt hashing

const app = express();
let mailTransporter;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    // Optional: if using self-signed certificates for local dev (not recommended for prod)
    // tls: {
    //   rejectUnauthorized: false
    // }
  });

  mailTransporter.verify(function(error, success) {
    if (error) {
      console.warn("Nodemailer: Error configuring mail transporter. Email sending will fail.", error.message);
    } else {
      console.log("Nodemailer: Server is ready to take our messages");
    }
  });
} else {
  console.warn("Nodemailer: SMTP environment variables not fully set. Email sending will be disabled.");
}



// --- Middlewares ---
app.use(cors()); // Allow all origins
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' })); // extended: true is generally better

// Serve static files from 'public' directory (HTML, CSS, client-side JS)
app.use(express.static(path.join(__dirname, 'public')));
// Serve uploaded files statically from 'public/uploads'
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Session Configuration
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db', // Can be same as your school.db or a new file
    dir: '.',          // Directory to store the database file (project root)
    table: 'sessions'  // Table name for sessions
  }),
  secret: process.env.SESSION_SECRET || 'please_change_this_super_secret_key_for_production', // Use environment variable or a strong random string
  resave: false,
  saveUninitialized: false, // Only create session when user logs in or session data is set
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true in production (HTTPS)
    httpOnly: true, // Prevents client-side JS from reading the cookie
    maxAge: 24 * 60 * 60 * 1000 // Session duration (e.g., 24 hours)
  }
}));

// Initialize SQLite database
const dbPath = './school.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Fatal error connecting to SQLite:", err.message);
    process.exit(1); // Exit if DB connection fails
  }
  console.log('Connected to the school SQLite database.');
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_name TEXT UNIQUE NOT NULL,
    setting_value TEXT
  )`, (err) => {
    if (err) console.error("Error creating settings table:", err.message);
  });

  db.run(`CREATE TABLE IF NOT EXISTS carousel_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_url TEXT NOT NULL,
    link_url TEXT,
    alt_text TEXT,
    file_name TEXT,
    display_order INTEGER
  )`, (err) => {
    if (err) console.error("Error creating carousel_images table:", err.message);
  });

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL /* Stores HASHED passwords */
  )`, (err) => {
    if (err) return console.error("Error creating users table:", err.message);
    
    const defaultAdminUsername = process.env.ADMIN_USERNAME || 'admin';
    const defaultAdminPasswordPlain = process.env.ADMIN_PASSWORD_PLAIN || 'password123'; // For initial setup

    db.get("SELECT * FROM users WHERE username = ?", [defaultAdminUsername], async (err, row) => {
      if (err) return console.error("Error checking admin user:", err.message);
      if (!row) {
        try {
          const hashedPassword = await bcrypt.hash(defaultAdminPasswordPlain, saltRounds);
          db.run("INSERT INTO users (username, password) VALUES (?, ?)", 
            [defaultAdminUsername, hashedPassword], (err) => {
            if (err) return console.error("Error inserting default admin:", err.message);
            console.log(`Default admin user ('${defaultAdminUsername}') created. Password ('${defaultAdminPasswordPlain}') is HASHED in DB.`);
            console.log("IMPORTANT: Change the default password via a secure mechanism in a real application.");
          });
        } catch (hashError) {
          console.error("Error hashing default admin password:", hashError);
        }
      } else {
        console.log(`Admin user ('${defaultAdminUsername}') already exists.`);
      }
    });
  });
});

// --- Authentication Middleware ---
function checkAuth(req, res, next) {
 console.log(`CheckAuth for ${req.originalUrl}. Session ID: ${req.sessionID}, Authenticated: ${req.session ? req.session.authenticated : 'No session'}`); // Log session state
  if (req.session && req.session.authenticated) {
    return next();
  }
  console.log('Auth check failed for path:', req.originalUrl, '- Redirecting to login.');
  res.redirect('/login.html?unauthorized=true');
}

// --- HTML Serving Routes ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/school', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school.html')));


// --- Authentication API Routes ---
app.post('/login', async (req, res) => {
  const { username, password: plainTextPassword } = req.body;
  if (!username || !plainTextPassword) {
    return res.status(400).redirect('/login.html?error=' + encodeURIComponent('Username and password are required.'));
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error("Login DB error:", err);
      return res.status(500).redirect('/login.html?error=' + encodeURIComponent('Server error during login.'));
    }
    
    if (user) {
        try {
          const match = await bcrypt.compare(plainTextPassword, user.password);
          if (match) {
            // Explicitly create or regenerate the session to ensure it's fresh
            req.session.regenerate(function(err) {
              if (err) {
                console.error("Error regenerating session:", err);
                return res.status(500).redirect('/login.html?error=' + encodeURIComponent('Server error during session regeneration.'));
              }

              // Now set properties on the new session
              req.session.authenticated = true;
              req.session.username = user.username;

              console.log(`User '${user.username}' logged in. Session authenticated: ${req.session.authenticated}`);
              console.log(`Session ID after login & regeneration: ${req.sessionID}`);

              req.session.save(err => {
                if (err) {
                  console.error("Error saving session after login:", err);
                  return res.status(500).redirect('/login.html?error=' + encodeURIComponent('Server error during session save.'));
                }
                console.log("Session saved successfully after login. Redirecting to /admin.html");
                res.redirect('/admin.html');
              });
            });
          } else {
            console.log(`Login failed for username '${username}' (password mismatch).`);
            res.redirect('/login.html?error=' + encodeURIComponent('Invalid username or password.'));
          }
        } catch (compareError) {
          console.error("Error comparing passwords:", compareError);
          res.status(500).redirect('/login.html?error=' + encodeURIComponent('Server error during login check.'));
        }
      } else {
        console.log(`Login failed for username '${username}' (user not found).`);
        res.redirect('/login.html?error=' + encodeURIComponent('Invalid username or password.'));
      }
  });
});

app.post('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        console.error("Error destroying session during logout:", err);
        return res.status(500).json({ message: "Logout failed. Could not clear session." });
      }
      res.clearCookie('connect.sid'); // Default session cookie name for express-session
      console.log('User logged out successfully.');
      return res.status(200).json({ message: 'Logout successful' });
    });
  } else {
    console.log('Logout attempt with no active session.');
    return res.status(200).json({ message: 'No active session to log out from.' });
  }
});


// --- Settings API ---

app.post('/api/settings', checkAuth, (req, res) => {
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: "Missing or invalid 'settings' object in request body." });
  }

  db.serialize(() => {
    db.run("BEGIN TRANSACTION;", (err) => {
        if (err) return res.status(500).json({ error: "Failed to start transaction: " + err.message });
    });

    const stmt = db.prepare('INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)');
    let operations = [];

    Object.entries(settings).forEach(([key, value]) => {
      let valueToStore = value;
      if (typeof value === 'object' && value !== null) {
        try {
          valueToStore = JSON.stringify(value);
        } catch (e) {
          console.error(`Could not stringify setting '${key}':`, e.message, ". Storing as plain string.");
          valueToStore = String(value); // Fallback: store as plain string
        }
      }
      // Ensure valueToStore is a string, even if it was originally a number or boolean, or null/undefined
      if (typeof valueToStore !== 'string') {
        valueToStore = valueToStore === null || typeof valueToStore === 'undefined' ? '' : String(valueToStore);
      }
      operations.push(new Promise((resolve, reject) => {
        stmt.run(key, valueToStore, function(err) {
          if (err) {
            console.error(`Error saving setting '${key}' with value '${valueToStore}':`, err.message);
            reject(err);
          } else {
            resolve();
          }
        });
      }));
    });

    Promise.all(operations)
      .then(() => {
        stmt.finalize((finalizeErr) => {
          if (finalizeErr) {
            console.error("Error finalizing settings statement:", finalizeErr.message);
            db.run("ROLLBACK;", (rbErr) => { if (rbErr) console.error("Rollback error:", rbErr.message);});
            return res.status(500).json({ error: "Failed to finalize settings update: " + finalizeErr.message });
          }
          db.run("COMMIT;", (commitErr) => {
            if (commitErr) {
              console.error("Error committing settings transaction:", commitErr.message);
              return res.status(500).json({ error: "Failed to commit settings: " + commitErr.message });
            }
            res.json({ message: 'Settings saved successfully' });
          });
        });
      })
      .catch(error => {
        console.error("Error during one or more setting saves:", error.message);
        stmt.finalize(); // Finalize statement even on error
        db.run("ROLLBACK;", (rbErr) => { if (rbErr) console.error("Rollback error after promise rejection:", rbErr.message);});
        res.status(500).json({ error: "Failed to save one or more settings." });
      });
  });
});
app.get('/api/settings', (req, res) => { // No checkAuth needed here; public site also needs settings
  db.all('SELECT setting_name, setting_value FROM settings', [], (err, rows) => {
    if (err) {
      console.error("GET /api/settings DB error:", err.message);
      return res.status(500).json({ error: 'Failed to retrieve settings from database.' });
    }

    const settings = {};
    // Define keys that are expected to be JSON strings and should be parsed
    const jsonKeys = [
        'socialLinks', 'facilityCards',
        'heroGradient', 'aboutGradient', 'admissionsGradient',
        'academicsGradient', 'facilitiesGradient', 'contactGradient'
    ];

    rows.forEach(row => {
      let value = row.setting_value;
      if (jsonKeys.includes(row.setting_name)) {
        try {
          // Ensure value is not null or empty string before attempting to parse
          if (value && typeof value === 'string' && value.trim() !== '') {
            value = JSON.parse(value);
          } else {
            // Provide a sensible default for empty/null structured data
            if (row.setting_name === 'facilityCards') value = [];
            else if (row.setting_name.endsWith('Gradient') || row.setting_name === 'socialLinks') value = {};
            else value = null; // Or keep as empty string depending on client expectation
          }
        } catch (e) {
          console.warn(`Could not parse setting '${row.setting_name}' as JSON. Raw value: "${row.setting_value}". Error:`, e.message);
          // Fallback if JSON is malformed
          if (row.setting_name === 'facilityCards') value = [];
          else if (row.setting_name.endsWith('Gradient') || row.setting_name === 'socialLinks') value = {};
          else value = row.setting_value; // Keep original string
        }
      }
      settings[row.setting_name] = value;
    });
    res.json(settings);
  });
});



// --- Multer Configuration ---
const UPLOADS_DIR_PUBLIC = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR_PUBLIC)) {
  try {
    fs.mkdirSync(UPLOADS_DIR_PUBLIC, { recursive: true });
    console.log(`Uploads directory created: ${UPLOADS_DIR_PUBLIC}`);
  } catch (mkdirErr) {
    console.error(`Fatal error creating uploads directory ${UPLOADS_DIR_PUBLIC}:`, mkdirErr.message);
    process.exit(1);
  }
}

const generateFilename = (originalName) => {
  const timestamp = Date.now();
  const randomString = Math.random().toString(36).substring(2, 8);
  const ext = path.extname(originalName);
  const basename = path.basename(originalName, ext).substring(0, 50); // Limit basename length
  const sanitizedBasename = basename.replace(/[^a-zA-Z0-9_.-]/g, '_');
  return `${sanitizedBasename}-${timestamp}-${randomString}${ext}`;
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR_PUBLIC);
  },
  filename: (req, file, cb) => {
    cb(null, generateFilename(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      console.warn("Attempted to upload non-image file:", file.originalname, file.mimetype);
      cb(new Error('File upload failed: Only image files (JPEG, PNG, GIF, WEBP, SVG) are allowed.'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Multer Error Handler Middleware (to be used after upload middleware in routes)
const multerErrorHandler = (error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        console.error("Multer error during upload:", error.code, error.field);
        return res.status(400).json({ message: `File upload error: ${error.message} (Field: ${error.field})` });
    } else if (error) { // Other errors (e.g., from fileFilter)
        console.error("Non-Multer error during upload:", error.message);
        return res.status(400).json({ message: error.message });
    }
    next(); // If no error, proceed
};

// --- Specific Image Upload API Endpoints ---
app.post('/api/upload-logo', checkAuth, upload.single('logo'), multerErrorHandler, (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No logo file provided.' });
  res.json({ message: 'Logo uploaded successfully', url: `/uploads/${req.file.filename}` });
});

app.post('/api/upload-about-image', checkAuth, upload.single('aboutImage'), multerErrorHandler, (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No "About Us" image file provided.' });
  res.json({ message: 'About Us image uploaded successfully', url: `/uploads/${req.file.filename}` });
});

app.post('/api/upload-academics-image', checkAuth, upload.single('academicsImage'), multerErrorHandler, (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No "Academics" image file provided.' });
  res.json({ message: 'Academics image uploaded successfully', url: `/uploads/${req.file.filename}` });
});


// --- Carousel API Endpoints ---
app.get('/api/carousel', (req, res) => {
  db.all('SELECT id, image_url, link_url, alt_text, file_name, display_order FROM carousel_images ORDER BY display_order ASC, id ASC', [], (err, rows) => {
    if (err) {
      console.error("GET /api/carousel error:", err.message);
      return res.status(500).json({ error: "Failed to retrieve carousel images: " + err.message });
    }
    res.json(rows);
  });
});

// Field name in upload.single() MUST match the key used in FormData.append() on the client
app.post('/api/carousel', checkAuth, upload.single('carouselImage'), multerErrorHandler, (req, res) => {
  if (!req.file) {
    // This case should ideally be caught by multerErrorHandler if fileFilter fails or no file,
    // but good to have a check here too.
    return res.status(400).json({ error: 'No carousel image file was uploaded.' });
  }

  const imageUrl = `/uploads/${req.file.filename}`;
  const linkURL = req.body.linkURL || null; // From admin.js form field
  const altText = req.body.altText || `Carousel Image`; // From admin.js form field
  const fileName = req.file.originalname;

  const sql = `INSERT INTO carousel_images (image_url, link_url, alt_text, file_name, display_order)
               VALUES (?, ?, ?, ?, (SELECT IFNULL(MAX(display_order), 0) + 1 FROM carousel_images))`;

  db.run(sql, [imageUrl, linkURL, altText, fileName], function(err) {
    if (err) {
      console.error("Carousel image insert DB error:", err.message);
      return res.status(500).json({ error: "Failed to save carousel image to database: " + err.message });
    }
    res.status(201).json({
        message: 'Carousel image added successfully.',
        image: { id: this.lastID, image_url: imageUrl, link_url: linkURL, alt_text: altText, file_name: fileName, display_order: null } // display_order is set by DB
    });
  });
});

app.delete('/api/carousel/:id', checkAuth, (req, res) => {
  const imageId = parseInt(req.params.id, 10); // Ensure it's an integer
  if (isNaN(imageId)) {
    return res.status(400).json({ error: 'Invalid image ID provided for deletion.' });
  }

  db.get('SELECT image_url FROM carousel_images WHERE id = ?', [imageId], (err, row) => {
    if (err) {
      console.error("Error finding image for deletion (DB):", err.message);
      return res.status(500).json({ error: 'Database error while trying to find image.' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Image not found in database.' });
    }

    const filePath = path.join(UPLOADS_DIR_PUBLIC, path.basename(row.image_url));
    
    fs.unlink(filePath, (unlinkErr) => {
      if (unlinkErr && unlinkErr.code !== 'ENOENT') { // ENOENT means file not found, which is okay if already deleted
          console.warn(`Filesystem: Image file ${filePath} could not be deleted:`, unlinkErr.message);
          // Don't stop; still try to delete from DB.
      }
      
      db.run('DELETE FROM carousel_images WHERE id = ?', [imageId], function(dbErr) { // Use function for this.changes
        if (dbErr) {
          console.error("Error deleting image from database (DB):", dbErr.message);
          return res.status(500).json({ error: 'Database error while deleting image record.' });
        }
        if (this.changes === 0) {
            // This could happen if the image was deleted between the SELECT and DELETE operations
            console.warn(`DB: Image ID ${imageId} not found for deletion, or already deleted.`);
            return res.status(404).json({ error: 'Image not found in database for deletion (or was already deleted).' });
        }
        console.log(`Carousel image ID ${imageId} deleted successfully (DB changes: ${this.changes}).`);
        res.json({ message: 'Carousel image deleted successfully.' });
      });
    });
  });
});
// ----whatsapp messaging---
// ---- CONTACT FORM SUBMISSION API ----
app.post('/api/submit-contact', async (req, res) => {
  const { contactName, contactEmail, contactSubject, contactMessage } = req.body;

  // Basic validation
  if (!contactName || !contactEmail || !contactSubject || !contactMessage) {
    return res.status(400).json({
      success: false,
      message: "All fields are required. Please fill out the form completely."
    });
  }

  // Fetch contactFormAction and schoolContactEmail from DB settings
  let contactFormActionSetting = process.env.CONTACT_FORM_ACTION_DEFAULT || 'whatsapp';
  let schoolContactEmailSetting = process.env.SCHOOL_CONTACT_EMAIL_TO; // Fallback to .env

  try {
    const settingsRow = await new Promise((resolve, reject) => {
      db.all('SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?, ?)',
        ['contactFormAction', 'schoolContactEmail'], (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });

    settingsRow.forEach(row => {
      if (row.setting_name === 'contactFormAction' && row.setting_value) {
        contactFormActionSetting = row.setting_value;
      }
      if (row.setting_name === 'schoolContactEmail' && row.setting_value) {
        schoolContactEmailSetting = row.setting_value; // Override .env if set in admin
      }
    });

  } catch (dbError) {
    console.error("Error fetching contact settings from DB:", dbError.message);
    // Proceed with defaults, but log the error
  }

  console.log(`Contact Form Action determined: ${contactFormActionSetting}`);

  if (contactFormActionSetting === 'whatsapp') {
    const schoolWhatsAppNumber = process.env.SCHOOL_WHATSAPP_NUMBER;
    if (!schoolWhatsAppNumber) {
      console.error("SCHOOL_WHATSAPP_NUMBER is not configured for WhatsApp action.");
      return res.status(500).json({
        success: false,
        message: "Server configuration error: WhatsApp number not set."
      });
    }

    const whatsappMessageBody = `New Contact Form Submission:
-----------------------------
Name: ${contactName}
Email: ${contactEmail}
Subject: ${contactSubject}
-----------------------------
Message:
${contactMessage}
-----------------------------
Sent from the school website.`;

    const whatsappUrl = `https://wa.me/${schoolWhatsAppNumber}?text=${encodeURIComponent(whatsappMessageBody)}`;
    console.log(`Preparing WhatsApp redirect to: ${whatsappUrl}`);
    return res.json({
      success: true,
      action: 'whatsapp',
      whatsappUrl: whatsappUrl,
      message: "Please click 'Send' in WhatsApp."
    });

  } else if (contactFormActionSetting === 'email') {
    if (!mailTransporter) {
      console.error("Mail transporter not available for email action.");
      return res.status(500).json({
        success: false,
        message: "Server configuration error: Email service not available."
      });
    }
    if (!schoolContactEmailSetting) {
      console.error("School contact email (to send TO) is not configured for email action.");
      return res.status(500).json({
        success: false,
        message: "Server configuration error: Recipient email not set."
      });
    }

    const mailOptions = {
      from: `"${contactName} via School Website" <${process.env.EMAIL_FROM_ADDRESS || 'noreply@example.com'}>`, // Sender address (shows as "Name <email>")
      replyTo: contactEmail, // Set Reply-To to the user's email
      to: schoolContactEmailSetting, // List of receivers (school's email)
      subject: `New Contact Form: ${contactSubject}`, // Subject line
      text: `You have a new contact form submission:\n\nName: ${contactName}\nEmail: ${contactEmail}\nSubject: ${contactSubject}\n\nMessage:\n${contactMessage}`, // Plain text body
      html: `<p>You have a new contact form submission:</p>
             <ul>
               <li><strong>Name:</strong> ${contactName}</li>
               <li><strong>Email:</strong> ${contactEmail}</li>
               <li><strong>Subject:</strong> ${contactSubject}</li>
             </ul>
             <p><strong>Message:</strong></p>
             <p>${contactMessage.replace(/\n/g, '<br>')}</p>`, // HTML body
    };

    try {
      await mailTransporter.sendMail(mailOptions);
      console.log('Email sent successfully to:', schoolContactEmailSetting);
      return res.json({
        success: true,
        action: 'email',
        message: 'Your message has been sent successfully!'
      });
    } catch (emailError) {
      console.error('Error sending email:', emailError);
      return res.status(500).json({
        success: false,
        action: 'email',
        message: 'Failed to send message. Please try again later or contact us directly.'
      });
    }
  } else {
    console.error(`Unknown contactFormAction: ${contactFormActionSetting}`);
    return res.status(500).json({
      success: false,
      message: "Server configuration error: Invalid contact form action."
    });
  }
});



// --- Server Start ---
const SERVER_PORT = process.env.PORT || 3000;
app.listen(SERVER_PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${SERVER_PORT}`);
  console.log(`Serving static files from: ${path.join(__dirname, 'public')}`);
  console.log(`Serving uploads from: ${path.join(__dirname, 'public', 'uploads')}`);
  console.log(`Admin credentials (default): ${process.env.ADMIN_USERNAME || 'admin'} / ${process.env.ADMIN_PASSWORD_PLAIN || 'password123'} (Hashed in DB)`);
  console.log(`Session Secret in use: ${process.env.SESSION_SECRET ? 'From ENV' : 'Default (INSECURE - CHANGE IT!)'}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`Contact Form Default Action: ${process.env.CONTACT_FORM_ACTION_DEFAULT}`);
    console.log(`School WhatsApp Number (for prefill): ${process.env.SCHOOL_WHATSAPP_NUMBER}`);
    console.log(`School Contact Email (to receive form data): ${process.env.SCHOOL_CONTACT_EMAIL_TO}`);
    console.log(`SMTP Host: ${process.env.SMTP_HOST}`);
}
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing SQLite database.');
  db.close((err) => {
    if (err) {
      return console.error(err.message);
    }
    console.log('SQLite database connection closed.');
    process.exit(0);
  });
});