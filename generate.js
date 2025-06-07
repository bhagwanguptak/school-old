// generateSecret.js
const crypto = require('crypto');
const secret = crypto.randomBytes(64).toString('hex'); // Generates a 128-character hex string
console.log(secret);