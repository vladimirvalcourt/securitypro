/**
 * Example Vulnerable Application
 * This file contains intentional security vulnerabilities for testing the auditor
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();

// ❌ VULNERABILITY: Hardcoded secrets (using placeholder values for demonstration)
const DB_PASSWORD = 'YOUR_DB_PASSWORD_HERE';
const API_KEY = 'YOUR_API_KEY_HERE';
const JWT_SECRET = 'YOUR_JWT_SECRET_HERE';

// ❌ VULNERABILITY: MongoDB connection string with credentials
mongoose.connect(`mongodb://admin:${DB_PASSWORD}@localhost:27017/myapp`);

// User Schema without proper validation
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String, // ❌ No hashing mentioned
  role: String,
  ssn: String // ❌ Sensitive data without encryption
});

const User = mongoose.model('User', userSchema);

app.use(express.json());

// ❌ VULNERABILITY: SQL Injection via string interpolation
app.get('/users', async (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
  const users = await mongoose.connection.db.collection('users').find().toArray();
  res.json(users); // ❌ Exposes entire user objects
});

// ❌ VULNERABILITY: No input validation
app.post('/register', async (req, res) => {
  const user = new User(req.body); // Mass assignment vulnerability
  await user.save();
  res.json(user);
});

// ❌ VULNERABILITY: Weak authentication
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // ❌ Plain text password comparison (no hashing)
  const user = await User.findOne({ email, password });

  if (user) {
    // ❌ JWT without expiration
    const token = jwt.sign(
      { userId: user._id, password: user.password }, // ❌ Sensitive data in token
      JWT_SECRET,
      { algorithm: 'none' } // ❌ Insecure algorithm
    );
    res.json({ token });
  } else {
    // ❌ Verbose error message
    res.status(401).json({ error: 'Invalid credentials', stack: new Error().stack });
  }
});

// ❌ VULNERABILITY: XSS via innerHTML
app.get('/profile/:id', async (req, res) => {
  const user = await User.findById(req.params.id); // ❌ No authorization check
  const html = `<div>${user.bio}</div>`; // User input directly in HTML
  res.send(html);
});

// ❌ VULNERABILITY: Command injection
const { exec } = require('child_process');
app.post('/process', (req, res) => {
  exec(`convert ${req.body.imagePath} output.png`, (err, stdout) => {
    res.json({ result: stdout });
  });
});

// ❌ VULNERABILITY: SSRF
app.get('/fetch', async (req, res) => {
  const response = await fetch(req.query.url); // User-controlled URL
  const data = await response.text();
  res.send(data);
});

// ❌ VULNERABILITY: CORS wildcard
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

// ❌ VULNERABILITY: Debug mode enabled
const DEBUG = true;
if (DEBUG) {
  app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack });
  });
}

// ❌ VULNERABILITY: eval() usage
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression); // Code injection
  res.json({ result });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});

module.exports = app;
