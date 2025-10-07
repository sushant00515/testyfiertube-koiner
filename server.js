// server.js - minimal single-device login server (no Redis)
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret_in_prod';
const JWT_EXPIRES = '2h';

// === In-memory user store (for testing) ===
// username: admin , password: 1234
const users = {
  admin: {
    id: '1',
    username: 'admin',
    passwordHash: bcrypt.hashSync('1234', 10),
    currentSessionId: null
  }
};

// Issue JWT token
function issueToken(userId, sessionId) {
  return jwt.sign({ sub: userId, sid: sessionId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// LOGIN endpoint
app.post('/api/login', (req, res) => {
  const { username, password, deviceInfo } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'username & password required' });

  const user = users[username];
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  // Allow only one device at a time
  if (user.currentSessionId) {
    return res.status(403).json({ error: 'Account already logged in on another device' });
  }

  const newSid = uuidv4();
  user.currentSessionId = newSid;

  const token = issueToken(user.id, newSid);
  return res.json({ token, expiresIn: JWT_EXPIRES });
});

// ME endpoint (verify login)
app.get('/api/me', (req, res) => {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'missing token' });

  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = Object.values(users).find(u => u.id === payload.sub);
    if (!user) return res.status(401).json({ error: 'invalid token' });
    if (!user.currentSessionId || user.currentSessionId !== payload.sid) {
      return res.status(401).json({ error: 'session invalid or logged in elsewhere' });
    }
    return res.json({ id: user.id, username: user.username });
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
});

// LOGOUT endpoint
app.post('/api/logout', (req, res) => {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'missing token' });

  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = Object.values(users).find(u => u.id === payload.sub);
    if (user && user.currentSessionId === payload.sid) {
      user.currentSessionId = null;
    }
  } catch {}
  return res.json({ ok: true });
});

// Serve login.html and sara.html from same folder
app.use(express.static('.'));

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log('Login with -> username: admin  password: 1234');
});
