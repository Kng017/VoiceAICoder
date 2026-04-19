require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 4000;

//  MIDDLEWARE
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(__dirname));

//  POSTGRESQL CONNECTION POOL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log('✅  Connected to Supabase PostgreSQL'))
  .catch(err => console.error('❌  DB connection error:', err.message));

//  HELPERS
const JWT_SECRET     = process.env.JWT_SECRET || 'change_me_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function tokenExpiresAt() {
  const ms = 7 * 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ms);
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });

  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user  = payload;
    req.token = token;
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
}

//  ROUTES

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !name.trim())
    return res.status(400).json({ field: 'name', error: 'Name is required' });
  if (!email || !/\S+@\S+\.\S+/.test(email))
    return res.status(400).json({ field: 'email', error: 'Valid email is required' });
  if (!password || password.length < 6)
    return res.status(400).json({ field: 'password', error: 'Password must be at least 6 characters' });

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      'SELECT * FROM public.sp_create_user($1, $2, $3)',
      [name.trim(), email.toLowerCase().trim(), hash]
    );

    const row = result.rows[0];

    if (!row.success) {
      if (row.error_code === 'EMAIL_EXISTS')
        return res.status(409).json({ field: 'email', error: 'Email already in use' });
      return res.status(500).json({ error: 'Registration failed' });
    }

    const userId = row.user_id;
    const token  = signToken({ id: userId, name: name.trim(), email: email.toLowerCase().trim() });

    await pool.query(
      'SELECT public.sp_create_session($1, $2, $3, $4, $5)',
      [userId, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]
    );

    res.status(201).json({
      message: 'Account created',
      token,
      user: { id: userId, name: name.trim(), email: email.toLowerCase().trim() },
    });

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// POST /auth/signin
app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  try {
    const result = await pool.query(
      'SELECT * FROM public.sp_get_user_by_email($1)',
      [email.toLowerCase().trim()]
    );

    const user = result.rows[0];

    if (!user)
      return res.status(401).json({ field: 'email', error: 'No account found with this email' });

    if (!user.is_active)
      return res.status(403).json({ error: 'Account is disabled' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ field: 'password', error: 'Incorrect password' });

    await pool.query('SELECT public.sp_update_last_login($1)', [user.id]);

    const token = signToken({ id: user.id, name: user.name, email: user.email });

    await pool.query(
      'SELECT public.sp_create_session($1, $2, $3, $4, $5)',
      [user.id, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]
    );

    res.json({
      message: 'Signed in',
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: 'Server error during sign in' });
  }
});

// POST /auth/signout
app.post('/auth/signout', authMiddleware, async (req, res) => {
  try {
    await pool.query('SELECT public.sp_delete_session($1)', [req.token]);
    res.json({ message: 'Signed out' });
  } catch (err) {
    console.error('Signout error:', err);
    res.status(500).json({ error: 'Server error during sign out' });
  }
});

// GET /auth/me
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM public.sp_validate_session($1)',
      [req.token]
    );

    if (!result.rows.length)
      return res.status(401).json({ error: 'Session expired' });

    const { id, name, email } = result.rows[0];
    res.json({ user: { id, name, email } });

  } catch (err) {
    console.error('/auth/me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// ── FILES (Cloud Save) ──
app.post('/files/save', authMiddleware, async (req, res) => {
  const { filename, code } = req.body;
  if (!filename || code === undefined) return res.status(400).json({ error: 'Missing fields' });
  try {
    const db = pool;
    await db.query(`
      INSERT INTO public.user_files (user_id, filename, code, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (user_id, filename)
      DO UPDATE SET code = $3, updated_at = NOW()
    `, [req.user.id, filename, code]);
    res.json({ success: true });
  } catch (err) {
    console.error('File save error:', err);
    res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/files/list', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, filename, code, updated_at FROM public.user_files WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 50',
      [req.user.id]
    );
    res.json({ files: result.rows });
  } catch (err) {
    console.error('File list error:', err);
    res.status(500).json({ error: 'List failed' });
  }
});

// ── DELETE FILE ──
app.delete('/files/delete/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM public.user_files WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('File delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ── SHARE CODE ──
app.post('/files/share', async (req, res) => {
  const { filename, code } = req.body;
  if (!code) return res.status(400).json({ error: 'No code' });
  try {
    const id = require('crypto').randomBytes(8).toString('hex');
    await pool.query(
      'INSERT INTO public.shared_files (share_id, filename, code, created_at) VALUES ($1, $2, $3, NOW())',
      [id, filename || 'snippet.cpp', code]
    );
    const url = `${process.env.FRONTEND_URL || 'https://voicecoder.netlify.app/index.html'}?share=${id}`;
    res.json({ url });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Share failed' });
  }
});

app.get('/files/share/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT filename, code FROM public.shared_files WHERE share_id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Fetch failed' });
  }
});

// ── AI CHAT HISTORY ──
app.post('/chat/save', authMiddleware, async (req, res) => {
  const { history } = req.body;
  if (!history) return res.status(400).json({ error: 'No history' });
  try {
    await pool.query(`
      INSERT INTO public.chat_history (user_id, history, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (user_id) DO UPDATE SET history = $2, updated_at = NOW()
    `, [req.user.id, JSON.stringify(history)]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/chat/history', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT history FROM public.chat_history WHERE user_id = $1', [req.user.id]);
    if (!result.rows.length) return res.json({ history: [] });
    res.json({ history: JSON.parse(result.rows[0].history) });
  } catch (err) {
    res.status(500).json({ error: 'Load failed' });
  }
});

// ── JUDGE0 PROXY ──
app.post('/compile/judge0', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code' });
  try {
    const nodeFetch = await import('node-fetch').then(m => m.default);
    const sub = await nodeFetch('https://judge0-ce.p.rapidapi.com/submissions?base64_encoded=false&wait=true', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-RapidAPI-Key': process.env.RAPIDAPI_KEY || '',
        'X-RapidAPI-Host': 'judge0-ce.p.rapidapi.com'
      },
      body: JSON.stringify({ source_code: code, language_id: 54, stdin: '' })
    });
    if (!sub.ok) {
      // Fallback to Paiza if no RapidAPI key
      const cr = await nodeFetch('https://api.paiza.io/runners/create?source_code=' + encodeURIComponent(code) + '&language=cpp&api_key=guest', { method: 'POST' });
      if (!cr.ok) return res.json({ success: false, error: 'Compiler unavailable' });
      const { id } = await cr.json();
      await new Promise(r => setTimeout(r, 3000));
      const gr = await nodeFetch('https://api.paiza.io/runners/get_details?id=' + id + '&api_key=guest');
      const d = await gr.json();
      if (d.build_result === 'failure') return res.json({ success: false, error: d.build_stderr || 'Build failed' });
      return res.json({ success: true, output: d.stdout || '(no output)' });
    }
    const d = await sub.json();
    if (d.compile_output) return res.json({ success: false, errors: [d.compile_output] });
    if (d.stderr) return res.json({ success: false, errors: [d.stderr] });
    res.json({ success: true, output: d.stdout || '(no output)' });
  } catch (err) {
    console.error('Judge0 proxy error:', err);
    res.json({ success: false, error: err.message });
  }
});

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date() }));

// COMPILE PROXY — avoids CORS issues from the browser

// Paiza.io proxy
app.post('/compile/paiza', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code provided' });
  try {
    const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
    const cr = await fetch(
      'https://api.paiza.io/runners/create?source_code=' + encodeURIComponent(code) + '&language=cpp&api_key=guest',
      { method: 'POST' }
    );
    if (!cr.ok) return res.json({ success: false, error: 'Paiza create failed: ' + cr.status });
    const { id } = await cr.json();
    await new Promise(r => setTimeout(r, 3000));
    const gr = await fetch('https://api.paiza.io/runners/get_details?id=' + id + '&api_key=guest');
    if (!gr.ok) return res.json({ success: false, error: 'Paiza details failed: ' + gr.status });
    const d = await gr.json();
    if (d.build_result === 'failure')
      return res.json({ success: false, error: d.build_stderr || 'Build failed' });
    return res.json({ success: true, output: d.stdout || '(no output)' });
  } catch (err) {
    console.error('Paiza proxy error:', err);
    res.json({ success: false, error: err.message });
  }
});

// JDoodle proxy
app.post('/compile/jdoodle', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code provided' });
  const clientId     = process.env.JDOODLE_CLIENT_ID;
  const clientSecret = process.env.JDOODLE_CLIENT_SECRET;
  if (!clientId || !clientSecret)
    return res.json({ success: false, error: 'JDoodle credentials not configured on server' });
  try {
    const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
    const r = await fetch('https://api.jdoodle.com/v1/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId, clientSecret, script: code, language: 'cpp17', versionIndex: '0' })
    });
    if (!r.ok) return res.json({ success: false, error: 'JDoodle HTTP ' + r.status });
    const d = await r.json();
    if (d.error) return res.json({ success: false, error: d.error });
    if (d.output?.toLowerCase().includes('error:'))
      return res.json({ success: false, error: d.output });
    return res.json({ success: true, output: d.output || '' });
  } catch (err) {
    console.error('JDoodle proxy error:', err);
    res.json({ success: false, error: err.message });
  }
});

//  START SERVER
app.listen(PORT, () => {
  console.log(`🚀  VoiceCoder server running on http://localhost:${PORT}`);
  console.log(`🌐  Open: http://localhost:${PORT}/voicecoder_ai_sql.html`);
});
