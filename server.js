'use strict';
require('dotenv').config();

const express = require('express');
const https   = require('https');
const crypto  = require('crypto');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 4000;

// ═══════════════════════════════════════════════════════════
//  CORS — manual middleware, no 'cors' package wildcard issues
// ═══════════════════════════════════════════════════════════
const ALLOWED_ORIGINS = [
  'https://voiceaicoder.netlify.app',
  'https://voicecoder.netlify.app',
  'http://localhost:8080',
  'http://localhost:3000',
  'http://localhost:4000',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',      origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods',     'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',     'Content-Type,Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json());
app.use(express.static(__dirname));

// ═══════════════════════════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
pool.connect()
  .then(() => console.log('✅  Connected to Supabase PostgreSQL'))
  .catch(err => console.error('❌  DB connection error:', err.message));

// ═══════════════════════════════════════════════════════════
//  JWT HELPERS
// ═══════════════════════════════════════════════════════════
const JWT_SECRET     = process.env.JWT_SECRET || 'change_me_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const signToken      = payload => jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
const tokenExpiresAt = ()      => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

// ═══════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user  = jwt.verify(auth.slice(7), JWT_SECRET);
    req.token = auth.slice(7);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
}

// ═══════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date() }));

// ═══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════
app.post('/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ field: 'name', error: 'Name is required' });
  if (!email || !/\S+@\S+\.\S+/.test(email))
    return res.status(400).json({ field: 'email', error: 'Valid email is required' });
  if (!password || password.length < 6)
    return res.status(400).json({ field: 'password', error: 'Password must be at least 6 characters' });
  try {
    const hash   = await bcrypt.hash(password, 12);
    const result = await pool.query('SELECT * FROM public.sp_create_user($1,$2,$3)',
      [name.trim(), email.toLowerCase().trim(), hash]);
    const row = result.rows[0];
    if (!row.success) {
      if (row.error_code === 'EMAIL_EXISTS')
        return res.status(409).json({ field: 'email', error: 'Email already in use' });
      return res.status(500).json({ error: 'Registration failed' });
    }
    const userId = row.user_id;
    const token  = signToken({ id: userId, name: name.trim(), email: email.toLowerCase().trim() });
    await pool.query('SELECT public.sp_create_session($1,$2,$3,$4,$5)',
      [userId, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]);
    res.status(201).json({ message: 'Account created', token,
      user: { id: userId, name: name.trim(), email: email.toLowerCase().trim() } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });
  try {
    const result = await pool.query('SELECT * FROM public.sp_get_user_by_email($1)',
      [email.toLowerCase().trim()]);
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
    await pool.query('SELECT public.sp_create_session($1,$2,$3,$4,$5)',
      [user.id, token, tokenExpiresAt(), req.ip || null, req.headers['user-agent'] || null]);
    res.json({ message: 'Signed in', token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: 'Server error during sign in' });
  }
});

app.post('/auth/signout', requireAuth, async (req, res) => {
  try {
    await pool.query('SELECT public.sp_delete_session($1)', [req.token]);
    res.json({ message: 'Signed out' });
  } catch (err) {
    console.error('Signout error:', err);
    res.status(500).json({ error: 'Server error during sign out' });
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM public.sp_validate_session($1)', [req.token]);
    if (!result.rows.length) return res.status(401).json({ error: 'Session expired' });
    const { id, name, email } = result.rows[0];
    res.json({ user: { id, name, email } });
  } catch (err) {
    console.error('/auth/me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════════════════════════════
//  FILES
// ═══════════════════════════════════════════════════════════
app.post('/files/save', requireAuth, async (req, res) => {
  const { filename, code } = req.body;
  if (!filename || code === undefined) return res.status(400).json({ error: 'Missing fields' });
  try {
    await pool.query(`
      INSERT INTO public.user_files (user_id,filename,code,updated_at) VALUES ($1,$2,$3,NOW())
      ON CONFLICT (user_id,filename) DO UPDATE SET code=$3, updated_at=NOW()
    `, [req.user.id, filename, code]);
    res.json({ success: true });
  } catch (err) {
    console.error('File save error:', err);
    res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/files/list', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id,filename,code,updated_at FROM public.user_files WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50',
      [req.user.id]);
    res.json({ files: result.rows });
  } catch (err) {
    console.error('File list error:', err);
    res.status(500).json({ error: 'List failed' });
  }
});

app.delete('/files/delete/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM public.user_files WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('File delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ═══════════════════════════════════════════════════════════
//  SHARE
// ═══════════════════════════════════════════════════════════
app.post('/files/share', async (req, res) => {
  const { filename, code } = req.body;
  if (!code) return res.status(400).json({ error: 'No code' });
  try {
    const id  = crypto.randomBytes(8).toString('hex');
    await pool.query('INSERT INTO public.shared_files (share_id,filename,code,created_at) VALUES ($1,$2,$3,NOW())',
      [id, filename || 'snippet.cpp', code]);
    const base = process.env.FRONTEND_URL || 'https://voicecoder.netlify.app';
    res.json({ url: `${base}?share=${id}` });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Share failed' });
  }
});

app.get('/files/share/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT filename,code FROM public.shared_files WHERE share_id=$1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Fetch failed' });
  }
});

// ═══════════════════════════════════════════════════════════
//  CHAT HISTORY
// ═══════════════════════════════════════════════════════════
app.post('/chat/save', requireAuth, async (req, res) => {
  const { history } = req.body;
  if (!history) return res.status(400).json({ error: 'No history' });
  try {
    await pool.query(`
      INSERT INTO public.chat_history (user_id,history,updated_at) VALUES ($1,$2,NOW())
      ON CONFLICT (user_id) DO UPDATE SET history=$2, updated_at=NOW()
    `, [req.user.id, JSON.stringify(history)]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/chat/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT history FROM public.chat_history WHERE user_id=$1', [req.user.id]);
    if (!result.rows.length) return res.json({ history: [] });
    res.json({ history: JSON.parse(result.rows[0].history) });
  } catch (err) {
    res.status(500).json({ error: 'Load failed' });
  }
});

// ═══════════════════════════════════════════════════════════
//  HTTPS HELPER  (server-side, no browser CORS limits)
// ═══════════════════════════════════════════════════════════
function httpPostJson(url, payload) {
  return new Promise((resolve, reject) => {
    const body   = JSON.stringify(payload);
    const parsed = new URL(url);
    const req    = https.request({
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try   { resolve({ ok: res.statusCode < 400, status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ ok: false, status: res.statusCode, data: {}, raw: data }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════
//  COMPILE PROXIES
// ═══════════════════════════════════════════════════════════
async function pistonCompile(code, res) {
  if (!code) return res.status(400).json({ success: false, error: 'No code provided' });
  try {
    const result = await httpPostJson('https://emkc.org/api/v2/piston/execute', {
      language: 'cpp', version: '*',
      files: [{ name: 'main.cpp', content: code }],
      stdin: '', args: [], compile_timeout: 10000, run_timeout: 5000,
    });
    if (!result.ok)
      return res.json({ success: false, error: `Compiler unavailable (${result.status})` });
    const d = result.data;
    if (d.compile && d.compile.code !== 0)
      return res.json({ success: false, errors: [(d.compile.stderr || d.compile.output || 'Compile error').trim()] });
    if (d.run && d.run.code !== 0 && d.run.stderr)
      return res.json({ success: false, errors: [d.run.stderr.trim()] });
    res.json({ success: true, output: (d.run?.output || d.run?.stdout || '').trim() || '(no output)' });
  } catch (err) {
    console.error('Piston error:', err.message);
    res.json({ success: false, error: 'Compiler error: ' + err.message });
  }
}

app.post('/compile/piston', (req, res) => pistonCompile(req.body?.code, res));
app.post('/compile/paiza',  (req, res) => pistonCompile(req.body?.code, res));

app.post('/compile/jdoodle', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'No code' });
  const clientId     = process.env.JDOODLE_CLIENT_ID;
  const clientSecret = process.env.JDOODLE_CLIENT_SECRET;
  if (!clientId || !clientSecret)
    return res.json({ success: false, error: 'JDoodle credentials not set in Railway Variables' });
  try {
    const r = await httpPostJson('https://api.jdoodle.com/v1/execute',
      { clientId, clientSecret, script: code, language: 'cpp17', versionIndex: '0' });
    const d = r.data;
    if (d.error) return res.json({ success: false, error: d.error });
    if ((d.output || '').toLowerCase().includes('error:'))
      return res.json({ success: false, errors: [d.output] });
    res.json({ success: true, output: d.output || '(no output)' });
  } catch (err) {
    console.error('JDoodle error:', err.message);
    res.json({ success: false, error: 'JDoodle error: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`🚀  VoiceCoder server running on http://localhost:${PORT}`);
  console.log(`🌐  Open: http://localhost:${PORT}/voicecoder_ai_sql.html`);
});
