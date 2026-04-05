const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const dotenv = require('dotenv');
const cors = require('cors');
const nodemailer = require('nodemailer');
const supabase = require('./db');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});
app.use(express.static('.'));

// Register
app.post('/api/register', async (req, res) => {
  const { fullname, email, password } = req.body;
  if (!fullname || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const emailTrim = (email || '').trim();
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!emailRegex.test(emailTrim)) return res.status(400).json({ error: 'Invalid email format' });



    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', emailTrim)
      .maybeSingle();
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(24).toString('hex');

    const { error: insertErr } = await supabase.from('users').insert({
      fullname,
      email: emailTrim,
      password_hash: hash,
      verification_token: token,
      email_verified: false
    });
    if (insertErr) throw insertErr;

    const host = process.env.APP_HOST || `http://localhost:${process.env.PORT || 3000}`;
    const verifyUrl = `${host.replace(/\/$/, '')}/verify?token=${token}`;

    (async function sendMail() {
      try {
        if (process.env.SMTP_HOST && process.env.SMTP_USER) {
          const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
          });
          await transporter.sendMail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: emailTrim,
            subject: 'Please verify your email',
            text: `Click to verify: ${verifyUrl}`,
            html: `<p>Click to verify your email: <a href="${verifyUrl}">${verifyUrl}</a></p>`
          });
          console.log('Verification email sent to', emailTrim);
        } else {
          console.log('Verification URL (no SMTP configured):', verifyUrl);
        }
      } catch (err) {
        console.warn('Unable to send verification email', err && err.message ? err.message : err);
      }
    })();

    const exposeVerify = !process.env.SMTP_HOST || process.env.SHOW_VERIFY_LINK === 'true';
    const resp = { success: true, message: 'Registration OK — verification email sent if SMTP configured' };
    if (exposeVerify) resp.verifyUrl = verifyUrl;
    return res.json(resp);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Email verification route
app.get('/verify', async (req, res) => {
  const token = (req.query.token || '').trim();
  if (!token) return res.status(400).send('Missing token');
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('verification_token', token)
      .maybeSingle();
    if (error || !user) return res.status(400).send('Invalid or expired token');

    await supabase
      .from('users')
      .update({ email_verified: true, verification_token: null })
      .eq('id', user.id);

    const host = process.env.APP_HOST || `http://localhost:${process.env.PORT || 3000}`;
    return res.redirect(`${host.replace(/\/$/, '')}/login.html?verified=1`);
  } catch (err) {
    console.error('verify error', err);
    return res.status(500).send('Server error');
  }
});

// Resend verification link
app.post('/api/resend-verification', async (req, res) => {
  const email = (req.body && req.body.email) ? String(req.body.email).trim() : '';
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const { data: user } = await supabase
      .from('users')
      .select('id, email_verified')
      .eq('email', email)
      .maybeSingle();

    if (!user) {
      console.log('Resend-verification requested for unknown email:', email);
      return res.json({ success: true, message: 'If an account exists, a verification link was sent.' });
    }
    if (user.email_verified) return res.json({ success: true, message: 'Email already verified' });

    const token = crypto.randomBytes(24).toString('hex');
    await supabase.from('users').update({ verification_token: token }).eq('id', user.id);

    const host = process.env.APP_HOST || `http://localhost:${process.env.PORT || 3000}`;
    const verifyUrl = `${host.replace(/\/$/, '')}/verify?token=${token}`;

    (async function sendMail() {
      try {
        if (process.env.SMTP_HOST && process.env.SMTP_USER) {
          const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
          });
          await transporter.sendMail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: email,
            subject: 'Please verify your email',
            text: `Click to verify: ${verifyUrl}`,
            html: `<p>Click to verify your email: <a href="${verifyUrl}">${verifyUrl}</a></p>`
          });
        } else {
          console.log('Verification URL (no SMTP configured):', verifyUrl);
        }
      } catch (err) {
        console.warn('Unable to send verification email', err && err.message ? err.message : err);
      }
    })();

    const exposeVerify = !process.env.SMTP_HOST || process.env.SHOW_VERIFY_LINK === 'true';
    const resp = { success: true, message: 'If an account exists, a verification link was sent.' };
    if (exposeVerify) resp.verifyUrl = verifyUrl;
    return res.json(resp);
  } catch (err) {
    console.error('resend-verification error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { data: user } = await supabase
      .from('users')
      .select('id, fullname, password_hash, email_verified')
      .eq('email', email)
      .maybeSingle();

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.email_verified) return res.status(403).json({ error: 'Email not verified' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);
    return res.json({ success: true, fullname: user.fullname, email });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Create order
app.post('/api/orders', async (req, res) => {
  const { email, fullname, total, paymentMethod, items, address, phone } = req.body || {};
  console.log('/api/orders payload:', { email, fullname, total, paymentMethod, items: (items || []).length, address, phone });
  if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'No items' });
  if (!phone || !/^\d{10,11}$/.test(phone)) return res.status(400).json({ error: 'Phone number must be 10 or 11 digits.' });

  try {
    let userId = null;
    if (email) {
      const { data: u } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (u) userId = u.id;
    }

    const { data: order, error: orderErr } = await supabase
      .from('orders')
      .insert({ user_id: userId, fullname: fullname || '', email: email || '', total: Number(total) || 0, payment_method: paymentMethod || null, address: address || null, phone: phone || null })
      .select('id')
      .single();
    if (orderErr) { console.error('Supabase order insert error:', orderErr); throw orderErr; }

    const itemRows = items.map(it => ({
      order_id: order.id,
      name: it.name || '',
      price: Number(it.price) || 0,
      qty: Number(it.qty) || 0,
      img: it.img || null,
      description: it.desc || it.description || null
    }));
    const { error: itemsErr } = await supabase.from('order_items').insert(itemRows);
    if (itemsErr) throw itemsErr;

    return res.json({ success: true, orderId: order.id });
  } catch (err) {
    console.error('order error', err);
    return res.status(500).json({ error: 'Unable to create order' });
  }
});

// Save delivery details
app.post('/api/delivery', async (req, res) => {
  const { email, fullname, address, phone } = req.body || {};
  if (!address || !phone) return res.status(400).json({ error: 'Missing address or phone' });
  if (!/^\d{10,11}$/.test(phone)) return res.status(400).json({ error: 'Phone number must be 10 or 11 digits.' });

  try {
    let userId = null;
    if (email) {
      const { data: u } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (u) userId = u.id;
    }

    const { data: order, error } = await supabase
      .from('orders')
      .insert({ user_id: userId, fullname: fullname || '', email: email || '', total: 0, payment_method: 'SavedDetails', address: address || null, phone: phone || null })
      .select('id')
      .single();
    if (error) throw error;

    return res.json({ success: true, orderId: order.id });
  } catch (err) {
    console.error('delivery save error', err);
    return res.status(500).json({ error: 'Unable to save delivery', detail: err && err.message });
  }
});

// Fetch orders for a user (by email)
app.get('/api/orders', async (req, res) => {
  const email = (req.query.email || '').trim();
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const { data: orders, error } = await supabase
      .from('orders')
      .select('id, user_id, fullname, email, total, payment_method, address, phone, created_at')
      .eq('email', email)
      .order('created_at', { ascending: false });
    if (error) throw error;

    const results = [];
    for (const o of orders) {
      const { data: items } = await supabase
        .from('order_items')
        .select('id, name, price, qty, img, description')
        .eq('order_id', o.id);
      results.push({ order: o, items: items || [] });
    }
    return res.json({ success: true, orders: results });
  } catch (err) {
    console.error('orders fetch error', err);
    return res.status(500).json({ error: 'Unable to fetch orders', detail: err && err.message });
  }
});

// Update profile
app.post('/api/profile', async (req, res) => {
  const { email, fullname } = req.body || {};
  if (!email || !fullname) return res.status(400).json({ error: 'Missing email or fullname' });
  try {
    await supabase.from('users').update({ fullname }).eq('email', email);
    await supabase.from('orders').update({ fullname }).eq('email', email);
    return res.json({ success: true });
  } catch (err) {
    console.error('profile update error', err);
    return res.status(500).json({ error: 'Unable to update profile', detail: err && err.message });
  }
});

// Forgot password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });
  try {
    const { data: user } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
    if (!user) {
      console.log('Forgot-password requested for unknown email:', email);
      return res.json({ success: true, message: 'If an account exists, a reset link was sent.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await supabase.from('users').update({ reset_token: token, reset_expires: expires }).eq('id', user.id);

    const host = process.env.APP_HOST || `http://localhost:${process.env.PORT || 3000}`;
    const resetUrl = `${host.replace(/\/$/, '')}/reset-password.html?token=${token}`;
    console.log('Password reset URL for', email, resetUrl);
    return res.json({ success: true, message: 'If an account exists, a reset link was sent.' });
  } catch (err) {
    console.error('forgot-password error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Reset password using token
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const { data: user } = await supabase
      .from('users')
      .select('id')
      .eq('reset_token', token)
      .gt('reset_expires', new Date().toISOString())
      .maybeSingle();
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

    const hash = await bcrypt.hash(password, 10);
    await supabase.from('users').update({ password_hash: hash, reset_token: null, reset_expires: null }).eq('id', user.id);
    console.log('Password reset for user id', user.id);
    return res.json({ success: true, message: 'Password has been reset' });
  } catch (err) {
    console.error('reset-password error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Simple reset (no token)
app.post('/api/reset-password-simple', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const { data: user } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
    if (!user) {
      console.log('Simple reset requested for unknown email:', email);
      return res.json({ success: true, message: 'If an account exists, the password was reset.' });
    }
    const hash = await bcrypt.hash(password, 10);
    await supabase.from('users').update({ password_hash: hash, reset_token: null, reset_expires: null }).eq('id', user.id);
    console.log('Password reset (simple) for user id', user.id);
    return res.json({ success: true, message: 'If an account exists, the password was reset.' });
  } catch (err) {
    console.error('reset-password-simple error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on port ${PORT}`));
