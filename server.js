const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const AWS = require('aws-sdk');
const Stripe = require('stripe');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const fetch = require('node-fetch');

const path = require('path');

const PORT = process.env.PORT || 4000;
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/postgres';
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

const pool = new Pool({ connectionString: DATABASE_URL });

const app = express();

async function searchProducts(q, country) {
  // very simple SQL search for scaffold - fulltext or Elastic recommended for prod
  const like = '%' + (q || '') + '%';
  let sql = `SELECT p.*, c.name as company_name, pm.url as image FROM products p LEFT JOIN companies c ON c.id=p.company_id LEFT JOIN product_media pm ON pm.product_id=p.id AND pm.ordering=0 WHERE (p.title ILIKE $1 OR p.description ILIKE $1 OR c.name ILIKE $1) GROUP BY p.id, c.name, pm.url ORDER BY p.created_at DESC LIMIT 20`;
  const params = [like];
  const { rows } = await pool.query(sql, params);
  return rows.map(r=>({ id:r.id, title:r.title, company_name:r.company_name, base_price:r.base_price, base_currency:r.base_currency, image:r.image }));
}


app.use(cors());
// Ensure uploads folders
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const MSG_UPLOADS_DIR = path.join(UPLOADS_DIR, 'messages');
if (!require('fs').existsSync(UPLOADS_DIR)) require('fs').mkdirSync(UPLOADS_DIR);
if (!require('fs').existsSync(MSG_UPLOADS_DIR)) require('fs').mkdirSync(MSG_UPLOADS_DIR);
app.use('/uploads', express.static(UPLOADS_DIR));

app.use(bodyParser.json());

// Uploads folder (for issue images) - simple local storage for scaffold
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!require('fs').existsSync(UPLOADS_DIR)) require('fs').mkdirSync(UPLOADS_DIR);
const storage = multer.diskStorage({


  destination: function (req, file, cb) { cb(null, UPLOADS_DIR); },
  filename: function (req, file, cb) { cb(null, Date.now() + '_' + file.originalname); }
});
const upload = multer({ storage });
app.use('/uploads', express.static(UPLOADS_DIR));

// Security middleware
app.use(helmet());
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }); // 200 requests per 15 minutes
app.use(apiLimiter);

// AWS S3 setup for presigned uploads (if env vars provided)
let s3 = null;
if(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY && process.env.AWS_REGION && process.env.S3_BUCKET){
  AWS.config.update({ accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, region: process.env.AWS_REGION });
  s3 = new AWS.S3();
}

// Stripe init (optional)
let stripe = null;
if(process.env.STRIPE_SECRET_KEY){
  try{ stripe = Stripe(process.env.STRIPE_SECRET_KEY); }catch(e){ console.error('Stripe init error', e); }
}



// --- Auth helpers ---
const ACCESS_TOKEN_EXP = '15m';
const REFRESH_TOKEN_EXP_DAYS = 30;
function generateAccessToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXP }); }
function generateRefreshToken(){ return crypto.randomBytes(40).toString('hex'); }

// Middleware to protect routes
function authMiddleware(req,res,next){

// Middleware: verify that user purchased a product (simple check)
async function verifyPurchase(req, res, next){
  try{
    const userId = req.body.user_id || (req.user && req.user.id) || null;
    const productId = parseInt(req.params.id || req.body.product_id);
    if(!userId || !productId) return res.status(400).json({ error:'user_id and product_id required' });
    const { rows } = await pool.query('SELECT 1 FROM orders WHERE buyer_id=$1 AND product_id=$2 AND payment_status=$3 LIMIT 1', [userId, productId, 'paid']);
    if(rows.length===0) return res.status(403).json({ error:'Purchase not verified' });
    next();
  }catch(e){ console.error(e); return res.status(500).json({ error:'verifyPurchase failed' }); }
}

  const auth = req.headers['authorization'];
  if(!auth) return res.status(401).json({error:'No token'});
  const parts = auth.split(' ');
  if(parts.length!==2) return res.status(401).json({error:'Invalid token'});
  const token = parts[1];
  try{
    const data = jwt.verify(token, JWT_SECRET);
    req.user = { id: data.userId, role: data.role };
    next();
  }catch(e){ return res.status(401).json({ error: 'Invalid or expired token' }); }
}

// --- Auth endpoints ---
app.post('/auth/register', [ body('email').optional().isEmail(), body('phone').optional().isString().isLength({min:6}), body('password').optional().isLength({min:6}) ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, phone, password, name, role } = req.body;
  const hashed = password ? bcrypt.hashSync(password, 10) : null;
  const { rows } = await pool.query('INSERT INTO users(role,email,phone,password_hash,name) VALUES($1,$2,$3,$4,$5) RETURNING id,email,role,name', [role||'client', email, phone, hashed, name]);
  const user = rows[0];
  const access = generateAccessToken({ userId: user.id, role: user.role });
  const refresh = generateRefreshToken();
  const expires = new Date(); expires.setDate(expires.getDate() + REFRESH_TOKEN_EXP_DAYS);
  await pool.query('INSERT INTO refresh_tokens(user_id,token,expires_at) VALUES($1,$2,$3)', [user.id, refresh, expires]);
  res.json({ user, accessToken: access, refreshToken: refresh });
});

app.post('/auth/login', [ body('email').optional().isEmail(), body('phone').optional().isString(), body('password').optional().isString() ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, phone, password } = req.body;
  const { rows } = await pool.query('SELECT id,role,email,phone,password_hash,name FROM users WHERE email=$1 OR phone=$2 LIMIT 1', [email, phone]);
  if(rows.length===0) return res.status(401).json({error:'Not found'});
  const user = rows[0];
  if(user.password_hash){
    const ok = password && bcrypt.compareSync(password, user.password_hash);
    if(!ok) return res.status(401).json({ error:'Invalid credentials' });
  }
  const access = generateAccessToken({ userId: user.id, role: user.role });
  const refresh = generateRefreshToken();
  const expires = new Date(); expires.setDate(expires.getDate() + REFRESH_TOKEN_EXP_DAYS);
  await pool.query('INSERT INTO refresh_tokens(user_id,token,expires_at) VALUES($1,$2,$3)', [user.id, refresh, expires]);
  res.json({ user: {id:user.id,email:user.email,role:user.role,name:user.name}, accessToken: access, refreshToken: refresh });
});

app.post('/auth/refresh', async (req,res)=>{
  const { token } = req.body;
  if(!token) return res.status(400).json({ error:'token required' });
  const { rows } = await pool.query('SELECT * FROM refresh_tokens WHERE token=$1 LIMIT 1', [token]);
  if(rows.length===0) return res.status(401).json({ error:'Invalid refresh token' });
  const rt = rows[0];
  if(new Date(rt.expires_at) < new Date()) return res.status(401).json({ error:'Refresh token expired' });
  // load user
  const { rows: urows } = await pool.query('SELECT id,role FROM users WHERE id=$1', [rt.user_id]);
  if(urows.length===0) return res.status(401).json({ error:'User not found' });
  const user = urows[0];
  const access = generateAccessToken({ userId: user.id, role: user.role });
  res.json({ accessToken: access });
});

// --- OTP (mock SMS) ---
app.post('/auth/request-otp', async (req,res)=>{
  const { phone } = req.body;
  if(!phone) return res.status(400).json({ error:'phone required' });
  const code = Math.floor(100000 + Math.random()*900000).toString();
  const expires = new Date(); expires.setMinutes(expires.getMinutes() + 10);
  await pool.query('INSERT INTO otps(phone,code,expires_at) VALUES($1,$2,$3)', [phone, code, expires]);
  // In real app: send SMS. Here we return the code in response for testing.
  res.json({ ok:true, code });
});

app.post('/auth/verify-otp', async (req,res)=>{
  const { phone, code } = req.body;
  const { rows } = await pool.query('SELECT * FROM otps WHERE phone=$1 AND code=$2 AND used=false LIMIT 1', [phone, code]);
  if(rows.length===0) return res.status(400).json({ error:'Invalid code' });
  const otp = rows[0];
  if(new Date(otp.expires_at) < new Date()) return res.status(400).json({ error:'Code expired' });
  await pool.query('UPDATE otps SET used=true WHERE id=$1', [otp.id]);
  // find or create user by phone
  let { rows: u } = await pool.query('SELECT * FROM users WHERE phone=$1 LIMIT 1', [phone]);
  let user;
  if(u.length===0){ const r = await pool.query('INSERT INTO users(role,phone) VALUES($1,$2) RETURNING id,phone,role', ['client',phone]); user = r.rows[0]; }
  else user = u[0];
  const access = generateAccessToken({ userId: user.id, role: user.role });
  const refresh = generateRefreshToken();
  const expires = new Date(); expires.setDate(expires.getDate() + REFRESH_TOKEN_EXP_DAYS);
  await pool.query('INSERT INTO refresh_tokens(user_id,token,expires_at) VALUES($1,$2,$3)', [user.id, refresh, expires]);
  res.json({ user: { id:user.id, phone:user.phone }, accessToken: access, refreshToken: refresh });
});



// Simple health
app.get('/health', (req,res)=> res.json({ok:true}));

// Auth stub (signup / login minimal)
app.post('/auth/signup', async (req,res)=>{
  const { email, phone, password, name, role } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO users(role,email,phone,password_hash,name) VALUES($1,$2,$3,$4,$5) RETURNING id,email,role',
    [role||'client', email, phone, password ? password : null, name]
  );
  res.json({ user: rows[0] });
});

app.post('/auth/login', [ body('email').optional().isEmail(), body('phone').optional().isString(), body('password').optional().isString() ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, phone } = req.body;
  const { rows } = await pool.query('SELECT id,role,email,phone,name FROM users WHERE email=$1 OR phone=$2 LIMIT 1', [email, phone]);
  if(rows.length===0) return res.status(401).json({error:'Not found'});
  const user = rows[0];
  const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user });
});

// Products endpoints
app.get('/products', async (req,res)=>{
  const { country, company_id } = req.query;
  // Very simple filter: if company_id provided, filter; otherwise return sample from DB
  if(company_id){
    const { rows } = await pool.query('SELECT p.*, c.name as company_name FROM products p LEFT JOIN companies c ON c.id=p.company_id WHERE p.company_id=$1', [company_id]);
    return res.json(rows);
  }
  const { rows } = await pool.query('SELECT p.*, c.name as company_name FROM products p LEFT JOIN companies c ON c.id=p.company_id ORDER BY p.created_at DESC LIMIT 50');
  res.json(rows);
});

app.get('/products/:id', async (req,res)=>{
  const id = req.params.id;
  const { rows } = await pool.query('SELECT p.*, c.name as company_name, c.verified_status FROM products p LEFT JOIN companies c ON c.id=p.company_id WHERE p.id=$1', [id]);
  if(rows.length===0) return res.status(404).json({error:'Not found'});
  const product = rows[0];
  const { rows: media } = await pool.query('SELECT * FROM product_media WHERE product_id=$1 ORDER BY ordering ASC', [id]);
  product.media = media;
  res.json(product);
});

// Companies endpoints
app.get('/companies/:id/catalogue', async (req,res)=>{
  const id = req.params.id;
  const { rows } = await pool.query('SELECT * FROM products WHERE company_id=$1', [id]);
  res.json(rows);
});

app.post('/companies/:id/kyc', async (req,res)=>{
  // In a real app, handle file uploads. Here accept JSON body with doc info.
  const id = req.params.id;
  const { doc_type, file_url } = req.body;
  const { rows } = await pool.query('INSERT INTO kyc_documents(company_id,doc_type,file_url) VALUES($1,$2,$3) RETURNING id', [id, doc_type, file_url]);
  res.json({ id: rows[0].id });
});

app.get('/admin/kyc/pending', async (req,res)=>{
  const { rows } = await pool.query("SELECT k.*, c.name as company_name FROM kyc_documents k LEFT JOIN companies c ON c.id=k.company_id WHERE k.status='uploaded'");
  res.json(rows);
});

// Simple create company/product for testing
app.post('/companies', async (req,res)=>{
  const { name, year_founded } = req.body;
  const { rows } = await pool.query('INSERT INTO companies(name,year_founded) VALUES($1,$2) RETURNING *', [name, year_founded]);
  res.json(rows[0]);
});
app.post('/products', async (req,res)=>{
  const p = req.body;
  const { rows } = await pool.query('INSERT INTO products(company_id,title,sku,description,base_price,base_currency,moq,stock,category) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
  [p.company_id,p.title,p.sku,p.description,p.base_price,p.base_currency,p.moq,p.stock,p.category]);
  res.json(rows[0]);
});



// --- Shipments endpoints ---
app.post('/shipments', async (req,res)=>{
  const { transaction_id, forwarder_id, carrier_id, tracking_number } = req.body;
  const { rows } = await pool.query('INSERT INTO shipments(transaction_id, forwarder_id, carrier_id, tracking_number) VALUES($1,$2,$3,$4) RETURNING *', [transaction_id, forwarder_id, carrier_id, tracking_number]);
  res.json(rows[0]);
});

app.get('/shipments/:id', async (req,res)=>{
  const { id } = req.params;
  const { rows } = await pool.query('SELECT * FROM shipments WHERE id=$1', [id]);
  if(rows.length===0) return res.status(404).json({error:'Not found'});
  res.json(rows[0]);
});

app.patch('/shipments/:id/status', async (req,res)=>{
  const { id } = req.params;
  const { status } = req.body;
  await pool.query('UPDATE shipments SET status=$1, updated_at=now() WHERE id=$2', [status, id]);
  const { rows } = await pool.query('SELECT * FROM shipments WHERE id=$1', [id]);
  res.json(rows[0]);
});

// --- Receptions & Issues ---
app.post('/receptions/:transaction_id', async (req,res)=>{
  const transaction_id = parseInt(req.params.transaction_id);
  const { buyer_id, received } = req.body;
  // create or update reception
  const { rows } = await pool.query('INSERT INTO receptions(transaction_id,buyer_id,received) VALUES($1,$2,$3) RETURNING *', [transaction_id,buyer_id,received]);
  res.json(rows[0]);
});

app.post('/receptions/:transaction_id/issue', upload.array('issue_images', 5), async (req,res)=>{
  const transaction_id = parseInt(req.params.transaction_id);
  const { buyer_id, issue_description } = req.body;
  const files = req.files || [];
  const urls = files.map(f=> `${req.protocol}://${req.get('host')}/uploads/${f.filename}`);
  const { rows } = await pool.query('INSERT INTO receptions(transaction_id,buyer_id,received,issue_reported,issue_description,issue_images) VALUES($1,$2,$3,$4,$5) RETURNING *', [transaction_id,buyer_id,false,true,issue_description, JSON.stringify(urls)]);
  // notify: in real app send emails/notifications
  res.json(rows[0]);
});

app.get('/receptions/issues', async (req,res)=>{
  const { rows } = await pool.query('SELECT r.*, u.name as buyer_name FROM receptions r LEFT JOIN users u ON u.id=r.buyer_id WHERE r.issue_reported=true AND r.resolved=false');
  res.json(rows);
});

// --- Messages (chat linked to transaction) ---

// Upload attachment for a transaction (message attachments)
app.post('/messages/:transaction_id/upload', messageUpload.single('file'), async (req,res)=>{
  try{
    const transaction_id = parseInt(req.params.transaction_id);
    const file = req.file;
    if(!file) return res.status(400).json({ error: 'file required' });
    const url = `${req.protocol}://${req.get('host')}/uploads/messages/${file.filename}`;
    const { rows } = await pool.query('INSERT INTO attachments(transaction_id, uploader_id, url, filename, content_type) VALUES($1,$2,$3,$4,$5) RETURNING *', [transaction_id, req.body.uploader_id || null, url, file.originalname, file.mimetype]);
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'upload failed' }); }
});


app.get('/messages/:transaction_id', async (req,res)=>{
  const transaction_id = parseInt(req.params.transaction_id);
  const { rows } = await pool.query('SELECT m.*, u.name as sender_name, u.role as sender_role FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.transaction_id=$1 ORDER BY m.created_at ASC', [transaction_id]);
  res.json(rows);
});

app.post('/messages/:transaction_id', async (req,res)=>{
  const transaction_id = parseInt(req.params.transaction_id);
  const { sender_id, recipient_role, content, attachments } = req.body;
  const { rows } = await pool.query('INSERT INTO messages(transaction_id,sender_id,recipient_role,content,attachments) VALUES($1,$2,$3,$4,$5) RETURNING *', [transaction_id,sender_id,recipient_role,content, JSON.stringify(attachments||[])]);
  res.json(rows[0]);

    try{ if(typeof io !== 'undefined') io.to('txn_' + String(transaction_id)).emit('new_message', message); }catch(e){console.error('emit error',e);} 
}
);

// Note: This scaffold stores uploaded issue images locally in backend/uploads and serves them via /uploads/*.



// --- Search endpoint (with image preview) ---
app.get('/search', async (req,res)=>{
  const q = req.query.q || '';
  const country = req.query.country || null;
  const results = await searchProducts(q, country);
  res.json(results);
});

// --- Product bulk pricing endpoints ---
app.post('/products/:id/prices', async (req,res)=>{
  const product_id = parseInt(req.params.id);
  const prices = req.body.prices || [];
  // delete existing and insert new (simple approach)
  await pool.query('DELETE FROM product_prices WHERE product_id=$1', [product_id]);
  for(const p of prices){
    await pool.query('INSERT INTO product_prices(product_id,min_qty,max_qty,unit_price) VALUES($1,$2,$3,$4)', [product_id,p.min_qty,p.max_qty,p.unit_price]);
  }
  await pool.query('UPDATE products SET has_bulk_pricing = $1 WHERE id=$2', [prices.length>0, product_id]);
  res.json({ok:true});
});
app.get('/products/:id/prices', async (req,res)=>{
  const product_id = parseInt(req.params.id);
  const { rows } = await pool.query('SELECT * FROM product_prices WHERE product_id=$1 ORDER BY min_qty ASC', [product_id]);
  res.json(rows);
});

// --- User payment link (dashboard) ---
app.post('/users/:id/payment_link', async (req,res)=>{
  const id = parseInt(req.params.id);
  const { payment_link } = req.body;
  await pool.query('UPDATE users SET payment_link=$1, payment_status=$2 WHERE id=$3', [payment_link, payment_link ? 'active' : 'inactive', id]);
  const { rows } = await pool.query('SELECT id,payment_link,payment_status FROM users WHERE id=$1', [id]);
  res.json(rows[0]);
});

// --- Payments (mock) ---
app.post('/payments/initiate', async (req,res)=>{
  const { buyer_id, seller_id, product_id, quantity, currency, method } = req.body;
  // compute price simple: fetch product or use base_price
  const prod = await pool.query('SELECT * FROM products WHERE id=$1', [product_id]);
  if(prod.rows.length===0) return res.status(404).json({error:'Product not found'});
  const p = prod.rows[0];
  // try bulk price
  const prices = await pool.query('SELECT * FROM product_prices WHERE product_id=$1 ORDER BY min_qty ASC', [product_id]);
  let unit_price = p.base_price || 0;
  for(const row of prices.rows){
    if(quantity >= row.min_qty && (row.max_qty IS NULL OR quantity <= row.max_qty)) unit_price = row.unit_price;
  }
  const total = Number(unit_price) * Number(quantity);
  const { rows } = await pool.query('INSERT INTO orders(buyer_id,seller_id,product_id,quantity,total_amount,currency,payment_method) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *', [buyer_id,seller_id,product_id,quantity,total,currency,method]);
  const order = rows[0];
  // create a fake payment url
  const payment_id = 'pay_' + Date.now();
  const payment_url = `https://mock-pay.example.com/${method}/${payment_id}`;
  // For Mobile Money we simulate immediate success for demo
  if(method==='mobile_money'){
    await pool.query('UPDATE orders SET payment_status=$1 WHERE id=$2', ['paid', order.id]);
  }
  res.json({ order, payment_url, payment_id });
});

app.get('/payments/status/:orderId', async (req,res)=>{
  const id = parseInt(req.params.orderId);
  const { rows } = await pool.query('SELECT * FROM orders WHERE id=$1', [id]);
  if(rows.length===0) return res.status(404).json({error:'Not found'});
  res.json({ payment_status: rows[0].payment_status, order: rows[0] });
});



app.post('/companies', async (req,res)=>{
  const { name, year_founded } = req.body;
  const { rows } = await pool.query('INSERT INTO companies(name,year_founded) VALUES($1,$2) RETURNING *', [name, year_founded]);
  res.json(rows[0]);
});
app.post('/products', async (req,res)=>{
  const p = req.body;
  const { rows } = await pool.query('INSERT INTO products(company_id,title,sku,description,base_price,base_currency,moq,stock,category) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
  [p.company_id,p.title,p.sku,p.description,p.base_price,p.base_currency,p.moq,p.stock,p.category]);
  res.json(rows[0]);
});

// --- Search endpoint (simple SQL LIKE, returns thumbnail if exists) ---
app.get('/search', async (req,res)=>{
  const q = (req.query.q || '').trim();
  if(!q) return res.json([]);
  const like = '%' + q + '%';
  const { rows } = await pool.query("SELECT p.id, p.title as name, p.base_price, p.base_currency, c.name as company, pm.url as image FROM products p LEFT JOIN companies c ON c.id=p.company_id LEFT JOIN product_media pm ON pm.product_id=p.id AND pm.ordering=0 WHERE p.title ILIKE $1 OR c.name ILIKE $1 LIMIT 20", [like]);
  res.json(rows);
});

// --- Product bulk pricing endpoints ---
app.get('/products/:id/prices', async (req,res)=>{
  const id = parseInt(req.params.id);
  const { rows } = await pool.query('SELECT * FROM product_prices WHERE product_id=$1 ORDER BY min_qty ASC', [id]);
  res.json(rows);
});

app.post('/products/:id/prices', async (req,res)=>{
  const id = parseInt(req.params.id);
  // expect body: [{min_qty,max_qty,unit_price}, ...]
  const tiers = req.body.tiers || [];
  // delete existing tiers for product (simple approach)
  await pool.query('DELETE FROM product_prices WHERE product_id=$1', [id]);
  for(const t of tiers){
    await pool.query('INSERT INTO product_prices(product_id,min_qty,max_qty,unit_price) VALUES($1,$2,$3,$4)', [id, t.min_qty, t.max_qty || null, t.unit_price]);
  }
  await pool.query('UPDATE products SET has_bulk_pricing = $1 WHERE id=$2', [tiers.length>0, id]);
  const { rows } = await pool.query('SELECT * FROM product_prices WHERE product_id=$1 ORDER BY min_qty ASC', [id]);
  res.json(rows);
});

// --- Orders & Payments (mock) ---
app.post('/orders', async (req,res)=>{
  const { buyer_id, seller_id, product_id, quantity, unit_price, currency, payment_method } = req.body;
  const total = parseFloat(unit_price) * parseInt(quantity);
  const { rows } = await pool.query('INSERT INTO orders(buyer_id,seller_id,product_id,quantity,unit_price,total_amount,currency,payment_method,payment_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [buyer_id,seller_id,product_id,quantity,unit_price,total,currency,payment_method,'pending']);
  // create a mock payment id in memory? For scaffold, return order id and a fake payment_link
  const order = rows[0];
  const payment_link = `https://mock-payments.example.com/pay/order/${order.id}?method=${payment_method}`;
  res.json({ order, payment_link });
});

app.get('/orders/:id', async (req,res)=>{
  const { id } = req.params;
  const { rows } = await pool.query('SELECT o.*, u.name as buyer_name, s.name as seller_name, p.title as product_title FROM orders o LEFT JOIN users u ON u.id=o.buyer_id LEFT JOIN users s ON s.id=o.seller_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=$1', [id]);
  if(rows.length===0) return res.status(404).json({error:'Not found'});
  res.json(rows[0]);
});

// --- Payments mock endpoints ---
const payments = {}; // in-memory store for mock payments
app.post('/payments/initiate', async (req,res)=>{
  const { order_id, method } = req.body;
  const pid = 'pay_' + Date.now();
  payments[pid] = { order_id, method, status: 'pending', created_at: new Date() };
  // return fake redirect link
  res.json({ payment_id: pid, redirect_url: `https://mock-pay.example.com/pay/${pid}` });
});

app.get('/payments/status/:id', async (req,res)=>{
  const id = req.params.id;
  const p = payments[id];
  if(!p) return res.status(404).json({ error: 'not found' });
  res.json(p);
});



// Admin: set payment link for user (simulation)


// --- Cart endpoints ---
app.post('/cart/add',[ body('user_id').isInt(), body('product_id').isInt(), body('quantity').isInt({min:1}) ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { user_id, product_id, quantity, unit_price } = req.body;
  // find or create cart for user
  let { rows } = await pool.query('SELECT id FROM carts WHERE user_id=$1 LIMIT 1', [user_id]);
  let cart_id
  if(rows.length===0){ const r = await pool.query('INSERT INTO carts(user_id) VALUES($1) RETURNING id', [user_id]); cart_id = r.rows[0].id } else { cart_id = rows[0].id }
  // insert item
  const ins = await pool.query('INSERT INTO cart_items(cart_id,product_id,quantity,unit_price) VALUES($1,$2,$3,$4) RETURNING *', [cart_id,product_id,quantity||1,unit_price||null]);
  res.json({ cart_id, item: ins.rows[0] });
});

app.get('/cart/:user_id', async (req,res)=>{
  const user_id = parseInt(req.params.user_id);
  const { rows } = await pool.query('SELECT c.id as cart_id, ci.* , p.title as product_title, p.base_currency FROM carts c LEFT JOIN cart_items ci ON ci.cart_id=c.id LEFT JOIN products p ON p.id=ci.product_id WHERE c.user_id=$1', [user_id]);
  res.json(rows);
});

app.delete('/cart/item/:id', async (req,res)=>{
  const id = parseInt(req.params.id);
  await pool.query('DELETE FROM cart_items WHERE id=$1', [id]);
  res.json({ ok:true });
});

// Checkout: convert cart items into orders and return payment links
app.post('/cart/:user_id/checkout', async (req,res)=>{
  const user_id = parseInt(req.params.user_id);
  const { payment_method } = req.body;
  // fetch cart items
  const { rows: items } = await pool.query('SELECT ci.*, p.company_id, p.base_currency FROM carts c JOIN cart_items ci ON ci.cart_id=c.id JOIN products p ON p.id=ci.product_id WHERE c.user_id=$1', [user_id]);
  if(items.length===0) return res.status(400).json({ error:'Cart empty' });
  const created_orders = [];
  for(const it of items){
    const total = parseFloat(it.unit_price || 0) * parseInt(it.quantity);
    const { rows } = await pool.query('INSERT INTO orders(buyer_id,seller_id,product_id,quantity,unit_price,total_amount,currency,payment_method,payment_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [user_id,it.company_id,it.product_id,it.quantity,it.unit_price,total,it.base_currency,payment_method,'pending']);
    created_orders.push(rows[0]);
  }
  // clear cart
  await pool.query('DELETE FROM cart_items WHERE cart_id IN (SELECT id FROM carts WHERE user_id=$1)', [user_id]);
  // return mock payment links for each order
  const links = created_orders.map(o=> ({ order_id: o.id, payment_link: `https://mock-payments.example.com/pay/order/${o.id}?method=${payment_method}` }));
  res.json({ orders: created_orders, payment_links: links });
});

app.post('/admin/set-payment-link', async (req,res)=>{
  const { user_id, payment_link } = req.body;
  await pool.query('UPDATE users SET payment_link=$1, payment_status=$2 WHERE id=$3', [payment_link, 'active', user_id]);
  const { rows } = await pool.query('SELECT id, payment_link, payment_status FROM users WHERE id=$1', [user_id]);
  res.json(rows[0]);
});



// --- PSP Integrations (sandbox mocks + webhook handlers) ---
// Environment variables expected for real integrations:
// STRIPE_SECRET_KEY, FLUTTERWAVE_SECRET, PAYPAL_CLIENT_ID, PAYPAL_SECRET, ALIPAY_APP_ID

// Stripe-like mock: create checkout session
app.post('/payments/stripe/create-session', async (req,res)=>{
  const { order_id, amount, currency, success_url, cancel_url } = req.body;
  // In real integration, call Stripe SDK here. For scaffold, return mock session id and url
  const sessionId = 'cs_test_' + Date.now();
  const checkout_url = `https://mock-stripe.example.com/checkout/${sessionId}`;
  // store mapping if needed
  res.json({ sessionId, checkout_url });
});

// Stripe webhook (mock)
app.post('/payments/webhook/stripe', bodyParser.raw({type: 'application/json'}), async (req,res)=>{
  // In real app, verify signature
  try{
    const event = JSON.parse(req.body.toString());
    console.log('Stripe webhook event:', event.type);
    // handle checkout.session.completed -> mark order paid
    if(event.type === 'checkout.session.completed'){
      const orderId = event.data.object.metadata.order_id;
      await pool.query('UPDATE orders SET payment_status=$1 WHERE id=$2', ['paid', orderId]);
    }
  }catch(e){ console.error(e); }
  res.json({ received: true });
});

// Flutterwave-like mock initiate
app.post('/payments/flutterwave/initiate', async (req,res)=>{
  const { order_id, amount, currency, phone } = req.body;
  const flw_ref = 'flw_' + Date.now();
  res.json({ flw_ref, checkout_url: `https://mock-flutterwave.example.com/pay/${flw_ref}` });
});
app.post('/payments/webhook/flutterwave', async (req,res)=>{
  const event = req.body;
  console.log('Flutterwave webhook', event);
  if(event && event.event === 'charge.success'){
    const orderId = event.data && event.data.meta && event.data.meta.order_id;
    if(orderId) await pool.query('UPDATE orders SET payment_status=$1 WHERE id=$2', ['paid', orderId]);
  }
  res.json({ ok:true });
});

// PayPal mock
app.post('/payments/paypal/create', async (req,res)=>{
  const { order_id, amount, currency } = req.body;
  const pay_id = 'pp_' + Date.now();
  res.json({ pay_id, approve_url: `https://mock-paypal.example.com/approve/${pay_id}` });
});
app.post('/payments/webhook/paypal', async (req,res)=>{
  const event = req.body; console.log('PayPal webhook', event);
  if(event && event.event_type === 'PAYMENT.SALE.COMPLETED'){
    const orderId = event.resource && event.resource.invoice_number;
    if(orderId) await pool.query('UPDATE orders SET payment_status=$1 WHERE id=$2', ['paid', orderId]);
  }
  res.json({ ok:true });
});

// Alipay mock (simple)
app.post('/payments/alipay/create', async (req,res)=>{
  const { order_id, amount, currency } = req.body;
  const pay_id = 'ali_' + Date.now();
  res.json({ pay_id, redirect_url: `https://mock-alipay.example.com/pay/${pay_id}` });
});
app.post('/payments/webhook/alipay', async (req,res)=>{ console.log('Alipay webhook', req.body); res.json({ ok:true }); });

// Helper: return payment providers available for a seller (checks payment_status)
app.get('/sellers/:id/payment-providers', async (req,res)=>{
  const sid = parseInt(req.params.id);
  const { rows } = await pool.query('SELECT payment_link, payment_status FROM users WHERE id=$1', [sid]);
  if(rows.length===0) return res.status(404).json({ error:'Seller not found' });
  const s = rows[0];
  // For scaffold: return a list indicating available providers depending on payment_link content
  const providers = [];
  if(s.payment_status === 'active'){
    providers.push('momo','card','paypal','alipay');
  }
  res.json({ providers, payment_link: s.payment_link });
});


// --- S3 presigned upload endpoint ---
app.post('/uploads/presign', async (req,res)=>{
  if(!s3) return res.status(400).json({ error:'S3 not configured' });
  const { filename, contentType } = req.body;
  if(!filename || !contentType) return res.status(400).json({ error:'filename and contentType required' });
  const params = { Bucket: process.env.S3_BUCKET, Key: `uploads/${Date.now()}_${filename}`, Expires: 60*5, ContentType: contentType };
  try{
    const url = await s3.getSignedUrlPromise('putObject', params);
    res.json({ url, key: params.Key });
  }catch(e){ console.error(e); res.status(500).json({ error:'presign failed' }); }
});


// --- Stripe real integration (if configured) ---
app.post('/payments/stripe/session', bodyParser.json(), async (req,res)=>{
  if(!stripe) return res.status(400).json({ error:'Stripe not configured' });
  const { order_id, amount, currency, success_url, cancel_url } = req.body;
  try{
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [{ price_data: { currency: currency, product_data: { name: `Order ${order_id}` }, unit_amount: Math.round(amount*100) }, quantity: 1 }],
      success_url: success_url,
      cancel_url: cancel_url,
      metadata: { order_id: order_id }
    });
    res.json({ id: session.id, url: session.url });
  }catch(e){ console.error(e); res.status(500).json({ error:'stripe error' }); }
});

// Stripe webhook with signature verification
app.post('/payments/webhook/stripe', bodyParser.raw({type: 'application/json'}), async (req,res)=>{
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if(!webhookSecret){ console.log('No stripe webhook secret configured — skipping verification'); }
  try{
    let event;
    if(webhookSecret && stripe){
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    }else{
      event = JSON.parse(req.body.toString());
    }
    if(event.type === 'checkout.session.completed'){
      const orderId = event.data.object.metadata && event.data.object.metadata.order_id;
      if(orderId) await pool.query('UPDATE orders SET payment_status=$1 WHERE id=$2', ['paid', orderId]);
    }
    res.json({ received: true });
  }catch(e){ console.error('Webhook error', e); res.status(400).send(`Webhook Error: ${e.message}`); }
});


// Multer storage for message attachments
const messageStorage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, MSG_UPLOADS_DIR); },
  filename: function (req, file, cb) { cb(null, Date.now() + '_' + file.originalname); }
});
const messageUpload = multer({ storage: messageStorage, limits: { fileSize: 10 * 1024 * 1024 } });



// Translation endpoint (mock or using external provider if configured)
app.get('/messages/:id/translate', async (req,res)=>{
  const id = parseInt(req.params.id);
  const target = req.query.lang || 'en';
  try{
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [id]);
    if(rows.length===0) return res.status(404).json({ error:'message not found' });
    const msg = rows[0];
    const original = msg.content || '';
    // If external provider configured, call it (not implemented here). Otherwise return mock translation
    if(process.env.TRANSLATION_PROVIDER && process.env.TRANSLATION_API_KEY){
      // Placeholder: in real app call provider API
      // For now, respond with provider-not-configured error to avoid external calls
      return res.status(501).json({ error:'External translation provider not implemented in scaffold' });
    }
    const translated = `[translated to ${target}] ${original}`;
    // save translation
    await pool.query('INSERT INTO translations(message_id,target_lang,translated_text,provider) VALUES($1,$2,$3,$4)', [id, target, translated, 'mock']);
    res.json({ translated });
  }catch(e){ console.error(e); res.status(500).json({ error:'translation failed' }); }
});

// Store translation (optional)
app.post('/messages/:id/translate', async (req,res)=>{
  const id = parseInt(req.params.id);
  const { target_lang, translated_text, provider } = req.body;
  try{
    const { rows } = await pool.query('INSERT INTO translations(message_id,target_lang,translated_text,provider) VALUES($1,$2,$3,$4) RETURNING *', [id, target_lang, translated_text, provider || 'manual']);
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'store translation failed' }); }
});

app.listen(PORT, ()=> console.log('Backend listening on', PORT));


const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);
  socket.on('join', (room) => { socket.join(room); });
  socket.on('leave', (room) => { socket.leave(room); });
  socket.on('send_message', async (data) => {
    try{
      const { transaction_id, sender_id, recipient_role, content, attachments } = data;
      const res = await pool.query('INSERT INTO messages(transaction_id,sender_id,recipient_role,content,attachments) VALUES($1,$2,$3,$4,$5) RETURNING *', [transaction_id,sender_id,recipient_role,content, JSON.stringify(attachments||[])]);
      const message = res.rows[0];
      io.to('txn_' + String(transaction_id)).emit('new_message', message);
    }catch(e){ console.error('socket send_message error', e); }
  });
});

server.listen(PORT, ()=> console.log('Backend + Socket.IO listening on', PORT));


// --- Reviews endpoints ---
// Create product review (user must have purchased the product)
app.post('/products/:id/reviews', authMiddleware, async (req,res)=>{
  try{
    const productId = parseInt(req.params.id);
    const { rating, comment, images, order_id } = req.body;
    const userId = req.user && req.user.id;
    if(!userId) return res.status(401).json({ error:'Auth required' });
    // Verify purchase: ensure there's a paid order matching this user/order/product
    const { rows: ok } = await pool.query('SELECT 1 FROM orders WHERE id=$1 AND buyer_id=$2 AND product_id=$3 AND payment_status=$4 LIMIT 1', [order_id, userId, productId, 'paid']);
    if(ok.length===0) return res.status(403).json({ error:'You can only review products you bought' });
    const { rows } = await pool.query('INSERT INTO product_reviews(product_id,user_id,order_id,rating,comment,images) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', [productId, userId, order_id, rating, comment, JSON.stringify(images || [])]);
    // Optionally update product avg rating (could be computed on the fly)
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'create review failed' }); }
});

// List product reviews
app.get('/products/:id/reviews', async (req,res)=>{
  try{
    const productId = parseInt(req.params.id);
    const { rows } = await pool.query('SELECT pr.*, u.name as user_name FROM product_reviews pr LEFT JOIN users u ON u.id=pr.user_id WHERE pr.product_id=$1 ORDER BY pr.created_at DESC LIMIT 200', [productId]);
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({ error:'list reviews failed' }); }
});

// Summary (average + distribution)
app.get('/products/:id/reviews/summary', async (req,res)=>{
  try{
    const productId = parseInt(req.params.id);
    const { rows } = await pool.query("SELECT AVG(rating)::numeric(10,2) as average, COUNT(*) as count FROM product_reviews WHERE product_id=$1", [productId]);
    const avg = rows[0].average || 0;
    const cnt = parseInt(rows[0].count || 0);
    // distribution
    const distRows = await pool.query('SELECT rating, COUNT(*) as c FROM product_reviews WHERE product_id=$1 GROUP BY rating ORDER BY rating DESC', [productId]);
    res.json({ average: avg, count: cnt, distribution: distRows.rows });
  }catch(e){ console.error(e); res.status(500).json({ error:'summary failed' }); }
});

// Create company review (after purchase)
app.post('/companies/:id/reviews', authMiddleware, async (req,res)=>{
  try{
    const companyId = parseInt(req.params.id);
    const { reliability, shipping_speed, communication, comment, images, order_id } = req.body;
    const userId = req.user && req.user.id;
    if(!userId) return res.status(401).json({ error:'Auth required' });
    // Verify purchase: ensure order belongs to this buyer and seller company (seller)
    const { rows: ok } = await pool.query('SELECT 1 FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id=$1 AND o.buyer_id=$2 AND p.company_id=$3 AND o.payment_status=$4 LIMIT 1', [order_id, userId, companyId, 'paid']);
    if(ok.length===0) return res.status(403).json({ error:'You can only review a company you bought from' });
    const { rows } = await pool.query('INSERT INTO company_reviews(company_id,user_id,order_id,reliability,shipping_speed,communication,comment,images) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [companyId, userId, order_id, reliability, shipping_speed, communication, comment, JSON.stringify(images || [])]);
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'create company review failed' }); }
});

// List company reviews
app.get('/companies/:id/reviews', async (req,res)=>{
  try{
    const companyId = parseInt(req.params.id);
    const { rows } = await pool.query('SELECT cr.*, u.name as user_name FROM company_reviews cr LEFT JOIN users u ON u.id=cr.user_id WHERE cr.company_id=$1 ORDER BY cr.created_at DESC LIMIT 200', [companyId]);
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({ error:'list company reviews failed' }); }
});

// Company review summary
app.get('/companies/:id/reviews/summary', async (req,res)=>{
  try{
    const companyId = parseInt(req.params.id);
    const { rows } = await pool.query("SELECT AVG((coalesce(reliability,0)+coalesce(shipping_speed,0)+coalesce(communication,0))/3)::numeric(10,2) as average, COUNT(*) as count FROM company_reviews WHERE company_id=$1", [companyId]);
    res.json({ average: rows[0].average || 0, count: parseInt(rows[0].count || 0) });
  }catch(e){ console.error(e); res.status(500).json({ error:'company summary failed' }); }
});

// Reply to a review (seller/admin)
app.post('/reviews/:id/reply', authMiddleware, async (req,res)=>{
  try{
    const reviewId = parseInt(req.params.id);
    const { message } = req.body;
    const replierId = req.user && req.user.id;
    const { rows } = await pool.query('INSERT INTO review_replies(review_id,replier_id,message) VALUES($1,$2,$3) RETURNING *', [reviewId, replierId, message]);
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'reply failed' }); }
});

// Report a review (user)
app.post('/reviews/:id/report', authMiddleware, async (req,res)=>{
  try{
    const reviewId = parseInt(req.params.id);
    const { reason } = req.body;
    const reporter = req.user && req.user.id;
    const { rows } = await pool.query('INSERT INTO review_reports(review_id,reporter_id,reason) VALUES($1,$2,$3) RETURNING *', [reviewId, reporter, reason]);
    res.json(rows[0]);
  }catch(e){ console.error(e); res.status(500).json({ error:'report failed' }); }
});


// Admin helper: get reviews for seller's products (simple)
app.get('/admin/seller-reviews', authMiddleware, async (req,res)=>{
  try{
    const userId = req.user && req.user.id;
    // Find companies owned by this user or seller's company; for scaffold, return recent product_reviews joined to products
    const { rows } = await pool.query('SELECT pr.*, p.title as product_title, u.name as user_name FROM product_reviews pr JOIN products p ON p.id=pr.product_id LEFT JOIN users u ON u.id=pr.user_id ORDER BY pr.created_at DESC LIMIT 200');
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({ error:'admin seller reviews failed' }); }
});
