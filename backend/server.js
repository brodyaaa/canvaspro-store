// server.js - Complete CanvasPro Backend (SECURE VERSION) with Success Page Support
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// CRITICAL: These should be in your Replit environment variables
// NEVER hardcode these values!
if (!process.env.STRIPE_SECRET_KEY) {
    console.error('⚠️  WARNING: STRIPE_SECRET_KEY not set in environment variables!');
}
if (!process.env.STRIPE_PUBLISHABLE_KEY) {
    console.error('⚠️  WARNING: STRIPE_PUBLISHABLE_KEY not set in environment variables!');
}

// Stripe & Resend setup - Using environment variables ONLY
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;
const { Resend } = require('resend');
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

console.log('Server starting...');
console.log('Stripe configured:', process.env.STRIPE_SECRET_KEY ? 'Yes' : 'No');
console.log('Resend configured:', process.env.RESEND_API_KEY ? 'Yes' : 'No');

// Middleware
app.use(cors({
    origin: function(origin, callback) {
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.raw({ type: 'application/json' }));

// Database setup
const db = new sqlite3.Database('./keys.db');

// Initialize database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        email TEXT,
        product TEXT DEFAULT 'canvaspro',
        plan TEXT,
        price REAL,
        stripe_session_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS key_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        device_id TEXT,
        ip_address TEXT,
        success BOOLEAN DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_number TEXT UNIQUE,
        email TEXT,
        product TEXT,
        plan TEXT,
        amount REAL,
        key_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES keys (id)
    )`);
});

// Generate license key
function generateLicenseKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    return segments.join('-');
}

// Generate order number
function generateOrderNumber() {
    const year = new Date().getFullYear();
    const random = Math.floor(Math.random() * 9999).toString().padStart(4, '0');
    return `CP-${year}-${random}`;
}

// Calculate expiry date
function getExpiryDate(plan) {
    const now = new Date();
    switch(plan) {
        case 'test':
            now.setHours(now.getHours() + 1);
            break;
        case 'daily':
            now.setDate(now.getDate() + 1);
            break;
        case 'weekly':
            now.setDate(now.getDate() + 7);
            break;
        case 'monthly':
            now.setMonth(now.getMonth() + 1);
            break;
        case 'yearly':
            now.setFullYear(now.getFullYear() + 1);
            break;
        case 'lifetime':
            now.setFullYear(now.getFullYear() + 100);
            break;
        default:
            now.setDate(now.getDate() + 7);
    }
    return now;
}

// Send order email
async function sendOrderEmail(order) {
    if (!resend) {
        console.log('Resend not configured, skipping email');
        return;
    }
    
    try {
        const { data, error } = await resend.emails.send({
            from: 'CanvasPro <onboarding@resend.dev>',
            to: [order.email],
            subject: `Your CanvasPro License Key - Order #${order.orderNumber}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #ff6633, #ff8855); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
                        <h1 style="margin: 0;">Welcome to CanvasPro!</h1>
                    </div>
                    <div style="padding: 30px; background: #f5f5f5;">
                        <h2 style="color: #333;">Order #${order.orderNumber}</h2>
                        
                        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                            <h3 style="color: #ff6633; margin-top: 0;">Your License Key:</h3>
                            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; font-size: 20px; font-family: monospace; text-align: center; border: 2px dashed #ff6633;">
                                ${order.licenseKey}
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin-top: 30px;">
                            <a href="https://discord.gg/JfecsrHqC6" style="background: #5865F2; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Join Discord for Support</a>
                        </div>
                    </div>
                </div>
            `
        });
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Email error:', error);
    }
}

// CRITICAL: Public config endpoint (safe to expose)
app.get('/api/config', (req, res) => {
    res.json({ 
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
        testMode: !process.env.STRIPE_SECRET_KEY
    });
});

// Health check
app.get('/', (req, res) => {
    res.json({ 
        status: 'CanvasPro Backend Running',
        version: '2.0.0',
        secure: true,
        endpoints: {
            config: '/api/config',
            checkout: '/api/create-checkout',
            validate: '/api/validate-key',
            webhook: '/api/webhook',
            session: '/api/session/:sessionId'
        }
    });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Create Stripe checkout session
app.post('/api/create-checkout', async (req, res) => {
    try {
        const { email, plan = 'weekly', price = 13, product = 'canvaspro' } = req.body;

        console.log('Creating checkout:', { email, plan, price, product });

        // Check if Stripe is configured
        if (!stripe) {
            console.log('No Stripe key - generating test key');
            
            const orderNumber = generateOrderNumber();
            const licenseKey = generateLicenseKey();
            const expiresAt = getExpiryDate(plan);
            
            db.run(
                `INSERT INTO keys (key, email, product, plan, price, expires_at, is_active) 
                 VALUES (?, ?, ?, ?, ?, ?, 1)`,
                [licenseKey, email, product, plan, price, expiresAt.toISOString()],
                async function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ error: 'Database error' });
                    }

                    const keyId = this.lastID;

                    db.run(
                        `INSERT INTO orders (order_number, email, product, plan, amount, key_id) 
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        [orderNumber, email, product, plan, price, keyId]
                    );

                    await sendOrderEmail({
                        orderNumber,
                        licenseKey,
                        email,
                        plan,
                        expiresAt
                    });

                    res.json({ 
                        success: true,
                        testMode: true,
                        orderNumber,
                        license: licenseKey,
                        plan,
                        expires: expiresAt.toISOString()
                    });
                }
            );
            return;
        }

        // Real Stripe checkout - UPDATED SUCCESS URL TO POINT TO SUCCESS.HTML
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            customer_email: email,
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: `CanvasPro ${plan.charAt(0).toUpperCase() + plan.slice(1)} License`,
                        description: `${plan} access to CanvasPro automation tools`,
                        images: ['https://i.imgur.com/OozsIMD.png']
                    },
                    unit_amount: Math.round(price * 100),
                },
                quantity: 1,
            }],
            mode: 'payment',
            // UPDATED: Point to success.html page with session_id parameter
            success_url: `${process.env.FRONTEND_URL || 'https://learnlabs.shop'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL || 'https://learnlabs.shop'}`,
            metadata: {
                email,
                plan,
                product,
                price: price.toString()
            }
        });

        console.log('Stripe session created:', session.id);
        res.json({ url: session.url });
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({ 
            error: 'Failed to create checkout session',
            details: error.message 
        });
    }
});

// Stripe webhook
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    if (!stripe) {
        return res.status(400).send('Stripe not configured');
    }
    
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error('Webhook error:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        
        const orderNumber = generateOrderNumber();
        const licenseKey = generateLicenseKey();
        const expiresAt = getExpiryDate(session.metadata.plan);
        
        db.run(
            `INSERT INTO keys (key, email, product, plan, price, stripe_session_id, expires_at, is_active) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
            [
                licenseKey,
                session.customer_email || session.metadata.email,
                session.metadata.product || 'canvaspro',
                session.metadata.plan,
                parseFloat(session.metadata.price),
                session.id,
                expiresAt.toISOString()
            ],
            async function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return;
                }

                const keyId = this.lastID;

                db.run(
                    `INSERT INTO orders (order_number, email, product, plan, amount, key_id) 
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [
                        orderNumber,
                        session.customer_email || session.metadata.email,
                        session.metadata.product || 'canvaspro',
                        session.metadata.plan,
                        parseFloat(session.metadata.price),
                        keyId
                    ]
                );

                await sendOrderEmail({
                    orderNumber,
                    licenseKey,
                    email: session.customer_email || session.metadata.email,
                    plan: session.metadata.plan,
                    expiresAt
                });

                console.log('Order created from webhook:', { orderNumber, licenseKey });
            }
        );
    }

    res.json({received: true});
});

// NEW: Get session details (for success page)
app.get('/api/session/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    
    if (!sessionId) {
        return res.status(400).json({ error: 'No session ID provided' });
    }
    
    console.log('Looking up session:', sessionId);
    
    db.get(
        `SELECT k.*, o.order_number 
         FROM keys k 
         LEFT JOIN orders o ON o.key_id = k.id 
         WHERE k.stripe_session_id = ?`,
        [sessionId],
        (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ found: false, error: 'Database error' });
            }
            
            if (!row) {
                console.log('No order found for session:', sessionId);
                return res.status(404).json({ found: false, error: 'Order not found' });
            }
            
            console.log('Found order:', row.order_number);
            
            res.json({
                found: true,
                orderNumber: row.order_number,
                licenseKey: row.key,
                plan: row.plan,
                expiresAt: row.expires_at,
                email: row.email,
                product: row.product
            });
        }
    );
});

// Validate key (for Tampermonkey)
app.post('/api/validate-key', (req, res) => {
    const { key, deviceId } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    console.log('Validating key:', key?.substring(0, 8) + '...');

    if (!key) {
        return res.json({ valid: false, error: 'No key provided' });
    }

    db.get(
        `SELECT * FROM keys WHERE key = ? AND is_active = 1`,
        [key],
        (err, keyData) => {
            if (err || !keyData) {
                if (!err) {
                    db.run(
                        `INSERT INTO key_logs (key, device_id, ip_address, success) 
                         VALUES (?, ?, ?, 0)`,
                        [key, deviceId, ip]
                    );
                }
                return res.json({ valid: false, error: 'Invalid key' });
            }

            if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
                return res.json({ valid: false, error: 'Key expired' });
            }

            db.run(
                `INSERT INTO key_logs (key, device_id, ip_address, success) 
                 VALUES (?, ?, ?, 1)`,
                [key, deviceId, ip]
            );

            res.json({
                valid: true,
                product: keyData.product,
                plan: keyData.plan,
                expires_at: keyData.expires_at,
                features: {
                    autoAdvance: true,
                    autoAnswers: true,
                    antiLogout: true
                }
            });
        }
    );
});

// Client area lookup
app.post('/api/client/lookup', (req, res) => {
    const { lookup } = req.body;
    
    if (!lookup) {
        return res.status(400).json({ error: 'Please provide email or license key' });
    }
    
    const query = lookup.includes('-') 
        ? `SELECT * FROM keys WHERE key = ?`
        : `SELECT * FROM keys WHERE email = ? ORDER BY created_at DESC LIMIT 1`;
    
    db.get(query, [lookup], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ found: false, error: 'No order found' });
        }

        res.json({
            found: true,
            order: {
                product: row.product,
                plan: row.plan,
                createdAt: row.created_at,
                expiresAt: row.expires_at,
                status: new Date() > new Date(row.expires_at) ? 'expired' : 'active',
                licenseKey: row.key
            }
        });
    });
});

// Admin endpoints (for internal use)
app.get('/api/admin/stats', (req, res) => {
    // Add authentication here in production
    db.all(`
        SELECT 
            plan,
            COUNT(*) as count,
            SUM(price) as revenue
        FROM keys 
        WHERE is_active = 1 
        GROUP BY plan
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ stats: rows });
    });
});

app.get('/api/admin/recent-orders', (req, res) => {
    // Add authentication here in production
    db.all(`
        SELECT 
            o.order_number,
            o.email,
            o.plan,
            o.amount,
            o.created_at,
            k.key
        FROM orders o
        JOIN keys k ON k.id = o.key_id
        ORDER BY o.created_at DESC
        LIMIT 20
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ orders: rows });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        availableEndpoints: [
            'GET /',
            'GET /api/health',
            'GET /api/config',
            'POST /api/create-checkout',
            'POST /api/webhook',
            'GET /api/session/:sessionId',
            'POST /api/validate-key',
            'POST /api/client/lookup'
        ]
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 CanvasPro Backend running on port ${PORT}`);
    console.log(`📍 Health check: http://localhost:${PORT}/`);
    console.log(`🔑 Stripe configured: ${stripe ? 'Yes' : 'No (Test Mode)'}`);
    console.log(`📧 Resend configured: ${resend ? 'Yes' : 'No'}`);
    
    if (!process.env.STRIPE_SECRET_KEY) {
        console.log('\n⚠️  Running in TEST MODE - Set environment variables for production:');
        console.log('   STRIPE_SECRET_KEY');
        console.log('   STRIPE_PUBLISHABLE_KEY');
        console.log('   STRIPE_WEBHOOK_SECRET');
        console.log('   RESEND_API_KEY');
    }
    
    console.log('\n✅ All endpoints ready:');
    console.log('   🛒 Checkout: /api/create-checkout');
    console.log('   🎉 Success: /api/session/:sessionId');
    console.log('   🔐 Validate: /api/validate-key');
    console.log('   📧 Webhook: /api/webhook');
});