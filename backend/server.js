// server.js - Complete Enhanced CanvasPro Backend with ALL endpoints - FIXED VERSION
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;  // Use 3000 as fallback, not 0

console.log('🚀 Starting Enhanced CanvasPro Backend...');

// Initialize services
let stripe = null;
let resend = null;

try {
    if (process.env.STRIPE_SECRET_KEY) {
        stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        console.log('✅ Stripe initialized');
    } else {
        console.log('⚠️ Running in test mode - no Stripe key');
    }
} catch (error) {
    console.error('❌ Stripe error:', error.message);
}

try {
    if (process.env.RESEND_API_KEY) {
        const { Resend } = require('resend');
        resend = new Resend(process.env.RESEND_API_KEY);
        console.log('✅ Resend initialized');
    } else {
        console.log('⚠️ Email disabled - no Resend key');
    }
} catch (error) {
    console.error('❌ Resend error:', error.message);
}

// Enhanced Security Configuration
const SECURITY = {
    // Admin users (change these!)
    admins: {
        'admin': process.env.ADMIN_PASSWORD || 'CanvasPro2024!',
        'brodypeeler': process.env.BRODY_PASSWORD || 'BrodyAdmin123!'
    },

    // Device binding settings
    maxDevicesPerKey: 2, // Allow key on max 2 devices
    deviceBindingEnabled: true,

    // Rate limiting
    maxValidationAttempts: 10,
    validationWindow: 3600000, // 1 hour

    // Key obfuscation
    keyEncryptionSecret: process.env.KEY_ENCRYPTION_SECRET || 'your-secret-key-here-change-this'
};

// Middleware - Order matters!
// First, handle raw body for webhook
app.use('/api/webhook', express.raw({ type: 'application/json' }));

// Then handle CORS
app.use(cors({
    origin: function(origin, callback) {
        // Allow all origins for now
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'stripe-signature']
}));

// Then parse JSON for other routes
app.use(express.json());

// Serve static files (for admin panel, etc)
app.use(express.static('./'));

// Enhanced Database Schema
const db = new sqlite3.Database('./keys.db');

db.serialize(() => {
    // Enhanced keys table with device binding
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        encrypted_key TEXT UNIQUE NOT NULL,
        email TEXT,
        product TEXT DEFAULT 'canvaspro',
        plan TEXT,
        price REAL,
        stripe_session_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT 1,
        created_by TEXT,
        last_used_at DATETIME,
        usage_count INTEGER DEFAULT 0
    )`);

    // Device binding table
    db.run(`CREATE TABLE IF NOT EXISTS key_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER,
        device_id TEXT NOT NULL,
        device_fingerprint TEXT,
        first_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        usage_count INTEGER DEFAULT 1,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (key_id) REFERENCES keys (id),
        UNIQUE(key_id, device_id)
    )`);

    // Enhanced key logs with device tracking
    db.run(`CREATE TABLE IF NOT EXISTS key_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER,
        device_id TEXT,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN DEFAULT 1,
        error_message TEXT,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES keys (id)
    )`);

    // Rate limiting table
    db.run(`CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        attempts INTEGER DEFAULT 1,
        window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(identifier)
    )`);

    // Orders table (enhanced)
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_number TEXT UNIQUE,
        email TEXT,
        product TEXT,
        plan TEXT,
        amount REAL,
        key_id INTEGER,
        stripe_session_id TEXT,
        status TEXT DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES keys (id)
    )`);

    // Admin actions log
    db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user TEXT,
        action TEXT,
        target_id TEXT,
        details TEXT,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('✅ Enhanced database schema created');
});

// Fixed Encryption helpers using createCipheriv
function encryptKey(key) {
    try {
        const algorithm = 'aes-256-cbc';
        const password = SECURITY.keyEncryptionSecret;
        
        // Create a proper key and IV from the password
        const keyHash = crypto.createHash('sha256').update(password).digest();
        const iv = crypto.createHash('md5').update(password).digest();
        
        const cipher = crypto.createCipheriv(algorithm, keyHash, iv);
        let encrypted = cipher.update(key, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return encrypted;
    } catch (error) {
        console.error('❌ Encryption error:', error);
        // Return a fallback - just hash the key
        return crypto.createHash('sha256').update(key).digest('hex');
    }
}

function decryptKey(encryptedKey) {
    try {
        const algorithm = 'aes-256-cbc';
        const password = SECURITY.keyEncryptionSecret;
        
        // Create a proper key and IV from the password
        const keyHash = crypto.createHash('sha256').update(password).digest();
        const iv = crypto.createHash('md5').update(password).digest();
        
        const decipher = crypto.createDecipheriv(algorithm, keyHash, iv);
        let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('❌ Decryption error:', error);
        return null;
    }
}

// Device fingerprinting
function generateDeviceFingerprint(userAgent, ip) {
    return crypto.createHash('sha256')
        .update(userAgent + ip + Date.now().toString())
        .digest('hex')
        .substring(0, 16);
}

// Rate limiting
async function checkRateLimit(identifier) {
    return new Promise((resolve) => {
        const now = new Date();
        const windowStart = new Date(now.getTime() - SECURITY.validationWindow);

        db.get(
            `SELECT attempts FROM rate_limits WHERE identifier = ? AND window_start > ?`,
            [identifier, windowStart.toISOString()],
            (err, row) => {
                if (err || !row) {
                    // Create new rate limit entry
                    db.run(
                        `INSERT OR REPLACE INTO rate_limits (identifier, attempts, window_start) 
                         VALUES (?, 1, ?)`,
                        [identifier, now.toISOString()]
                    );
                    resolve(true);
                } else if (row.attempts >= SECURITY.maxValidationAttempts) {
                    resolve(false);
                } else {
                    // Increment attempts
                    db.run(
                        `UPDATE rate_limits SET attempts = attempts + 1 WHERE identifier = ?`,
                        [identifier]
                    );
                    resolve(true);
                }
            }
        );
    });
}

// Admin authentication middleware
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).json({ error: 'Admin authentication required' });
    }

    const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
    const [username, password] = credentials.split(':');

    if (SECURITY.admins[username] && SECURITY.admins[username] === password) {
        req.adminUser = username;
        next();
    } else {
        res.status(403).json({ error: 'Invalid admin credentials' });
    }
}

// Log admin actions
function logAdminAction(adminUser, action, targetId, details, ip) {
    db.run(
        `INSERT INTO admin_logs (admin_user, action, target_id, details, ip_address)
         VALUES (?, ?, ?, ?, ?)`,
        [adminUser, action, targetId, JSON.stringify(details), ip]
    );
}

// Utility functions
function generateLicenseKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    return segments.join('-');
}

function generateOrderNumber() {
    const year = new Date().getFullYear();
    const random = Math.floor(Math.random() * 9999).toString().padStart(4, '0');
    return `CP-${year}-${random}`;
}

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

async function sendOrderEmail(order) {
    if (!resend) {
        console.log('⚠️ Skipping email - Resend not configured');
        return false;
    }

    try {
        await resend.emails.send({
            from: 'CanvasPro <onboarding@resend.dev>',
            to: [order.email],
            subject: `Your CanvasPro License Key - Order #${order.orderNumber}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #ff6633, #ff8855); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
                        <h1 style="margin: 0;">Welcome to CanvasPro! 🎉</h1>
                    </div>
                    <div style="padding: 30px; background: #f5f5f5;">
                        <h2 style="color: #333;">Order #${order.orderNumber}</h2>

                        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                            <h3 style="color: #ff6633; margin-top: 0;">🔑 Your License Key:</h3>
                            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; font-size: 20px; font-family: monospace; text-align: center; border: 2px dashed #ff6633;">
                                ${order.licenseKey}
                            </div>
                            <p style="color: #666; margin-top: 10px; font-size: 14px;">
                                ⚠️ This key is device-bound and can only be used on ${SECURITY.maxDevicesPerKey} device(s).
                            </p>
                        </div>

                        <div style="text-align: center; margin-top: 30px;">
                            <a href="https://discord.gg/JfecsrHqC6" style="background: #5865F2; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Join Discord for Support</a>
                        </div>
                    </div>
                </div>
            `
        });
        console.log('✅ Email sent successfully to:', order.email);
        return true;
    } catch (error) {
        console.error('❌ Email error:', error.message);
        return false;
    }
}

// Routes
app.get('/', (req, res) => {
    res.json({ 
        status: 'CanvasPro Enhanced Backend Running',
        version: '3.0.0',
        secure: true,
        features: {
            deviceBinding: SECURITY.deviceBindingEnabled,
            maxDevicesPerKey: SECURITY.maxDevicesPerKey,
            encryption: true,
            rateLimit: true
        },
        stripe: stripe ? 'configured' : 'test mode',
        email: resend ? 'configured' : 'disabled',
        timestamp: new Date().toISOString(),
        endpoints: {
            config: '/api/config',
            checkout: '/api/create-checkout',
            validate: '/api/validate-key',
            webhook: '/api/webhook',
            session: '/api/session/:sessionId',
            lookup: '/api/client/lookup',
            admin: {
                stats: '/api/admin/stats',
                keys: '/api/admin/keys',
                orders: '/api/admin/orders',
                generate: '/api/admin/generate-key',
                delete: '/api/admin/delete-key/:keyId'
            }
        }
    });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/config', (req, res) => {
    res.json({ 
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
        testMode: !process.env.STRIPE_SECRET_KEY,
        deviceBinding: SECURITY.deviceBindingEnabled,
        maxDevices: SECURITY.maxDevicesPerKey
    });
});

// Enhanced key validation with device binding
app.post('/api/validate-key', async (req, res) => {
    const { key, deviceId } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';

    console.log('🔑 Key validation request:', { key: key?.substring(0, 8) + '...', deviceId: deviceId?.substring(0, 8) + '...' });

    if (!key || !deviceId) {
        return res.json({ valid: false, error: 'Key and device ID required' });
    }

    // Rate limiting
    const rateLimitId = `${ip}:${deviceId}`;
    const canProceed = await checkRateLimit(rateLimitId);
    if (!canProceed) {
        return res.json({ valid: false, error: 'Rate limit exceeded' });
    }

    // Find key by encrypted or plain text
    db.get(
        `SELECT * FROM keys WHERE (key = ? OR encrypted_key = ?) AND is_active = 1`,
        [key, encryptKey(key)],
        async (err, keyData) => {
            if (err || !keyData) {
                // Log failed attempt
                db.run(
                    `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success, error_message)
                     VALUES (NULL, ?, ?, ?, 0, ?)`,
                    [deviceId, ip, userAgent, 'Invalid key']
                );
                return res.json({ valid: false, error: 'Invalid key' });
            }

            // Check expiration
            if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
                db.run(
                    `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success, error_message)
                     VALUES (?, ?, ?, ?, 0, ?)`,
                    [keyData.id, deviceId, ip, userAgent, 'Key expired']
                );
                return res.json({ valid: false, error: 'Key expired' });
            }

            // Device binding check
            if (SECURITY.deviceBindingEnabled) {
                db.all(
                    `SELECT * FROM key_devices WHERE key_id = ? AND is_active = 1`,
                    [keyData.id],
                    (err, devices) => {
                        if (err) {
                            return res.json({ valid: false, error: 'Database error' });
                        }

                        const existingDevice = devices.find(d => d.device_id === deviceId);

                        if (existingDevice) {
                            // Device already bound, update usage
                            db.run(
                                `UPDATE key_devices SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 
                                 WHERE key_id = ? AND device_id = ?`,
                                [keyData.id, deviceId]
                            );
                        } else if (devices.length >= SECURITY.maxDevicesPerKey) {
                            // Too many devices
                            db.run(
                                `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success, error_message)
                                 VALUES (?, ?, ?, ?, 0, ?)`,
                                [keyData.id, deviceId, ip, userAgent, 'Device limit exceeded']
                            );
                            return res.json({ 
                                valid: false, 
                                error: `Key already bound to ${SECURITY.maxDevicesPerKey} device(s)` 
                            });
                        } else {
                            // Bind new device
                            const fingerprint = generateDeviceFingerprint(userAgent, ip);
                            db.run(
                                `INSERT INTO key_devices (key_id, device_id, device_fingerprint)
                                 VALUES (?, ?, ?)`,
                                [keyData.id, deviceId, fingerprint]
                            );
                        }

                        // Update key usage
                        db.run(
                            `UPDATE keys SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 
                             WHERE id = ?`,
                            [keyData.id]
                        );

                        // Log successful validation
                        db.run(
                            `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success)
                             VALUES (?, ?, ?, ?, 1)`,
                            [keyData.id, deviceId, ip, userAgent]
                        );

                        res.json({
                            valid: true,
                            product: keyData.product,
                            plan: keyData.plan,
                            expires_at: keyData.expires_at,
                            devices_used: devices.length + (existingDevice ? 0 : 1),
                            max_devices: SECURITY.maxDevicesPerKey,
                            features: {
                                autoAdvance: true,
                                autoAnswers: true,
                                antiLogout: true
                            }
                        });
                    }
                );
            } else {
                // No device binding, proceed normally
                db.run(
                    `UPDATE keys SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 
                     WHERE id = ?`,
                    [keyData.id]
                );

                db.run(
                    `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success)
                     VALUES (?, ?, ?, ?, 1)`,
                    [keyData.id, deviceId, ip, userAgent]
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
        }
    );
});

app.post('/api/create-checkout', async (req, res) => {
    try {
        const { email, plan = 'weekly', price = 13, product = 'canvaspro' } = req.body;

        console.log('📝 Creating checkout:', { email, plan, price, product });

        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Valid email required' });
        }

        // Test mode - create license immediately
        if (!stripe) {
            console.log('🧪 Test mode - generating license');

            const orderNumber = generateOrderNumber();
            const licenseKey = generateLicenseKey();
            const encryptedKey = encryptKey(licenseKey);
            const expiresAt = getExpiryDate(plan);

            db.run(
                `INSERT INTO keys (key, encrypted_key, email, product, plan, price, expires_at, is_active, created_by) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'system')`,
                [licenseKey, encryptedKey, email, product, plan, price, expiresAt.toISOString()],
                async function(err) {
                    if (err) {
                        console.error('❌ Database error:', err);
                        return res.status(500).json({ error: 'Database error' });
                    }

                    const keyId = this.lastID;

                    db.run(
                        `INSERT INTO orders (order_number, email, product, plan, amount, key_id, status) 
                         VALUES (?, ?, ?, ?, ?, ?, 'completed')`,
                        [orderNumber, email, product, plan, price, keyId]
                    );

                    await sendOrderEmail({
                        orderNumber,
                        licenseKey,
                        email,
                        plan,
                        expiresAt
                    });

                    console.log('✅ Test order created:', orderNumber);

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

        // Real Stripe checkout
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
            success_url: `${process.env.FRONTEND_URL || 'https://learnlabs.shop'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL || 'https://learnlabs.shop'}`,
            metadata: { email, plan, product, price: price.toString() }
        });

        console.log('✅ Stripe session created:', session.id);
        res.json({ url: session.url });
    } catch (error) {
        console.error('❌ Checkout error:', error);
        res.status(500).json({ 
            error: 'Failed to create checkout session',
            details: error.message 
        });
    }
});

// Stripe webhook
app.post('/api/webhook', async (req, res) => {
    if (!stripe) {
        return res.status(400).json({ error: 'Stripe not configured' });
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
        console.error('❌ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log('📨 Webhook received:', event.type);

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const orderNumber = generateOrderNumber();
        const licenseKey = generateLicenseKey();
        const encryptedKey = encryptKey(licenseKey);
        const expiresAt = getExpiryDate(session.metadata.plan);

        db.run(
            `INSERT INTO keys (key, encrypted_key, email, product, plan, price, stripe_session_id, expires_at, is_active, created_by) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'stripe')`,
            [
                licenseKey,
                encryptedKey,
                session.customer_email || session.metadata.email,
                session.metadata.product || 'canvaspro',
                session.metadata.plan,
                parseFloat(session.metadata.price),
                session.id,
                expiresAt.toISOString()
            ],
            async function(err) {
                if (err) {
                    console.error('❌ Database error in webhook:', err);
                    return;
                }

                const keyId = this.lastID;

                db.run(
                    `INSERT INTO orders (order_number, email, product, plan, amount, key_id, stripe_session_id, status) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 'completed')`,
                    [
                        orderNumber,
                        session.customer_email || session.metadata.email,
                        session.metadata.product || 'canvaspro',
                        session.metadata.plan,
                        parseFloat(session.metadata.price),
                        keyId,
                        session.id
                    ]
                );

                await sendOrderEmail({
                    orderNumber,
                    licenseKey,
                    email: session.customer_email || session.metadata.email,
                    plan: session.metadata.plan,
                    expiresAt
                });

                console.log('✅ Webhook order processed:', { orderNumber, email: session.customer_email });
            }
        );
    }

    res.json({ received: true });
});

// Session lookup for success page
app.get('/api/session/:sessionId', (req, res) => {
    const { sessionId } = req.params;

    if (!sessionId) {
        return res.status(400).json({ error: 'Session ID required' });
    }

    console.log('🔍 Looking up session:', sessionId);

    db.get(
        `SELECT k.*, o.order_number 
         FROM keys k 
         LEFT JOIN orders o ON o.key_id = k.id 
         WHERE k.stripe_session_id = ?`,
        [sessionId],
        (err, row) => {
            if (err) {
                console.error('❌ Database error:', err);
                return res.status(500).json({ found: false, error: 'Database error' });
            }

            if (!row) {
                console.log('⚠️ No order found for session:', sessionId);
                return res.status(404).json({ found: false, error: 'Order not found' });
            }

            console.log('✅ Found order:', row.order_number);

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

app.post('/api/client/lookup', (req, res) => {
    const { lookup } = req.body;

    if (!lookup) {
        return res.status(400).json({ error: 'Email or license key required' });
    }

    const query = lookup.includes('-') 
        ? `SELECT * FROM keys WHERE key = ?`
        : `SELECT * FROM keys WHERE email = ? ORDER BY created_at DESC LIMIT 1`;

    db.get(query, [lookup], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ found: false, error: 'Order not found' });
        }

        const isExpired = new Date() > new Date(row.expires_at);

        res.json({
            found: true,
            order: {
                product: row.product,
                plan: row.plan,
                createdAt: row.created_at,
                expiresAt: row.expires_at,
                status: isExpired ? 'expired' : 'active',
                licenseKey: row.key
            }
        });
    });
});

// ADMIN ENDPOINTS
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    console.log('📊 Admin stats requested by:', req.adminUser);

    const queries = [
        `SELECT COUNT(*) as totalKeys FROM keys WHERE is_active = 1`,
        `SELECT COUNT(*) as activeKeys FROM keys WHERE is_active = 1 AND expires_at > datetime('now')`,
        `SELECT COALESCE(SUM(amount), 0) as todayRevenue FROM orders WHERE date(created_at) = date('now')`
    ];

    Promise.all(queries.map(query => 
        new Promise((resolve) => {
            db.get(query, (err, row) => resolve(row || {}));
        })
    )).then(results => {
        res.json({
            totalKeys: results[0].totalKeys || 0,
            activeKeys: results[1].activeKeys || 0,
            todayRevenue: results[2].todayRevenue || 0
        });
    });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
    console.log('🔑 Admin keys requested by:', req.adminUser);

    db.all(
        `SELECT k.*, 
                COUNT(kd.id) as device_count,
                MAX(kd.last_used_at) as last_device_use
         FROM keys k
         LEFT JOIN key_devices kd ON k.id = kd.key_id AND kd.is_active = 1
         GROUP BY k.id
         ORDER BY k.created_at DESC
         LIMIT 100`,
        (err, rows) => {
            if (err) {
                console.error('❌ Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Don't send plain text keys to frontend
            const safeKeys = rows.map(key => ({
                ...key,
                key_display: key.key ? key.key.substring(0, 4) + '-****-****-' + key.key.substring(key.key.length - 4) : 'HIDDEN',
                key: undefined, // Remove actual key from response
                encrypted_key: undefined // Remove from response
            }));

            console.log(`✅ Returning ${safeKeys.length} keys to admin`);
            res.json(safeKeys);
        }
    );
});

app.get('/api/admin/orders', requireAdmin, (req, res) => {
    console.log('📦 Admin orders requested by:', req.adminUser);

    db.all(
        `SELECT o.*, k.key 
         FROM orders o
         LEFT JOIN keys k ON o.key_id = k.id
         ORDER BY o.created_at DESC
         LIMIT 100`,
        (err, rows) => {
            if (err) {
                console.error('❌ Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Obfuscate keys in orders too
            const safeOrders = rows.map(order => ({
                ...order,
                key: order.key ? order.key.substring(0, 4) + '-****-****-' + order.key.substring(order.key.length - 4) : null
            }));

            console.log(`✅ Returning ${safeOrders.length} orders to admin`);
            res.json(safeOrders);
        }
    );
});

// FIXED Generate Key Endpoint
app.post('/api/admin/generate-key', requireAdmin, async (req, res) => {
    const { email, plan, price = 0, customExpiry } = req.body;
    const adminUser = req.adminUser;
    const ip = req.ip || req.connection.remoteAddress;

    console.log(`🔑 Admin ${adminUser} generating key for ${email}, plan: ${plan}`);

    if (!email || !plan) {
        return res.status(400).json({ error: 'Email and plan are required' });
    }

    try {
        const orderNumber = generateOrderNumber();
        const licenseKey = generateLicenseKey();
        const encryptedKey = encryptKey(licenseKey);
        const expiresAt = customExpiry ? new Date(customExpiry) : getExpiryDate(plan);

        // Use a Promise to handle the database operation properly
        const keyId = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO keys (key, encrypted_key, email, product, plan, price, expires_at, is_active, created_by) 
                 VALUES (?, ?, ?, 'canvaspro', ?, ?, ?, 1, ?)`,
                [licenseKey, encryptedKey, email, plan, price, expiresAt.toISOString(), adminUser],
                function(err) {
                    if (err) {
                        console.error('❌ Database error inserting key:', err);
                        reject(err);
                    } else {
                        resolve(this.lastID);
                    }
                }
            );
        });

        // Create order record
        await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO orders (order_number, email, product, plan, amount, key_id, status) 
                 VALUES (?, ?, 'canvaspro', ?, ?, ?, 'completed')`,
                [orderNumber, email, plan, price, keyId],
                function(err) {
                    if (err) {
                        console.error('❌ Database error inserting order:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });

        // Log admin action
        logAdminAction(adminUser, 'generate_key', keyId.toString(), {
            email, plan, price, customExpiry
        }, ip);

        // Try to send email but don't fail if it doesn't work
        try {
            const emailSent = await sendOrderEmail({
                orderNumber,
                licenseKey,
                email,
                plan,
                expiresAt
            });
            
            if (emailSent) {
                console.log(`✅ Email sent to ${email}`);
            } else {
                console.log(`⚠️ Email not sent (Resend not configured) but key was created`);
            }
        } catch (emailError) {
            console.error('⚠️ Email failed but key was created:', emailError.message);
            // Continue anyway - key was created successfully
        }

        console.log(`✅ Admin ${adminUser} generated key for ${email}: ${licenseKey}`);

        res.json({
            success: true,
            key: licenseKey,
            orderNumber,
            expires: expiresAt.toISOString()
        });

    } catch (error) {
        console.error('❌ Admin generate key error:', error);
        res.status(500).json({ 
            error: 'Failed to generate key', 
            details: error.message 
        });
    }
});

app.delete('/api/admin/delete-key/:keyId', requireAdmin, (req, res) => {
    const keyId = req.params.keyId;
    const adminUser = req.adminUser;
    const ip = req.ip;

    console.log(`🗑️ Admin ${adminUser} deleting key ${keyId}`);

    db.run(
        `UPDATE keys SET is_active = 0 WHERE id = ?`,
        [keyId],
        function(err) {
            if (err) {
                console.error('❌ Delete key error:', err);
                return res.status(500).json({ error: 'Failed to delete key' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: 'Key not found' });
            }

            // Deactivate all devices
            db.run(`UPDATE key_devices SET is_active = 0 WHERE key_id = ?`, [keyId]);

            // Log admin action
            logAdminAction(adminUser, 'delete_key', keyId, {}, ip);

            console.log(`✅ Admin ${adminUser} deleted key ${keyId}`);
            res.json({ success: true });
        }
    );
});

// Start server - FIXED FOR REPLIT
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Enhanced CanvasPro Backend running on port ${PORT}`);
    console.log(`📍 Health: http://0.0.0.0:${PORT}/`);
    console.log(`🔑 Stripe: ${stripe ? 'Live Mode ✅' : 'Test Mode ⚠️'}`);
    console.log(`📧 Email: ${resend ? 'Enabled ✅' : 'Disabled ⚠️'}`);
    console.log(`🔒 Device Binding: ${SECURITY.deviceBindingEnabled ? 'Enabled' : 'Disabled'}`);
    console.log(`👥 Max Devices: ${SECURITY.maxDevicesPerKey}`);
    console.log(`👨‍💼 Admin Users: ${Object.keys(SECURITY.admins).join(', ')}`);
    console.log('✅ All endpoints ready including admin endpoints!');
});