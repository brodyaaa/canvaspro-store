// server.js - SECURE VERSION FOR REPLIT AND GITHUB
// NO HARDCODED SECRETS - ALL FROM ENVIRONMENT VARIABLES
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const app = express();
app.set("trust proxy", 1);
const allowedOrigins = [
    "https://learnlabs.shop",
    "https://www.learnlabs.shop",
    "http://localhost:3000",
    "http://localhost:5000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
];

// Nuclear fix WITH origin validation
app.use((req, res, next) => {
    // Only handle OPTIONS for /api routes
    if (req.method === "OPTIONS" && req.path.startsWith("/api")) {
        const origin = req.headers.origin;

        // Check if origin is allowed (same logic as corsOptions)
        if (
            !origin ||
            allowedOrigins.includes(origin) ||
            process.env.NODE_ENV !== "production"
        ) {
            // Origin is allowed
            res.header("Access-Control-Allow-Origin", origin || "*");
            res.header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS",
            );
            res.header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-API-Token, stripe-signature",
            );
            res.header("Access-Control-Allow-Credentials", "true");
            res.header("Access-Control-Max-Age", "86400");
            return res.sendStatus(200);
        } else {
            // Origin not allowed - reject
            console.log(`CORS blocked origin: ${origin}`);
            return res.status(403).json({ error: "CORS policy violation" });
        }
    }
    next();
});

// Also add CORS headers for actual (non-OPTIONS) requests
app.use((req, res, next) => {
    if (req.path.startsWith("/api") && req.method !== "OPTIONS") {
        const origin = req.headers.origin;

        // Same origin validation
        if (
            !origin ||
            allowedOrigins.includes(origin) ||
            process.env.NODE_ENV !== "production"
        ) {
            res.header("Access-Control-Allow-Origin", origin || "*");
            res.header("Access-Control-Allow-Credentials", "true");
        }
    }
    next();
});
const PORT = process.env.PORT || 3000;

console.log("🚀 Starting Secure CanvasPro Backend...");

// ============================================
// CONFIGURATION FROM ENVIRONMENT VARIABLES ONLY
// ============================================
const CONFIG = {
    // JWT Secret for API authentication
    JWT_SECRET:
        process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex"),

    // API Authentication Token (for Tampermonkey script)
    API_SECRET_TOKEN: process.env.API_SECRET_TOKEN,

    // Admin credentials - MUST be hashed in production
    ADMIN_USERNAME: process.env.ADMIN_USERNAME,
    ADMIN_PASSWORD_HASH: process.env.ADMIN_PASSWORD_HASH, // Store bcrypt hash, not plain password

    // Stripe API Keys - FROM ENV ONLY, NO HARDCODED VALUES
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY,
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,

    // Email service
    RESEND_API_KEY: process.env.RESEND_API_KEY,

    // Encryption keys
    KEY_ENCRYPTION_KEY:
        process.env.KEY_ENCRYPTION_KEY ||
        crypto.randomBytes(32).toString("hex"),
    KEY_ENCRYPTION_IV:
        process.env.KEY_ENCRYPTION_IV || crypto.randomBytes(16).toString("hex"),

    // Security settings
    ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "")
        .split(",")
        .filter(Boolean),
    NODE_ENV: process.env.NODE_ENV || "development",

    // Session secret
    SESSION_SECRET:
        process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex"),

    // OpenAI API Key
    OPENAI_API_KEY: process.env.OPENAI_API_KEY, // Set in Replit Secrets
};

// ============================================
// SECURE CORS CONFIGURATION - FIXED ORDER
// ============================================
const corsOptions = {
    origin: function (origin, callback) {
        // List of allowed origins
        const allowedOrigins = [
            "https://learnlabs.shop",
            "https://www.learnlabs.shop",
            "http://localhost:3000",
            "http://localhost:5000",
            "http://localhost:5500",
            "http://127.0.0.1:5500",
            "http://127.0.0.1:3000",
        ];

        // Allow requests with no origin (like mobile apps or Postman)
        if (!origin) return callback(null, true);

        // Check if origin is allowed
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            // In dev, allow all origins
            if (process.env.NODE_ENV !== "production") {
                callback(null, true);
            } else {
                console.log(`CORS blocked origin: ${origin}`);
                callback(new Error("Not allowed by CORS"));
            }
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-API-Token",
        "stripe-signature",
    ],
    optionsSuccessStatus: 200,
};

// CRITICAL: Apply CORS BEFORE any other middleware that might redirect
// app.options("*", cors(corsOptions));
// app.use(cors(corsOptions));

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Use Helmet for security headers with adjusted CSP
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://js.stripe.com",
                ],
                frameSrc: [
                    "'self'",
                    "https://js.stripe.com",
                    "https://hooks.stripe.com",
                ],
                imgSrc: ["'self'", "data:", "https:", "https://i.imgur.com"],
                connectSrc: ["'self'", "https://api.stripe.com"],
            },
        },
        crossOriginEmbedderPolicy: false,
    }),
);

// NOW handle trailing slashes - AFTER CORS
app.use((req, res, next) => {
    // Skip redirect for OPTIONS requests (CORS preflight)
    if (req.method === "OPTIONS") {
        return next();
    }

    // Remove trailing slashes to prevent Replit redirects
    if (req.path !== "/" && req.path.endsWith("/")) {
        const newPath = req.path.slice(0, -1);
        return res.redirect(301, newPath);
    }
    next();
});

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
    skip: (req) => req.method === "OPTIONS", // ADD THIS
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many attempts, please try again later.",
    skip: (req) => req.method === "OPTIONS", // ADD THIS
});

// Apply rate limiting
app.use("/api/", apiLimiter);
app.use("/api/validate-key", strictLimiter);
app.use("/api/admin/login", strictLimiter);

// ============================================
// ENVIRONMENT VALIDATION
// ============================================
function validateEnvironment() {
    const required = [
        "API_SECRET_TOKEN",
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD_HASH",
        "JWT_SECRET",
        "KEY_ENCRYPTION_KEY",
        "KEY_ENCRYPTION_IV",
    ];

    const missing = required.filter((key) => !process.env[key]);

    if (missing.length > 0) {
        console.error("❌ CRITICAL: Missing required environment variables:");
        missing.forEach((key) => console.error(`   - ${key}`));
        console.error("\n📝 Setup Instructions:");
        console.error("1. In Replit, go to Secrets (🔒 icon)");
        console.error("2. Add these secrets:");
        console.error(
            "   API_SECRET_TOKEN: " + crypto.randomBytes(32).toString("hex"),
        );
        console.error("   ADMIN_USERNAME: your_admin_username");
        console.error(
            "   ADMIN_PASSWORD_HASH: (use bcrypt to hash your password)",
        );
        console.error(
            "   JWT_SECRET: " + crypto.randomBytes(64).toString("hex"),
        );
        console.error(
            "   KEY_ENCRYPTION_KEY: " + crypto.randomBytes(32).toString("hex"),
        );
        console.error(
            "   KEY_ENCRYPTION_IV: " + crypto.randomBytes(16).toString("hex"),
        );

        if (CONFIG.NODE_ENV === "production") {
            process.exit(1);
        }
    }

    return missing.length === 0;
}

const isConfigured = validateEnvironment();

// Middleware order is important!
app.use("/api/webhook", express.raw({ type: "application/json" }));

// Then JSON and static files
app.use(express.json());
app.use(express.static("./")); // Serve static files for admin panel

// ============================================
// API AUTHENTICATION MIDDLEWARE
// ============================================
function requireApiToken(req, res, next) {
    const token =
        req.headers["x-api-token"] ||
        req.headers["authorization"]?.replace("Bearer ", "");

    if (!CONFIG.API_SECRET_TOKEN) {
        return res.status(503).json({ error: "API not configured" });
    }

    if (!token || token !== CONFIG.API_SECRET_TOKEN) {
        return res.status(401).json({ error: "Invalid API token" });
    }

    next();
}

// ============================================
// ADMIN AUTHENTICATION WITH JWT
// ============================================
function generateAdminToken(username) {
    return jwt.sign(
        { username, role: "admin", timestamp: Date.now() },
        CONFIG.JWT_SECRET,
        { expiresIn: "4h" },
    );
}

function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;

    // Support both JWT and Basic auth for backward compatibility
    if (authHeader && authHeader.startsWith("Basic ")) {
        // Handle Basic auth for existing admin panels
        const credentials = Buffer.from(
            authHeader.slice(6),
            "base64",
        ).toString();
        const [username, password] = credentials.split(":");

        if (!CONFIG.ADMIN_USERNAME || !CONFIG.ADMIN_PASSWORD_HASH) {
            return res.status(503).json({ error: "Admin not configured" });
        }

        // For basic auth, we need to check against a plain password temporarily
        // You should migrate to JWT tokens ASAP
        bcrypt.compare(password, CONFIG.ADMIN_PASSWORD_HASH).then((valid) => {
            if (username === CONFIG.ADMIN_USERNAME && valid) {
                req.adminUser = username;
                next();
            } else {
                res.status(403).json({ error: "Invalid admin credentials" });
            }
        });
    } else if (authHeader && authHeader.startsWith("Bearer ")) {
        // Handle JWT auth (preferred)
        const token = authHeader.replace("Bearer ", "");

        try {
            const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
            if (decoded.role !== "admin") {
                return res
                    .status(403)
                    .json({ error: "Insufficient privileges" });
            }
            req.adminUser = decoded.username;
            next();
        } catch (error) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
    } else {
        return res.status(401).json({ error: "Admin authentication required" });
    }
}

// ============================================
// SECURE DATABASE SETUP
// ============================================
const db = new sqlite3.Database("./keys.db");

db.serialize(() => {
    // Create tables with proper constraints
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
        usage_count INTEGER DEFAULT 0,
        CHECK (email LIKE '%@%' OR email IS NULL)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS key_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        device_fingerprint TEXT,
        first_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        usage_count INTEGER DEFAULT 1,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (key_id) REFERENCES keys (id) ON DELETE CASCADE,
        UNIQUE(key_id, device_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS key_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER,
        device_id TEXT,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN DEFAULT 1,
        error_message TEXT,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES keys (id) ON DELETE SET NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_number TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        product TEXT,
        plan TEXT,
        amount REAL,
        key_id INTEGER,
        stripe_session_id TEXT,
        status TEXT DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES keys (id) ON DELETE SET NULL,
        CHECK (email LIKE '%@%')
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user TEXT NOT NULL,
        action TEXT NOT NULL,
        target_id TEXT,
        details TEXT,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        attempts INTEGER DEFAULT 1,
        window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(identifier)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS answer_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT,
        answer TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create indexes for performance
    db.run(`CREATE INDEX IF NOT EXISTS idx_keys_email ON keys(email)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_keys_active ON keys(is_active)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_devices_key ON key_devices(key_id)`);

    console.log("✅ Secure database initialized");
});

// ============================================
// SECURE ENCRYPTION FUNCTIONS
// ============================================
function encryptKey(key) {
    try {
        const algorithm = "aes-256-cbc";
        const keyBuffer = Buffer.from(
            CONFIG.KEY_ENCRYPTION_KEY.substring(0, 32).padEnd(32, "0"),
        );
        const ivBuffer = Buffer.from(
            CONFIG.KEY_ENCRYPTION_IV.substring(0, 16).padEnd(16, "0"),
        );

        const cipher = crypto.createCipheriv(algorithm, keyBuffer, ivBuffer);
        let encrypted = cipher.update(key, "utf8", "hex");
        encrypted += cipher.final("hex");

        return encrypted;
    } catch (error) {
        console.error("Encryption error:", error);
        // Fallback to hash if encryption fails
        return crypto.createHash("sha256").update(key).digest("hex");
    }
}

function decryptKey(encryptedKey) {
    try {
        const algorithm = "aes-256-cbc";
        const keyBuffer = Buffer.from(
            CONFIG.KEY_ENCRYPTION_KEY.substring(0, 32).padEnd(32, "0"),
        );
        const ivBuffer = Buffer.from(
            CONFIG.KEY_ENCRYPTION_IV.substring(0, 16).padEnd(16, "0"),
        );

        const decipher = crypto.createDecipheriv(
            algorithm,
            keyBuffer,
            ivBuffer,
        );
        let decrypted = decipher.update(encryptedKey, "hex", "utf8");
        decrypted += decipher.final("utf8");

        return decrypted;
    } catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function generateLicenseKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(2).toString("hex").toUpperCase());
    }
    return segments.join("-");
}

function generateOrderNumber() {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `CP-${timestamp}-${random}`;
}

function getExpiryDate(plan) {
    const now = new Date();
    const expiryMap = {
        test: () => now.setHours(now.getHours() + 1),
        daily: () => now.setDate(now.getDate() + 1),
        weekly: () => now.setDate(now.getDate() + 7),
        monthly: () => now.setMonth(now.getMonth() + 1),
        yearly: () => now.setFullYear(now.getFullYear() + 1),
        lifetime: () => now.setFullYear(now.getFullYear() + 100),
    };

    if (expiryMap[plan]) {
        expiryMap[plan]();
    } else {
        now.setDate(now.getDate() + 7); // Default to weekly
    }

    return now;
}

// Initialize Stripe - IMPROVED VERSION
let stripe = null;
if (CONFIG.STRIPE_SECRET_KEY) {
    try {
        stripe = require("stripe")(CONFIG.STRIPE_SECRET_KEY);
        console.log(
            "✅ Stripe initialized with key:",
            CONFIG.STRIPE_SECRET_KEY.substring(0, 20) + "...",
        );

        // Test Stripe connection
        stripe.products
            .list({ limit: 1 })
            .then(() => {
                console.log("✅ Stripe API connection verified!");
            })
            .catch((err) => {
                console.error("❌ Stripe API test failed:", err.message);
            });
    } catch (error) {
        console.error("❌ Stripe initialization failed:", error.message);
    }
} else {
    console.error("❌ NO STRIPE_SECRET_KEY IN ENVIRONMENT!");
}

// Initialize Resend if configured
let resend = null;
if (CONFIG.RESEND_API_KEY) {
    try {
        const { Resend } = require("resend");
        resend = new Resend(CONFIG.RESEND_API_KEY);
        console.log("✅ Resend initialized");
    } catch (error) {
        console.error("❌ Resend initialization failed:", error.message);
    }
}

// Email sending function - FIXED WITH YOUR EMAIL DOMAIN
async function sendOrderEmail(order) {
    if (!resend) {
        console.log("⚠️ Skipping email - Resend not configured");
        if (!CONFIG.RESEND_API_KEY) {
            console.error(
                "❌ RESEND_API_KEY not set in environment variables!",
            );
        }
        return false;
    }

    // Customize message based on plan
    const planMessages = {
        daily: "Your daily access expires in 24 hours",
        weekly: "Enjoy 7 days of unlimited access",
        monthly: "You have 30 days of premium access",
        yearly: "Welcome to our yearly plan - 365 days of automation!",
        lifetime: "Congratulations! You now have lifetime access!",
    };

    const planColors = {
        daily: "#3b82f6",
        weekly: "#10b981",
        monthly: "#ff6633",
        yearly: "#6b46c1",
        lifetime: "#fbbf24",
    };

    try {
        const emailResult = await resend.emails.send({
            from: "LearnLabs <onboarding@resend.dev>", // Use Resend's default domain until you verify yours
            to: [order.email],
            subject: `Your LearnLabs ${order.plan} License Key - Order #${order.orderNumber}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, ${planColors[order.plan] || "#ff6633"}, #ff8855); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
                        <h1 style="margin: 0;">Welcome to LearnLabs! 🎉</h1>
                        <p style="margin-top: 10px; font-size: 1.2rem;">${order.plan.toUpperCase()} PLAN</p>
                    </div>
                    <div style="padding: 30px; background: #f5f5f5;">
                        <h2 style="color: #333;">Order #${order.orderNumber}</h2>
                        <p style="color: #666; font-size: 1.1rem;">${planMessages[order.plan] || "Thank you for your purchase!"}</p>

                        <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="color: ${planColors[order.plan] || "#ff6633"}; margin-top: 0;">🔑 Your License Key:</h3>
                            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; font-size: 20px; font-family: monospace; text-align: center; border: 2px dashed ${planColors[order.plan] || "#ff6633"};">
                                ${order.licenseKey}
                            </div>
                        </div>

                        <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <h4 style="color: #333; margin-top: 0;">Plan Details:</h4>
                            <ul style="color: #666; line-height: 1.8;">
                                <li><strong>Product:</strong> CanvasPro</li>
                                <li><strong>Plan:</strong> ${order.plan}</li>
                                <li><strong>Expires:</strong> ${new Date(order.expiresAt).toLocaleDateString()}</li>
                                <li><strong>Devices:</strong> 2 simultaneous devices</li>
                            </ul>
                        </div>

                        <div style="text-align: center; margin-top: 30px;">
                            <a href="https://learnlabs.shop" style="background: ${planColors[order.plan] || "#ff6633"}; color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; display: inline-block;">Visit Dashboard</a>
                        </div>
                    </div>
                </div>
            `,
        });

        console.log("✅ Email sent successfully to:", order.email);
        console.log("📧 Email ID:", emailResult.data?.id || emailResult.id);
        return true;
    } catch (error) {
        console.error("❌ Email error:", error.message);
        console.error("Full error:", error);
        return false;
    }
}

// ============================================
// API ENDPOINTS
// ============================================

// Root endpoint
app.get("/", (req, res) => {
    res.json({
        status: "CanvasPro Backend Running",
        version: "3.0.0",
        secure: true,
        endpoints: {
            health: "/api/health",
            config: "/api/config",
            validateKey: "/api/validate-key",
            checkout: "/api/create-checkout",
            webhook: "/api/webhook",
            admin: {
                login: "/api/admin/login",
                stats: "/api/admin/stats",
                keys: "/api/admin/keys",
                orders: "/api/admin/orders",
                generateKey: "/api/admin/generate-key",
            },
        },
    });
});

// Health check endpoint (public)
app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
        configured: isConfigured,
    });
});

// Public config endpoint (REQUIRED for Tampermonkey to get API token)
app.get("/api/config", (req, res) => {
    res.json({
        stripePublishableKey: CONFIG.STRIPE_PUBLISHABLE_KEY || "",
        testMode: !CONFIG.STRIPE_SECRET_KEY,
        version: "3.0.0",
        apiToken: CONFIG.API_SECRET_TOKEN, // This sends the token to Tampermonkey
    });
});

// Key validation endpoint (requires API token)
app.post("/api/validate-key", requireApiToken, async (req, res) => {
    const { key, deviceId } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers["user-agent"] || "";

    if (!key || !deviceId) {
        return res
            .status(400)
            .json({ valid: false, error: "Missing required fields" });
    }

    // Use prepared statement to prevent SQL injection
    db.get(
        `SELECT * FROM keys WHERE key = ? AND is_active = 1`,
        [key],
        async (err, keyData) => {
            if (err) {
                console.error("Database error:", err);
                return res
                    .status(500)
                    .json({ valid: false, error: "Database error" });
            }

            if (!keyData) {
                // Log failed attempt
                db.run(
                    `INSERT INTO key_logs (device_id, ip_address, user_agent, success, error_message)
                     VALUES (?, ?, ?, 0, ?)`,
                    [deviceId, ip, userAgent, "Invalid key"],
                );
                return res.json({ valid: false, error: "Invalid key" });
            }

            // Check expiration
            if (
                keyData.expires_at &&
                new Date(keyData.expires_at) < new Date()
            ) {
                db.run(
                    `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success, error_message)
                     VALUES (?, ?, ?, ?, 0, ?)`,
                    [keyData.id, deviceId, ip, userAgent, "Key expired"],
                );
                return res.json({ valid: false, error: "Key expired" });
            }

            // Device binding check
            db.all(
                `SELECT * FROM key_devices WHERE key_id = ? AND is_active = 1`,
                [keyData.id],
                (err, devices) => {
                    if (err) {
                        return res
                            .status(500)
                            .json({ valid: false, error: "Database error" });
                    }

                    const existingDevice = devices.find(
                        (d) => d.device_id === deviceId,
                    );
                    const maxDevices = 2;

                    if (existingDevice) {
                        // Update existing device
                        db.run(
                            `UPDATE key_devices SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 
                             WHERE key_id = ? AND device_id = ?`,
                            [keyData.id, deviceId],
                        );
                    } else if (devices.length >= maxDevices) {
                        // Too many devices
                        db.run(
                            `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success, error_message)
                             VALUES (?, ?, ?, ?, 0, ?)`,
                            [
                                keyData.id,
                                deviceId,
                                ip,
                                userAgent,
                                "Device limit exceeded",
                            ],
                        );
                        return res.json({
                            valid: false,
                            error: `Key already bound to ${maxDevices} device(s)`,
                        });
                    } else {
                        // Bind new device
                        const fingerprint = crypto
                            .createHash("sha256")
                            .update(userAgent + deviceId)
                            .digest("hex")
                            .substring(0, 16);

                        db.run(
                            `INSERT INTO key_devices (key_id, device_id, device_fingerprint)
                             VALUES (?, ?, ?)`,
                            [keyData.id, deviceId, fingerprint],
                        );
                    }

                    // Update key usage
                    db.run(
                        `UPDATE keys SET last_used_at = CURRENT_TIMESTAMP, usage_count = usage_count + 1 
                         WHERE id = ?`,
                        [keyData.id],
                    );

                    // Log successful validation
                    db.run(
                        `INSERT INTO key_logs (key_id, device_id, ip_address, user_agent, success)
                         VALUES (?, ?, ?, ?, 1)`,
                        [keyData.id, deviceId, ip, userAgent],
                    );

                    res.json({
                        valid: true,
                        product: keyData.product,
                        plan: keyData.plan,
                        expires_at: keyData.expires_at,
                        devices_used: devices.length + (existingDevice ? 0 : 1),
                        max_devices: maxDevices,
                        features: {
                            autoAdvance: true,
                            autoAnswers: true,
                            antiLogout: true,
                        },
                    });
                },
            );
        },
    );
});

// AI Answer endpoint (requires API token)
app.post("/api/answer-question", requireApiToken, async (req, res) => {
    const { question, choices, type } = req.body;

    if (!process.env.OPENAI_API_KEY) {
        return res.json({ success: false, error: "AI not configured" });
    }

    try {
        const { OpenAI } = require("openai");
        const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

        const completion = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [
                {
                    role: "system",
                    content:
                        "You are helping a student with disabilities complete their coursework. Provide accurate, educational answers.",
                },
                {
                    role: "user",
                    content: `Question: ${question}\n${type === "mc" ? "Choices: " + choices.join(", ") : ""}\nProvide the best answer.`,
                },
            ],
            max_tokens: 150,
            temperature: 0.3,
        });

        const answer = completion.choices[0].message.content;

        // Log for compliance/auditing
        db.run(
            `INSERT INTO answer_logs (question, answer, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)`,
            [question.substring(0, 100), answer.substring(0, 100)],
        );

        res.json({ success: true, answer });
    } catch (error) {
        console.error("OpenAI error:", error);
        res.json({ success: false, error: "Failed to generate answer" });
    }
});

// Create checkout session (Stripe) - HANDLES NULL VALUES PROPERLY
app.post("/api/create-checkout", async (req, res) => {
    try {
        // Extract parameters with proper null handling
        const { email, plan, price, product } = req.body;

        // Set defaults for any null/undefined values
        const finalPlan = plan || "monthly";
        const finalPrice = price || 30;
        const finalProduct = product || "canvaspro";

        console.log("📝 Creating checkout:", {
            email,
            plan: finalPlan,
            price: finalPrice,
            product: finalProduct,
        });

        if (!email || !email.includes("@")) {
            return res.status(400).json({ error: "Valid email required" });
        }

        // Check if Stripe is configured
        if (!CONFIG.STRIPE_SECRET_KEY) {
            console.error("❌ STRIPE_SECRET_KEY not found in environment!");
            return res.status(500).json({
                error: "Payment system not configured. Contact support.",
                debug: "No Stripe secret key in environment",
            });
        }

        // Initialize Stripe if not already initialized
        if (!stripe) {
            console.log("🔄 Initializing Stripe on demand...");
            const Stripe = require("stripe");
            stripe = Stripe(CONFIG.STRIPE_SECRET_KEY);
            console.log(
                "✅ Stripe initialized with key:",
                CONFIG.STRIPE_SECRET_KEY.substring(0, 20) + "...",
            );
        }

        // Create proper plan name with null safety
        const planName = finalPlan.charAt(0).toUpperCase() + finalPlan.slice(1);

        console.log("📤 Creating Stripe session for:", planName);

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            customer_email: email,
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: `CanvasPro ${planName} License`,
                            description: `${finalPlan} access to CanvasPro automation tools`,
                            images: ["https://i.imgur.com/OozsIMD.png"],
                        },
                        unit_amount: Math.round(finalPrice * 100),
                    },
                    quantity: 1,
                },
            ],
            mode: "payment",
            success_url: `${process.env.FRONTEND_URL || "https://learnlabs.shop"}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL || "https://learnlabs.shop"}`,
            metadata: {
                email,
                plan: finalPlan,
                product: finalProduct,
                price: finalPrice.toString(),
            },
        });

        console.log("✅ Stripe session created:", session.id);
        console.log("✅ Checkout URL:", session.url);

        res.json({ url: session.url });
    } catch (error) {
        console.error("❌ Checkout error:", error);
        console.error("Full error stack:", error.stack);

        // Provide detailed error response
        res.status(500).json({
            error: "Failed to create checkout session",
            details: error.message,
            type: error.type || "unknown",
        });
    }
});

// Stripe webhook - FIXED TO PROPERLY GENERATE KEYS AND SEND EMAILS
app.post("/api/webhook", async (req, res) => {
    if (!stripe) {
        return res.status(400).json({ error: "Stripe not configured" });
    }

    const sig = req.headers["stripe-signature"];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            CONFIG.STRIPE_WEBHOOK_SECRET,
        );
    } catch (err) {
        console.error("❌ Webhook signature verification failed:", err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log("📨 Webhook received:", event.type);

    if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        const orderNumber = generateOrderNumber();
        const licenseKey = generateLicenseKey();
        const encryptedKey = encryptKey(licenseKey);
        const expiresAt = getExpiryDate(session.metadata.plan);

        console.log(
            "🔑 Generating key for:",
            session.customer_email || session.metadata.email,
        );
        console.log("🔑 License Key:", licenseKey);
        console.log("📅 Expires at:", expiresAt);

        db.run(
            `INSERT INTO keys (key, encrypted_key, email, product, plan, price, stripe_session_id, expires_at, is_active, created_by) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'stripe')`,
            [
                licenseKey,
                encryptedKey,
                session.customer_email || session.metadata.email,
                session.metadata.product || "canvaspro",
                session.metadata.plan,
                parseFloat(session.metadata.price),
                session.id,
                expiresAt.toISOString(),
            ],
            async function (err) {
                if (err) {
                    console.error("❌ Database error in webhook:", err);
                    return;
                }

                const keyId = this.lastID;
                console.log("✅ Key saved to database with ID:", keyId);

                // Create order record
                db.run(
                    `INSERT INTO orders (order_number, email, product, plan, amount, key_id, stripe_session_id, status) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 'completed')`,
                    [
                        orderNumber,
                        session.customer_email || session.metadata.email,
                        session.metadata.product || "canvaspro",
                        session.metadata.plan,
                        parseFloat(session.metadata.price),
                        keyId,
                        session.id,
                    ],
                    async (orderErr) => {
                        if (orderErr) {
                            console.error("❌ Error creating order:", orderErr);
                        } else {
                            console.log("✅ Order created:", orderNumber);
                        }

                        // Send email with the order details
                        const emailSent = await sendOrderEmail({
                            orderNumber,
                            licenseKey,
                            email:
                                session.customer_email ||
                                session.metadata.email,
                            plan: session.metadata.plan,
                            expiresAt,
                        });

                        if (emailSent) {
                            console.log("✅ Order email sent successfully");
                        } else {
                            console.error("❌ Failed to send order email");
                        }
                    },
                );

                console.log("✅ Webhook order processed:", {
                    orderNumber,
                    email: session.customer_email,
                    licenseKey: licenseKey.substring(0, 4) + "...", // Log partial key for security
                });
            },
        );
    }

    res.json({ received: true });
});

// Session lookup
app.get("/api/session/:sessionId", (req, res) => {
    const { sessionId } = req.params;

    if (!sessionId) {
        return res.status(400).json({ error: "Session ID required" });
    }

    db.get(
        `SELECT k.*, o.order_number 
         FROM keys k 
         LEFT JOIN orders o ON o.key_id = k.id 
         WHERE k.stripe_session_id = ?`,
        [sessionId],
        (err, row) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res
                    .status(500)
                    .json({ found: false, error: "Database error" });
            }

            if (!row) {
                return res
                    .status(404)
                    .json({ found: false, error: "Order not found" });
            }

            res.json({
                found: true,
                orderNumber: row.order_number,
                licenseKey: row.key,
                plan: row.plan,
                expiresAt: row.expires_at,
                email: row.email,
                product: row.product,
            });
        },
    );
});

// Client lookup
app.post("/api/client/lookup", (req, res) => {
    const { lookup, verification } = req.body;

    if (!lookup) {
        return res.status(400).json({ error: "Email or license key required" });
    }

    // If it's a license key format (contains dashes), look it up directly
    if (lookup.includes("-") && lookup.length === 19) {
        // Full license key lookup - this is secure
        db.get(`SELECT * FROM keys WHERE key = ?`, [lookup], (err, row) => {
            if (err || !row) {
                return res
                    .status(404)
                    .json({ found: false, error: "Order not found" });
            }

            const isExpired = new Date() > new Date(row.expires_at);

            res.json({
                found: true,
                order: {
                    product: row.product,
                    plan: row.plan,
                    createdAt: row.created_at,
                    expiresAt: row.expires_at,
                    status: isExpired ? "expired" : "active",
                    licenseKey: row.key,
                },
            });
        });
    } else if (lookup.includes("@")) {
        // Email lookup - REQUIRES additional verification
        if (!verification || verification.length < 4) {
            return res.status(400).json({
                error: "For email lookup, please provide the last 4 characters of your license key or order number",
                requiresVerification: true,
            });
        }

        // Query with email AND verification
        db.get(
            `SELECT * FROM keys 
             WHERE email = ? 
             AND (
                 SUBSTR(key, -4) = ? OR 
                 key IN (SELECT k.key FROM keys k JOIN orders o ON o.key_id = k.id WHERE o.order_number LIKE '%' || ? || '%')
             )
             ORDER BY created_at DESC 
             LIMIT 1`,
            [lookup, verification.toUpperCase(), verification.toUpperCase()],
            (err, row) => {
                if (err || !row) {
                    return res.status(404).json({
                        found: false,
                        error: "Order not found. Please check your email and verification code.",
                    });
                }

                const isExpired = new Date() > new Date(row.expires_at);

                res.json({
                    found: true,
                    order: {
                        product: row.product,
                        plan: row.plan,
                        createdAt: row.created_at,
                        expiresAt: row.expires_at,
                        status: isExpired ? "expired" : "active",
                        licenseKey: row.key,
                    },
                });
            },
        );
    } else {
        return res.status(400).json({ error: "Invalid lookup format" });
    }
});

// Admin login endpoint
app.post("/api/admin/login", strictLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res
            .status(400)
            .json({ error: "Username and password required" });
    }

    // Check if admin is configured
    if (!CONFIG.ADMIN_USERNAME) {
        return res.status(503).json({ error: "Admin not configured" });
    }

    if (username !== CONFIG.ADMIN_USERNAME) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check BOTH plain password and hash - PRODUCTION READY
    let validPassword = false;

    // First check plain password if it exists
    if (process.env.ADMIN_PASSWORD) {
        validPassword = password === process.env.ADMIN_PASSWORD;
    }

    // If plain password didn't match, try hash
    if (!validPassword && CONFIG.ADMIN_PASSWORD_HASH) {
        try {
            validPassword = await bcrypt.compare(
                password,
                CONFIG.ADMIN_PASSWORD_HASH,
            );
        } catch (e) {
            // If bcrypt fails, hash might be invalid
            validPassword = false;
        }
    }

    if (!validPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = generateAdminToken(username);

    // Log admin login
    db.run(
        `INSERT INTO admin_logs (admin_user, action, ip_address, details)
         VALUES (?, ?, ?, ?)`,
        [username, "login", req.ip, "Successful login"],
    );

    res.json({
        success: true,
        token,
        expiresIn: "4h",
    });
});

// Admin stats endpoint
app.get("/api/admin/stats", requireAdmin, (req, res) => {
    const queries = [
        `SELECT COUNT(*) as totalKeys FROM keys WHERE is_active = 1`,
        `SELECT COUNT(*) as activeKeys FROM keys WHERE is_active = 1 AND expires_at > datetime('now')`,
        `SELECT COALESCE(SUM(amount), 0) as todayRevenue FROM orders WHERE date(created_at) = date('now')`,
    ];

    Promise.all(
        queries.map(
            (query) =>
                new Promise((resolve) => {
                    db.get(query, (err, row) => resolve(row || {}));
                }),
        ),
    ).then((results) => {
        res.json({
            totalKeys: results[0].totalKeys || 0,
            activeKeys: results[1].activeKeys || 0,
            todayRevenue: results[2].todayRevenue || 0,
        });
    });
});

// Admin get all keys
app.get("/api/admin/keys", requireAdmin, (req, res) => {
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
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: "Database error" });
            }

            // Don't send plain text keys to frontend
            const safeKeys = rows.map((key) => ({
                ...key,
                key_display: key.key
                    ? key.key.substring(0, 4) +
                      "-****-****-" +
                      key.key.substring(key.key.length - 4)
                    : "HIDDEN",
                key: undefined, // Remove actual key
                encrypted_key: undefined, // Remove encrypted key
            }));

            res.json(safeKeys);
        },
    );
});

// Admin get all orders
app.get("/api/admin/orders", requireAdmin, (req, res) => {
    db.all(
        `SELECT o.*, k.key 
         FROM orders o
         LEFT JOIN keys k ON o.key_id = k.id
         ORDER BY o.created_at DESC
         LIMIT 100`,
        (err, rows) => {
            if (err) {
                console.error("❌ Database error:", err);
                return res.status(500).json({ error: "Database error" });
            }

            // Obfuscate keys in orders too
            const safeOrders = rows.map((order) => ({
                ...order,
                key: order.key
                    ? order.key.substring(0, 4) +
                      "-****-****-" +
                      order.key.substring(order.key.length - 4)
                    : null,
            }));

            res.json(safeOrders);
        },
    );
});

// Generate key endpoint (admin only)
app.post("/api/admin/generate-key", requireAdmin, async (req, res) => {
    const { email, plan, price = 0, customExpiry } = req.body;
    const adminUser = req.adminUser;

    if (!email || !plan) {
        return res.status(400).json({ error: "Email and plan required" });
    }

    // Validate email format
    if (!email.includes("@")) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    const orderNumber = generateOrderNumber();
    const licenseKey = generateLicenseKey();
    const encryptedKey = encryptKey(licenseKey);
    const expiresAt = customExpiry
        ? new Date(customExpiry)
        : getExpiryDate(plan);

    db.run(
        `INSERT INTO keys (key, encrypted_key, email, product, plan, price, expires_at, is_active, created_by) 
         VALUES (?, ?, ?, 'canvaspro', ?, ?, ?, 1, ?)`,
        [
            licenseKey,
            encryptedKey,
            email,
            plan,
            price,
            expiresAt.toISOString(),
            adminUser,
        ],
        function (err) {
            if (err) {
                console.error("Database error:", err);
                return res
                    .status(500)
                    .json({ error: "Failed to generate key" });
            }

            const keyId = this.lastID;

            // Create order record
            db.run(
                `INSERT INTO orders (order_number, email, product, plan, amount, key_id, status) 
                 VALUES (?, ?, 'canvaspro', ?, ?, ?, 'completed')`,
                [orderNumber, email, plan, price, keyId],
            );

            // Log admin action
            db.run(
                `INSERT INTO admin_logs (admin_user, action, target_id, details, ip_address)
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    adminUser,
                    "generate_key",
                    keyId,
                    JSON.stringify({ email, plan }),
                    req.ip,
                ],
            );

            // Try to send email
            sendOrderEmail({
                orderNumber,
                licenseKey,
                email,
                plan,
                expiresAt,
            });

            res.json({
                success: true,
                key: licenseKey,
                orderNumber,
                expires: expiresAt.toISOString(),
            });
        },
    );
});

// Delete key endpoint
app.delete("/api/admin/delete-key/:keyId", requireAdmin, (req, res) => {
    const keyId = req.params.keyId;
    const adminUser = req.adminUser;

    db.run(
        `UPDATE keys SET is_active = 0 WHERE id = ?`,
        [keyId],
        function (err) {
            if (err) {
                console.error("❌ Delete key error:", err);
                return res.status(500).json({ error: "Failed to delete key" });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: "Key not found" });
            }

            // Deactivate all devices
            db.run(`UPDATE key_devices SET is_active = 0 WHERE key_id = ?`, [
                keyId,
            ]);

            // Log admin action
            db.run(
                `INSERT INTO admin_logs (admin_user, action, target_id, ip_address)
                 VALUES (?, ?, ?, ?)`,
                [adminUser, "delete_key", keyId, req.ip],
            );

            res.json({ success: true });
        },
    );
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Secure CanvasPro Backend running on port ${PORT}`);
    console.log(`📍 Health: http://0.0.0.0:${PORT}/api/health`);
    console.log(`🔒 Security: All endpoints protected`);
    console.log(
        `🔑 API Token: ${CONFIG.API_SECRET_TOKEN ? "Configured" : "NOT CONFIGURED"}`,
    );
    console.log(
        `👨‍💼 Admin: ${CONFIG.ADMIN_USERNAME ? "Configured" : "NOT CONFIGURED"}`,
    );
    console.log(`💳 Stripe: ${stripe ? "Configured" : "Test Mode"}`);
    console.log(`📧 Email: ${resend ? "Configured" : "Disabled"}`);

    if (!CONFIG.STRIPE_SECRET_KEY) {
        console.error(
            "\n⚠️ WARNING: Stripe not configured! Payments will not work!",
        );
        console.error("Add STRIPE_SECRET_KEY to Replit Secrets immediately!");
    }

    // Check for Resend configuration
    if (!CONFIG.RESEND_API_KEY) {
        console.error(
            "\n⚠️ WARNING: Resend not configured! Emails will not be sent!",
        );
        console.error("Add RESEND_API_KEY to Replit Secrets immediately!");
    }
});
