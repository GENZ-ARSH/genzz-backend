require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const { body, validationResult } = require('express-validator');
const { Telegraf } = require('telegraf');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const csurf = require('csurf');

const app = express();

// Environment Variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SHRINKME_API_KEY = process.env.SHRINKME_API_KEY || '6878c6b4d4cd486e5aa2735266cc5cafdf93e651';
const NETLIFY_URL = process.env.NETLIFY_URL || 'https://genzz-library.netlify.app';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/genzz';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || 'your_telegram_bot_token';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || 'your_telegram_chat_id';
const FREEIMAGE_API_KEY = process.env.FREEIMAGE_API_KEY || 'your_freeimage_api_key';

// Validate Environment Variables
if (!JWT_SECRET || JWT_SECRET === 'default-insecure-secret') {
    console.warn('WARNING: JWT_SECRET is not set or using default. Set a secure value in production.');
}
if (!MONGO_URI) {
    console.error('ERROR: MONGO_URI is not set. MongoDB connection will fail.');
    process.exit(1);
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD === 'admin123') {
    console.warn('WARNING: ADMIN_PASSWORD is not set or using default. Set a secure value in production.');
}
if (!TELEGRAM_BOT_TOKEN || TELEGRAM_BOT_TOKEN === 'your_telegram_bot_token') {
    console.warn('WARNING: TELEGRAM_BOT_TOKEN is not set. Telegram integration will fail.');
}
if (!TELEGRAM_CHAT_ID || TELEGRAM_CHAT_ID === 'your_telegram_chat_id') {
    console.warn('WARNING: TELEGRAM_CHAT_ID is not set. Telegram integration will fail.');
}
if (!FREEIMAGE_API_KEY || FREEIMAGE_API_KEY === 'your_freeimage_api_key') {
    console.warn('WARNING: FREEIMAGE_API_KEY is not set. Image uploads may fail.');
}

// Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console(),
    ],
});

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    logger.info('Created uploads directory');
}

// MongoDB Connection
const connectToMongo = async () => {
    try {
        await mongoose.connect(MONGO_URI, {
            connectTimeoutMS: 10000,
            serverSelectionTimeoutMS: 5000,
            maxPoolSize: 10,
        });
        logger.info('Connected to MongoDB');
    } catch (err) {
        logger.error(`MongoDB connection error: ${err.message}`);
        process.exit(1);
    }
};
connectToMongo();

// Graceful Shutdown
process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM. Closing MongoDB connection.');
    await mongoose.connection.close();
    process.exit(0);
});

// Schemas
const bookSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    title: { type: String, required: true },
    author: { type: String, required: true },
    link: { type: String, required: true },
    image_url: { type: String, required: true },
    class: { type: String, default: 'Unknown' },
    exam: { type: String, default: 'Unknown' },
    category: { type: String, default: 'General' }, // New field for category
    clicks: { type: Number, default: 0 },
});

const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
});

const Book = mongoose.model('Book', bookSchema);
const Review = mongoose.model('Review', reviewSchema);

// Telegram Bot
const bot = new Telegraf(TELEGRAM_BOT_TOKEN);
bot.on('message', (ctx) => {
    logger.info(`Received message from chat ID: ${ctx.chat.id}, Message: ${ctx.message.text}`);
});
const sendToTelegram = async (message) => {
    let retries = 3;
    let delay = 1000;
    while (retries) {
        try {
            await bot.telegram.sendMessage(TELEGRAM_CHAT_ID, message);
            logger.info(`Message sent to Telegram: ${message}`);
            return true;
        } catch (err) {
            retries -= 1;
            logger.error(`Failed to send message to Telegram: ${err.message}, Retries left: ${retries}`);
            if (!retries) {
                logger.error('All Telegram send retries failed.');
                return false;
            }
            await new Promise(resolve => setTimeout(resolve, delay));
            delay *= 2;
        }
    }
};
bot.launch().then(() => {
    logger.info('Telegraf bot launched successfully');
    bot.telegram.getMe().then(botInfo => {
        logger.info(`Bot info: ${JSON.stringify(botInfo)}`);
    }).catch(err => {
        logger.error(`Failed to get bot info: ${err.message}`);
    });
}).catch(err => logger.error(`Telegraf launch failed: ${err.message}`));

// FreeImage Upload
async function uploadToFreeImage(file) {
    if (!FREEIMAGE_API_KEY) {
        logger.warn('FREEIMAGE_API_KEY not set, using placeholder URL');
        return 'https://via.placeholder.com/150';
    }
    try {
        const formData = new FormData();
        formData.append('source', fs.createReadStream(file.path));
        formData.append('key', FREEIMAGE_API_KEY);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        const response = await fetch('https://freeimage.host/api/1/upload', {
            method: 'POST',
            body: formData,
            signal: controller.signal,
        });
        clearTimeout(timeoutId);

        const data = await response.json();
        if (data.image && data.image.url) {
            logger.info(`Image uploaded to FreeImage: ${data.image.url}`);
            return data.image.url;
        } else {
            logger.warn(`FreeImage upload failed: ${JSON.stringify(data)}`);
            return 'https://via.placeholder.com/150';
        }
    } catch (err) {
        logger.error(`FreeImage upload failed: ${err.message}`);
        return 'https://via.placeholder.com/150';
    }
}

// Multer Setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'Uploads/'),
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only JPEG/PNG images allowed!'));
        }
    },
});

// Middleware
const allowedOrigins = [NETLIFY_URL, 'http://localhost:3000', 'http://localhost:8080'];
app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                logger.warn(`CORS blocked for origin: ${origin}`);
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    })
);
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://telegram.org', 'https://www.googletagmanager.com'],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            imgSrc: [
                "'self'",
                'data:',
                'https://*.cloudfront.net',
                'https://*.amazon.com',
                'https://via.placeholder.com',
                'https://booksfy.in',
                'https://imgv2-2-f.scribdassets.com',
                'https://freeimage.host',
            ],
            connectSrc: ["'self'", 'https://genzz-backend.onrender.com', 'https://linkcent.in', 'https://freeimage.host'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            mediaSrc: ["'self'", 'https://static.vecteezy.com'],
        },
    },
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csurf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' } }));
app.use(
    rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 100,
        message: { error: 'Too many requests, please try again later.' },
    })
);
app.use('/Uploads', express.static('Uploads'));

// Rate limit for /api/auth
app.use(
    '/api/auth',
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 10,
        message: { error: 'Too many auth attempts, try again later.' },
    })
);

// CSRF Token Endpoint
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.stack}`);
    if (err.message === 'Only JPEG/PNG images allowed!') {
        return res.status(400).json({ error: err.message });
    }
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    res.status(500).json({ error: 'Internal server error' });
});

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Genzz Backend API running.' });
});

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) {
        logger.warn('No token provided');
        return res.status(401).json({ error: 'No token' });
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        logger.error(`Invalid token: ${err.message}`);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Admin Check Middleware
const verifyAdmin = (req, res, next) => {
    if (req.cookies.isAdmin === 'true' || req.headers['x-admin'] === 'true') {
        next();
    } else {
        logger.warn('Admin access denied');
        res.status(403).json({ error: 'Admin only' });
    }
};

// Shorten URL
async function shortenUrl(originalUrl) {
    if (!SHRINKME_API_KEY) {
        logger.info('No SHRINKME_API_KEY, returning original URL');
        return originalUrl;
    }
    try {
        const alias = `genzz-${uuidv4().slice(0, 8)}`;
        const apiUrl = `https://shrinkme.io/api?api=${SHRINKME_API_KEY}&url=${encodeURIComponent(originalUrl)}&alias=${alias}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(apiUrl, { signal: controller.signal });
        clearTimeout(timeoutId);
        const data = await response.json();
        if (data.status === 'success' && data.shortenedUrl) {
            return data.shortenedUrl;
        }
        logger.warn(`ShrinkMe API failed: ${JSON.stringify(data)}`);
        return originalUrl;
    } catch (err) {
        logger.error(`URL shortening failed: ${err.message}`);
        return originalUrl;
    }
}

// Generate Key
app.post(
    '/api/generate-key',
    [
        body('duration').isIn(['24hr', '48hr']).withMessage('Invalid duration'),
        body('userId').isUUID().withMessage('Invalid userId'),
        body('url').isString().notEmpty().withMessage('URL required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors in generate-key: ' + JSON.stringify(errors.array()));
            return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
        }

        const { duration, userId, url } = req.body;
        try {
            const expiryMs = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
            const expiry = Date.now() + expiryMs;
            const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryMs / 1000 });

            const fullUrl = url.startsWith('http') ? url : `${NETLIFY_URL}${url.startsWith('/') ? url : '/' + url}`;
            const shortUrl = await shortenUrl(fullUrl);

            res.cookie('token', token, {
                httpOnly: true,
                sameSite: 'strict',
                secure: process.env.NODE_ENV === 'production',
                maxAge: expiryMs,
            });
            res.json({ token, expiry, shortUrl });
        } catch (err) {
            logger.error(`Error in generate-key: ${err.message}`);
            res.status(500).json({ error: 'Failed to generate key' });
        }
    }
);

// Validate Key
app.post('/api/validate-key', (req, res, next) => {
    if (req.cookies.access === 'true') {
        res.json({ success: true, userId: 'special-access', expiry: Date.now() + 24 * 60 * 60 * 1000 });
        return;
    }
    verifyToken(req, res, () => {
        const { userId, expiry } = req.user;
        res.json({ success: true, userId, expiry });
    });
});

// Auth Endpoint
app.post(
    '/api/auth',
    [
        body('password').isString().notEmpty().withMessage('Password required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors in auth: ' + JSON.stringify(errors.array()));
            return res.status(400).json({ success: false, error: errors.array().map(e => e.msg).join(', ') });
        }

        const { password } = req.body;
        if (password !== ADMIN_PASSWORD) {
            logger.warn('Incorrect auth password');
            return res.status(401).json({ success: false, error: 'Wrong password' });
        }

        res.cookie('access', 'true', {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000,
        });
        res.json({ success: true });
    }
);

// Admin Login
app.post(
    '/api/admin-login',
    [
        body('password').isString().notEmpty().withMessage('Password required'),
        body('_csrf').isString().notEmpty().withMessage('CSRF token required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors in admin-login: ' + JSON.stringify(errors.array()));
            return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
        }

        const { password } = req.body;
        if (password !== ADMIN_PASSWORD) {
            logger.warn('Incorrect admin password');
            return res.status(401).json({ error: 'Wrong password' });
        }
        res.cookie('isAdmin', 'true', {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000,
        });
        res.json({ success: true });
    }
);

// Submit Review
app.post(
    '/api/reviews',
    [
        body('name').isString().notEmpty().withMessage('Name required'),
        body('message').isString().notEmpty().withMessage('Message required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors in submit review: ' + JSON.stringify(errors.array()));
            return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
        }

        const { name, message } = req.body;
        try {
            const review = new Review({ name, message });
            await review.save();
            const sent = await sendToTelegram(`New Review:\nName: ${name}\nMessage: ${message}\nTime: ${new Date().toISOString()}`);
            res.json({ success: true, warning: sent ? null : 'Review saved but Telegram notification failed' });
            logger.info(`Review submitted by ${name}`);
        } catch (err) {
            logger.error(`Error submitting review: ${err.message}`);
            res.status(500).json({ error: 'Failed to submit review' });
        }
    }
);

// Get All Reviews
app.get('/api/reviews', verifyAdmin, async (req, res) => {
    try {
        const reviews = await Review.find().sort({ timestamp: -1 });
        res.json(reviews);
    } catch (err) {
        logger.error(`Error fetching reviews: ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch reviews' });
    }
});

// Get All Books
app.get('/api/books', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (err) {
        logger.error(`Error fetching books: ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch books' });
    }
});

// Add Book
app.post(
    '/api/books',
    verifyAdmin,
    upload.single('image'),
    [
        body('title').isString().notEmpty().withMessage('Title required'),
        body('author').isString().notEmpty().withMessage('Author required'),
        body('link').isURL().withMessage('Valid link required'),
        body('class').optional().isString().withMessage('Invalid class'),
        body('exam').optional().isString().withMessage('Invalid exam'),
        body('category').optional().isString().withMessage('Invalid category'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation errors in add book: ' + JSON.stringify(errors.array()));
            return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
        }

        const { title, author, link, class: bookClass, exam, category } = req.body;
        let image_url = 'https://via.placeholder.com/150';
        if (req.file) {
            image_url = await uploadToFreeImage(req.file);
            fs.unlink(req.file.path, (err) => {
                if (err) logger.error(`Failed to delete local file: ${err.message}`);
            });
        }

        try {
            const newBook = new Book({
                id: uuidv4(),
                title,
                author,
                link,
                image_url,
                class: bookClass || 'Unknown',
                exam: exam || 'Unknown',
                category: category || 'General',
                clicks: 0,
            });
            await newBook.save();
            logger.info(`Book added: ${title}`);
            res.json({ success: true, book: newBook });
        } catch (err) {
            logger.error(`Error adding book: ${err.message}`);
            res.status(500).json({ error: 'Failed to add book' });
        }
    }
);

// Delete Book
app.delete('/api/books/:id', verifyAdmin, async (req, res) => {
    try {
        const book = await Book.findOneAndDelete({ id: req.params.id });
        if (!book) {
            logger.warn(`Book not found: ${req.params.id}`);
            return res.status(404).json({ error: 'Not found' });
        }
        logger.info(`Book deleted: ${req.params.id}`);
        res.json({ success: true });
    } catch (err) {
        logger.error(`Error deleting book: ${err.message}`);
        res.status(500).json({ error: 'Failed to delete book' });
    }
});

// Track Click
app.post('/api/books/:id/click', async (req, res) => {
    try {
        const book = await Book.findOne({ id: req.params.id });
        if (!book) {
            logger.warn(`Book not found for click tracking: ${req.params.id}`);
            return res.status(404).json({ error: 'Not found' });
        }
        book.clicks += 1;
        await book.save();
        logger.info(`Click tracked for book: ${req.params.id}`);
        res.json({ success: true });
    } catch (err) {
        logger.error(`Error tracking click: ${err.message}`);
        res.status(500).json({ error: 'Failed to track click' });
    }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server running on http://0.0.0.0:${PORT}`);
});