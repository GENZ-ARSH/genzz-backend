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
const fetch = require('node-fetch');
const multer = require('multer');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

// Create public/uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const app = express();

// Load environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const LINK_PAYS_API_KEY = process.env.LINK_PAYS_API_KEY || null;
const NETLIFY_URL = process.env.NETLIFY_URL || 'https://genzz-library.netlify.app';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/genzz';
const FREEIMAGE_API_KEY = process.env.FREEIMAGE_API_KEY;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ],
});

// MongoDB connection
mongoose.connect(MONGO_URI)
    .then(() => logger.info('Connected to MongoDB'))
    .catch(err => logger.error('MongoDB connection error:', err));

const bookSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    title: String,
    author: String,
    link: String,
    image_url: String,
    class: String,
    exam: String,
    clicks: Number,
});

const Book = mongoose.model('Book', bookSchema);

// Multer setup for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Images only (jpg, jpeg, png)!'));
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Middleware
const allowedOrigins = ['http://localhost:3000', NETLIFY_URL];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(express.static('public')); // Serve static files (e.g., uploads)

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Genzz Backend API running.' });
});

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Admin check
const verifyAdmin = (req, res, next) => {
    if (req.cookies.isAdmin === 'true' || req.headers['x-admin'] === 'true') next();
    else res.status(403).json({ error: 'Admin only' });
};

// Shorten URL using LinkPays
async function shortenUrl(originalUrl) {
    if (!LINK_PAYS_API_KEY) return originalUrl;
    try {
        const apiUrl = `https://linkpays.in/api?api=${LINK_PAYS_API_KEY}&url=${encodeURIComponent(originalUrl)}`;
        const response = await fetch(apiUrl);
        const data = await response.json();
        return data.status === 'success' && data.shortenedUrl ? data.shortenedUrl : originalUrl;
    } catch {
        return originalUrl;
    }
}

// Image Upload Route
app.post('/api/upload-cover', verifyAdmin, upload.single('cover'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    if (FREEIMAGE_API_KEY) {
        // FreeImage.host upload
        const formData = new FormData();
        formData.append('source', fs.createReadStream(req.file.path));
        formData.append('key', FREEIMAGE_API_KEY);

        try {
            const response = await axios.post('https://freeimage.host/api/1/upload', formData, {
                headers: formData.getHeaders()
            });
            fs.unlinkSync(req.file.path); // Delete local file
            const coverUrl = response.data.image.url;
            logger.info(`Image uploaded to FreeImage.host: ${coverUrl}`);
            res.json({ success: true, coverUrl });
        } catch (error) {
            logger.error('FreeImage.host upload error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    } else {
        // Local storage fallback
        const coverUrl = `/uploads/${req.file.filename}`;
        logger.info(`Image uploaded locally: ${coverUrl}`);
        res.json({ success: true, coverUrl });
    }
});

// Generate Key
app.post('/api/generate-key', async (req, res) => {
    const { duration, userId, url } = req.body;
    if (!duration || !userId || !url) return res.status(400).json({ error: 'Missing fields' });

    const expiryMs = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
    const expiry = Date.now() + expiryMs;
    const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryMs / 1000 });

    const fullUrl = `${NETLIFY_URL}${url}?token=${token}`;
    const shortUrl = await shortenUrl(fullUrl);

    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    res.json({ token, expiry, shortUrl });
});

// Validate Key
app.post('/api/validate-key', verifyToken, (req, res) => {
    const { userId, expiry } = req.user;
    if (Date.now() > expiry) return res.status(401).json({ error: 'Token expired' });
    res.json({ success: true, userId, expiry });
});

// Admin login
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
    res.cookie('isAdmin', 'true', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    res.json({ success: true });
});

// Get all books
app.get('/api/books', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (err) {
        logger.error('Error fetching books:', err);
        res.status(500).json({ error: err.message });
    }
});

// Add book
app.post('/api/books', verifyAdmin, async (req, res) => {
    const { title, author, link, image_url, class: bookClass, exam } = req.body;
    if (!title || !author || !link) return res.status(400).json({ error: 'Missing required fields' });

    try {
        const newBook = new Book({
            id: uuidv4(),
            title,
            author,
            link,
            image_url: image_url || 'https://via.placeholder.com/150',
            class: bookClass || 'Unknown',
            exam: exam || 'Unknown',
            clicks: 0,
        });
        await newBook.save();
        logger.info(`Book added: ${title}`);
        res.json({ success: true, book: newBook });
    } catch (err) {
        logger.error('Error adding book:', err);
        res.status(500).json({ error: err.message });
    }
});

// Delete book
app.delete('/api/books/:id', verifyAdmin, async (req, res) => {
    try {
        const book = await Book.findOneAndDelete({ id: req.params.id });
        if (!book) return res.status(404).json({ error: 'Not found' });
        logger.info(`Book deleted: ${book.title}`);
        res.json({ success: true });
    } catch (err) {
        logger.error('Error deleting book:', err);
        res.status(500).json({ error: err.message });
    }
});

// Track click
app.post('/api/books/:id/click', async (req, res) => {
    try {
        const book = await Book.findOne({ id: req.params.id });
        if (!book) return res.status(404).json({ error: 'Not found' });

        book.clicks += 1;
        await book.save();
        logger.info(`Click tracked for book: ${book.title}`);
        res.json({ success: true });
    } catch (err) {
        logger.error('Error tracking click:', err);
        res.status(500).json({ error: err.message });
    }
});

// Reviews (Telegram placeholder)
app.post('/api/reviews', async (req, res) => {
    const { name, message } = req.body;
    if (!name || !message) return res.status(400).json({ error: 'Missing fields' });

    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
        const TelegramBot = require('node-telegram-bot-api');
        const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
        try {
            await bot.sendMessage(TELEGRAM_CHAT_ID, `Query from ${name}: ${message}`);
            logger.info(`Review sent to Telegram: ${name}`);
            res.json({ success: true });
        } catch (err) {
            logger.error('Telegram error:', err);
            res.status(500).json({ error: err.message });
        }
    } else {
        // Fallback: Log review
        logger.info(`Review received (no Telegram): ${name} - ${message}`);
        res.json({ success: true });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server running on http://0.0.0.0:${PORT}`);
});
