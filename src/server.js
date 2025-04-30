// server.js
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
const fetch = require('node-fetch'); // required for URL shortening

const app = express();

// Load environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const LINK_PAYS_API_KEY = process.env.LINK_PAYS_API_KEY || null;
const NETLIFY_URL = process.env.NETLIFY_URL || 'https://genzz-library.netlify.app';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/genzz';

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

// Generate Key
app.post('/api/generate-key', async (req, res) => {
    const { duration, userId, url } = req.body;
    if (!duration || !userId || !url) return res.status(400).json({ error: 'Missing fields' });

    const expiryMs = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
    const expiry = Date.now() + expiryMs;
    const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryMs / 1000 });

    const fullUrl = `${NETLIFY_URL}${url}?token=${token}`;
    const shortUrl = await shortenUrl(fullUrl);

    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: false });
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
    res.cookie('isAdmin', 'true', { httpOnly: true, sameSite: 'strict', secure: false });
    res.json({ success: true });
});

// Get all books
app.get('/api/books', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (err) {
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
        res.json({ success: true, book: newBook });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete book
app.delete('/api/books/:id', verifyAdmin, async (req, res) => {
    try {
        const book = await Book.findOneAndDelete({ id: req.params.id });
        if (!book) return res.status(404).json({ error: 'Not found' });
        res.json({ success: true });
    } catch (err) {
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
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server running on http://0.0.0.0:${PORT}`);
});
