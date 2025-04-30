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

const app = express();

// Load environment variables
const PORT = process.env.PORT || 0; // Dynamic port for Render, random port locally
const JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const LINK_PAYS_API_KEY = process.env.LINK_PAYS_API_KEY || null;
const NETLIFY_URL = process.env.NETLIFY_URL || 'https://genzz-library.netlify.app';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/genzz';

// Validate critical environment variables
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'default-insecure-secret') {
    console.warn('WARNING: JWT_SECRET is not set or using default. Set a secure value in production.');
}
if (!process.env.MONGO_URI) {
    console.error('ERROR: MONGO_URI is not set. MongoDB connection will fail.');
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

// MongoDB connection with retry
const connectToMongo = async () => {
    let retries = 5;
    while (retries) {
        try {
            await mongoose.connect(MONGO_URI, { connectTimeoutMS: 10000 });
            logger.info('Connected to MongoDB');
            return;
        } catch (err) {
            retries -= 1;
            logger.error(`MongoDB connection error, ${retries} retries left: ${err.message}`);
            if (!retries) {
                logger.error('Failed to connect to MongoDB after retries. Exiting.');
                process.exit(1);
            }
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
};
connectToMongo();

const bookSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    title: String,
    author: String,
    link: String,
    image_url: String,
    class: String,
    exam: String,
    clicks: { type: Number, default: 0 },
});

const Book = mongoose.model('Book', bookSchema);

// Middleware
const allowedOrigins = [
    'http://localhost:8080', // For local testing with live-server
    NETLIFY_URL,
    'https://genzz-library.netlify.app', // Fallback Netlify URL
];
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
    })
);
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // 100 requests per IP
    })
);

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.message}`);
    res.status(500).json({ error: 'Internal server error' });
});

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Genzz Backend API running.' });
});

// JWT verification middleware
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
        logger.warn(`Invalid token: ${err.message}`);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Admin check
const verifyAdmin = (req, res, next) => {
    if (req.cookies.isAdmin === 'true' || req.headers['x-admin'] === 'true') {
        next();
    } else {
        logger.warn('Admin access denied');
        res.status(403).json({ error: 'Admin only' });
    }
};

// Shorten URL using LinkPays
async function shortenUrl(originalUrl) {
    if (!LINK_PAYS_API_KEY) {
        logger.info('No LINK_PAYS_API_KEY provided, skipping URL shortening');
        return originalUrl;
    }
    try {
        const apiUrl = `https://linkpays.in/api?api=${LINK_PAYS_API_KEY}&url=${encodeURIComponent(originalUrl)}`;
        const response = await fetch(apiUrl, { method: 'GET' });
        const data = await response.json();
        return data.status === 'success' && data.shortenedUrl ? data.shortenedUrl : originalUrl;
    } catch (err) {
        logger.error(`URL shortening failed: ${err.message}`);
        return originalUrl;
    }
}

// Generate Key
app.post('/api/generate-key', async (req, res) => {
    const { duration, userId, url } = req.body;
    if (!duration || !userId || !url) {
        logger.warn('Missing fields in generate-key request');
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        const expiryMs = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
        const expiry = Date.now() + expiryMs;
        const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryMs / 1000 });

        const fullUrl = `${NETLIFY_URL}${url}?token=${token}`;
        const shortUrl = await shortenUrl(fullUrl);

        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production', // Secure cookies in production
        });
        res.json({ token, expiry, shortUrl });
    } catch (err) {
        logger.error(`Error in generate-key: ${err.message}`);
        res.status(500).json({ error: 'Failed to generate key' });
    }
});

// Validate Key
app.post('/api/validate-key', verifyToken, (req, res) => {
    const { userId, expiry } = req.user;
    if (Date.now() > expiry) {
        logger.warn('Token expired');
        return res.status(401).json({ error: 'Token expired' });
    }
    res.json({ success: true, userId, expiry });
});

// Admin login
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    if (!password) {
        logger.warn('No password provided for admin login');
        return res.status(400).json({ error: 'Password required' });
    }
    if (password !== ADMIN_PASSWORD) {
        logger.warn('Incorrect admin password');
        return res.status(401).json({ error: 'Wrong password' });
    }
    res.cookie('isAdmin', 'true', {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production', // Secure cookies in production
    });
    res.json({ success: true });
});

// Get all books
app.get('/api/books', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (err) {
        logger.error(`Error fetching books: ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch books' });
    }
});

// Add book
app.post('/api/books', verifyAdmin, async (req, res) => {
    const { title, author, link, image_url, class: bookClass, exam } = req.body;
    if (!title || !author || !link) {
        logger.warn('Missing required fields in add book request');
        return res.status(400).json({ error: 'Missing required fields' });
    }

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
        logger.error(`Error adding book: ${err.message}`);
        res.status(500).json({ error: 'Failed to add book' });
    }
});

// Delete book
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

// Track click
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server running on http://0.0.0.0:${PORT}`);
});

