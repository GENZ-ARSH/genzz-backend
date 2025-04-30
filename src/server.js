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

// Environment variables
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || (() => {
    console.warn('Warning: JWT_SECRET is not set. Using default value.');
    return 'default-insecure-secret';
})();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const LINK_PAYS_API_KEY = process.env.LINK_PAYS_API_KEY || (() => {
    console.warn('Warning: LINK_PAYS_API_KEY is not set.');
    return null;
})();
const NETLIFY_URL = process.env.NETLIFY_URL || 'https://genzz1.netlify.app';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/genzz';

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ],
});

// MongoDB setup
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => logger.info('Connected to MongoDB'))
    .catch(err => logger.error('MongoDB connection error:', err));

const bookSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    title: { type: String, required: true },
    author: { type: String, required: true },
    link: { type: String, required: true },
    image_url: { type: String, default: 'https://via.placeholder.com/150' },
    class: { type: String, default: 'Unknown' },
    exam: { type: String, default: 'Unknown' },
    clicks: { type: Number, default: 0 },
});

const Book = mongoose.model('Book', bookSchema);

// Middleware
const allowedOrigins = ['http://localhost:3000', NETLIFY_URL];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));
app.use(helmet()); // Security headers
app.use(express.json());
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
});
app.use(limiter);

// Root route for testing
app.get('/', (req, res) => {
    res.json({ message: 'Genzz Backend API is running. Use /api endpoints (e.g., /api/generate-key, /api/books).' });
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) {
        logger.warn('No token provided');
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        logger.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
    const isAdmin = req.cookies.isAdmin === 'true' || req.headers['x-admin'] === 'true';
    if (!isAdmin) {
        logger.warn('Admin access denied');
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// LinkPays API integration (updated to GET)
async function shortenUrl(originalUrl) {
    if (!LINK_PAYS_API_KEY) {
        logger.error('LinkPays API key is missing');
        return originalUrl;
    }

    try {
        const encodedUrl = encodeURIComponent(originalUrl);
        const apiUrl = `https://linkpays.in/api?api=${LINK_PAYS_API_KEY}&url=${encodedUrl}`;
        logger.info('Attempting to shorten URL:', originalUrl);

        const response = await fetch(apiUrl, { method: 'GET' });
        const data = await response.json();
        logger.info('LinkPays response:', data);

        if (data.status === 'success' && data.shortenedUrl) {
            logger.info('Shortened URL:', data.shortenedUrl);
            return data.shortenedUrl;
        } else {
            logger.error('LinkPays API error:', data);
            return originalUrl;
        }
    } catch (error) {
        logger.error('Error calling LinkPays API:', error);
        return originalUrl;
    }
}

// API Endpoints
app.post('/api/generate-key', async (req, res) => {
    const { duration, userId, url } = req.body;
    if (!duration || !userId || !url) {
        logger.warn('Missing required fields for generate-key');
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const expiryDuration = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
        const expiry = Date.now() + expiryDuration;
        const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryDuration / 1000 });

        const originalUrl = `${NETLIFY_URL}${url}?token=${token}`;
        const shortUrl = await shortenUrl(originalUrl);
        logger.info('Generated shortUrl:', shortUrl);

        if (!shortUrl.startsWith('https://') && !shortUrl.startsWith('http://')) {
            logger.error('Invalid shortUrl generated:', shortUrl);
            return res.status(500).json({ error: 'Failed to generate valid short URL' });
        }

        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.json({ success: true, token, expiry, shortUrl });
    } catch (error) {
        logger.error('Generate key error:', error);
        res.status(500).json({ error: 'Failed to generate key' });
    }
});

app.post('/api/validate-key', verifyToken, (req, res) => {
    try {
        const { userId, expiry } = req.user;
        if (Date.now() > expiry) {
            logger.warn('Token expired');
            return res.status(401).json({ error: 'Token expired' });
        }
        res.json({ success: true, userId, expiry });
    } catch (error) {
        logger.error('Validate key error:', error);
        res.status(500).json({ error: 'Failed to validate key' });
    }
});

app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    if (!password) {
        logger.warn('Password missing for admin-login');
        return res.status(400).json({ error: 'Password is required' });
    }

    if (password !== ADMIN_PASSWORD) {
        logger.warn('Invalid admin password');
        return res.status(401).json({ error: 'Invalid password' });
    }

    res.cookie('isAdmin', 'true', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ success: true });
});

app.get('/api/books', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (error) {
        logger.error('Get books error:', error);
        res.status(500).json({ error: 'Failed to fetch books' });
    }
});

app.post('/api/books', verifyAdmin, async (req, res) => {
    const { title, author, link, image_url, class: bookClass, exam } = req.body;
    if (!title || !author || !link) {
        logger.warn('Missing required fields for adding book');
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
        logger.info('Book added:', newBook);
        res.json({ success: true, book: newBook });
    } catch (error) {
        logger.error('Add book error:', error);
        res.status(500).json({ error: 'Failed to add book' });
    }
});

app.delete('/api/books/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const book = await Book.findOneAndDelete({ id });
        if (!book) {
            logger.warn(`Book not found: ${id}`);
            return res.status(404).json({ error: 'Book not found' });
        }
        logger.info('Book deleted:', id);
        res.json({ success: true });
    } catch (error) {
        logger.error('Delete book error:', error);
        res.status(500).json({ error: 'Failed to delete book' });
    }
});

app.post('/api/books/:id/click', async (req, res) => {
    const { id } = req.params;
    try {
        const book = await Book.findOne({ id });
        if (!book) {
            logger.warn(`Book not found: ${id}`);
            return res.status(404).json({ error: 'Book not found' });
        }
        book.clicks += 1;
        await book.save();
        logger.info(`Click tracked for book: ${id}, clicks: ${book.clicks}`);
        res.json({ success: true, clicks: book.clicks });
    } catch (error) {
        logger.error('Track click error:', error);
        res.status(500).json({ error: 'Failed to track click' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
