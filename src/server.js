require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');

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
const NETLIFY_URL = process.env.NETLIFY_URL || 'http://localhost:3000';

// Middleware
const allowedOrigins = [
    'http://localhost:3000',
    NETLIFY_URL,
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`CORS blocked for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// In-memory storage
let books = [
    {
        id: uuidv4(),
        title: 'Sample Book',
        author: 'John Doe',
        link: 'https://drive.google.com/file/d/sample',
        image_url: 'https://via.placeholder.com/150',
        class: '10th',
        exam: 'Board',
        clicks: 0,
    },
];

// Root route for testing
app.get('/', (req, res) => {
    res.json({ message: 'Genzz Backend API is running. Use /api endpoints (e.g., /api/generate-key, /api/books).' });
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
    const isAdmin = req.cookies.isAdmin === 'true' || req.headers['x-admin'] === 'true';
    if (!isAdmin) return res.status(403).json({ error: 'Admin access required' });
    next();
};

// Linkpays.in API integration
async function shortenUrl(originalUrl) {
    if (!LINK_PAYS_API_KEY) {
        console.error('Linkpays.in API key is missing');
        return originalUrl;
    }

    try {
        console.log('Attempting to shorten URL:', originalUrl);
        const response = await fetch('https://linkpays.in/api', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${LINK_PAYS_API_KEY}`,
            },
            body: JSON.stringify({ url: originalUrl }),
        });

        const data = await response.json();
        console.log('Linkpays.in response:', data);
        if (data.status === 'success' && data.shortenedUrl) {
            console.log('Shortened URL:', data.shortenedUrl);
            return data.shortenedUrl;
        } else {
            console.error('Linkpays.in API error:', data);
            return originalUrl;
        }
    } catch (error) {
        console.error('Error calling Linkpays.in API:', error);
        return originalUrl;
    }
}

// API Endpoints
app.post('/api/generate-key', async (req, res) => {
    const { duration, userId, url } = req.body;
    if (!duration || !userId || !url) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const expiryDuration = duration === '24hr' ? 24 * 60 * 60 * 1000 : 48 * 60 * 60 * 1000;
        const expiry = Date.now() + expiryDuration;
        const token = jwt.sign({ userId, expiry }, JWT_SECRET, { expiresIn: expiryDuration / 1000 });

        const originalUrl = `${NETLIFY_URL}${url}?token=${token}`;
        const shortUrl = await shortenUrl(originalUrl);
        console.log('Generated shortUrl:', shortUrl);

        if (!shortUrl.startsWith('https://') && !shortUrl.startsWith('http://')) {
            console.error('Invalid shortUrl generated:', shortUrl);
            return res.status(500).json({ error: 'Failed to generate valid short URL' });
        }

        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.json({ success: true, token, expiry, shortUrl });
    } catch (error) {
        console.error('Generate key error:', error);
        res.status(500).json({ error: 'Failed to generate key' });
    }
});

app.post('/api/validate-key', verifyToken, (req, res) => {
    try {
        const { userId, expiry } = req.user;
        if (Date.now() > expiry) {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.json({ success: true, userId, expiry });
    } catch (error) {
        console.error('Validate key error:', error);
        res.status(500).json({ error: 'Failed to validate key' });
    }
});

app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: 'Password is required' });
    }

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Invalid password' });
    }

    res.cookie('isAdmin', 'true', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ success: true });
});

app.get('/api/books', (req, res) => {
    try {
        res.json(books);
    } catch (error) {
        console.error('Get books error:', error);
        res.status(500).json({ error: 'Failed to fetch books' });
    }
});

app.post('/api/books', verifyAdmin, (req, res) => {
    const { title, author, link, image_url, class: bookClass, exam } = req.body;
    if (!title || !author || !link) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const newBook = {
            id: uuidv4(),
            title,
            author,
            link,
            image_url: image_url || 'https://via.placeholder.com/150',
            class: bookClass || 'Unknown',
            exam: exam || 'Unknown',
            clicks: 0,
        };
        books.push(newBook);
        res.json({ success: true, book: newBook });
    } catch (error) {
        console.error('Add book error:', error);
        res.status(500).json({ error: 'Failed to add book' });
    }
});

app.delete('/api/books/:id', verifyAdmin, (req, res) => {
    const { id } = req.params;
    try {
        const bookIndex = books.findIndex(book => book.id === id);
        if (bookIndex === -1) {
            return res.status(404).json({ error: 'Book not found' });
        }
        books.splice(bookIndex, 1);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete book error:', error);
        res.status(500).json({ error: 'Failed to delete book' });
    }
});

app.post('/api/books/:id/click', (req, res) => {
    const { id } = req.params;
    try {
        const book = books.find(book => book.id === id);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }
        book.clicks = (book.clicks || 0) + 1;
        res.json({ success: true, clicks: book.clicks });
    } catch (error) {
        console.error('Track click error:', error);
        res.status(500).json({ error: 'Failed to track click' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});