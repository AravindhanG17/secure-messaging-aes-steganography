const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 501;

// Database Configuration (Using Connection Pool)
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'admin', // Replace with your MySQL password
    database: 'testing',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// JWT Secret Key
const SECRET_KEY = 'your_secret_key_here'; // Replace with a secure key

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(__dirname));

// Serve HTML Pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// Register User
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Please provide all required fields' });
        }

        const db = await pool.getConnection();
        const [existingUser] = await db.execute('SELECT * FROM users WHERE user_email = ?', [email]);

        if (existingUser.length > 0) {
            db.release();
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute('INSERT INTO users (user_email, user_password, user_name) VALUES (?, ?, ?)', [email, hashedPassword, name]);
        db.release();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Login User
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Please provide both email and password' });
        }

        const db = await pool.getConnection();
        const [users] = await db.execute('SELECT * FROM users WHERE user_email = ?', [email]);

        if (users.length === 0) {
            db.release();
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.user_password);
        db.release();

        if (!isPasswordValid) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign({ userId: user.user_id }, SECRET_KEY, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// JWT Authentication Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Submit Ticket
app.post('/submit-ticket', verifyToken, async (req, res) => {
    try {
        const { title, category, priority, description } = req.body;
        const user_id = req.user.userId;

        if (!title || !category || !priority || !description) {
            return res.status(400).json({ error: 'Please provide all required fields' });
        }

        const validCategories = ['Technical', 'Billing', 'Account', 'Feature', 'Other'];
        const validPriorities = ['Low', 'Medium', 'High', 'Critical'];
        if (!validCategories.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        if (!validPriorities.includes(priority)) {
            return res.status(400).json({ error: 'Invalid priority' });
        }

        const created_at = new Date();
        const ticketStatus = 'Open';

        const db = await pool.getConnection();
        const sql = `INSERT INTO new_tickets (user_id, title, category, priority, description, created_at, status)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`;
        const [result] = await db.execute(sql, [user_id, title, category, priority, description, created_at, ticketStatus]);
        db.release();

        console.log('Ticket stored successfully with ID:', result.insertId);
        res.status(201).json({ success: true, message: 'Ticket submitted successfully', ticketId: result.insertId });
    } catch (error) {
        console.error('Error storing ticket:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Get User-Specific Tickets
app.get('/user-tickets', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const db = await pool.getConnection();
        const [tickets] = await db.execute('SELECT * FROM new_tickets WHERE user_id = ?', [userId]);
        db.release();

        res.status(200).json(tickets);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Start Server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
