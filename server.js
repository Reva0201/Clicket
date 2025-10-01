const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
// Serve static files (for register.html and others)
app.use(express.static(__dirname));
// Serve index.html for root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Helper to read users
function readUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
}

// Helper to write users
function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Registration endpoint
app.post('/register', async (req, res) => {
    const { fullname, username, email, password, role } = req.body;
    if (!fullname || !username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    const users = readUsers();
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(409).json({ error: 'Username already exists.' });
    }
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return res.status(409).json({ error: 'Email already registered.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
        fullname,
        username,
        email,
        password: hashedPassword,
        role: role && role.toLowerCase() === 'admin' ? 'admin' : 'user'
    });
    writeUsers(users);
    res.json({ success: true });
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required.' });
    }
    const users = readUsers();
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.status(401).json({ error: 'Invalid username or password.' });
    }
    res.json({ success: true, fullname: user.fullname, email: user.email, role: user.role || 'user' });
});

// Admin: Get all users (no password)
app.get('/users', (req, res) => {
    const users = readUsers();
    const usersNoPassword = users.map(({ password, ...rest }) => rest);
    res.json(usersNoPassword);
});

// Admin: Make user admin
app.post('/users/make-admin', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    const users = readUsers();
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.role = 'admin';
    writeUsers(users);
    res.json({ success: true });
});

// Admin: Delete user
app.post('/users/delete', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    let users = readUsers();
    const before = users.length;
    users = users.filter(u => u.username.toLowerCase() !== username.toLowerCase());
    if (users.length === before) return res.status(404).json({ error: 'User not found' });
    writeUsers(users);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
