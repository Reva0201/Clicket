const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const EVENTS_FILE = path.join(__dirname, 'events.json');
const PURCHASES_FILE = path.join(__dirname, 'purchases.json');
// Serve static files (for register.html and others)
app.use(express.static(__dirname));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Simple request logger for debugging
app.use((req, res, next) => {
    try {
        console.log('[REQ]', req.method, req.url);
    } catch (e) {
        console.error('[LOGGER ERROR]', e.message);
    }
    next();
});

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
    // Find max id and increment
    let maxId = 0;
    users.forEach(u => {
        if (typeof u.id === 'number' && u.id > maxId) maxId = u.id;
    });
    const newId = maxId + 1;
    users.push({
        id: newId,
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

app.get('/events', (req, res) => {
    if (!fs.existsSync(EVENTS_FILE)) return res.json([]);
    const data = fs.readFileSync(EVENTS_FILE);
    let events = [];
    try {
        events = JSON.parse(data);
    } catch (e) {
        return res.status(500).json({ error: 'Failed to parse events data.' });
    }
    res.json(events);
});

// Update events 
function readEvents() {
    if (!fs.existsSync(EVENTS_FILE)) return [];
    const data = fs.readFileSync(EVENTS_FILE);
    return JSON.parse(data);
}
// Tulis lagi
function writeEvents(events) {
    fs.writeFileSync(EVENTS_FILE, JSON.stringify(events, null, 2));
}

function readPurchases() {
    if (!fs.existsSync(PURCHASES_FILE)) return [];
    const data = fs.readFileSync(PURCHASES_FILE);
    return JSON.parse(data);
}

function writePurchases(purchases) {
    fs.writeFileSync(PURCHASES_FILE, JSON.stringify(purchases, null, 2));
}

// Add event menu
app.post('/events/add', (req, res) => {
    try {
        console.log('[EVENTS.ADD] START - body=', JSON.stringify(req.body));
        const body = req.body || {};
        const { name, price, amount, userId } = body;
        console.log('[EVENTS.ADD] Extracted: name=%s, price=%s, amount=%s, userId=%s', name, price, amount, userId);
        
        if (!name || price === undefined || amount === undefined) {
            console.log('[EVENTS.ADD] Validation failed: missing fields');
            return res.status(400).json({ error: 'Name, price and amount are required.' });
        }
        
        const priceNum = Number(price);
        const amountNum = Number(amount);
        console.log('[EVENTS.ADD] Converted: price=%f, amount=%f', priceNum, amountNum);
        
        if (!Number.isFinite(priceNum) || !Number.isFinite(amountNum)) {
            console.log('[EVENTS.ADD] Not finite');
            return res.status(400).json({ error: 'Price and amount must be numbers.' });
        }
        
        const uid = (userId !== undefined && userId !== null) ? Number(userId) : 0;
        console.log('[EVENTS.ADD] userId=%d', uid);
        
        console.log('[EVENTS.ADD] Reading events...');
        let events = readEvents();
        console.log('[EVENTS.ADD] Got %d events', events.length);
        
        let event = events.find(e => e.name && String(e.name).toLowerCase() === String(name).toLowerCase());
        console.log('[EVENTS.ADD] Found existing event: %s', event ? 'yes' : 'no');
        
        if (event) {
            let priceObj = event.prices.find(p => Number(p.price) === priceNum);
            if (priceObj) {
                priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + amountNum;
            } else {
                event.prices.push({ price: priceNum, stock: amountNum, userId: uid });
            }
            event.prices.sort((a, b) => a.price - b.price);
        } else {
            let maxId = events.reduce((max, e) => (e && e.id && e.id > max) ? e.id : max, 0);
            events.push({
                id: maxId + 1,
                name: String(name),
                prices: [{ price: priceNum, stock: amountNum, userId: uid }]
            });
        }
        
        console.log('[EVENTS.ADD] Writing events...');
        writeEvents(events);
        console.log('[EVENTS.ADD] SUCCESS');
        res.json({ success: true, message: 'Successfully added event' });
    } catch (err) {
        console.error('[EVENTS.ADD] CAUGHT ERROR:', err.message, err.stack);
        res.status(500).json({ error: 'Failed to add event', detail: err.message });
    }
});

// Update event (rename, add/update price tier)
app.post('/events/update', (req, res) => {
    const { id, name, price, amount } = req.body;
    if (!id) return res.status(400).json({ error: 'Event id required' });
    let events = readEvents();
    const ev = events.find(e => String(e.id) === String(id));
    if (!ev) return res.status(404).json({ error: 'Event not found' });
    if (name && String(name).trim()) ev.name = String(name).trim();
    // Support explicit prices array (replace tiers) or legacy price+amount (increment)
    if (Array.isArray(req.body.prices)) {
        try {
            const newPrices = req.body.prices.map(p => ({ price: Number(p.price), stock: Number(p.stock) }));
            // sanitize NaN
            ev.prices = newPrices.map(p => ({ price: Number.isFinite(p.price) ? p.price : 0, stock: Number.isFinite(p.stock) ? p.stock : 0 }));
            ev.prices.sort((a, b) => a.price - b.price);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid prices array' });
        }
    } else if (price && amount) {
        const priceVal = Number(price);
        const amountVal = Number(amount);
        let priceObj = ev.prices.find(p => Number(p.price) === priceVal);
        if (priceObj) {
            priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + amountVal;
        } else {
            ev.prices.push({ price: priceVal, stock: amountVal });
        }
        ev.prices.sort((a, b) => a.price - b.price);
    }
    writeEvents(events);
    res.json({ success: true, message: 'Event updated' });
});

// Delete an event by id
app.post('/events/delete', (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'Event id required' });
    let events = readEvents();
    const idx = events.findIndex(e => String(e.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'Event not found' });
    events.splice(idx, 1);
    writeEvents(events);
    res.json({ success: true, message: 'Event deleted' });
});

// Purchase tickets - atomically decrement stock
app.post('/tickets/purchase', (req, res) => {
    const { eventId, quantity } = req.body;
    const qty = Number(quantity);
    if (!eventId || !qty || qty < 1) return res.status(400).json({ error: 'eventId and positive quantity required' });

    let events = readEvents();
    // find by id or name (case-insensitive)
    let ev = events.find(e => String(e.id) === String(eventId));
    if (!ev) ev = events.find(e => e.name && String(e.name).trim().toLowerCase() === String(eventId).trim().toLowerCase());
    if (!ev) return res.status(404).json({ error: 'Event not found' });

    // work on a copy of prices sorted ascending
    const prices = (ev.prices || []).slice().sort((a, b) => a.price - b.price);
    let qtyLeft = qty;
    const breakdown = [];
    for (let p of prices) {
        if (qtyLeft <= 0) break;
        const available = Number.isFinite(p.stock) ? p.stock : 0;
        const take = Math.min(available, qtyLeft);
        if (take > 0) {
            breakdown.push({ price: p.price, count: take });
            qtyLeft -= take;
        }
    }
    if (qtyLeft > 0) {
        // compute total available stock
        const totalStock = (ev.prices || []).reduce((s, p) => s + (Number.isFinite(p.stock) ? p.stock : 0), 0);
        return res.status(400).json({ error: 'Not enough stock', available: totalStock });
    }

    // Commit: decrement stocks on the real event object in events array
    let remaining = qty;
    for (let i = 0; i < ev.prices.length; i++) {
        if (remaining <= 0) break;
        const p = ev.prices[i];
        const avail = Number.isFinite(p.stock) ? p.stock : 0;
        const take = Math.min(avail, remaining);
        if (take > 0) {
            p.stock = avail - take;
            remaining -= take;
        }
    }

    writeEvents(events);
    // Record purchase in purchases.json
    try {
        const purchases = readPurchases();
        const maxId = purchases.reduce((m, it) => (typeof it.id === 'number' && it.id > m ? it.id : m), 0);
        const total = breakdown.reduce((s, b) => s + (b.price * b.count), 0);
        const purchaseRecord = {
            id: maxId + 1,
            timestamp: Date.now(),
            eventId: ev.id != null ? ev.id : ev.name,
            eventName: ev.name,
            quantity: qty,
            breakdown,
            total
        };
        purchases.push(purchaseRecord);
        writePurchases(purchases);
    } catch (e) {
        console.error('Failed to record purchase', e);
    }

    res.json({ success: true, breakdown });
});

// Return purchase history
app.get('/purchases', (req, res) => {
    try {
        let purchases = readPurchases();
        // optional filters: q (search), event, from, to
        const q = req.query.q ? String(req.query.q).trim().toLowerCase() : '';
        const eventFilter = req.query.event ? String(req.query.event).trim().toLowerCase() : '';
        const from = req.query.from ? Number(req.query.from) : 0;
        const to = req.query.to ? Number(req.query.to) : 0;
        if (q) {
            purchases = purchases.filter(p => (p.eventName && String(p.eventName).toLowerCase().includes(q)) || (String(p.id || '').toLowerCase().includes(q)) );
        }
        if (eventFilter) {
            purchases = purchases.filter(p => p.eventName && p.eventName.toLowerCase() === eventFilter);
        }
        if (from) purchases = purchases.filter(p => (p.timestamp || 0) >= from);
        if (to) purchases = purchases.filter(p => (p.timestamp || 0) <= to);
        purchases.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        res.json(purchases);
    } catch (e) {
        res.status(500).json({ error: 'Failed to read purchases' });
    }
});

// Export purchases as CSV with same filters
function exportPurchasesHandler(req, res) {
    console.log('[EXPORT] request', req.method, req.url);
    try {
        // reuse the /purchases logic by building a fake query and calling helper
        let purchases = readPurchases();
        const q = req.query.q ? String(req.query.q).trim().toLowerCase() : '';
        const eventFilter = req.query.event ? String(req.query.event).trim().toLowerCase() : '';
        const from = req.query.from ? Number(req.query.from) : 0;
        const to = req.query.to ? Number(req.query.to) : 0;
        if (q) purchases = purchases.filter(p => (p.eventName && String(p.eventName).toLowerCase().includes(q)) || (String(p.id || '').toLowerCase().includes(q)) );
        if (eventFilter) purchases = purchases.filter(p => p.eventName && p.eventName.toLowerCase() === eventFilter);
        if (from) purchases = purchases.filter(p => (p.timestamp || 0) >= from);
        if (to) purchases = purchases.filter(p => (p.timestamp || 0) <= to);
        // Build CSV with proper escaping and UTF-8 BOM for Excel compatibility
        function esc(val) {
            if (val === null || val === undefined) return '""';
            const s = String(val).replace(/"/g, '""');
            return '"' + s + '"';
        }
        const headers = ['id','timestamp','date','eventId','eventName','quantity','total','breakdown','cancelled'];
        const rows = purchases.map(p => {
            const date = new Date(p.timestamp || 0).toISOString();
            const breakdown = (p.breakdown || []).map(b => `${b.count}x${b.price}`).join(';');
            return [esc(p.id), esc(p.timestamp), esc(date), esc(p.eventId), esc(p.eventName), esc(p.quantity), esc(p.total || 0), esc(breakdown), esc(p.cancelled ? 'yes' : 'no')].join(',');
        });
        let csv = headers.map(h => '"' + h + '"').join(',') + '\n' + rows.join('\n');
        // prepend UTF-8 BOM so Excel recognizes UTF-8 correctly
        csv = '\uFEFF' + csv;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="purchases.csv"');
        res.send(csv);
    } catch (e) {
        console.error('[EXPORT] error', e);
        res.status(500).json({ error: 'Failed to export purchases' });
    }
}

app.get('/purchases/export', exportPurchasesHandler);
app.get('/purchases/export.csv', exportPurchasesHandler);
app.get('/export-purchases', exportPurchasesHandler);

// Cancel a purchase and restore stock
app.post('/purchases/cancel', (req, res) => {
    const { id } = req.body;
    const pid = Number(id);
    if (!pid) return res.status(400).json({ error: 'purchase id required' });
    try {
        const purchases = readPurchases();
        const idx = purchases.findIndex(p => Number(p.id) === pid);
        if (idx === -1) return res.status(404).json({ error: 'Purchase not found' });
        const purchase = purchases[idx];
        if (purchase.cancelled) return res.status(400).json({ error: 'Purchase already cancelled' });

        // Restore stock according to breakdown
        const events = readEvents();
        const ev = events.find(e => String(e.id) === String(purchase.eventId)) || events.find(e => e.name && String(e.name).trim().toLowerCase() === String(purchase.eventName || purchase.eventId).trim().toLowerCase());
        if (ev && Array.isArray(purchase.breakdown)) {
            for (const b of purchase.breakdown) {
                // find matching price tier
                const priceVal = Number(b.price);
                let priceObj = ev.prices.find(p => Number(p.price) === priceVal);
                if (priceObj) {
                    priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + Number(b.count || 0);
                } else {
                    ev.prices.push({ price: priceVal, stock: Number(b.count || 0) });
                }
            }
            // ensure prices sorted
            ev.prices.sort((a, b) => a.price - b.price);
            writeEvents(events);
        }

        // mark cancelled
        purchase.cancelled = true;
        purchase.cancelledAt = Date.now();
        writePurchases(purchases);
        res.json({ success: true });
    } catch (e) {
        console.error('Failed to cancel purchase', e);
        res.status(500).json({ error: 'Failed to cancel purchase' });
    }
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
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.role && user.role.toLowerCase() === 'admin') {
        return res.status(403).json({ error: 'Admin users cannot be deleted.' });
    }
    users = users.filter(u => u.username.toLowerCase() !== username.toLowerCase());
    writeUsers(users);
    res.json({ success: true });
});

// Forgot password - generate token and (in real app) email it to user
app.post('/forgot', (req, res) => {
    const emailRaw = (req.body && req.body.email) ? String(req.body.email) : '';
    const email = emailRaw.trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const users = readUsers();
    const emailLower = email.toLowerCase();
    // match by normalized email, or as fallback by username
    const user = users.find(u => {
        if (!u) return false;
        if (u.email && String(u.email).trim().toLowerCase() === emailLower) return true;
        if (u.username && String(u.username).trim().toLowerCase() === emailLower) return true;
        return false;
    });
    console.log('[FORGOT] lookup for:', email, 'found:', !!user);
    if (!user) return res.status(404).json({ error: 'Email not found' });
    const token = crypto.randomBytes(20).toString('hex');
    const expires = Date.now() + 1000 * 60 * 60; // 1 hour
    user.resetToken = token;
    user.resetExpires = expires;
    writeUsers(users);
    // In production you'd email a link like: https://your-site/reset?token=...&email=...
    // For now return the token (so frontend can display it or simulate email)
    res.json({ success: true, message: 'Reset token generated', token });
});

// Reset password with token
app.post('/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ error: 'Email, token and newPassword required' });
    const users = readUsers();
    const user = users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase());
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.resetToken || !user.resetExpires || user.resetToken !== token || Date.now() > user.resetExpires) {
        return res.status(400).json({ error: 'Invalid or expired token' });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    delete user.resetToken;
    delete user.resetExpires;
    writeUsers(users);
    res.json({ success: true, message: 'Password updated' });
});

// Change password (user knows current password)
app.post('/users/change-password', async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;
    if (!username || !currentPassword || !newPassword) return res.status(400).json({ error: 'username, currentPassword and newPassword required' });
    try {
        const users = readUsers();
        const user = users.find(u => u.username && u.username.toLowerCase() === String(username).toLowerCase());
        if (!user) return res.status(404).json({ error: 'User not found' });
        const match = await bcrypt.compare(String(currentPassword), user.password);
        if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
        const hashed = await bcrypt.hash(String(newPassword), 10);
        user.password = hashed;
        writeUsers(users);
        res.json({ success: true, message: 'Password changed' });
    } catch (e) {
        console.error('Change password error', e);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// 404 handler
app.use((req, res) => {
    console.log('[404] Not found:', req.method, req.url);
    res.status(404).json({ error: 'Not found' });
});

// Error handling middleware - MUST come after all routes
app.use((err, req, res, next) => {
    console.error('[MIDDLEWARE ERROR]', err.message);
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error', detail: err.message });
});

// Global error handlers
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[FATAL] Unhandled Rejection at:', promise, 'reason:', reason);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
