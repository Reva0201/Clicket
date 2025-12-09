const express = require('express');
const app = express();
const PORT = 3000;

console.log('[START] Creating app');

app.use(express.json());
console.log('[INIT] Added JSON parser');

app.use((req, res, next) => {
    console.log('[REQ] METHOD=' + req.method + ' URL=' + req.url);
    next();
});
console.log('[INIT] Added logger middleware');

app.get('/', (req, res) => {
    console.log('[GET /] handler called');
    res.json({ status: 'ok' });
});
console.log('[INIT] Added GET / route');

app.post('/events/add', (req, res) => {
    console.log('[POST /events/add] handler called');
    console.log('[POST /events/add] body=', req.body);
    res.json({ success: true, message: 'Event added' });
});
console.log('[INIT] Added POST /events/add route');

app.listen(PORT, () => {
    console.log('[LISTEN] Server running on http://localhost:' + PORT);
});
console.log('[INIT] Called app.listen()');
