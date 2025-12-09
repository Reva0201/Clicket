#!/usr/bin/env node
const http = require('http');

const payload = {
  name: 'Test Event from CLI',
  price: 50,
  amount: 10,
  userId: 1
};

const data = JSON.stringify(payload);

console.log('Sending POST /events/add with payload:', payload);
console.log('JSON data:', data);

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/events/add',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
};

const req = http.request(options, (res) => {
  console.log(`\nResponse Status: ${res.statusCode}`);
  console.log(`Response Headers: ${JSON.stringify(res.headers)}`);
  
  let body = '';
  res.on('data', (chunk) => {
    console.log('Received chunk:', chunk.toString());
    body += chunk;
  });
  
  res.on('end', () => {
    console.log('Response Body:', body);
    try {
      const json = JSON.parse(body);
      console.log('Parsed JSON:', json);
    } catch (e) {
      console.log('Failed to parse JSON:', e.message);
    }
    process.exit(0);
  });
});

req.on('error', (err) => {
  console.error('Request Error:', err);
  process.exit(1);
});

req.on('timeout', () => {
  console.error('Request Timeout');
  req.destroy();
  process.exit(1);
});

req.setTimeout(5000);

console.log('Writing data...');
req.write(data);
console.log('Ending request...');
req.end();

console.log('Waiting for response...');
