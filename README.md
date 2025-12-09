Clicket — Local Ticketing Demo

Overview
- Small Node/Express + static frontend demo for ticketing and simple CMS/reporting.
- Data is stored in local JSON files: `users.json`, `events.json`, `purchases.json` (for development only).

Implemented Features
- Responsive UI: `index.html`, `ticket.html`, `payment.html` include responsive layouts and mobile-friendly tweaks.
- Signup & Login: `/register` and `/login` endpoints with client-side validation; registration redirects to login.
- CMS / Events Management (CRUD):
  - Add events: `/events/add` (used by Events UI).
  - Update events: `/events/update` (rename event or add price tier / stock).
  - Delete events: `/events/delete`.
  - Admin UI: "Events" menu includes Add/Edit/Delete and validation.
- Purchases / Transactions:
  - `/tickets/purchase` atomically allocates tickets across price tiers and records purchases in `purchases.json`.
  - `/purchases` returns purchase history and supports filters via query parameters: `q`, `event`, `from`, `to`.
  - `/purchases/export` exports filtered purchases as CSV for reporting.
  - Client-side Purchase History UI includes filters and CSV export button.
- Admin user management: `/users`, `/users/make-admin`, `/users/delete`.
- Password flows: `/forgot`, `/reset-password`, `/users/change-password` (Change Password UI in Settings redirects to login on success).

Security / Notes
- This is a development demo. Passwords are hashed with `bcrypt`, but there are no sessions or tokens — endpoints accept username/password in requests.
- File-based storage (`*.json`) is not safe for production concurrency. Use a real database for real apps.


1. Start the server:

```powershell
node server.js
```

2. Open `http://localhost:3000` in your browser.

Quick testing checklist
- Register a user via the Create account form.
- Login, go to "Events" and add events (name + price + amount).
- From "Tickets" buy tickets and then view "Purchase History" to see records.
- Use "Purchase History" filters and click "Export CSV" to download a report.
- In "Events" you can Edit (rename/add price tier) and Delete events.

Files of interest
- `server.js` — backend endpoints and JSON file helpers.
- `index.html` — main frontend app; contains admin UI, events, history, settings.
- `ticket.html`, `payment.html` — standalone pages used in flows.
- `events.json`, `users.json`, `purchases.json` — file-based data stores.