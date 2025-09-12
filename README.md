Server README

This project exposes a small Express server that provides several endpoints used by the frontend.

Environment variables (place in a .env file locally; never commit secrets):

- SMTP_SERVER - SMTP host (e.g. email-smtp.ap-south-1.amazonaws.com)
- SMTP_PORT - SMTP port (e.g. 587)
- SMTP_USER - SMTP username
- SMTP_PASS - SMTP password
- EMAIL_FROM - From address for outgoing emails
- EMAIL_TO - Optional. Destination email address for form submissions. If not set, EMAIL_FROM will be used.
- FIREBASE_DATABASE_URL - Firebase RTDB URL (used by some endpoints)

How to run locally:

1. Create a `.env` file in the repo root using `.env.example` as reference.
2. Install dependencies: `npm install` in the project root and also `server` dependencies if managed separately.
3. Start the server: `node server/index.js` or use your dev tooling.

Security:
- Do not commit real credentials to git. Use secrets manager or CI-level secrets for production.

Endpoint added for sending emails:
- POST /send-email - Accepts JSON { name, mobile, city, interest } and will send an email using the SMTP settings above.
