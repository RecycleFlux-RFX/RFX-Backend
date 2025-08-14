
# RFX-Backend

This is a backend authentication system built with Node.js, Express.js, and MongoDB.

## Features

- User registration with email verification
- User login with JWT
- Two-factor authentication (2FA) with TOTP
- Rate limiting
- Secure password hashing with bcrypt
- Feature toggles for email verification
- Forgot password functionality
- SSO with Metamask

## Prerequisites

- Node.js
- MongoDB

## Getting Started

1. **Clone the repository:**

   ```bash
   git clone https://github.com/RecycleFlux-RFX/RFX-Backend.git
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Create a `.env` file** in the root of the project and add the following environment variables:

   ```
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/auth-system
   JWT_SECRET=your-jwt-secret
   JWT_EXPIRES_IN=1h

   # Feature Toggles
   ENABLE_EMAIL_VERIFICATION=true

   # Email Configuration
   EMAIL_HOST=smtp.example.com
   EMAIL_PORT=587
   EMAIL_USER=your-email@example.com
   EMAIL_PASS=your-email-password
   EMAIL_FROM=your-email@example.com
   ```

4. **Start the server:**

   ```bash
   node server.js
   ```

## API Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login a user
- `GET /api/auth/metamask/nonce/:walletAddress` - Get a nonce for Metamask login
- `POST /api/auth/metamask/verify` - Verify a Metamask signature
- `GET /api/auth/verify-email/:token` - Verify a user's email
- `POST /api/auth/2fa/generate` - Generate a new 2FA secret
- `POST /api/auth/2fa/verify` - Verify a 2FA token
- `POST /api/auth/forgot-password` - Send a password reset email
- `POST /api/auth/reset-password/:token` - Reset a user's password
