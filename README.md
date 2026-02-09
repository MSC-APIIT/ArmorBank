# ArmorBank

# Auth Project – Risk-Based Authentication System

A secure authentication system implementing **risk-based MFA** with support for **password authentication**, **Rate limit**, **email OTP**, **WebAuthn passkeys**, and **TOTP authenticator apps**.

---

## Tech Stack

- **Framework:** Next.js (App Router)
- **Runtime:** Node.js
- **Database:** MongoDB
- **Authentication:** Session-based authentication using HTTP-only cookies
- **MFA Methods:**
  - Email OTP
  - WebAuthn (Passkeys / Biometrics)
  - TOTP Authenticator (Google Authenticator, Microsoft Authenticator, Authy)
- **Validation & Config:** Zod

---

## System Requirements

The following must be installed on the system:

- Node.js (LTS recommended)
- npm / pnpm / yarn
- MongoDB (local or MongoDB Atlas)
- Git (optional)

---

## How to Run (Any System)

### 1) Clone the repository

```bash
git clone <YOUR_REPO_URL>
cd <YOUR_PROJECT_FOLDER>
```

### 2) Install dependencies

```bash
npm install
```

### 3) Configure environment variables

Create a file named **`.env.local`** in the project root.

```env
# MongoDB
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority
MONGODB_DB=bank_auth

# Session & Token Secrets
SESSION_SECRET=replace-with-long-random-secret
JWT_ACCESS_SECRET=replace-with-strong-secret
JWT_REFRESH_SECRET=replace-with-strong-secret

ACCESS_TOKEN_TTL_SECONDS=900
REFRESH_TOKEN_TTL_SECONDS=604800

# Email OTP (Gmail SMTP)
GMAIL_USER=yourgmail@gmail.com
GMAIL_APP_PASSWORD=your_gmail_app_password

# Cookie Settings
COOKIE_SECURE=true
```

### 4) Run in development mode

```bash
npm run dev
```

Application will be available at:

```
http://localhost:3000
```

### 5) Run in production

```bash
npm run build
npm start
```

---

## Features

- Secure password-based authentication
- Session creation using encrypted server-side payloads
- User enumeration protection
- Login attempt tracking and lockout protection
- Risk-based MFA enforcement
- Passkey registration and authentication using WebAuthn
- TOTP-based authenticator integration
- Email OTP fallback mechanism
- Dashboard-based MFA management

---

## Risk Engine

This project uses a **risk-based authentication engine** to determine whether MFA is required for a login attempt.  
Risk is calculated per login and categorized as **LOW**, **MEDIUM**, or **HIGH**.

### Risk Considering Values

The risk score is derived using three main categories:

---

### 1) Device-Based Risk

Used to detect new or suspicious devices.

- Device ID consistency
- Known vs unknown device
- Device change since last successful login
- Browser / OS fingerprint (if enabled)
- Passkey availability on the device

**Examples**
- Known device → low risk
- New or changed device → increased risk

---

### 2) IP / Network-Based Risk

Used to detect unusual access patterns.

- IP address comparison
- IP change frequency
- Geo-location mismatch (optional)
- Network reputation (optional)

**Examples**
- Same IP / region → low risk
- New IP / different region → higher risk

---

### 3) Credential & Behavior-Based Risk

Used to detect brute-force or compromised credentials.

- Failed login attempt count
- Recent lockout history
- Login velocity
- Time-based anomalies

**Examples**
- Clean history → low risk
- Multiple failures or lockouts → high risk

---

## Risk Decision Flow

- **LOW risk:** Login allowed without MFA
- **MEDIUM risk:** MFA required (Passkey / TOTP preferred)
- **HIGH risk:** Strong MFA enforced or login blocked

---

## Security Notes

- OTPs and secrets are never stored in plain text
- TOTP secrets must be encrypted at rest
- Always use HTTPS in production (required for WebAuthn)
- Cookies are configured as:
  - HttpOnly
  - Secure (production)
  - SameSite=Lax or Strict
- Dummy bcrypt comparison is used to prevent user enumeration

---

## Notes

- WebAuthn works on `http://localhost` for development
- Production deployments must use HTTPS
- Environment variables must be present before build/start

---

## License

Internal / Private Project
