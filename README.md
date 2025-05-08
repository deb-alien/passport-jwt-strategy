# Express Authentication with Passport.js, JWT, Cookies & Mongoose

This is a secure Node.js authentication system built with:

-   **Express.js** for the server
-   **Passport.js** with JWT strategies (access & refresh)
-   **HTTP-only cookies** for secure token handling
-   **Mongoose** for MongoDB
-   **Hashed refresh tokens** for extra security

---

## 📦 Features

-   ✅ Signup & Login with email/password
-   ✅ Access tokens for route protection
-   ✅ Refresh tokens to renew sessions
-   ✅ Secure, HTTP-only cookies (no localStorage)
-   ✅ Refresh token hashed and stored in MongoDB
-   ✅ Logout clears tokens and revokes refresh access
-   ✅ Protected `/me` route to get logged-in user

---

## 🛠 Tech Stack

-   Node.js / Express.js
-   MongoDB / Mongoose
-   Passport.js
-   bcrypt
-   jsonwebtoken
-   dotenv
-   cookie-parser

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/your-username/express-auth-jwt-cookie.git
cd express-auth-jwt-cookie
```

### 2. Install dependencies

```bash
npm i
```

### 3. Create **.env** file

```env
PORT=5000
MONGO_URI=mongodb://localhost:27017/auth_demo
ACCESS_TOKEN_SECRET=youraccesstokensecret
REFRESH_TOKEN_SECRET=yourrefreshtokensecret
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d
NODE_ENV=development
```

**_Use secure secrets in production!_**

### 4. Run the server

```bash
npm start
```

Server will start on http://127.0.0.1:1337

### 📂API Endpoints

| Method | Route               | Description                   |
| ------ | ------------------- | ----------------------------- |
| POST   | `/api/auth/signup`  | Create a new user             |
| POST   | `/api/auth/login`   | Login user, set cookies       |
| GET    | `/api/auth/refresh` | Refresh access token (cookie) |
| POST   | `/api/auth/logout`  | Clear tokens, logout user     |
| GET    | `/api/auth/me`      | Get authenticated user        |

### 🔐 Security Notes

-   Refresh tokens are hashed with bcrypt before saving to DB.
-   Cookies are set with:

    -   httpOnly: true
    -   sameSite: 'lax'
    -   secure: true (in production)
    -   signed: true

-   JWTs are short-lived for better security.
