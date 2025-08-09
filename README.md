# Pocket Replacement – API-01 User Account System

TypeScript/Express + Prisma (PostgreSQL) with JWT access tokens and rotating refresh tokens.
Includes: register, login, refresh, logout, and `GET /auth/me` (protected).

## Quick start

1) Create a `.env` from `.env.example` and set secrets.
2) Start Postgres via Docker Compose and run migrations:
   ```bash
   docker compose up -d db
   npx prisma migrate dev --name init
   ```
3) Start the API (dev):
   ```bash
   npm run dev
   ```

## Endpoints
- `POST /auth/register`  body: `{ email, password, name? }`
- `POST /auth/login`     body: `{ email, password }`
- `POST /auth/refresh`   (uses cookie) returns new access token; rotates refresh token
- `POST /auth/logout`    (uses cookie) revokes current refresh token
- `GET  /auth/me`        (Authorization: Bearer <accessToken>)

Access token is short-lived (default 15m) and returned in JSON.
Refresh token is set as HttpOnly Secure cookie by default.

## Scripts
- `npm run dev` – ts-node-dev hot reloading
- `npm run build` – build to `dist`
- `npm start` – run compiled server
- `npm run lint` – eslint
- `npm run prisma:*` – common Prisma helpers

