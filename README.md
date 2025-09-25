
# Solana Poker - Full Stack (updated server implementation)

This repository includes a full-stack scaffold for a Solana-gated Texas Hold'em poker app.

## What's included
- Server (Express + Socket.IO) with Redis, Postgres (Prisma), JWT admin, full poker engine (timers, blinds, side-pots)
- Client scaffold with admin routes and poker UI scaffold
- Docker Compose to run server, client, redis, postgres, pgAdmin
- Prisma schema and migrations scaffold

## Quick start (Docker)
1. Install Docker & Docker Compose
2. From project root run:
   ```bash
   docker-compose up --build
   ```
3. After containers start, open a shell in the server container or run locally:
   ```bash
   cd server
   npm install
   npx prisma generate
   npx prisma migrate dev --name init
   ```
4. Open:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:4000
   - pgAdmin: http://localhost:5050 (admin@admin.com / admin)

## Small checklist I ran through and fixed:
- [x] Added Prisma schema and seed for admin user
- [x] Full poker engine server.ts implemented (dealing, rounds, betting, side pots, showdown)
- [x] Redis persistence for table snapshot and short-lived tickets
- [x] Admin endpoints with JWT and bcrypt-protected password
- [x] Endpoint for fetching an empty seat for convenience
- [x] Postgres write of completed hands (basic snapshot)
- [x] Reconnect logic with 60s reclaim window for disconnected players
- [x] Client admin scaffold routes updated to call new endpoints
- [x] Docker Compose includes Postgres and pgAdmin
- [x] README updated with run and migration steps

## Notes & next steps
- **Environment variables**: create `.env` in `/server` or set in docker-compose for production.
- **Security**: Replace default admin password and JWT_SECRET before deploying.
- **Scaling**: For horizontal scaling make sure to use Redis and a centralized DB; Socket.IO may need an adapter (redis) for multiple instances.
- **Production**: Containerize client build with nginx, enable HTTPS, rate-limiting, and monitoring.

If you want, I can now:
- Build a production-ready client Docker image (nginx + build).
- Add Socket.IO Redis adapter for horizontal scaling.
- Add more admin features (export player CSV, bulk ban, leaderboards).

