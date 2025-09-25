
/**
 * server.ts
 * Full server implementation for Solana-gated Poker demo.
 *
 * Features:
 * - Express API endpoints for wallet challenge, auth-check (token holding), admin JWT login, admin config
 * - Prisma integration (Postgres) for Player, TableConfig, AdminUser, Hand, Action
 * - Redis (ioredis) for fast state persistence, tickets, and table snapshot
 * - Socket.IO poker engine: seating, dealing, betting rounds, blinds, timers, side-pots, showdown
 * - Reconnect support and persistence
 *
 * ENV required (example .env):
 * DATABASE_URL=postgres://poker:pokerpass@postgres:5432/pokerdb
 * REDIS_URL=redis://redis:6379
 * JWT_SECRET=supersecretjwt
 * SOLANA_RPC=https://api.devnet.solana.com
 */

import express from "express";
import bodyParser from "body-parser";
import http from "http";
import { Server as IOServer, Socket } from "socket.io";
import { Connection, PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import crypto from "crypto";
import Redis from "ioredis";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { PrismaClient } from "@prisma/client";

dotenv.config();
const prisma = new PrismaClient();

// Config
const PORT = Number(process.env.PORT || 4000);
const RPC = process.env.SOLANA_RPC || "https://api.devnet.solana.com";
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const DATABASE_URL = process.env.DATABASE_URL || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";
const ACTION_TIMEOUT_MS = Number(process.env.ACTION_TIMEOUT_MS || 20000);
const SMALL_BLIND = Number(process.env.SMALL_BLIND || 1);
const BIG_BLIND = Number(process.env.BIG_BLIND || 2);
const SEAT_COUNT = Number(process.env.SEAT_COUNT || 6);
const MIN_PLAYERS_TO_START = Number(process.env.MIN_PLAYERS_TO_START || 2);

// Solana connection
const connection = new Connection(RPC, "confirmed");
const redis = new Redis(REDIS_URL);

// Express setup
const app = express();
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  next();
});

// ----------------- Helpers -----------------
function randomNonce() {
  return crypto.randomBytes(16).toString("hex");
}
function now() { return Date.now(); }

// ----------------- Challenge endpoints -----------------
app.get("/api/challenge", async (_req, res) => {
  const nonce = randomNonce();
  await redis.setex(`challenge:${nonce}`, 300, "1"); // 5 minutes
  res.json({ challenge: nonce });
});

// ----------------- Auth-check: verify signature and token holdings -----------------
app.post("/api/auth-check", async (req, res) => {
  try {
    const { pubkey, signature, challenge } = req.body;
    if (!pubkey || !signature || !challenge) return res.status(400).json({ error: "missing fields" });

    const exists = await redis.get(`challenge:${challenge}`);
    if (!exists) return res.status(400).json({ error: "invalid or expired challenge" });

    const msg = new TextEncoder().encode(challenge);
    const sig = Buffer.from(signature, "base64");
    const pubkeyBytes = new PublicKey(pubkey).toBytes();
    const valid = nacl.sign.detached.verify(msg, sig, pubkeyBytes);
    if (!valid) return res.status(401).json({ allowed: false, reason: "signature invalid" });

    // Read token config from Postgres (via Prisma)
    let cfg = await prisma.tableConfig.findFirst();
    if (!cfg) {
      // default: allow anyone (for safety), but log a warning
      console.warn("No TableConfig found in DB; defaulting to allow (set config via admin).");
      cfg = await prisma.tableConfig.create({ data: { tokenMint: "", minBalance: 0 } });
    }

    // If tokenMint is empty or minBalance==0, allow (development)
    if (!cfg.tokenMint || cfg.minBalance <= 0) {
      // issue short-lived ticket (JWT)
      const token = jwt.sign({ pubkey }, JWT_SECRET, { expiresIn: "60s" });
      await redis.setex(`ticket:${token}`, 60, pubkey);
      return res.json({ allowed: true, ticket: token, totalUi: 0 });
    }

    // Query Solana for token accounts
    const owner = new PublicKey(pubkey);
    const parsed = await connection.getParsedTokenAccountsByOwner(owner, {
      programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    });

    let totalUi = 0;
    for (const acc of parsed.value) {
      try {
        const pa = acc.account.data.parsed;
        if (pa.info?.mint === cfg.tokenMint) {
          const amount = Number(pa.info.tokenAmount.uiAmount ?? 0);
          totalUi += amount;
        }
      } catch (e) { /* ignore parse errors */ }
    }

    if (totalUi < cfg.minBalance) return res.json({ allowed: false, totalUi });

    // issue short-lived ticket (JWT)
    const token = jwt.sign({ pubkey }, JWT_SECRET, { expiresIn: "60s" });
    await redis.setex(`ticket:${token}`, 60, pubkey);
    res.json({ allowed: true, ticket: token, totalUi });
  } catch (err) {
    console.error("auth-check error", err);
    res.status(500).json({ error: "server error" });
  }
});

// ----------------- Admin endpoints -----------------
// Seed admin user if none
async function ensureAdmin() {
  const a = await prisma.adminUser.findFirst();
  if (!a) {
    const hash = await bcrypt.hash("changeme", 10);
    await prisma.adminUser.create({ data: { username: "admin", password: hash } });
    console.log("Seeded admin user: admin / changeme");
  }
}
ensureAdmin().catch(e => console.error(e));

app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await prisma.adminUser.findUnique({ where: { username } });
    if (!admin) return res.status(401).json({ error: "bad creds" });
    const ok = await bcrypt.compare(password, admin.password);
    if (!ok) return res.status(401).json({ error: "bad creds" });
    const token = jwt.sign({ uid: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: "2h" });
    res.json({ token });
  } catch (e) {
    console.error("admin login error", e);
    res.status(500).json({ error: "server error" });
  }
});

function requireAdmin(req: any, res: any, next: any) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "missing auth" });
  const m = auth.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ error: "bad auth format" });
  try {
    const payload: any = jwt.verify(m[1], JWT_SECRET);
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

app.get("/api/admin/config", requireAdmin, async (_req, res) => {
  const cfg = await prisma.tableConfig.findFirst();
  res.json(cfg);
});

app.post("/api/admin/config", requireAdmin, async (req, res) => {
  const { tokenMint, minBalance } = req.body;
  let cfg = await prisma.tableConfig.findFirst();
  if (cfg) {
    cfg = await prisma.tableConfig.update({ where: { id: cfg.id }, data: { tokenMint, minBalance: Number(minBalance) } });
  } else {
    cfg = await prisma.tableConfig.create({ data: { tokenMint, minBalance: Number(minBalance) } });
  }
  res.json(cfg);
});

// Admin user management
app.get("/api/admin/users", requireAdmin, async (_req, res) => {
  const players = await prisma.player.findMany();
  res.json(players);
});
app.post("/api/admin/users/:id/ban", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const p = await prisma.player.update({ where: { id }, data: { banned: true } });
  res.json(p);
});
app.post("/api/admin/users/:id/unban", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const p = await prisma.player.update({ where: { id }, data: { banned: false } });
  res.json(p);
});
app.post("/api/admin/users/:id/reset-chips", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const p = await prisma.player.update({ where: { id }, data: { chips: 1000 } });
  res.json(p);
});

// Utility endpoint used by client to get a seat suggestion (simple)
app.get("/api/get_empty_seat", async (_req, res) => {
  // look up current table snapshot in redis
  const raw = await redis.get("table:table-1");
  if (!raw) return res.json({ seat: 0 });
  try {
    const obj = JSON.parse(raw);
    const seats = obj.seats || [];
    for (let i = 0; i < seats.length; i++) {
      if (!seats[i]) return res.json({ seat: i });
    }
    return res.json({ seat: 0 });
  } catch (e) {
    return res.json({ seat: 0 });
  }
});

// ----------------- Poker engine (Socket.IO) -----------------
const httpServer = http.createServer(app);
const io = new IOServer(httpServer, { cors: { origin: "*" } });

// Card utilities and evaluator
type Suit = "s" | "h" | "d" | "c";
type Rank = number;
const RANKS: Rank[] = [2,3,4,5,6,7,8,9,10,11,12,13,14];
const SUITS: Suit[] = ["s","h","d","c"];
function cardStr(r: Rank, s: Suit) { return `${r}${s}`; }
function fullDeck(): string[] { const d: string[] = []; for (const r of RANKS) for (const s of SUITS) d.push(cardStr(r,s)); return d; }
function shuffle<T>(arr: T[]) { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
function parseCard(card: string){ const suit = card.slice(-1) as Suit; const r = Number(card.slice(0,-1)); return { r, s: suit }; }
function combinations<T>(arr: T[], k: number){ const res: T[][] = []; const n = arr.length; const pick: number[] = []; function rec(start:number){ if (pick.length === k){ res.push(pick.map(i=>arr[i])); return; } for (let i = start; i < n; i++){ pick.push(i); rec(i+1); pick.pop(); }} rec(0); return res; }
function compareEval(a:number[], b:number[]){ for (let i = 0; i < Math.max(a.length, b.length); i++){ const av = a[i] ?? 0; const bv = b[i] ?? 0; if (av > bv) return 1; if (av < bv) return -1; } return 0; }
function evaluate5(cards:string[]): number[] {
  const ps = cards.map(parseCard).sort((a,b)=>b.r-a.r);
  const ranks = ps.map(p=>p.r);
  const suits = ps.map(p=>p.s);
  const isFlush = suits.every(s=>s===suits[0]);
  const uniqueRanks = Array.from(new Set(ranks));
  const sortedUnique = uniqueRanks.slice().sort((a,b)=>b-a);
  let isStraight=false; let topStraight=0;
  if (sortedUnique.length===5) {
    let ok=true;
    for (let i=0;i<4;i++){ if (sortedUnique[i]-sortedUnique[i+1]!==1){ ok=false; break; } }
    if (ok) { isStraight = true; topStraight = sortedUnique[0]; }
    else {
      const wheel = [14,5,4,3,2];
      if (JSON.stringify(sortedUnique.sort((a,b)=>b-a)) === JSON.stringify(wheel)) { isStraight = true; topStraight = 5; }
    }
  }
  const counts: Record<number,number> = {};
  for (const r of ranks) counts[r] = (counts[r] || 0) + 1;
  const byCount = Object.entries(counts).map(([r,c])=>({ r: Number(r), c })).sort((a,b)=>{ if (b.c !== a.c) return b.c - a.c; return b.r - a.r; });
  if (isStraight && isFlush) return [8, topStraight];
  if (byCount[0].c === 4) return [7, byCount[0].r, byCount.slice(1).map(x=>x.r)[0]];
  if (byCount[0].c === 3 && byCount[1] && byCount[1].c === 2) return [6, byCount[0].r, byCount[1].r];
  if (isFlush) return [5, ...ranks];
  if (isStraight) return [4, topStraight];
  if (byCount[0].c === 3) return [3, byCount[0].r, ...byCount.slice(1).map(x=>x.r).slice(0,2)];
  if (byCount[0].c === 2 && byCount[1] && byCount[1].c === 2) return [2, byCount[0].r, byCount[1].r, byCount.slice(2).map(x=>x.r)[0]];
  if (byCount[0].c === 2) return [1, byCount[0].r, ...byCount.slice(1).map(x=>x.r).slice(0,3)];
  return [0, ...ranks];
}
function bestHandFromSeven(cards7:string[]){ const combosList = combinations(cards7,5); let bestEval:number[]|null=null; let bestHand:string[] = []; for (const h of combosList){ const e = evaluate5(h); if (!bestEval || compareEval(e, bestEval) > 0){ bestEval = e; bestHand = h.slice(); } } return { bestEval: bestEval!, bestHand }; }

// Table class with persistence and timers
type Seat = {
  socketId?: string | null;
  pubkey?: string | null;
  chips: number;
  currentBet: number;
  totalContributed: number;
  folded: boolean;
  holeCards: string[];
  active: boolean;
  allIn?: boolean;
  reconnectTimeout?: number | null;
};
class Table {
  id: string;
  seats: (Seat | null)[];
  deck: string[];
  community: string[];
  pot: number;
  currentBetToCall: number;
  dealerIndex: number;
  currentTurnIndex: number;
  stage: "waiting"|"preflop"|"flop"|"turn"|"river"|"showdown";
  lastRaiseAmount: number;
  actionTimer?: NodeJS.Timeout;
  constructor(id: string, seatCount = SEAT_COUNT){
    this.id = id;
    this.seats = Array.from({length: seatCount}).map(()=>null);
    this.deck = [];
    this.community = [];
    this.pot = 0;
    this.currentBetToCall = 0;
    this.dealerIndex = -1;
    this.currentTurnIndex = 0;
    this.stage = "waiting";
    this.lastRaiseAmount = BIG_BLIND;
  }

  async persist(){
    try {
      await redis.set(`table:${this.id}`, JSON.stringify(this.serialize()));
    } catch (e) { console.error("redis persist error", e); }
  }
  serialize(){
    return {
      id: this.id,
      seats: this.seats,
      deck: this.deck,
      community: this.community,
      pot: this.pot,
      currentBetToCall: this.currentBetToCall,
      dealerIndex: this.dealerIndex,
      currentTurnIndex: this.currentTurnIndex,
      stage: this.stage,
      lastRaiseAmount: this.lastRaiseAmount
    };
  }
  async restore(){
    try {
      const raw = await redis.get(`table:${this.id}`);
      if (!raw) return;
      const data = JSON.parse(raw);
      this.seats = data.seats;
      this.deck = data.deck;
      this.community = data.community;
      this.pot = data.pot;
      this.currentBetToCall = data.currentBetToCall;
      this.dealerIndex = data.dealerIndex;
      this.currentTurnIndex = data.currentTurnIndex;
      this.stage = data.stage;
      this.lastRaiseAmount = data.lastRaiseAmount;
    } catch (e) { console.error("restore error", e); }
  }

  seatPlayer(index:number, pubkey:string, socketId:string){
    this.seats[index] = {
      socketId,
      pubkey,
      chips: 1000,
      currentBet: 0,
      totalContributed: 0,
      folded: false,
      holeCards: [],
      active: true,
      allIn: false,
      reconnectTimeout: null
    };
  }

  removePlayerBySocket(socketId:string){
    for (let i=0;i<this.seats.length;i++){
      const s = this.seats[i];
      if (s && s.socketId === socketId) this.seats[i] = null;
    }
  }

  readyPlayerCount(){ return this.seats.filter(s=>s && s.active).length; }

  nextOccupiedFrom(startIdx:number){
    const n = this.seats.length;
    for (let i=1;i<=n;i++){
      const cand = (startIdx + i) % n;
      const s = this.seats[cand];
      if (s && s.active && !s.folded && !s.allIn) return cand;
    }
    return -1;
  }

  nextOccupiedForBlinds(startIdx:number){
    const n = this.seats.length;
    for (let i=1;i<=n;i++){
      const cand = (startIdx + i) % n;
      const s = this.seats[cand];
      if (s && s.active) return cand;
    }
    return startIdx;
  }

  clearActionTimer(){ if (this.actionTimer){ clearTimeout(this.actionTimer); this.actionTimer = undefined; } }

  startActionTimer(io: IOServer){
    this.clearActionTimer();
    this.actionTimer = setTimeout(()=>{
      const idx = this.currentTurnIndex;
      const seat = this.seats[idx];
      if (seat && !seat.folded && !seat.allIn){
        seat.folded = true;
        io.to(this.id).emit("auto_fold", { seatIndex: idx });
        if (this.isBettingRoundComplete()) { this.advanceStage(io); return; }
        const next = this.nextOccupiedFrom(idx);
        if (next === -1){ this.advanceStage(io); return; }
        this.currentTurnIndex = next;
        this.broadcastTableState(io);
        this.startActionTimer(io);
      }
    }, ACTION_TIMEOUT_MS);
  }

  async startHandIfReady(io: IOServer){
    if (this.stage !== "waiting") return;
    if (this.readyPlayerCount() < MIN_PLAYERS_TO_START) return;

    this.deck = shuffle(fullDeck());
    this.community = [];
    this.pot = 0;
    this.currentBetToCall = 0;
    this.stage = "preflop";
    this.lastRaiseAmount = BIG_BLIND;

    for (const s of this.seats) if (s) { s.currentBet = 0; s.folded = false; s.holeCards = []; s.totalContributed = 0; s.allIn = false; }

    for (let r=0;r<2;r++){
      for (let i=0;i<this.seats.length;i++){
        const s = this.seats[i];
        if (!s) continue;
        s.holeCards.push(this.deck.pop()!);
      }
    }

    // rotate dealer
    this.dealerIndex = (this.dealerIndex + 1) % this.seats.length;
    const sb = this.nextOccupiedForBlinds(this.dealerIndex);
    const bb = this.nextOccupiedForBlinds(sb);
    const sbSeat = this.seats[sb]!;
    const bbSeat = this.seats[bb]!;

    const small = Math.min(SMALL_BLIND, sbSeat.chips);
    const big = Math.min(BIG_BLIND, bbSeat.chips);

    sbSeat.chips -= small; sbSeat.currentBet += small; sbSeat.totalContributed += small; this.pot += small;
    if (sbSeat.chips === 0) sbSeat.allIn = true;
    bbSeat.chips -= big; bbSeat.currentBet += big; bbSeat.totalContributed += big; this.pot += big;
    if (bbSeat.chips === 0) bbSeat.allIn = true;

    this.currentBetToCall = big;
    const first = this.nextOccupiedFrom(bb);
    this.currentTurnIndex = first === -1 ? bb : first;

    this.broadcastTableState(io);
    await this.persist();
    this.startActionTimer(io);
  }

  isBettingRoundComplete(){
    for (const s of this.seats){
      if (!s || s.folded) continue;
      if (s.allIn) continue;
      if (s.currentBet !== this.currentBetToCall) return false;
    }
    return true;
  }

  findNextAny(startIdx:number){
    const n = this.seats.length;
    for (let i=1;i<=n;i++){
      const cand = (startIdx + i) % n;
      const s = this.seats[cand];
      if (s && s.active && !s.folded) return cand;
    }
    return -1;
  }

  async handleAction(io: IOServer, seatIndex:number, action:{ type:"fold"|"call"|"raise"|"check", amount?:number }){
    const seat = this.seats[seatIndex];
    if (!seat || seat.folded || seat.allIn) return;
    if (this.currentTurnIndex !== seatIndex) return;

    this.clearActionTimer();

    if (action.type === "fold"){
      seat.folded = true;
    } else if (action.type === "check"){
      if (seat.currentBet !== this.currentBetToCall) { this.startActionTimer(io); return; }
    } else if (action.type === "call"){
      const toCall = this.currentBetToCall - seat.currentBet;
      const callAmount = Math.min(toCall, seat.chips);
      seat.chips -= callAmount;
      seat.currentBet += callAmount;
      seat.totalContributed += callAmount;
      this.pot += callAmount;
      if (seat.chips === 0) seat.allIn = true;
    } else if (action.type === "raise"){
      const raiseAmt = action.amount ?? 0;
      const toCall = this.currentBetToCall - seat.currentBet;
      const minRaise = Math.max(this.lastRaiseAmount, BIG_BLIND);
      if (raiseAmt < minRaise){ this.startActionTimer(io); return; }
      const totalInvest = toCall + raiseAmt;
      const invest = Math.min(totalInvest, seat.chips);
      seat.chips -= invest;
      seat.currentBet += invest;
      seat.totalContributed += invest;
      this.pot += invest;
      if (seat.currentBet > this.currentBetToCall){
        this.lastRaiseAmount = raiseAmt;
        this.currentBetToCall = seat.currentBet;
      }
      if (seat.chips === 0) seat.allIn = true;
    }

    // advance turn
    let next = this.nextOccupiedFrom(this.currentTurnIndex);
    if (next === -1) {
      if (this.isBettingRoundComplete()) { this.advanceStage(io); return; }
      next = this.findNextAny(this.currentTurnIndex);
      if (next === -1) { this.advanceStage(io); return; }
    }
    this.currentTurnIndex = next;

    if (this.isBettingRoundComplete()) { this.advanceStage(io); } else {
      this.broadcastTableState(io);
      await this.persist();
      this.startActionTimer(io);
    }
  }

  async advanceStage(io: IOServer){
    for (const s of this.seats) if (s) s.currentBet = 0;

    if (this.stage === "preflop"){
      this.community.push(this.deck.pop()!, this.deck.pop()!, this.deck.pop()!);
      this.stage = "flop";
    } else if (this.stage === "flop"){
      this.community.push(this.deck.pop()!);
      this.stage = "turn";
    } else if (this.stage === "turn"){
      this.community.push(this.deck.pop()!);
      this.stage = "river";
    } else if (this.stage === "river"){
      this.stage = "showdown";
      await this.resolveShowdown(io);
      return;
    }

    this.currentBetToCall = 0;
    this.lastRaiseAmount = BIG_BLIND;
    const first = this.nextOccupiedFrom(this.dealerIndex);
    this.currentTurnIndex = first === -1 ? this.dealerIndex : first;
    this.broadcastTableState(io);
    await this.persist();
    this.startActionTimer(io);
  }

  async resolveShowdown(io: IOServer){
    const activePlayers = this.seats.map((s, idx) => ({ s, idx })).filter(x => x.s && !x.s.folded);
    if (activePlayers.length === 0){
      this.resetHand();
      this.broadcastTableState(io);
      return;
    }

    const results: { idx:number; bestEval:number[]; bestHand:string[]; contrib:number }[] = [];
    for (const p of activePlayers){
      const seven = [...p.s!.holeCards, ...this.community];
      const { bestEval, bestHand } = bestHandFromSeven(seven);
      results.push({ idx: p.idx, bestEval, bestHand, contrib: p.s!.totalContributed });
    }

    const contribs = Array.from(new Set(results.map(r => r.contrib))).sort((a,b)=>a-b);
    const pots: { amount:number; eligibleIndices:number[] }[] = [];
    let prev = 0;
    for (const level of contribs){
      const eligible = results.filter(r => r.contrib >= level).map(r => r.idx);
      const portion = (level - prev) * eligible.length;
      pots.push({ amount: portion, eligibleIndices: eligible });
      prev = level;
    }

    const winnersByPot: { potIndex:number; winners:number[] }[] = [];
    for (let i=0;i<pots.length;i++){
      const pot = pots[i];
      const eligResults = results.filter(r => pot.eligibleIndices.includes(r.idx));
      eligResults.sort((a,b)=>compareEval(b.bestEval, a.bestEval));
      const best = eligResults[0].bestEval;
      const winners = eligResults.filter(r => compareEval(r.bestEval, best) === 0).map(r => r.idx);
      winnersByPot.push({ potIndex: i, winners });
    }

    for (let i=0;i<pots.length;i++){
      const pot = pots[i];
      const winners = winnersByPot[i].winners;
      const share = Math.floor(pot.amount / winners.length);
      for (const w of winners){
        const seat = this.seats[w]!;
        seat.chips += share;
      }
      const leftover = pot.amount - share * winners.length;
      if (leftover > 0){
        const firstWinner = this.seats[winners[0]]!;
        firstWinner.chips += leftover;
      }
    }

    const winnersInfo = winnersByPot.map(wp => ({ potIndex: wp.potIndex, winners: wp.winners }));

    // Persist hand + actions into Postgres (simple snapshot)
    try {
      const hand = await prisma.hand.create({
        data: {
          tableId: this.id,
          dealer: this.dealerIndex,
          board: JSON.stringify(this.community),
          pot: this.pot,
          winner: JSON.stringify(winnersInfo),
        }
      });
      // actions could be added similarly if tracked per-action (omitted detailed action log for brevity)
    } catch (e) { console.error("prisma hand save error", e); }

    this.stage = "waiting";
    this.deck = [];
    this.community = [];
    this.pot = 0;
    this.currentBetToCall = 0;
    this.broadcastTableState(io, { showdown: { winners: winnersInfo } });
    await this.persist();

    setTimeout(()=> this.startHandIfReady(io), 2000);
  }

  broadcastTableState(io: IOServer, extras:any = {}){
    const publicSeats = this.seats.map(s => s ? {
      pubkey: s.pubkey,
      chips: s.chips,
      active: s.active,
      folded: s.folded,
      currentBet: s.currentBet,
      totalContributed: s.totalContributed,
      allIn: s.allIn ?? false
    } : null);
    const state = {
      id: this.id,
      seats: publicSeats,
      community: this.community,
      pot: this.pot,
      stage: this.stage,
      currentBetToCall: this.currentBetToCall,
      currentTurnIndex: this.currentTurnIndex,
      dealerIndex: this.dealerIndex,
      lastRaiseAmount: this.lastRaiseAmount,
      actionTimeoutMs: ACTION_TIMEOUT_MS,
      ...extras
    };
    io.to(this.id).emit("table_state", state);

    for (let i=0;i<this.seats.length;i++){
      const s = this.seats[i];
      if (s && s.socketId){
        const socket = io.sockets.sockets.get(s.socketId);
        if (socket){
          socket.emit("private_state", { myIndex: i, myHole: s.holeCards, timeMs: ACTION_TIMEOUT_MS });
        }
      }
    }
  }

  resetHand(){
    for (const s of this.seats) if (s){ s.currentBet = 0; s.totalContributed = 0; s.holeCards = []; s.folded = false; s.allIn = false; }
    this.community = [];
    this.deck = [];
    this.pot = 0;
    this.currentBetToCall = 0;
    this.stage = "waiting";
  }
}

// create and restore table
const table = new Table("table-1", SEAT_COUNT);
table.restore().then(()=> console.log("table restored (if present)"));

// Socket handlers
io.on("connection", (socket: Socket) => {
  console.log("socket connected", socket.id);

  socket.on("authenticate_with_ticket", async (data:{ ticket: string }) => {
    try {
      // validate ticket: check redis or jwt
      const pubkeyFromRedis = await redis.get(`ticket:${data.ticket}`);
      let pubkey: string | null = null;
      if (pubkeyFromRedis) pubkey = pubkeyFromRedis;
      else {
        try { const payload: any = jwt.verify(data.ticket, JWT_SECRET); pubkey = payload.pubkey; } catch(e) { }
      }
      if (!pubkey){ socket.emit("auth_error", { error: "invalid ticket" }); return; }
      (socket as any).pubkey = pubkey;
      socket.join(table.id);
      socket.emit("auth_ok", { tableId: table.id, pubkey });
      // record or update player in Postgres
      try {
        await prisma.player.upsert({ where: { pubkey }, update: {}, create: { pubkey, chips: 1000 } });
      } catch (e) { console.error("prisma upsert player error", e); }
    } catch (e) {
      socket.emit("auth_error", { error: "server_error" });
    }
  });

  socket.on("sit", (data:{ seatIndex: number }) => {
    const pubkey = (socket as any).pubkey;
    if (!pubkey){ socket.emit("error_msg", { error: "not authenticated" }); return; }
    const idx = data.seatIndex;
    if (idx < 0 || idx >= table.seats.length){ socket.emit("error_msg", { error: "bad seat" }); return; }
    if (table.seats[idx]){ socket.emit("error_msg", { error: "seat taken" }); return; }
    // check if player banned
    prisma.player.findUnique({ where: { pubkey } }).then(p => {
      if (p && p.banned){ socket.emit("error_msg", { error: "banned" }); return; }
      table.seatPlayer(idx, pubkey, socket.id);
      socket.emit("sat", { seatIndex: idx });
      table.broadcastTableState(io);
      table.persist();
      table.startHandIfReady(io);
    }).catch(err => { console.error(err); socket.emit("error_msg", { error: "server" }); });
  });

  socket.on("action", (data:{ seatIndex:number; action:{ type:"fold"|"call"|"raise"|"check", amount?:number } }) => {
    const pubkey = (socket as any).pubkey;
    if (!pubkey){ socket.emit("error_msg", { error: "not authenticated" }); return; }
    const s = table.seats[data.seatIndex];
    if (!s || s.pubkey !== pubkey){ socket.emit("error_msg", { error: "not your seat" }); return; }
    table.handleAction(io, data.seatIndex, data.action);
  });

  socket.on("leave", () => {
    table.removePlayerBySocket(socket.id);
    table.broadcastTableState(io);
    table.persist();
  });

  socket.on("disconnect", () => {
    // mark socket removed but keep seat for short reconnect window
    const pubkey = (socket as any).pubkey;
    if (pubkey) {
      for (let i=0;i<table.seats.length;i++){
        const s = table.seats[i];
        if (s && s.pubkey === pubkey && s.socketId === socket.id){
          // keep seat, clear socketId and set reconnect timer (60s)
          s.socketId = null;
          s.reconnectTimeout = Date.now() + 60000;
          // schedule removal after timeout if not reclaimed
          setTimeout(()=>{
            const cur = table.seats[i];
            if (cur && cur.pubkey === pubkey && !cur.socketId && cur.reconnectTimeout && Date.now() > cur.reconnectTimeout){
              table.seats[i] = null;
              table.broadcastTableState(io);
              table.persist();
            }
          }, 61000);
        }
      }
    }
    table.broadcastTableState(io);
    table.persist();
  });
});

httpServer.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
