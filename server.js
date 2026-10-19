// POK DENG • Red & Gold • simulated credits only.
// Node.js 24+. No third-party dependencies.

import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import {
  randomBytes,
  randomUUID,
  createHash,
  scryptSync,
  timingSafeEqual
} from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

process.umask(0o077);

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(
  process.env.DATA_DIR || path.join(root, 'data')
);

mkdirSync(dataDir, { recursive: true, mode: 0o700 });

const sqlite = new DatabaseSync(path.join(dataDir, 'pok.sqlite'));

sqlite.exec(`
  PRAGMA journal_mode=WAL;
  PRAGMA busy_timeout=5000;
  PRAGMA foreign_keys=ON;

  CREATE TABLE IF NOT EXISTS desk (
    id TEXT PRIMARY KEY NOT NULL,
    dealer TEXT,
    name TEXT,
    until INTEGER DEFAULT 0 NOT NULL
  );

  CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    credits INTEGER DEFAULT 100 NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rounds (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    bet INTEGER NOT NULL,
    state TEXT NOT NULL,
    status TEXT NOT NULL,
    delta INTEGER DEFAULT 0 NOT NULL,
    created TEXT NOT NULL,
    day TEXT NOT NULL,
    dealer TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS topups (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL,
    dealer_id TEXT,
    approved_by TEXT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER DEFAULT 0 NOT NULL,
    op TEXT NOT NULL,
    state TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL
  );

  CREATE UNIQUE INDEX IF NOT EXISTS one_owner
  ON accounts(role) WHERE role='owner';

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    guest_name TEXT,
    expires INTEGER NOT NULL
  );
`);

const query = (sql, args = []) => sqlite.prepare(sql).get(...args);

const hashToken = value =>
  createHash('sha256').update(value).digest('hex');

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString('hex');
}

function addAccount(email, name, password, role = 'member') {
  const salt = randomBytes(16).toString('hex');
  const id = randomUUID();

  sqlite.prepare(
    'INSERT INTO accounts VALUES(?,?,?,?,?,?)'
  ).run(id, email, name, passwordHash(password, salt), salt, role);

  return { id, email, name, role };
}

let owner = query("SELECT * FROM accounts WHERE role='owner'");

if (!owner) {
  const email = (
    process.env.OWNER_EMAIL || 'owner@pok.local'
  ).trim().toLowerCase();

  const password =
    process.env.OWNER_PASSWORD ||
    randomBytes(18).toString('base64url');

  if (password.length < 8 || password.length > 128) {
    throw Error('OWNER_PASSWORD must contain 8–128 characters');
  }

  owner = addAccount(email, 'เจ้าของโต๊ะ', password, 'owner');

  console.log(
    '\nบัญชีเจ้ามือถูกสร้างแล้ว เก็บข้อมูลนี้ไว้:\nอีเมล: ' +
    email +
    (process.env.OWNER_PASSWORD
      ? '\nรหัสผ่าน: ตามค่า OWNER_PASSWORD'
      : '\nรหัสผ่าน: ' + password) +
    '\n'
  );
}

owner = query("SELECT * FROM accounts WHERE role='owner'");

// Existing owner keeps the same ID, email, credits and history.
// OWNER_PASSWORD updates the owner's password on every server start.
if (process.env.OWNER_PASSWORD) {
  const password = process.env.OWNER_PASSWORD;

  if (password.length < 8 || password.length > 128) {
    throw Error('OWNER_PASSWORD must contain 8–128 characters');
  }

  if (passwordHash(password, owner.salt) !== owner.hash) {
    const salt = randomBytes(16).toString('hex');

    sqlite.exec('BEGIN IMMEDIATE');

    try {
      sqlite.prepare(
        'UPDATE accounts SET hash=?,salt=? WHERE id=?'
      ).run(passwordHash(password, salt), salt, owner.id);

      sqlite.prepare(
        'DELETE FROM sessions WHERE user_id=?'
      ).run(owner.id);

      sqlite.exec('COMMIT');
    } catch (error) {
      sqlite.exec('ROLLBACK');
      throw error;
    }

    console.log(
      'Owner password updated from OWNER_PASSWORD. ' +
      'Existing credits and history preserved.'
    );
  }
}

class Statement {
  constructor(sql, args = []) {
    this.sql = sql;
    this.args = args;
  }

  bind(...args) {
    return new Statement(this.sql, args);
  }

  first() {
    return sqlite.prepare(this.sql).get(...this.args) || null;
  }

  all() {
    return {
      results: sqlite.prepare(this.sql).all(...this.args)
    };
  }

  run() {
    const result = sqlite.prepare(this.sql).run(...this.args);
    return { meta: { changes: Number(result.changes) } };
  }
}

const env = {
  DEALER_OWNER_EMAIL: owner.email,
  DB: {
    prepare(sql) {
      return new Statement(sql);
    },

    batch(list) {
      sqlite.exec('BEGIN IMMEDIATE');

      try {
        const result = list.map(statement => statement.run());
        sqlite.exec('COMMIT');
        return result;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    }
  }
};

const requestContext = new AsyncLocalStorage();

async function getChatGPTUser() {
  return requestContext.getStore()?.user || null;
}

const COOKIE = 'pok_session';

function sessionFor(req) {
  const token = (req.headers.cookie || '')
    .split(';')
    .map(value => value.trim())
    .find(value => value.startsWith(COOKIE + '='))
    ?.slice(COOKIE.length + 1);

  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;

  const row = query(
    'SELECT * FROM sessions WHERE token_hash=? AND expires>?',
    [hashToken(token), Date.now()]
  );

  if (!row) return null;

  if (row.user_id.startsWith('guest:')) {
    return {
      userId: row.user_id,
      email: row.user_id + '@practice.invalid',
      displayName: row.guest_name,
      kind: 'guest'
    };
  }

  const account = query(
    'SELECT id,email,name,role FROM accounts WHERE id=?',
    [row.user_id]
  );

  return account
    ? {
        userId: account.id,
        email: account.email,
        displayName: account.name,
        kind: account.role
      }
    : null;
}

function issueSession(req, res, user, guestName = null) {
  const token = randomBytes(32).toString('hex');

  sqlite.prepare(
    'INSERT INTO sessions VALUES(?,?,?,?)'
  ).run(
    hashToken(token),
    user,
    guestName,
    Date.now() + 7 * 86400000
  );

  const secure =
    !!req.socket.encrypted ||
    (
      process.env.TRUST_PROXY === '1' &&
      req.headers['x-forwarded-proto'] === 'https'
    );

  res.setHeader(
    'Set-Cookie',
    COOKIE + '=' + token +
    '; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800' +
    (secure ? '; Secure' : '')
  );
}

const loginLimits = new Map();

function rateLimit(key) {
  const now = Date.now();
  let entry = loginLimits.get(key);

  if (!entry || entry.until < now) {
    entry = { count: 0, until: now + 600000 };
    loginLimits.set(key, entry);
  }

  return ++entry.count <= 12;
}

function send(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });

  res.end(JSON.stringify(data));
}

async function bodyBytes(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;

    if (size > 32768) throw Error('Request too large');

    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

// ---------- Card rules ----------

function points(hand) {
  return hand.reduce(
    (total, card) =>
      total + (card.r === 1 ? 1 : card.r >= 10 ? 0 : card.r),
    0
  ) % 10;
}

function evaluate(hand) {
  const p = points(hand);
  const same = hand.every(card => card.s === hand[0].s);
  const ranks = hand.map(card => card.r).sort((a, b) => a - b);

  if (hand.length === 2 && p >= 8) {
    return {
      rank: p === 9 ? 7 : 6,
      p: 0,
      m: same || ranks[0] === ranks[1] ? 2 : 1,
      name: 'ป๊อก ' + p
    };
  }

  if (hand.length === 3) {
    if (ranks[0] === ranks[2]) {
      return { rank: 5, p: 0, m: 5, name: 'ตอง' };
    }

    const sequence =
      (
        ranks[0] + 1 === ranks[1] &&
        ranks[1] + 1 === ranks[2]
      ) ||
      ranks.join(',') === '1,12,13';

    if (sequence) {
      return {
        rank: same ? 4 : 3,
        p: 0,
        m: same ? 5 : 3,
        name: same ? 'เรียงดอกเดียว' : 'เรียง'
      };
    }

    if (ranks.every(rank => rank >= 11)) {
      return { rank: 2, p: 0, m: 3, name: 'เซียน' };
    }
  }

  return {
    rank: 1,
    p,
    m: same
      ? hand.length
      : hand.length === 2 && ranks[0] === ranks[1] ? 2 : 1,
    name: p + ' แต้ม'
  };
}

function deck() {
  const cards = Array.from(
    { length: 52 },
    (_, index) => ({
      r: index % 13 + 1,
      s: Math.floor(index / 13)
    })
  );

  for (let index = 51; index > 0; index--) {
    let random;
    const cap =
      Math.floor(4294967296 / (index + 1)) * (index + 1);

    do {
      random = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (random >= cap);

    const target = random % (index + 1);

    [cards[index], cards[target]] = [cards[target], cards[index]];
  }

  return cards;
}

function settle(player, banker, bet) {
  const a = evaluate(player);
  const b = evaluate(banker);
  const difference = a.rank - b.rank || a.p - b.p;

  // Ties favor the dealer. No hidden outcome manipulation.
  return difference > 0 ? bet * a.m : -bet * b.m;
}

// ---------- Shared table ----------

const MAX_PEOPLE = 6;
const MAX_LEGS = 16;
const MIN_BET = 5;
const MAX_BET = 50;

const emptyTable = () => ({
  phase: 'lobby',
  players: [],
  b: [],
  d: [],
  deadline: 0,
  roundId: '',
  dealer: 'BOT',
  created: '',
  day: ''
});

function setReady(state, uid, bet, count, now) {
  if (state.phase !== 'lobby') throw Error('รอจบตานี้ก่อน');

  const player = state.players.find(player => player.uid === uid);

  if (!player) throw Error('กรุณาเข้าร่วมโต๊ะก่อน');

  if (!Number.isInteger(bet) || bet < MIN_BET || bet > MAX_BET) {
    throw Error('เดิมพันขาละ 5–50 เครดิต');
  }

  if (
    !Number.isInteger(count) ||
    count < 1 ||
    count > MAX_LEGS
  ) {
    throw Error('เลือก 1–16 ขาตามที่ว่าง');
  }

  const otherLegs = state.players
    .filter(player => player.uid !== uid && player.ready)
    .reduce((total, player) => total + player.count, 0);

  if (otherLegs + count > MAX_LEGS) {
    throw Error('ไพ่หนึ่งสำรับรองรับรวมสูงสุด 16 ขา');
  }

  Object.assign(player, {
    bet,
    count,
    ready: true,
    lastSeen: now,
    reserve: bet * count * 5
  });
}

function begin(state, now, dealer, id, day) {
  if (
    state.phase !== 'lobby' ||
    !state.players.length ||
    state.players.some(player => !player.ready)
  ) {
    throw Error('รอสมาชิกทุกคนกดยืนยันพร้อม');
  }

  if (
    state.players.length > MAX_PEOPLE ||
    state.players.reduce(
      (total, player) => total + player.count, 0
    ) > MAX_LEGS
  ) {
    throw Error('จำนวนคนหรือจำนวนขาเกิน');
  }

  state.phase = 'playing';
  state.d = deck();
  state.b = [];
  state.roundId = id;
  state.dealer = dealer;
  state.created = new Date(now).toISOString();
  state.day = day;
  state.deadline = now + 45000;

  for (const player of state.players) {
    player.reserve = player.bet * player.count * 5;
    player.legs = Array.from(
      { length: player.count },
      () => ({ cards: [], done: false })
    );
  }

  for (let pass = 0; pass < 2; pass++) {
    for (const player of state.players) {
      for (const leg of player.legs) {
        leg.cards.push(state.d.pop());
      }
    }

    state.b.push(state.d.pop());
  }

  const bankPok = evaluate(state.b).rank >= 6;

  for (const player of state.players) {
    for (const leg of player.legs) {
      leg.done = bankPok || evaluate(leg.cards).rank >= 6;
    }
  }
}

function decide(state, uid, index, draw) {
  if (state.phase !== 'playing') {
    throw Error('ตานี้ยังไม่เริ่มหรือจบแล้ว');
  }

  const player = state.players.find(player => player.uid === uid);
  const leg = player?.legs[index];

  if (!Number.isInteger(index) || !leg || leg.done) {
    throw Error('ขานี้ดำเนินการแล้ว หรือไม่ใช่ขาของคุณ');
  }

  if (draw) leg.cards.push(state.d.pop());

  leg.done = true;
}

function complete(state, now) {
  if (state.phase !== 'playing') return false;

  if (now >= state.deadline) {
    for (const player of state.players) {
      for (const leg of player.legs) leg.done = true;
    }
  }

  if (
    state.players.some(player =>
      player.legs.some(leg => !leg.done)
    )
  ) {
    return false;
  }

  const allPok = state.players.every(player =>
    player.legs.every(leg => evaluate(leg.cards).rank >= 6)
  );

  if (
    evaluate(state.b).rank < 6 &&
    !allPok &&
    points(state.b) <= 4
  ) {
    state.b.push(state.d.pop());
  }

  for (const player of state.players) {
    for (const leg of player.legs) {
      leg.delta = settle(leg.cards, state.b, player.bet);
    }
  }

  state.phase = 'done';
  state.d = [];

  return true;
}

function visible(state, uid) {
  return {
    ...state,
    d: undefined,
    b: state.phase === 'done' ? state.b : [],
    players: state.players.map(player => ({
      ...player,
      legs: player.legs.map(leg => ({
        ...leg,
        cards:
          state.phase === 'done' || player.uid === uid
            ? leg.cards
            : []
      }))
    }))
  };
}

const tableSQL = {
  startCheck: `
    AND NOT EXISTS(
      SELECT 1
      FROM json_each(?,'$.players') p
      LEFT JOIN members m
        ON m.id=json_extract(p.value,'$.uid')
      WHERE m.id IS NULL
        OR m.credits<json_extract(p.value,'$.reserve')
        OR EXISTS(
          SELECT 1 FROM rounds r
          WHERE r.user_id=m.id AND r.status='active'
        )
    )`,

  cas: `
    UPDATE rooms
    SET state=?,revision=revision+1,op=?
    WHERE id='main' AND revision=?`,

  reserve: `
    UPDATE members SET credits=credits-?
    WHERE id=?
      AND EXISTS(
        SELECT 1 FROM rooms WHERE id='main' AND op=?
      )`,

  payout: `
    UPDATE members SET credits=credits+?
    WHERE id=?
      AND EXISTS(
        SELECT 1 FROM rooms WHERE id='main' AND op=?
      )`,

  history: `
    INSERT OR IGNORE INTO rounds(
      id,user_id,bet,state,status,delta,created,day,dealer
    )
    SELECT ?,?,?,?,'done',?,?,?,?
    WHERE EXISTS(
      SELECT 1 FROM rooms WHERE id='main' AND op=?
    )`
};

async function read() {
  const db = env.DB;

  await db.prepare(`
    INSERT OR IGNORE INTO rooms(id,revision,op,state)
    VALUES('main',0,'',?)
  `).bind(JSON.stringify(emptyTable())).run();

  return await db.prepare(
    "SELECT revision,state FROM rooms WHERE id='main'"
  ).first();
}

async function write(revision, state, mode = 'normal') {
  const db = env.DB;
  const op = crypto.randomUUID();

  let sql = tableSQL.cas;

  if (mode === 'start') sql += tableSQL.startCheck;

  const serialized = JSON.stringify(state);
  const args = [serialized, op, revision];

  if (mode === 'start') args.push(serialized);

  const statements = [db.prepare(sql).bind(...args)];

  if (mode === 'start') {
    for (const player of state.players) {
      statements.push(
        db.prepare(tableSQL.reserve).bind(
          player.reserve, player.uid, op
        )
      );
    }
  }

  if (mode === 'finish') {
    for (const player of state.players) {
      const delta = player.legs.reduce(
        (total, leg) => total + (leg.delta || 0), 0
      );

      statements.push(
        db.prepare(tableSQL.payout).bind(
          player.reserve + delta, player.uid, op
        )
      );

      for (let index = 0; index < player.legs.length; index++) {
        const leg = player.legs[index];

        statements.push(
          db.prepare(tableSQL.history).bind(
            state.roundId + ':' + player.uid + ':' + index,
            player.uid,
            player.bet,
            JSON.stringify({
              p: leg.cards,
              b: state.b,
              tableRound: state.roundId,
              leg: index + 1
            }),
            leg.delta,
            state.created,
            state.day,
            state.dealer,
            op
          )
        );
      }
    }
  }

  const results = await db.batch(statements);

  return !!results[0].meta.changes;
}

async function tick() {
  for (let attempt = 0; attempt < 6; attempt++) {
    const row = await read();
    const state = JSON.parse(row.state);
    const now = Date.now();

    if (complete(state, now)) {
      await write(row.revision, state, 'finish');
      continue;
    }

    if (
      state.phase === 'done' &&
      state.players.every(player =>
        player.lastSeen <= now - 60000
      )
    ) {
      await write(row.revision, emptyTable());
      continue;
    }

    if (state.phase === 'lobby') {
      const before = state.players.length;

      state.players = state.players.filter(
        player => player.lastSeen > now - 60000
      );

      if (state.players.length !== before) {
        await write(row.revision, state);
        continue;
      }
    }

    return state;
  }

  throw Error('โต๊ะกำลังอัปเดต กรุณาลองใหม่');
}

async function tableSnapshot(uid) {
  return visible(await tick(), uid);
}

async function tableAction(
  uid, name, body, canDealer = false
) {
  await tick();

  for (let attempt = 0; attempt < 6; attempt++) {
    const row = await read();
    const state = JSON.parse(row.state);
    const now = Date.now();
    const player = state.players.find(player => player.uid === uid);

    let mode = 'normal';

    switch (body.action) {
      case 'tableJoin':
        if (state.phase !== 'lobby') {
          throw Error('รอจบตานี้ก่อนเข้าร่วม');
        }

        if (!player) {
          if (state.players.length >= MAX_PEOPLE) {
            throw Error('โต๊ะเต็ม 6 คนแล้ว');
          }

          state.players.push({
            uid,
            name,
            bet: 5,
            count: 1,
            ready: false,
            lastSeen: now,
            legs: [],
            reserve: 0
          });
        } else {
          player.lastSeen = now;
        }
        break;

      case 'tablePing':
        if (!player || player.lastSeen > now - 10000) return;
        player.lastSeen = now;
        break;

      case 'tableLeave':
        if (state.phase === 'playing') {
          throw Error('รอจบตานี้ก่อนออกจากโต๊ะ');
        }

        state.players = state.players.filter(
          player => player.uid !== uid
        );

        if (state.phase === 'done' && !state.players.length) {
          Object.assign(state, emptyTable());
        }
        break;

      case 'tableReady': {
        if (body.accept !== true) {
          throw Error('กรุณารับทราบกติกาก่อนยืนยัน');
        }

        setReady(
          state, uid, Number(body.bet), Number(body.count), now
        );

        const member = await env.DB.prepare(
          'SELECT credits FROM members WHERE id=?'
        ).bind(uid).first();

        if (
          !member ||
          member.credits <
            Number(body.bet) * Number(body.count) * 5
        ) {
          throw Error(
            'เครดิตไม่พอสำรอง 5 เท่าของทุกขา กรุณาเติมเครดิต'
          );
        }
        break;
      }

      case 'tableUnready':
        if (state.phase !== 'lobby' || !player) {
          throw Error('แก้ไขไม่ได้ในช่วงนี้');
        }

        Object.assign(player, {
          ready: false,
          count: 1,
          reserve: 0,
          lastSeen: now
        });
        break;

      case 'tableStart': {
        const host = await env.DB.prepare(
          "SELECT * FROM desk WHERE id='main'"
        ).first();

        if (host && host.until > now) {
          if (!canDealer || host.dealer !== uid) {
            throw Error('โหมดสมาชิก: รอเจ้าของโต๊ะเริ่มแจกไพ่');
          }
        } else if (!player && !canDealer) {
          throw Error('ต้องร่วมโต๊ะก่อนเริ่ม');
        }

        const dealer =
          host && host.until > now ? host.name : 'BOT';

        begin(
          state,
          now,
          dealer,
          crypto.randomUUID(),
          new Intl.DateTimeFormat(
            'en-CA', { timeZone: 'Asia/Singapore' }
          ).format(new Date(now))
        );

        mode = 'start';
        break;
      }

      case 'tableDraw':
      case 'tableStay':
        if (body.roundId !== state.roundId) {
          throw Error('ตาที่เลือกจบแล้ว กรุณาโหลดใหม่');
        }

        decide(
          state, uid, Number(body.leg), body.action === 'tableDraw'
        );

        if (player) player.lastSeen = now;
        break;

      case 'tableNext':
        if (state.phase !== 'done') {
          throw Error('ตานี้ยังไม่จบ');
        }

        if (!player && !canDealer) {
          throw Error(
            'เฉพาะผู้ร่วมตานี้หรือเจ้าของโต๊ะเปิดตาใหม่ได้'
          );
        }

        Object.assign(state, emptyTable(), {
          players: state.players
            .filter(player => player.lastSeen > now - 60000)
            .map(player => ({
              ...player,
              ready: false,
              legs: [],
              reserve: 0,
              count: 1,
              lastSeen:
                player.uid === uid ? now : player.lastSeen
            }))
        });
        break;

      default:
        throw Error('ไม่พบคำสั่งโต๊ะ');
    }

    if (await write(row.revision, state, mode)) {
      await tick();
      return;
    }

    if (mode === 'start') {
      const current = await read();

      if (current.revision === row.revision) {
        throw Error(
          'เครดิตสมาชิกบางคนไม่พอ หรือมีมือเดิมค้างอยู่'
        );
      }
    }
  }

  throw Error('มีสมาชิกอัปเดตโต๊ะพร้อมกัน กรุณาลองใหม่');
}

// ---------- Simulated credit topups ----------

const topupSQL = {
  create: `
    INSERT OR IGNORE INTO topups(
      id,user_id,amount,status,dealer_id,
      approved_by,created,updated
    )
    SELECT ?,?,?,
      CASE WHEN EXISTS(
        SELECT 1 FROM desk WHERE id='main' AND until>?
      ) THEN 'pending' ELSE 'approved' END,
      (SELECT dealer FROM desk WHERE id='main' AND until>?),
      CASE WHEN EXISTS(
        SELECT 1 FROM desk WHERE id='main' AND until>?
      ) THEN NULL ELSE 'BOT' END,?,?
    WHERE EXISTS(
      SELECT 1 FROM members WHERE id=? AND credits+?<=1000000
    )
    AND NOT EXISTS(
      SELECT 1 FROM topups WHERE user_id=? AND status='pending'
    )`,

  creditCreated: `
    UPDATE members
    SET credits=credits+(
      SELECT amount FROM topups WHERE id=? AND user_id=?
    )
    WHERE id=? AND changes()=1
      AND EXISTS(
        SELECT 1 FROM topups
        WHERE id=? AND user_id=? AND status='approved'
      )`,

  approve: `
    UPDATE topups
    SET status='approved',approved_by=?,updated=?
    WHERE id=? AND status='pending' AND dealer_id=?
      AND EXISTS(
        SELECT 1 FROM desk
        WHERE id='main' AND dealer=? AND until>?
      )
      AND EXISTS(
        SELECT 1 FROM members
        WHERE id=topups.user_id
          AND credits+topups.amount<=1000000
      )`,

  creditApproved: `
    UPDATE members
    SET credits=credits+(SELECT amount FROM topups WHERE id=?)
    WHERE id=(SELECT user_id FROM topups WHERE id=?)
      AND changes()=1`,

  reject: `
    UPDATE topups
    SET status='rejected',approved_by=?,updated=?
    WHERE id=? AND status='pending' AND dealer_id=?
      AND EXISTS(
        SELECT 1 FROM desk
        WHERE id='main' AND dealer=? AND until>?
      )`,

  cancel: `
    UPDATE topups SET status='cancelled',updated=?
    WHERE id=? AND user_id=? AND status='pending'`
};

function isDealerOwner(email, configured) {
  return !!email && !!configured &&
    email.trim().toLowerCase() === configured.trim().toLowerCase();
}

const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { 'Cache-Control': 'no-store' }
  });

const canOwnDealer = user =>
  isDealerOwner(user.email, env.DEALER_OWNER_EMAIL);

const day = () =>
  new Intl.DateTimeFormat(
    'en-CA', { timeZone: 'Asia/Singapore' }
  ).format(new Date());

async function snapshot(uid, canDealer = false) {
  const db = env.DB;
  const table = await tableSnapshot(uid);

  const member = await db.prepare(
    'SELECT * FROM members WHERE id=?'
  ).bind(uid).first();

  const active = await db.prepare(`
    SELECT * FROM rounds
    WHERE user_id=? AND status='active' LIMIT 1
  `).bind(uid).first();

  let hand = null;

  if (active) {
    const state = JSON.parse(active.state);

    hand = {
      id: active.id,
      bet: active.bet,
      p: state.p,
      b: [],
      dealer: active.dealer
    };
  }

  const history = await db.prepare(`
    SELECT id,bet,delta,created,dealer,state
    FROM rounds
    WHERE user_id=? AND status='done'
    ORDER BY created DESC LIMIT 20
  `).bind(uid).all();

  const stats = canDealer
    ? await db.prepare(`
        SELECT COUNT(*) AS count,COALESCE(SUM(-delta),0) AS profit
        FROM rounds WHERE status='done' AND day=?
      `).bind(day()).first()
    : null;

  const host = await db.prepare(
    'SELECT * FROM desk WHERE id=?'
  ).bind('main').first();

  const liveHost =
    host && host.until > Date.now() ? host : null;

  const topups = await db.prepare(`
    SELECT id,amount,status,approved_by,created,updated
    FROM topups WHERE user_id=?
    ORDER BY created DESC LIMIT 30
  `).bind(uid).all();

  const myPending = await db.prepare(`
    SELECT id,amount,status,created FROM topups
    WHERE user_id=? AND status='pending' LIMIT 1
  `).bind(uid).first();

  const requests =
    canDealer && liveHost?.dealer === uid
      ? await db.prepare(`
          SELECT t.id,t.amount,t.created,m.name
          FROM topups t JOIN members m ON m.id=t.user_id
          WHERE t.status='pending' AND t.dealer_id=?
          ORDER BY t.created
        `).bind(uid).all()
      : null;

  return {
    canDealer,
    mode: liveHost ? 'members' : 'guests',
    table,
    member,
    hand,
    history: history.results,
    stats,
    host: liveHost,
    day: day(),
    topups: topups.results,
    myPending,
    requests: requests?.results || []
  };
}

async function GET() {
  const user = await getChatGPTUser();

  if (!user) return json({ error: 'กรุณาเข้าสู่ระบบ' }, 401);

  await env.DB.prepare(`
    INSERT OR IGNORE INTO members(id,name,credits)
    VALUES(?,?,100)
  `).bind(user.userId, user.displayName).run();

  return json(
    await snapshot(user.userId, canOwnDealer(user))
  );
}

async function POST(req) {
  const user = await getChatGPTUser();

  if (!user) return json({ error: 'กรุณาเข้าสู่ระบบ' }, 401);

  if (new URL(req.url).origin !== req.headers.get('origin')) {
    return json({ error: 'คำขอไม่ถูกต้อง' }, 403);
  }

  let body;

  try {
    body = await req.json();
  } catch {
    return json({ error: 'ข้อมูลไม่ถูกต้อง' }, 400);
  }

  const db = env.DB;

  await db.prepare(`
    INSERT OR IGNORE INTO members(id,name,credits)
    VALUES(?,?,100)
  `).bind(user.userId, user.displayName).run();

  if (!body || typeof body !== 'object') {
    return json({ error: 'ข้อมูลไม่ถูกต้อง' }, 400);
  }

  if (
    ['host', 'leave', 'approveTopup', 'rejectTopup']
      .includes(body.action) &&
    !canOwnDealer(user)
  ) {
    return json({
      error: 'เฉพาะเจ้าของโต๊ะเท่านั้นที่เป็นเจ้ามือและยืนยันเครดิตได้'
    }, 403);
  }

  if (
    typeof body.action === 'string' &&
    body.action.startsWith('table')
  ) {
    try {
      await tableAction(
        user.userId,
        user.displayName,
        body,
        canOwnDealer(user)
      );

      return json(
        await snapshot(user.userId, canOwnDealer(user))
      );
    } catch (error) {
      return json({
        error: error.message || 'อัปเดตโต๊ะไม่สำเร็จ'
      }, 400);
    }
  }

  if (body.action === 'topup') {
    const amount = Number(body.amount);
    const key = body.requestKey;

    if (
      !Number.isInteger(amount) ||
      amount < 1 ||
      amount > 10000 ||
      typeof key !== 'string' ||
      !/^[a-f0-9-]{36}$/i.test(key)
    ) {
      return json({
        error: 'ระบุจำนวนเต็ม 1–10,000 เครดิต'
      }, 400);
    }

    const now = Date.now();
    const stamp = new Date(now).toISOString();

    await db.batch([
      db.prepare(topupSQL.create).bind(
        key,
        user.userId,
        amount,
        now,
        now,
        now,
        stamp,
        stamp,
        user.userId,
        amount,
        user.userId
      ),
      db.prepare(topupSQL.creditCreated).bind(
        key, user.userId, user.userId, key, user.userId
      )
    ]);

    const entry = await db.prepare(
      'SELECT status FROM topups WHERE id=? AND user_id=?'
    ).bind(key, user.userId).first();

    if (!entry) {
      return json({
        error: 'มีคำขอรออนุมัติอยู่แล้ว หรือยอดเครดิตจะเกิน 1,000,000'
      }, 409);
    }

    return json({
      ...await snapshot(user.userId, canOwnDealer(user)),
      message:
        entry.status === 'approved'
          ? 'เติมเครดิตจำลองสำเร็จ'
          : entry.status === 'pending'
            ? 'ส่งคำขอแล้ว รอเจ้ามือยืนยัน'
            : 'รายการนี้ดำเนินการแล้ว'
    });
  }

  if (
    body.action === 'approveTopup' ||
    body.action === 'rejectTopup'
  ) {
    if (typeof body.topupId !== 'string') {
      return json({ error: 'ไม่พบรายการ' }, 400);
    }

    const now = Date.now();

    const args = [
      user.userId,
      new Date(now).toISOString(),
      body.topupId,
      user.userId,
      user.userId,
      now
    ];

    const result = body.action === 'approveTopup'
      ? await db.batch([
          db.prepare(topupSQL.approve).bind(...args),
          db.prepare(topupSQL.creditApproved).bind(
            body.topupId, body.topupId
          )
        ])
      : [
          await db.prepare(topupSQL.reject)
            .bind(...args).run()
        ];

    if (!result[0].meta.changes) {
      return json({
        error: 'อนุมัติไม่ได้: ต้องเป็นเจ้ามือผู้รับคำขอที่ยังออนไลน์ รายการต้องยังรออนุมัติ และยอดรวมไม่เกิน 1,000,000'
      }, 409);
    }

    return json({
      ...await snapshot(user.userId, canOwnDealer(user)),
      message:
        body.action === 'approveTopup'
          ? 'อนุมัติและเพิ่มเครดิตแล้ว'
          : 'ปฏิเสธคำขอแล้ว'
    });
  }

  if (body.action === 'cancelTopup') {
    await db.prepare(topupSQL.cancel).bind(
      new Date().toISOString(),
      body.topupId,
      user.userId
    ).run();

    return json({
      ...await snapshot(user.userId, canOwnDealer(user)),
      message: 'ยกเลิกคำขอแล้ว'
    });
  }

  if (body.action === 'host') {
    await db.prepare(`
      INSERT INTO desk(id,dealer,name,until)
      VALUES(?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        dealer=excluded.dealer,
        name=excluded.name,
        until=excluded.until
      WHERE desk.until < ? OR desk.dealer=?
    `).bind(
      'main',
      user.userId,
      user.displayName,
      Date.now() + 45000,
      Date.now(),
      user.userId
    ).run();

    return json(
      await snapshot(user.userId, canOwnDealer(user))
    );
  }

  if (body.action === 'leave') {
    await db.prepare(
      'DELETE FROM desk WHERE id=? AND dealer=?'
    ).bind('main', user.userId).run();

    return json(
      await snapshot(user.userId, canOwnDealer(user))
    );
  }

  if (body.action === 'deal') {
    return json({
      error: 'กรุณาใช้โต๊ะร่วมใหม่ เดิมพันขาละ 5–50 เครดิต'
    }, 400);
  }

  if (body.action === 'draw' || body.action === 'stay') {
    return finish(
      user.userId,
      body.id,
      body.action === 'draw',
      canOwnDealer(user)
    );
  }

  return json({ error: 'ไม่พบคำสั่ง' }, 400);
}

// Compatibility for unfinished legacy hands.
async function finish(uid, id, draw, canDealer = false) {
  const db = env.DB;

  const round = await db.prepare(`
    SELECT * FROM rounds
    WHERE id=? AND user_id=? AND status='active'
  `).bind(id, uid).first();

  if (!round) {
    return json({
      error: 'มือนี้จบแล้ว กรุณาโหลดใหม่'
    }, 409);
  }

  const state = JSON.parse(round.state);

  if (
    evaluate(state.p).rank < 6 &&
    evaluate(state.b).rank < 6
  ) {
    if (draw) state.p.push(state.d.pop());

    if (points(state.b) <= 4) state.b.push(state.d.pop());
  }

  const delta = settle(state.p, state.b, round.bet);

  const result = await db.batch([
    db.prepare(`
      UPDATE rounds SET status='done',state=?,delta=?
      WHERE id=? AND user_id=? AND status='active'
    `).bind(
      JSON.stringify({ p: state.p, b: state.b }),
      delta,
      id,
      uid
    ),
    db.prepare(`
      UPDATE members SET credits=credits+?
      WHERE id=? AND changes()=1
    `).bind(5 * round.bet + delta, uid)
  ]);

  if (!result[0].meta.changes) {
    return json({ error: 'มือนี้จบแล้ว' }, 409);
  }

  return json({
    ...await snapshot(uid, canDealer),
    result: {
      p: state.p,
      b: state.b,
      delta,
      bet: round.bet,
      dealer: round.dealer
    }
  });
}

// ---------- HTTP server ----------

const html = readFileSync(path.join(root, 'index.html'));

const server = http.createServer(async (req, res) => {
  try {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');

    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "connect-src 'self'; img-src 'self' data:; " +
      "frame-ancestors 'none'"
    );

    const protocol =
      req.socket.encrypted ||
      (
        process.env.TRUST_PROXY === '1' &&
        req.headers['x-forwarded-proto'] === 'https'
      )
        ? 'https'
        : 'http';

    const origin = protocol + '://' + req.headers.host;
    const url = new URL(req.url, origin);

    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });

      return res.end(html);
    }

    if (!url.pathname.startsWith('/api/')) {
      return send(res, 404, { error: 'Not found' });
    }

    if (!['GET', 'POST'].includes(req.method)) {
      return send(res, 405, { error: 'Method not allowed' });
    }

    if (
      req.method === 'POST' &&
      req.headers.origin !== origin
    ) {
      return send(res, 403, { error: 'คำขอไม่ถูกต้อง' });
    }

    const bytes =
      req.method === 'POST' ? await bodyBytes(req) : null;

    let body = {};

    if (bytes) {
      try {
        body = JSON.parse(bytes);
      } catch {
        return send(res, 400, { error: 'ข้อมูลไม่ถูกต้อง' });
      }

      if (
        !body ||
        Array.isArray(body) ||
        typeof body !== 'object'
      ) {
        return send(res, 400, { error: 'ข้อมูลไม่ถูกต้อง' });
      }
    }

    let user = sessionFor(req);

    if (
      url.pathname === '/api/auth' &&
      req.method === 'POST'
    ) {
      const ip = req.socket.remoteAddress || 'unknown';

      if (!rateLimit(ip)) {
        return send(res, 429, {
          error: 'ลองหลายครั้งเกินไป กรุณารอ 10 นาที'
        });
      }

      if (body.action === 'logout') {
        const token = (req.headers.cookie || '')
          .split(';')
          .map(value => value.trim())
          .find(value => value.startsWith(COOKIE + '='))
          ?.slice(COOKIE.length + 1);
