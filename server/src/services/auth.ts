import crypto from 'crypto';
import { getDb } from '../db/index.js';
import { hashPassword, verifyPassword } from '../lib/password.js';

// Dashboard authentication: email + password accounts with opaque session
// tokens. Distinct from the unified API key, which authenticates the /v1 proxy
// for apps — this gates the /api/* admin surface for the human operator (#35).

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

type StatelessSessionPayload = {
  userId: number;
  email: string;
  expiresAt: number;
};

function isVercelRuntime(): boolean {
  return !!process.env.VERCEL;
}

function sessionSigningSecret(): string {
  const secret = process.env.ENCRYPTION_KEY?.trim();
  if (!secret) {
    throw new Error('ENCRYPTION_KEY is required for stateless Vercel dashboard sessions.');
  }
  return secret;
}

function encodeStatelessSession(payload: StatelessSessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSigningSecret()).update(body).digest('base64url');
  return `v1.${body}.${signature}`;
}

function decodeStatelessSession(token: string): StatelessSessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  const body = parts[1]!;
  const provided = parts[2]!;
  const expected = crypto.createHmac('sha256', sessionSigningSecret()).update(body).digest('base64url');
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as StatelessSessionPayload;
    if (!payload || typeof payload.userId !== 'number' || typeof payload.email !== 'string' || typeof payload.expiresAt !== 'number') {
      return null;
    }
    if (payload.expiresAt < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export interface SessionUser {
  userId: number;
  email: string;
}

function sha256(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/** The one spelling of an address the DB is keyed on. Exported so callers that
 *  bucket by email (the login throttle in routes/auth.ts) key on exactly what
 *  verifyCredentials will look up — keying on anything else lets a padded
 *  address authenticate against the real row while landing in its own bucket. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function userCount(): number {
  const row = getDb().prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
  return row.c;
}

/** Create a user. Throws { code: 'email_taken' } if the email already exists. */
export function createUser(email: string, password: string): SessionUser {
  const db = getDb();
  const normalized = normalizeEmail(email);
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalized);
  if (existing) {
    const err = new Error('An account with that email already exists') as any;
    err.code = 'email_taken';
    throw err;
  }
  const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
    .run(normalized, hashPassword(password));
  return { userId: Number(result.lastInsertRowid), email: normalized };
}

/** Verify credentials. Returns the user on success, null on failure. */
export function verifyCredentials(email: string, password: string): SessionUser | null {
  const db = getDb();
  const row = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?')
    .get(normalizeEmail(email)) as { id: number; email: string; password_hash: string } | undefined;
  if (!row) return null;
  if (!verifyPassword(password, row.password_hash)) return null;
  return { userId: row.id, email: row.email };
}

/** Mint a session and return the raw token (only the hash is persisted). */
export function createSession(userId: number): string {
  if (isVercelRuntime()) {
    const row = getDb().prepare('SELECT email FROM users WHERE id = ?').get(userId) as { email: string } | undefined;
    if (!row) throw new Error('Cannot create session for unknown user');
    return encodeStatelessSession({
      userId,
      email: row.email,
      expiresAt: Date.now() + SESSION_TTL_MS,
    });
  }

  const token = crypto.randomBytes(32).toString('hex');
  getDb().prepare('INSERT INTO sessions (token_hash, user_id, expires_at_ms) VALUES (?, ?, ?)')
    .run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
  return token;
}

/** Resolve a session token to its user, or null if missing/expired. */
export function validateSession(token: string | undefined | null): SessionUser | null {
  if (!token) return null;

  if (isVercelRuntime()) {
    const payload = decodeStatelessSession(token);
    return payload ? { userId: payload.userId, email: payload.email } : null;
  }

  const db = getDb();
  const row = db.prepare(`
    SELECT s.user_id, s.expires_at_ms, u.email
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(sha256(token)) as { user_id: number; expires_at_ms: number; email: string } | undefined;
  if (!row) return null;
  if (row.expires_at_ms < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return null;
  }
  return { userId: row.user_id, email: row.email };
}

export function deleteSession(token: string | undefined | null): void {
  if (!token) return;
  if (isVercelRuntime()) return;
  getDb().prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

/** Update the email of the authenticated user after verifying the current password. Throws { code: 'email_taken' } on conflict. */
export function updateEmail(userId: number, currentPassword: string, newEmail: string): boolean {
  const db = getDb();
  const row = db.prepare('SELECT password_hash FROM users WHERE id = ?')
    .get(userId) as { password_hash: string } | undefined;
  if (!row) return false;
  if (!verifyPassword(currentPassword, row.password_hash)) return false;

  const normalized = normalizeEmail(newEmail);
  const existing = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(normalized, userId);
  if (existing) {
    const err = new Error('An account with that email already exists') as any;
    err.code = 'email_taken';
    throw err;
  }
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(normalized, userId);
  // Keep sessions alive; the new email will be reflected on the next validateSession call.
  return true;
}

/** Update the password of the authenticated user after verifying the current one. Invalidates all sessions on success. */
export function updatePassword(userId: number, currentPassword: string, newPassword: string): boolean {
  const db = getDb();
  const row = db.prepare('SELECT password_hash FROM users WHERE id = ?')
    .get(userId) as { password_hash: string } | undefined;
  if (!row) return false;
  if (!verifyPassword(currentPassword, row.password_hash)) return false;
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), userId);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  return true;
}

/**
 * Reset the password for the single existing user and invalidate all
 * sessions.
 * Returns false if no user exists.
 */
export function resetUserPassword(newPassword: string): boolean {
  const db = getDb();
  const row = db.prepare('SELECT id FROM users LIMIT 1').get() as { id: number } | undefined;
  if (!row) return false;
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), row.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.id);
  return true;
}
