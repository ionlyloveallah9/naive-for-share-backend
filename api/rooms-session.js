import { createClient } from "@supabase/supabase-js";
import {
  createHmac,
  randomBytes,
  scrypt,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const ROOM_LIFETIME_MS = 30 * 60 * 1000;
const SESSION_LIFETIME_SECONDS = 30 * 60;
const MAX_TEXT_LENGTH = 20000;

function send(res, status, data) {
  return res.status(status).json(data);
}

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) throw new Error("SERVER_CONFIG_MISSING");

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
}

function getSessionSecret() {
  const secret = process.env.ROOM_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("SESSION_CONFIG_MISSING");
  }
  return secret;
}

function validCode(code) {
  return typeof code === "string" && /^[a-f0-9]{8}$/i.test(code);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 8 && password.length <= 128;
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const derived = await scryptAsync(password, salt, 64);
  return `scrypt$${salt}$${derived.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;

  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;

  const [, salt, expectedHex] = parts;
  if (!/^[a-f0-9]{32}$/i.test(salt) ||
      !/^[a-f0-9]{128}$/i.test(expectedHex)) return false;

  const actual = await scryptAsync(password, salt, 64);
  return timingSafeEqual(actual, Buffer.from(expectedHex, "hex"));
}

function newExpiry() {
  return new Date(Date.now() + ROOM_LIFETIME_MS).toISOString();
}

function sign(value) {
  return createHmac("sha256", getSessionSecret())
    .update(value)
    .digest("base64url");
}

function issueSession(room) {
  const payload = Buffer.from(JSON.stringify({
    v: 1,
    roomId: room.id,
    code: room.room_code,
    exp: Math.floor(Date.now() / 1000) + SESSION_LIFETIME_SECONDS
  })).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

function verifySession(token, room) {
  if (typeof token !== "string" || token.length > 2048) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;
  const expected = Buffer.from(sign(payload));
  const received = Buffer.from(signature);

  if (expected.length !== received.length ||
      !timingSafeEqual(expected, received)) return false;

  try {
    const claims = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    return claims.v === 1 &&
      claims.roomId === room.id &&
      claims.code === room.room_code &&
      Number.isInteger(claims.exp) &&
      claims.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function findActiveRoom(db, code) {
  const { data, error } = await db
    .from("share_rooms")
    .select("id, room_code, room_password_hash, shared_text, created_at, expires_at")
    .eq("room_code", code)
    .maybeSingle();

  if (error) {
    console.error("Room lookup failed:", error.code);
    throw new Error("DATABASE_ERROR");
  }

  if (!data) return { room: null, expired: false };
  if (Date.parse(data.expires_at) <= Date.now()) {
    return { room: null, expired: true };
  }

  return { room: data, expired: false };
}

async function refreshActivity(db, room, changes = {}) {
  const now = new Date().toISOString();
  const expiry = newExpiry();

  const { data, error } = await db
    .from("share_rooms")
    .update({
      ...changes,
      last_activity_at: now,
      expires_at: expiry
    })
    .eq("id", room.id)
    .gt("expires_at", now)
    .select("room_code, shared_text, created_at, expires_at")
    .maybeSingle();

  if (error) {
    console.error("Room update failed:", error.code);
    throw new Error("DATABASE_ERROR");
  }

  return data;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { ok: false, error: "Method not allowed" });
  }

  try {
    const body = req.body ?? {};
    const { action } = body;

    if (typeof action !== "string") {
      return send(res, 400, { ok: false, error: "An action is required" });
    }

    const db = getSupabase();

    if (action === "create") {
      const { password } = body;

      if (!validPassword(password)) {
        return send(res, 400, {
          ok: false,
          error: "Password must be between 8 and 128 characters"
        });
      }

      const roomCode = randomBytes(4).toString("hex");
      const passwordHash = await hashPassword(password);
      const expiry = newExpiry();

      const { data, error } = await db
        .from("share_rooms")
        .insert({
          room_code: roomCode,
          room_password_hash: passwordHash,
          is_public: false,
          shared_text: "",
          last_activity_at: new Date().toISOString(),
          expires_at: expiry
        })
        .select("room_code, created_at, expires_at")
        .single();

      if (error) {
        console.error("Room creation failed:", error.code);
        return send(res, 503, { ok: false, error: "Unable to create room" });
      }

      return send(res, 201, { ok: true, room: data });
    }

    const { code } = body;

    if (!validCode(code)) {
      return send(res, 400, {
        ok: false,
        error: "Room code must contain 8 hexadecimal characters"
      });
    }

    const result = await findActiveRoom(db, code);

    if (result.expired) {
      return send(res, 410, { ok: false, error: "This room has expired" });
    }

    if (!result.room) {
      return send(res, 404, {
        ok: false,
        error: "Room not found or credentials are invalid"
      });
    }

    const room = result.room;

    if (action === "join") {
      if (!validPassword(body.password) ||
          !room.room_password_hash ||
          !(await verifyPassword(body.password, room.room_password_hash))) {
        return send(res, 401, {
          ok: false,
          error: "Incorrect room code or password"
        });
      }

      const updated = await refreshActivity(db, room);
      if (!updated) {
        return send(res, 410, { ok: false, error: "This room has expired" });
      }

      return send(res, 200, {
        ok: true,
        token: issueSession(room),
        room: updated
      });
    }

    if (action !== "get-text" && action !== "update-text") {
      return send(res, 400, { ok: false, error: "Unsupported action" });
    }

    if (!verifySession(body.token, room)) {
      return send(res, 401, {
        ok: false,
        error: "Room session is invalid or expired. Join again."
      });
    }

    if (action === "get-text") {
      const updated = await refreshActivity(db, room);
      if (!updated) {
        return send(res, 410, { ok: false, error: "This room has expired" });
      }

      return send(res, 200, { ok: true, room: updated });
    }

    if (typeof body.text !== "string" ||
        body.text.length > MAX_TEXT_LENGTH) {
      return send(res, 400, {
        ok: false,
        error: `Text must be a string of at most ${MAX_TEXT_LENGTH} characters`
      });
    }

    const updated = await refreshActivity(db, room, {
      shared_text: body.text
    });

    if (!updated) {
      return send(res, 410, { ok: false, error: "This room has expired" });
    }

    return send(res, 200, { ok: true, room: updated });
  } catch (error) {
    if (error.message === "SERVER_CONFIG_MISSING" ||
        error.message === "SESSION_CONFIG_MISSING") {
      return send(res, 503, {
        ok: false,
        error: "Server configuration is missing"
      });
    }

    if (error.message === "DATABASE_ERROR") {
      return send(res, 503, {
        ok: false,
        error: "Database operation failed"
      });
    }

    console.error("Room session API failed:", error?.name, error?.message);
    return send(res, 500, { ok: false, error: "Internal server error" });
  }
}
