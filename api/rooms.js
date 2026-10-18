import { createClient } from "@supabase/supabase-js";
import {
  randomBytes,
  scrypt,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const ROOM_LIFETIME_MS = 30 * 60 * 1000;
const MAX_TEXT_LENGTH = 20000;

function send(res, status, data) {
  return res.status(status).json(data);
}

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    throw new Error("SERVER_CONFIG_MISSING");
  }

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
}

function validCode(code) {
  return typeof code === "string" &&
    /^[a-f0-9]{8}$/i.test(code);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128;
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const derived = await scryptAsync(password, salt, 64);

  return `scrypt$${salt}$${derived.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;

  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }

  const [, salt, expectedHex] = parts;

  if (!/^[a-f0-9]{32}$/i.test(salt) ||
      !/^[a-f0-9]{128}$/i.test(expectedHex)) {
    return false;
  }

  const actual = await scryptAsync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");

  return timingSafeEqual(actual, expected);
}

function newExpiry() {
  return new Date(Date.now() + ROOM_LIFETIME_MS).toISOString();
}

async function findActiveRoom(db, code) {
  const { data, error } = await db
    .from("share_rooms")
    .select(
      "id, room_code, room_password_hash, is_public, shared_text, created_at, last_activity_at, expires_at"
    )
    .eq("room_code", code)
    .maybeSingle();

  if (error) {
    console.error("Room lookup failed:", error.code);
    throw new Error("DATABASE_ERROR");
  }

  if (!data) return { room: null, expired: false };

  if (Date.parse(data.expires_at) <= Date.now()) {
    return { room: null, expired: true, id: data.id };
  }

  return { room: data, expired: false };
}

async function refreshActivity(db, room) {
  const now = new Date().toISOString();
  const expiry = newExpiry();

  const { error } = await db
    .from("share_rooms")
    .update({
      last_activity_at: now,
      expires_at: expiry
    })
    .eq("id", room.id);

  if (error) {
    console.error("Room activity update failed:", error.code);
    throw new Error("DATABASE_ERROR");
  }

  return expiry;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, {
      ok: false,
      error: "Method not allowed"
    });
  }

  try {
    const body = req.body ?? {};
    const { action } = body;

    if (typeof action !== "string") {
      return send(res, 400, {
        ok: false,
        error: "An action is required"
      });
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
        return send(res, 503, {
          ok: false,
          error: "Unable to create room"
        });
      }

      return send(res, 201, {
        ok: true,
        room: data
      });
    }

    const { code, password } = body;

    if (!validCode(code)) {
      return send(res, 400, {
        ok: false,
        error: "Room code must contain 8 hexadecimal characters"
      });
    }

    if (!validPassword(password)) {
      return send(res, 400, {
        ok: false,
        error: "A valid room password is required"
      });
    }

    const result = await findActiveRoom(db, code);

    if (result.expired) {
      return send(res, 410, {
        ok: false,
        error: "This room has expired"
      });
    }

    if (!result.room) {
      return send(res, 404, {
        ok: false,
        error: "Room not found"
      });
    }

    const room = result.room;

    if (!room.room_password_hash ||
        !(await verifyPassword(password, room.room_password_hash))) {
      return send(res, 401, {
        ok: false,
        error: "Incorrect room code or password"
      });
    }

    if (action === "join" || action === "get-text") {
      const expiresAt = await refreshActivity(db, room);

      return send(res, 200, {
        ok: true,
        room: {
          room_code: room.room_code,
          shared_text: room.shared_text,
          created_at: room.created_at,
          expires_at: expiresAt
        }
      });
    }

    if (action === "update-text") {
      const { text } = body;

      if (typeof text !== "string" ||
          text.length > MAX_TEXT_LENGTH) {
        return send(res, 400, {
          ok: false,
          error: `Text must be a string of at most ${MAX_TEXT_LENGTH} characters`
        });
      }

      const now = new Date().toISOString();
      const expiry = newExpiry();

      const { data, error } = await db
        .from("share_rooms")
        .update({
          shared_text: text,
          last_activity_at: now,
          expires_at: expiry
        })
        .eq("id", room.id)
        .select("room_code, shared_text, expires_at")
        .single();

      if (error) {
        console.error("Shared text update failed:", error.code);
        return send(res, 503, {
          ok: false,
          error: "Unable to update shared text"
        });
      }

      return send(res, 200, {
        ok: true,
        room: data
      });
    }

    return send(res, 400, {
      ok: false,
      error: "Unsupported action"
    });
  } catch (error) {
    if (error.message === "SERVER_CONFIG_MISSING") {
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

    console.error("Room API request failed:", error?.name, error?.message, error?.stack);
    return send(res, 500, {
      ok: false,
      error: "Internal server error"
    });
  }
}
