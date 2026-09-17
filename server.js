/*
 * One-to-one messenger server. Uses only Node.js built-ins: no API keys,
 * database account, or npm install is required.
 */
const http = require("node:http");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const DATABASE_FILE = path.join(DATA_DIR, "messenger.json");
const MAX_BODY = 26 * 1024 * 1024;

function freshDatabase() {
  return { users: [], sessions: {}, requests: [], conversations: [], messages: [] };
}
function loadDatabase() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(DATABASE_FILE)) {
    fs.writeFileSync(DATABASE_FILE, JSON.stringify(freshDatabase(), null, 2));
  }
  try {
    return { ...freshDatabase(), ...JSON.parse(fs.readFileSync(DATABASE_FILE, "utf8")) };
  } catch {
    return freshDatabase();
  }
}
let database = loadDatabase();
let writeQueue = Promise.resolve();

// WebRTC call setup data is short-lived. Audio/video travel directly
// between participants; server only relays encrypted setup signals.
let callEvents = [];
let nextCallEventId = 1;

function saveDatabase() {
  writeQueue = writeQueue
    .catch((err) => console.error("Previous database write failed:", err))
    .then(async () => {
      try {
        await fsp.writeFile(DATABASE_FILE, JSON.stringify(database, null, 2));
      } catch (err) {
        console.error("Failed to write database file:", err);
      }
    });
  return writeQueue;
}

function id() {
  return crypto.randomUUID();
}
function cleanText(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validUsername(value) {
  return /^[a-z0-9_]{3,30}$/.test(value);
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (error, key) =>
      error ? reject(error) : resolve({ salt, hash: key.toString("hex") })
    )
  );
}
async function matchesPassword(password, user) {
  const result = await hashPassword(password, user.salt);
  return crypto.timingSafeEqual(
    Buffer.from(result.hash, "hex"),
    Buffer.from(user.passwordHash, "hex")
  );
}
function parseCookies(request) {
  return Object.fromEntries(
    (request.headers.cookie || "")
      .split(";")
      .map((item) => item.trim().split(/=(.*)/s))
      .filter(([key]) => key)
      .map(([key, value]) => [key, decodeURIComponent(value || "")])
  );
}
function sessionUser(request) {
  const token = parseCookies(request).kip_session;
  const session = token && database.sessions[token];
  if (!session) return null;
  const ageMs = Date.now() - new Date(session.createdAt).getTime();
  if (isNaN(ageMs) || ageMs > 30 * 24 * 60 * 60 * 1000) {
    delete database.sessions[token];
    saveDatabase();
    return null;
  }
  return database.users.find((user) => user.id === session.userId);
}
function publicUser(user) {
  return { id: user.id, name: user.name, username: user.username, bio: user.bio || "" };
}

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Referrer-Policy": "strict-origin-when-cross-origin"
};

function send(response, status, payload, headers = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...SECURITY_HEADERS,
    ...headers
  });
  response.end(JSON.stringify(payload));
}
function fail(response, status, message) {
  send(response, status, { error: message });
}
function requireUser(request, response) {
  const user = sessionUser(request);
  if (!user) {
    fail(response, 401, "Please log in to continue.");
    return null;
  }
  return user;
}
function readBody(request) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let size = 0;
    request.on("data", (part) => {
      size += part.length;
      if (size > MAX_BODY) {
        reject(new Error("Upload is too large. Maximum size is 25 MB."));
        request.destroy();
      } else {
        parts.push(part);
      }
    });
    request.on("end", () => resolve(Buffer.concat(parts)));
    request.on("error", reject);
  });
}
async function readJson(request) {
  const raw = await readBody(request);
  try {
    return raw.length ? JSON.parse(raw.toString("utf8")) : {};
  } catch {
    throw new Error("Invalid request data.");
  }
}
function multipart(request, buffer) {
  const match = /boundary=([^;]+)/i.exec(request.headers["content-type"] || "");
  if (!match) throw new Error("Malformed upload.");
  const boundary = Buffer.from(`--${match[1].replaceAll('"', "")}`);
  const divider = Buffer.from(`\r\n--${match[1].replaceAll('"', "")}`);
  let position = buffer.indexOf(boundary) + boundary.length + 2;
  const fields = {};
  let file = null;
  while (position > boundary.length) {
    const headersEnd = buffer.indexOf(Buffer.from("\r\n\r\n"), position);
    if (headersEnd < 0) break;
    const headers = buffer.slice(position, headersEnd).toString("utf8");
    const next = buffer.indexOf(divider, headersEnd + 4);
    if (next < 0) break;
    const value = buffer.slice(headersEnd + 4, next);
    const disposition = /name="([^"]+)"(?:; filename="([^"]*)")?/i.exec(headers);
    const type = /content-type:\s*([^\r\n]+)/i.exec(headers);
    if (disposition) {
      if (disposition[2] !== undefined && disposition[2]) {
        file = {
          field: disposition[1],
          name: path.basename(disposition[2]),
          type: type?.[1].trim() || "application/octet-stream",
          buffer: value
        };
      } else {
        fields[disposition[1]] = value.toString("utf8");
      }
    }
    position = next + divider.length;
    if (buffer.slice(position, position + 2).toString() === "--") break;
    position += 2;
  }
  return { fields, file };
}
function findConversation(conversationId, userId) {
  return database.conversations.find(
    (chat) => chat.id === conversationId && (chat.userA === userId || chat.userB === userId)
  );
}
function counterpart(chat, userId) {
  return chat.userA === userId ? chat.userB : chat.userA;
}
function requestView(item, userId) {
  return {
    id: item.id,
    status: item.status,
    direction: item.senderId === userId ? "sent" : "received",
    person: publicUser(
      database.users.find(
        (user) => user.id === (item.senderId === userId ? item.receiverId : item.senderId)
      )
    ),
    createdAt: item.createdAt
  };
}
function pruneCallEvents() {
  const oldest = Date.now() - 10 * 60 * 1000;
  callEvents = callEvents.filter((event) => new Date(event.createdAt).getTime() >= oldest);
}
function validCallPayload(type, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  if (type === "offer" || type === "answer") {
    return (
      typeof payload.description?.type === "string" &&
      typeof payload.description?.sdp === "string" &&
      payload.description.sdp.length <= 20000
    );
  }
  if (type === "candidate") return JSON.stringify(payload.candidate || {}).length <= 6000;
  return Object.keys(payload).length === 0;
}

async function api(request, response, pathname, url) {
  if (request.method === "POST" && pathname === "/api/auth/signup") {
    const body = await readJson(request);
    const email = cleanText(body.email, 120).toLowerCase();
    const name = cleanText(body.name, 60);
    const username = cleanText(body.username, 30).toLowerCase().replace(/^@/, "");
    const password = typeof body.password === "string" ? body.password : "";
    if (!/^\S+@\S+\.\S+$/.test(email) || !name || !validUsername(username) || password.length < 8) {
      return fail(response, 400, "Use a valid email, name, username, and an 8-character password.");
    }
    if (database.users.some((user) => user.email === email)) {
      return fail(response, 409, "An account with that email already exists.");
    }
    if (database.users.some((user) => user.username === username)) {
      return fail(response, 409, "That username is already taken.");
    }
    const credential = await hashPassword(password);
    const user = {
      id: id(),
      email,
      name,
      username,
      bio: "",
      passwordHash: credential.hash,
      salt: credential.salt,
      createdAt: new Date().toISOString()
    };
    database.users.push(user);
    const token = id();
    database.sessions[token] = { userId: user.id, createdAt: new Date().toISOString() };
    await saveDatabase();
    return send(
      response,
      201,
      { user: publicUser(user) },
      { "Set-Cookie": `kip_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000` }
    );
  }

  if (request.method === "POST" && pathname === "/api/auth/login") {
    const body = await readJson(request);
    const email = cleanText(body.email, 120).toLowerCase();
    const user = database.users.find((item) => item.email === email);
    if (!user || !(await matchesPassword(body.password || "", user))) {
      return fail(response, 401, "Incorrect email or password.");
    }
    const token = id();
    database.sessions[token] = { userId: user.id, createdAt: new Date().toISOString() };
    await saveDatabase();
    return send(
      response,
      200,
      { user: publicUser(user) },
      { "Set-Cookie": `kip_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000` }
    );
  }

  if (request.method === "POST" && pathname === "/api/auth/logout") {
    const token = parseCookies(request).kip_session;
    if (token) {
      delete database.sessions[token];
      await saveDatabase();
    }
    return send(
      response,
      200,
      { ok: true },
      { "Set-Cookie": "kip_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" }
    );
  }

  if (request.method === "POST" && pathname === "/api/auth/reset-password") {
    const body = await readJson(request);
    const email = cleanText(body.email, 120).toLowerCase();
    const username = cleanText(body.username, 30).toLowerCase().replace(/^@/, "");
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
    if (!email || newPassword.length < 8) {
      return fail(response, 400, "Please enter a valid email and a new password with at least 8 characters.");
    }
    const user = database.users.find(
      (item) => item.email === email && (!username || item.username === username)
    );
    if (!user) return fail(response, 404, "No user found matching that email address (and username).");
    const credential = await hashPassword(newPassword);
    user.passwordHash = credential.hash;
    user.salt = credential.salt;
    for (const [token, session] of Object.entries(database.sessions)) {
      if (session.userId === user.id) delete database.sessions[token];
    }
    await saveDatabase();
    return send(response, 200, {
      ok: true,
      message: "Password has been successfully reset. Please log in with your new password."
    });
  }

  if (request.method === "GET" && pathname === "/api/me") {
    const user = requireUser(request, response);
    if (user) send(response, 200, { user: publicUser(user) });
    return;
  }

  const user = requireUser(request, response);
  if (!user) return;

  if (request.method === "POST" && pathname === "/api/auth/change-password") {
    const body = await readJson(request);
    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
    if (!currentPassword || newPassword.length < 8) {
      return fail(response, 400, "Provide your current password and a new password of at least 8 characters.");
    }
    if (!(await matchesPassword(currentPassword, user))) {
      return fail(response, 401, "Current password is incorrect.");
    }
    const credential = await hashPassword(newPassword);
    user.passwordHash = credential.hash;
    user.salt = credential.salt;
    await saveDatabase();
    return send(response, 200, { ok: true, message: "Password updated successfully." });
  }

  if (request.method === "PATCH" && pathname === "/api/me") {
    const body = await readJson(request);
    const name = cleanText(body.name, 60);
    const username = cleanText(body.username, 30).toLowerCase().replace(/^@/, "");
    const bio = cleanText(body.bio, 160);
    if (!name || !validUsername(username)) {
      return fail(response, 400, "Use a display name and a valid username.");
    }
    if (database.users.some((item) => item.id !== user.id && item.username === username)) {
      return fail(response, 409, "That username is already taken.");
    }
    user.name = name;
    user.username = username;
    user.bio = bio;
    await saveDatabase();
    return send(response, 200, { user: publicUser(user) });
  }

  if (request.method === "GET" && pathname === "/api/users") {
    const query = cleanText(url.searchParams.get("q") || "", 60).toLowerCase();
    const people = database.users
      .filter(
        (item) =>
          item.id !== user.id &&
          (!query || `${item.name} ${item.username}`.toLowerCase().includes(query))
      )
      .slice(0, 30)
      .map(publicUser);
    return send(response, 200, { users: people });
  }

  if (request.method === "GET" && pathname === "/api/requests") {
    return send(response, 200, {
      requests: database.requests
        .filter((item) => item.senderId === user.id || item.receiverId === user.id)
        .map((item) => requestView(item, user.id))
    });
  }

  if (request.method === "POST" && pathname === "/api/requests") {
    const body = await readJson(request);
    const receiver = database.users.find((item) => item.id === body.userId);
    if (!receiver || receiver.id === user.id) return fail(response, 400, "Choose another user.");
    const existing = database.requests.find(
      (item) =>
        (item.senderId === user.id && item.receiverId === receiver.id) ||
        (item.senderId === receiver.id && item.receiverId === user.id)
    );
    if (existing) {
      return fail(
        response,
        409,
        existing.status === "accepted"
          ? "You already have a private chat."
          : "A request already exists between you two."
      );
    }
    database.requests.push({
      id: id(),
      senderId: user.id,
      receiverId: receiver.id,
      status: "pending",
      createdAt: new Date().toISOString()
    });
    await saveDatabase();
    return send(response, 201, { ok: true });
  }

  const responseMatch = /^\/api\/requests\/([\w-]+)\/respond$/.exec(pathname);
  if (request.method === "POST" && responseMatch) {
    const item = database.requests.find(
      (requestItem) => requestItem.id === responseMatch[1] && requestItem.receiverId === user.id
    );
    const body = await readJson(request);
    if (!item || item.status !== "pending") {
      return fail(response, 404, "That pending request was not found.");
    }
    if (!["accepted", "declined"].includes(body.action)) {
      return fail(response, 400, "Invalid response.");
    }
    item.status = body.action;
    item.respondedAt = new Date().toISOString();
    let conversation = null;
    if (body.action === "accepted") {
      conversation = {
        id: id(),
        userA: item.senderId,
        userB: item.receiverId,
        createdAt: new Date().toISOString()
      };
      database.conversations.push(conversation);
    }
    await saveDatabase();
    return send(response, 200, { conversationId: conversation?.id || null });
  }

  if (request.method === "GET" && pathname === "/api/conversations") {
    const conversations = database.conversations
      .filter((chat) => chat.userA === user.id || chat.userB === user.id)
      .map((chat) => {
        const latest = database.messages
          .filter((message) => message.conversationId === chat.id)
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
        return {
          id: chat.id,
          person: publicUser(
            database.users.find((item) => item.id === counterpart(chat, user.id))
          ),
          createdAt: chat.createdAt,
          latest: latest
            ? { text: latest.text, mediaType: latest.mediaType, createdAt: latest.createdAt }
            : null
        };
      })
      .sort((a, b) =>
        (b.latest?.createdAt || b.createdAt).localeCompare(a.latest?.createdAt || a.createdAt)
      );
    return send(response, 200, { conversations });
  }

  const callEventMatch = /^\/api\/conversations\/([\w-]+)\/call-events$/.exec(pathname);
  if (callEventMatch && request.method === "GET") {
    const chat = findConversation(callEventMatch[1], user.id);
    if (!chat) return fail(response, 404, "Conversation not found.");
    pruneCallEvents();
    const after = Math.max(0, Number(url.searchParams.get("after")) || 0);
    const events = callEvents.filter(
      (event) =>
        event.conversationId === chat.id && event.senderId !== user.id && event.id > after
    );
    return send(response, 200, { events, cursor: nextCallEventId - 1 });
  }
  if (callEventMatch && request.method === "POST") {
    const chat = findConversation(callEventMatch[1], user.id);
    if (!chat) return fail(response, 404, "Conversation not found.");
    const body = await readJson(request);
    const type = cleanText(body.type, 20);
    const callId = cleanText(body.callId, 80);
    if (
      !["offer", "answer", "candidate", "end", "decline"].includes(type) ||
      !/^[a-zA-Z0-9-]{8,80}$/.test(callId) ||
      !validCallPayload(type, body.payload || {})
    ) {
      return fail(response, 400, "Invalid call signal.");
    }
    pruneCallEvents();
    callEvents.push({
      id: nextCallEventId++,
      conversationId: chat.id,
      senderId: user.id,
      type,
      callId,
      payload: body.payload || {},
      createdAt: new Date().toISOString()
    });
    return send(response, 201, { ok: true });
  }

  const messageMatch = /^\/api\/conversations\/([\w-]+)\/messages$/.exec(pathname);
  if (messageMatch && request.method === "GET") {
    const chat = findConversation(messageMatch[1], user.id);
    if (!chat) return fail(response, 404, "Conversation not found.");
    return send(response, 200, {
      conversation: {
        id: chat.id,
        person: publicUser(
          database.users.find((item) => item.id === counterpart(chat, user.id))
        )
      },
      messages: database.messages
        .filter((message) => message.conversationId === chat.id)
        .map((message) => ({
          ...message,
          mine: message.senderId === user.id,
          mediaUrl: message.mediaFile ? `/api/media/${message.id}` : null
        }))
    });
  }
  if (messageMatch && request.method === "POST") {
    const chat = findConversation(messageMatch[1], user.id);
    if (!chat) return fail(response, 404, "Conversation not found.");
    const parsed = multipart(request, await readBody(request));
    const text = cleanText(parsed.fields.text, 4000);
    const file = parsed.file;
    if (!text && !file) return fail(response, 400, "Write a message or attach media.");
    if (file && !/^(image|video|audio)\//.test(file.type)) {
      return fail(response, 400, "Only image, video, and audio files are allowed.");
    }
    const message = {
      id: id(),
      conversationId: chat.id,
      senderId: user.id,
      text,
      mediaType: file?.type.split("/")[0] || null,
      mediaName: file?.name || null,
      mediaMime: file?.type || null,
      mediaFile: null,
      createdAt: new Date().toISOString()
    };
    if (file) {
      const extension =
        path.extname(file.name).replace(/[^.a-zA-Z0-9]/g, "").slice(0, 10) || ".bin";
      message.mediaFile = `${message.id}${extension}`;
      await fsp.writeFile(path.join(UPLOAD_DIR, message.mediaFile), file.buffer);
    }
    database.messages.push(message);
    await saveDatabase();
    return send(response, 201, {
      message: {
        ...message,
        mine: true,
        mediaUrl: message.mediaFile ? `/api/media/${message.id}` : null
      }
    });
  }

  const mediaMatch = /^\/api\/media\/([\w-]+)$/.exec(pathname);
  if (request.method === "GET" && mediaMatch) {
    const message = database.messages.find((item) => item.id === mediaMatch[1]);
    if (!message || !message.mediaFile || !findConversation(message.conversationId, user.id)) {
      return fail(response, 404, "Media not found.");
    }
    const file = path.join(UPLOAD_DIR, message.mediaFile);
    if (!fs.existsSync(file)) return fail(response, 404, "Media file not found.");
    response.writeHead(200, {
      "Content-Type": message.mediaMime,
      "Content-Length": fs.statSync(file).size,
      "Cache-Control": "private, max-age=3600"
    });
    fs.createReadStream(file).pipe(response);
    return;
  }

  fail(response, 404, "Not found.");
}

function redirect(response, location) {
  response.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  response.end();
}

/*
 * The frontend is a single-page app: every non-API route serves index.html.
 * The client-side router decides which screen to render from the URL.
 */
function serveSite(request, response, pathname) {
  const user = sessionUser(request);
  const cleanPath = pathname.replace(/\/+$/, "") || "/";

  const authPages = ["/login", "/login.html", "/forgot-password", "/forgot-password.html"];
  const protectedPages = [
    "/",
    "/index",
    "/index.html",
    "/profile",
    "/profile.html",
    "/discover",
    "/discover.html",
    "/requests",
    "/requests.html"
  ];

  if (user && authPages.includes(cleanPath)) return redirect(response, "/");
  if (!user && protectedPages.includes(cleanPath)) return redirect(response, "/login");

  // Anything else that isn't an API route returns the SPA shell.
  const file = path.join(ROOT, "index.html");
  if (!fs.existsSync(file)) return fail(response, 500, "index.html not found.");
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    ...SECURITY_HEADERS
  });
  fs.createReadStream(file).pipe(response);
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  try {
    if (url.pathname.startsWith("/api/")) await api(request, response, url.pathname, url);
    else serveSite(request, response, url.pathname);
  } catch (error) {
    console.error("Server error:", error);
    if (!response.headersSent) {
      fail(response, error.message.includes("too large") ? 413 : 400, error.message || "Something went wrong.");
    } else {
      response.end();
    }
  }
});

process.on("unhandledRejection", (reason) => console.error("Unhandled Rejection:", reason));
process.on("uncaughtException", (error) => console.error("Uncaught Exception:", error));

async function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Saving data and shutting down cleanly...`);
  try {
    await saveDatabase();
  } catch {}
  server.close(() => {
    console.log("Server stopped.");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

server.listen(PORT, () =>
  console.log(`keep it private is running at http://localhost:${PORT}`)
);
