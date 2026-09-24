// R-DUB's Lawn Care — Backend Worker
// ------------------------------------------------------------------
// This is the real API server: authentication, sessions, and the
// data endpoints the app will call instead of window.storage.
//
// PERMISSION MODEL (matches what was agreed):
//   - owner: sees everything
//   - crew:  sees everything EXCEPT expenses, inventory, time logs,
//            and the payment_status/paid_at fields on jobs
//
// STATUS: Auth is fully built. Two data endpoints (estimates, expenses)
// are fully built as templates — one "everyone, but strip sensitive
// fields" pattern, one "owner-only" pattern. The remaining tables
// (bookings, appointments, customer_profiles, inventory_items,
// time_logs) follow one of these two exact patterns — see the
// bottom of this file for the mechanical checklist.
// ------------------------------------------------------------------

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const OWNER_ONLY_PREFIXES = ["/api/expenses", "/api/inventory-items", "/api/time-logs"];

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function corsPreflightResponse() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

// ---- Password hashing (Web Crypto — no Node crypto in Workers) ----

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(derivedBits)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, salt, expectedHash) {
  const computed = await hashPassword(password, salt);
  return computed === expectedHash;
}

function generateToken() {
  return crypto.randomUUID() + crypto.randomUUID();
}

function getToken(request) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

async function getUserFromToken(db, token) {
  if (!token) return null;
  const session = await db.prepare("SELECT * FROM sessions WHERE token = ? AND expires_at > ?").bind(token, Date.now()).first();
  if (!session) return null;
  const user = await db.prepare("SELECT id, username, role, name, disabled FROM users WHERE id = ?").bind(session.user_id).first();
  if (!user || user.disabled) return null;
  return user;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const db = env.DB; // D1 binding — set this name when wiring up the Worker

    if (request.method === "OPTIONS") return corsPreflightResponse();

    try {
      // ================= AUTH ROUTES (no login required) =================

      // Bootstraps the very first account. Only works once — refuses if an
      // owner already exists, so this can't be used to create a second one.
      if (path === "/api/auth/register-owner" && request.method === "POST") {
        const existingOwner = await db.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();
        if (existingOwner) return errorResponse("Owner already exists. Ask them for an invite instead.", 403);

        const { username, password, name } = await request.json();
        if (!username || !password) return errorResponse("Username and password required.");
        if (password.length < 8) return errorResponse("Password must be at least 8 characters.");

        const existing = await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) return errorResponse("That username is taken.");

        const salt = crypto.randomUUID();
        const hash = await hashPassword(password, salt);
        const result = await db.prepare(
          "INSERT INTO users (username, password_hash, role, name, created_at) VALUES (?, ?, 'owner', ?, ?)"
        ).bind(username, `${salt}:${hash}`, name || username, Date.now()).run();

        const token = generateToken();
        await db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
          .bind(token, result.meta.last_row_id, Date.now(), Date.now() + SESSION_DURATION_MS).run();

        return jsonResponse({ token, user: { username, role: "owner", name: name || username } });
      }

      // Owner invites a crew member by creating their account directly.
      // (Simpler and safer than an email-invite-link flow for a 2-3 person
      // team — the owner sets a temporary password and hands it over.)
      if (path === "/api/auth/invite" && request.method === "POST") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Only the owner can add crew members.", 403);

        const { username, password, name, role } = await request.json();
        if (!username || !password) return errorResponse("Username and password required.");
        if (password.length < 8) return errorResponse("Password must be at least 8 characters.");
        const accountRole = role === "manager" ? "manager" : "crew";

        const existing = await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) return errorResponse("That username is taken.");

        const salt = crypto.randomUUID();
        const hash = await hashPassword(password, salt);
        await db.prepare(
          "INSERT INTO users (username, password_hash, role, name, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(username, `${salt}:${hash}`, accountRole, name || username, Date.now()).run();

        return jsonResponse({ success: true, username, role: accountRole });
      }

      if (path === "/api/auth/users" && request.method === "GET") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Owner access only.", 403);
        const { results } = await db.prepare("SELECT id, username, role, name, created_at, disabled FROM users ORDER BY created_at ASC").all();
        return jsonResponse({ users: results });
      }

      if (path.startsWith("/api/auth/users/") && path.endsWith("/pause") && request.method === "POST") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Owner access only.", 403);
        const targetUsername = decodeURIComponent(path.split("/api/auth/users/")[1].replace(/\/pause$/, ""));
        if (targetUsername === user.username) return errorResponse("You can't pause your own account.", 400);
        const target = await db.prepare("SELECT id, role FROM users WHERE username = ?").bind(targetUsername).first();
        if (!target) return errorResponse("No account with that username.", 404);
        if (target.role === "owner") return errorResponse("Can't pause the owner account.", 400);
        const data = await request.json();
        await db.prepare("UPDATE users SET disabled = ? WHERE id = ?").bind(data.disabled ? 1 : 0, target.id).run();
        // Pausing kills any session immediately — the account is checked live on every
        // request (see getUserFromToken), not just at login, so this takes effect on
        // that account's very next action, not just their next login attempt.
        if (data.disabled) await db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/auth/users/") && request.method === "DELETE") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Owner access only.", 403);
        const targetUsername = decodeURIComponent(path.split("/api/auth/users/")[1]);
        if (targetUsername === user.username) return errorResponse("You can't remove your own account.", 400);
        const target = await db.prepare("SELECT id, role FROM users WHERE username = ?").bind(targetUsername).first();
        if (!target) return errorResponse("No account with that username.", 404);
        if (target.role === "owner") return errorResponse("Can't remove the owner account.", 400);
        await db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id).run();
        await db.prepare("DELETE FROM users WHERE id = ?").bind(target.id).run();
        return jsonResponse({ success: true });
      }

      // Public website content is readable without a crew login. Owner edits are handled below.
      if (path === "/api/site-content" && request.method === "GET") {
        const { results } = await db.prepare("SELECT key, value FROM site_content ORDER BY key").all();
        const content = {};
        for (const row of results || []) content[row.key] = row.value;
        return jsonResponse({ content });
      }


      // ================= PUBLIC WEBSITE: 2027 INTEREST LIST =================
      // No login required. Sends a lead only to R-DUB's verified destination.
      if (path === "/api/quote" && request.method === "POST") {
        const origin = request.headers.get("Origin") || "";
        const allowedOrigins = new Set([
          "https://rdubslawncare.com",
          "https://www.rdubslawncare.com"
        ]);
        if (origin && !allowedOrigins.has(origin)) return errorResponse("Website origin not allowed.", 403);
        if (!env.EMAIL || typeof env.EMAIL.send !== "function") return errorResponse("Email service is not configured.", 503);

        const data = await request.json();
        const clean = (value, max) => String(value ?? "").trim().slice(0, max);
        const name = clean(data.name, 120);
        const phone = clean(data.phone, 50);
        const address = clean(data.address, 240);
        const frequency = clean(data.frequency, 100);
        const lot = clean(data.lot, 100);
        const notes = clean(data.notes, 2000);
        // Honeypot: real visitors never see/fill this field.
        if (clean(data.website, 200)) return jsonResponse({ success: true });
        if (!name || !phone || !address) return errorResponse("Name, phone, and property address are required.");

        const submitted = new Date().toLocaleString("en-US", { timeZone: "America/Detroit", dateStyle: "full", timeStyle: "short" });
        const subject = `2027 INTEREST LEAD — ${name} — ${frequency || "Lawn Care"}`;
        const text = [
          "R-DUB'S LAWN CARE — NEW 2027 INTEREST LEAD",
          "",
          `Customer: ${name}`,
          `Phone: ${phone}`,
          `Property: ${address}`,
          `Interested in: ${frequency || "Not specified"}`,
          `Approx. lot size: ${lot || "Not specified"}`,
          "",
          "PROPERTY NOTES",
          notes || "None provided",
          "",
          `Submitted: ${submitted} ET`,
          "",
          "Interest request only — not a confirmed route reservation or service appointment."
        ].join("\n");
        const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
        const html = `
          <div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;color:#17121c">
            <div style="background:#17101e;border-top:6px solid #65ff32;padding:24px;color:#fff">
              <div style="color:#65ff32;font-size:12px;font-weight:800;letter-spacing:1.5px">R-DUB'S LAWN CARE</div>
              <h1 style="margin:8px 0 0;font-size:28px">New 2027 Interest Lead</h1>
            </div>
            <div style="padding:24px;border:1px solid #ddd;border-top:0">
              <h2 style="margin-top:0">${esc(name)}</h2>
              <p><strong>Phone:</strong> ${esc(phone)}<br><strong>Property:</strong> ${esc(address)}</p>
              <p><strong>Interested in:</strong> ${esc(frequency || "Not specified")}<br><strong>Approx. lot size:</strong> ${esc(lot || "Not specified")}</p>
              <div style="background:#f5f2f7;padding:16px;border-radius:10px"><strong>Property notes</strong><br>${esc(notes || "None provided").replace(/\n/g,"<br>")}</div>
              <p style="font-size:12px;color:#666;margin-top:22px">Submitted ${esc(submitted)} ET<br>Interest request only — not a confirmed route reservation or service appointment.</p>
            </div>
          </div>`;

        const result = await env.EMAIL.send({
          to: "rdubslawncare@gmail.com",
          from: "quote@rdubslawncare.com",
          replyTo: "quote@rdubslawncare.com",
          subject,
          text,
          html
        });
        return jsonResponse({ success: true, messageId: result && result.messageId ? result.messageId : null });
      }

      // A forgot-password request does not reveal whether a username exists.
      if (path === "/api/auth/forgot-password" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        if (!username) return errorResponse("Enter your username.");
        const target = await db.prepare("SELECT id, username FROM users WHERE username = ? AND disabled = 0").bind(username).first();
        if (target) {
          const existing = await db.prepare("SELECT id FROM password_reset_requests WHERE user_id = ? AND status = 'pending' LIMIT 1").bind(target.id).first();
          if (!existing) {
            await db.prepare("INSERT INTO password_reset_requests (id, user_id, username, requested_at, status) VALUES (?, ?, ?, ?, 'pending')")
              .bind(crypto.randomUUID(), target.id, target.username, Date.now()).run();
          }
        }
        return jsonResponse({ success: true, message: "If that account exists, the owner will see the reset request." });
      }

      if (path === "/api/auth/login" && request.method === "POST") {
        const { username, password } = await request.json();
        if (!username || !password) return errorResponse("Username and password required.");

        const user = await db.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!user) return errorResponse("Invalid username or password.", 401);

        const [salt, expectedHash] = user.password_hash.split(":");
        const valid = await verifyPassword(password, salt, expectedHash);
        if (!valid) return errorResponse("Invalid username or password.", 401);
        if (user.disabled) return errorResponse("This account has been paused. Contact the owner.", 403);

        const token = generateToken();
        await db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
          .bind(token, user.id, Date.now(), Date.now() + SESSION_DURATION_MS).run();

        return jsonResponse({ token, user: { username: user.username, role: user.role, name: user.name } });
      }

      if (path === "/api/auth/logout" && request.method === "POST") {
        const token = getToken(request);
        if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        return jsonResponse({ success: true });
      }

      if (path === "/api/auth/me" && request.method === "GET") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user) return errorResponse("Not logged in.", 401);
        return jsonResponse({ user });
      }

      // ================= EVERYTHING BELOW REQUIRES LOGIN =================

      const user = await getUserFromToken(db, getToken(request));
      if (!user) return errorResponse("Not logged in.", 401);

      if (OWNER_ONLY_PREFIXES.some((p) => path.startsWith(p)) && user.role !== "owner") {
        return errorResponse("Owner access only.", 403);
      }

      // ================= ACCOUNT / TEAM SETTINGS =================
      if (path === "/api/auth/change-password" && request.method === "POST") {
        const { currentPassword, newPassword } = await request.json();
        if (!currentPassword || !newPassword) return errorResponse("Current and new password are required.");
        if (newPassword.length < 8) return errorResponse("New password must be at least 8 characters.");
        const row = await db.prepare("SELECT password_hash FROM users WHERE id = ?").bind(user.id).first();
        if (!row || !row.password_hash) return errorResponse("Account password could not be verified.", 400);
        const [salt, expectedHash] = row.password_hash.split(":");
        if (!(await verifyPassword(currentPassword, salt, expectedHash))) return errorResponse("Current password is incorrect.", 401);
        const newSalt = crypto.randomUUID();
        const newHash = await hashPassword(newPassword, newSalt);
        await db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(`${newSalt}:${newHash}`, user.id).run();
        // Keep the current session, but invalidate every other logged-in device.
        const currentToken = getToken(request);
        await db.prepare("DELETE FROM sessions WHERE user_id = ? AND token <> ?").bind(user.id, currentToken).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/auth/users/") && path.endsWith("/reset-password") && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const targetUsername = decodeURIComponent(path.split("/api/auth/users/")[1].replace(/\/reset-password$/, ""));
        if (targetUsername === user.username) return errorResponse("Use Change Password for your own account.", 400);
        const target = await db.prepare("SELECT id, role FROM users WHERE username = ?").bind(targetUsername).first();
        if (!target) return errorResponse("No account with that username.", 404);
        if (target.role === "owner") return errorResponse("The owner password cannot be reset here.", 400);
        const { newPassword } = await request.json();
        if (!newPassword || newPassword.length < 8) return errorResponse("New password must be at least 8 characters.");
        const salt = crypto.randomUUID();
        const hash = await hashPassword(newPassword, salt);
        await db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(`${salt}:${hash}`, target.id).run();
        await db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id).run();
        await db.prepare("UPDATE password_reset_requests SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE user_id = ? AND status = 'pending'")
          .bind(Date.now(), user.username, target.id).run();
        return jsonResponse({ success: true });
      }

      if (path === "/api/auth/password-reset-requests" && request.method === "GET") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const { results } = await db.prepare("SELECT id, username, requested_at, status FROM password_reset_requests WHERE status = 'pending' ORDER BY requested_at DESC").all();
        return jsonResponse({ requests: results || [] });
      }

      if (path === "/api/crew-schedules" && request.method === "GET") {
        const { results } = await db.prepare(
          "SELECT u.username, u.name, u.role, cs.schedule_json FROM users u LEFT JOIN crew_schedules cs ON cs.user_id = u.id WHERE u.disabled = 0 ORDER BY CASE u.role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, u.name, u.username"
        ).all();
        const schedules = (results || []).map((r) => ({ username: r.username, name: r.name, role: r.role, schedule: r.schedule_json || "{}" }));
        return jsonResponse({ schedules });
      }

      if (path.startsWith("/api/crew-schedules/") && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const targetUsername = decodeURIComponent(path.split("/api/crew-schedules/")[1]);
        const target = await db.prepare("SELECT id FROM users WHERE username = ?").bind(targetUsername).first();
        if (!target) return errorResponse("No account with that username.", 404);
        const { schedule } = await request.json();
        if (!schedule || typeof schedule !== "object") return errorResponse("A schedule is required.");
        const scheduleJson = JSON.stringify(schedule);
        await db.prepare(
          "INSERT INTO crew_schedules (user_id, username, schedule_json, updated_at, updated_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, schedule_json = excluded.schedule_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by"
        ).bind(target.id, targetUsername, scheduleJson, Date.now(), user.username).run();
        return jsonResponse({ success: true });
      }

      if (path === "/api/site-content" && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const body = await request.json();
        if (!body.content || typeof body.content !== "object" || Array.isArray(body.content)) return errorResponse("Content is required.");
        const entries = Object.entries(body.content);
        for (const [key, value] of entries) {
          if (!/^[A-Za-z0-9_-]{1,80}$/.test(key)) return errorResponse("Invalid content key.");
          const stored = value == null ? "" : String(value);
          if (stored.length > 10000) return errorResponse(`Content for ${key} is too long.`);
          await db.prepare(
            "INSERT INTO site_content (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by"
          ).bind(key, stored, Date.now(), user.username).run();
        }
        return jsonResponse({ success: true });
      }

      // ================= EMPLOYEE WORKDAY TIME CLOCK =================
      // Separate from /api/time-logs, which measures individual job duration.
      // Punch timestamps are generated here on the server, never accepted from the client.

      if (path === "/api/time-clock/status" && request.method === "GET") {
        const activeEntry = await db.prepare(
          "SELECT * FROM employee_time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1"
        ).bind(user.id).first();
        const now = Date.now();
        const requestedWeekStart = Number(url.searchParams.get("weekStart"));
        const weekStart = Number.isFinite(requestedWeekStart) && requestedWeekStart > 0 ? requestedWeekStart : now - (7 * 24 * 60 * 60 * 1000);
        const { results: weekEntries } = await db.prepare(
          "SELECT clock_in, clock_out FROM employee_time_entries WHERE user_id = ? AND clock_in >= ? ORDER BY clock_in ASC"
        ).bind(user.id, weekStart).all();
        let weekMinutes = 0;
        for (const e of weekEntries) weekMinutes += Math.max(0, Math.floor(((e.clock_out || now) - e.clock_in) / 60000));
        return jsonResponse({ activeEntry, weekMinutes, weekStart });
      }

      if (path === "/api/time-clock/in" && request.method === "POST") {
        const existing = await db.prepare(
          "SELECT id FROM employee_time_entries WHERE user_id = ? AND clock_out IS NULL LIMIT 1"
        ).bind(user.id).first();
        if (existing) return errorResponse("You're already clocked in.", 409);
        const now = Date.now();
        const id = crypto.randomUUID();
        await db.prepare(`
          INSERT INTO employee_time_entries (id, user_id, username, employee_name, clock_in, clock_out, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
        `).bind(id, user.id, user.username, user.name || user.username, now, now, now).run();
        return jsonResponse({ success: true, id, clockIn: now });
      }

      if (path === "/api/time-clock/out" && request.method === "POST") {
        const active = await db.prepare(
          "SELECT * FROM employee_time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1"
        ).bind(user.id).first();
        if (!active) return errorResponse("You're not currently clocked in.", 409);
        const now = Date.now();
        if (now < active.clock_in) return errorResponse("Clock-out time is invalid.", 409);
        await db.prepare("UPDATE employee_time_entries SET clock_out = ?, updated_at = ? WHERE id = ?")
          .bind(now, now, active.id).run();
        return jsonResponse({ success: true, id: active.id, clockOut: now });
      }

      if (path === "/api/time-clock/me" && request.method === "GET") {
        const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 50));
        const { results } = await db.prepare(
          "SELECT * FROM employee_time_entries WHERE user_id = ? ORDER BY clock_in DESC LIMIT ?"
        ).bind(user.id, limit).all();
        return jsonResponse({ entries: results });
      }

      if (path === "/api/time-clock/team" && request.method === "GET") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit")) || 100));
        const { results } = await db.prepare(
          "SELECT * FROM employee_time_entries ORDER BY clock_in DESC LIMIT ?"
        ).bind(limit).all();
        const { results: active } = await db.prepare(
          "SELECT * FROM employee_time_entries WHERE clock_out IS NULL ORDER BY clock_in ASC"
        ).all();
        return jsonResponse({ entries: results, active });
      }

      if (path === "/api/time-clock/admin/edit" && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const data = await request.json();
        if (!data.id) return errorResponse("Entry id is required.");
        if (!data.reason || !String(data.reason).trim()) return errorResponse("A correction reason is required.");
        const before = await db.prepare("SELECT * FROM employee_time_entries WHERE id = ?").bind(data.id).first();
        if (!before) return errorResponse("Time entry not found.", 404);
        const clockIn = Number(data.clockIn ?? before.clock_in);
        const clockOut = data.clockOut === null ? null : Number(data.clockOut ?? before.clock_out);
        if (!Number.isFinite(clockIn) || (clockOut !== null && (!Number.isFinite(clockOut) || clockOut < clockIn))) {
          return errorResponse("Corrected punch times are invalid.");
        }
        const now = Date.now();
        await db.prepare(`UPDATE employee_time_entries SET clock_in = ?, clock_out = ?, updated_at = ?, edited_at = ?, edited_by = ?, edit_reason = ? WHERE id = ?`)
          .bind(clockIn, clockOut, now, now, user.username, String(data.reason).trim(), data.id).run();
        const after = await db.prepare("SELECT * FROM employee_time_entries WHERE id = ?").bind(data.id).first();
        await db.prepare(`INSERT INTO employee_time_audit (id, entry_id, action, changed_by, changed_at, before_json, after_json, reason) VALUES (?, ?, 'edit', ?, ?, ?, ?, ?)`)
          .bind(crypto.randomUUID(), data.id, user.username, now, JSON.stringify(before), JSON.stringify(after), String(data.reason).trim()).run();
        return jsonResponse({ success: true, entry: after });
      }

      if (path.startsWith("/api/time-clock/audit/") && request.method === "GET") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const entryId = decodeURIComponent(path.split("/api/time-clock/audit/")[1]);
        const { results } = await db.prepare("SELECT * FROM employee_time_audit WHERE entry_id = ? ORDER BY changed_at DESC").bind(entryId).all();
        return jsonResponse({ audit: results });
      }

      // ---- TEMPLATE PATTERN A: shared data, sensitive fields stripped ----
      // estimates/jobs are visible to everyone, but a crew member never
      // sees payment_status or paid_at on the way out.

      if (path === "/api/estimates" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM estimates ORDER BY timestamp DESC").all();
        const filtered = user.role === "owner"
          ? results
          : results.map(({ payment_status, paid_at, ...rest }) => rest);
        return jsonResponse({ estimates: filtered });
      }

      if (path === "/api/estimates" && request.method === "POST") {
        const data = await request.json();
        if (!data.timestamp) return errorResponse("timestamp is required.");
        // A crew member's write can't touch payment fields even if they send them.
        const paymentStatus = user.role === "owner" ? (data.paymentStatus || "unpaid") : undefined;
        const paidAt = user.role === "owner" ? (data.paidAt || null) : undefined;

        // Once a job is agreed or completed, its price is locked for crew — they can
        // still update status, notes, or photos, but the total/pricing details fall
        // back to whatever is already stored, even if the request tried to change them.
        let total = data.total || 0;
        let lines = JSON.stringify(data.lines || []);
        let builderState = JSON.stringify(data.builderState || {});
        if (user.role !== "owner") {
          const existing = await db.prepare("SELECT status, total, lines, builder_state FROM estimates WHERE timestamp = ?").bind(data.timestamp).first();
          if (existing && (existing.status === "confirmed" || existing.status === "completed")) {
            total = existing.total;
            lines = existing.lines;
            builderState = existing.builder_state;
          }
        }

        await db.prepare(`
          INSERT INTO estimates (timestamp, customer_name, phone, address, is_recurring, total, lines, builder_state, status, payment_status, paid_at, has_photo, has_before_photo)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(timestamp) DO UPDATE SET
            customer_name = excluded.customer_name, phone = excluded.phone, address = excluded.address,
            is_recurring = excluded.is_recurring, total = excluded.total, lines = excluded.lines,
            builder_state = excluded.builder_state, status = excluded.status,
            payment_status = COALESCE(excluded.payment_status, estimates.payment_status),
            paid_at = COALESCE(excluded.paid_at, estimates.paid_at),
            has_photo = excluded.has_photo, has_before_photo = excluded.has_before_photo
        `).bind(
          data.timestamp, data.customerName || "", data.phone || "", data.address || "",
          data.isRecurring ? 1 : 0, total, lines,
          builderState, data.status || "pending",
          paymentStatus ?? null, paidAt ?? null,
          data.hasPhoto ? 1 : 0, data.hasBeforePhoto ? 1 : 0
        ).run();
        return jsonResponse({ success: true });
      }

      // This was genuinely missing — estimate deletion (discarding a pending or
      // declined quote) has had no backend route at all, so it's been silently
      // 404ing since the app moved off window.storage. Fixed here, and owner-only
      // per the anti-grief pass, since there's no legitimate crew need to
      // permanently delete a quote record rather than just declining it.
      if (path.startsWith("/api/estimates/") && request.method === "DELETE") {
        if (user.role !== "owner") return errorResponse("Only the owner can delete a quote record.", 403);
        const id = decodeURIComponent(path.split("/api/estimates/")[1]);
        await db.prepare("DELETE FROM estimates WHERE timestamp = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      // ---- TEMPLATE PATTERN B: owner-only data (gate already enforced above) ----

      if (path === "/api/expenses" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM expenses ORDER BY timestamp DESC").all();
        return jsonResponse({ expenses: results });
      }

      if (path === "/api/expenses" && request.method === "POST") {
        const data = await request.json();
        if (!data.timestamp) return errorResponse("timestamp is required.");
        await db.prepare(`
          INSERT INTO expenses (timestamp, date, category, description, amount, vendor, job_timestamp, job_customer_name)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(timestamp) DO UPDATE SET
            date = excluded.date, category = excluded.category, description = excluded.description,
            amount = excluded.amount, vendor = excluded.vendor,
            job_timestamp = excluded.job_timestamp, job_customer_name = excluded.job_customer_name
        `).bind(
          data.timestamp, data.date, data.category, data.description, data.amount,
          data.vendor || "", data.jobTimestamp || null, data.jobCustomerName || null
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/expenses/") && request.method === "DELETE") {
        const timestamp = path.split("/").pop();
        await db.prepare("DELETE FROM expenses WHERE timestamp = ?").bind(timestamp).run();
        return jsonResponse({ success: true });
      }

      // ---- bookings (Pattern A: shared, no sensitive fields) ----

      if (path === "/api/bookings" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM bookings ORDER BY start_ms ASC").all();
        return jsonResponse({ bookings: results });
      }

      if (path === "/api/bookings" && request.method === "POST") {
        const data = await request.json();
        if (!data.id) return errorResponse("id is required.");
        await db.prepare(`
          INSERT INTO bookings (id, date_iso, slot_id, slot_label, start_ms, phone, customer_name, status, job_timestamp, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            date_iso = excluded.date_iso, slot_id = excluded.slot_id, slot_label = excluded.slot_label,
            start_ms = excluded.start_ms, phone = excluded.phone, customer_name = excluded.customer_name,
            status = excluded.status, job_timestamp = excluded.job_timestamp
        `).bind(
          data.id, data.dateISO ?? null, data.slotId ?? null, data.slotLabel ?? null, data.startMs ?? null,
          data.phone || "", data.customerName || "", data.status || "accepted",
          data.jobTimestamp || null, data.createdAt || Date.now()
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/bookings/") && request.method === "DELETE") {
        const id = decodeURIComponent(path.split("/api/bookings/")[1]);
        await db.prepare("DELETE FROM bookings WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      // Bulk day-wide reschedule (rain-day tool) — owner-only. The frontend still does
      // all the slot-finding; this just applies the resulting batch of moves atomically,
      // so the one-click "clear a whole day" action can't be triggered by crew, while
      // their everyday single-booking cancellations (the generic endpoints above) stay
      // untouched.
      if (path === "/api/bookings/bulk-reschedule" && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Only the owner can bulk-reschedule a day.", 403);
        const data = await request.json();
        const moves = Array.isArray(data.moves) ? data.moves : [];
        let applied = 0;
        for (const m of moves) {
          try {
            if (m.oldBookingKey) await db.prepare("DELETE FROM bookings WHERE id = ?").bind(m.oldBookingKey).run();
            if (m.newBooking) {
              const b = m.newBooking;
              await db.prepare(`
                INSERT INTO bookings (id, date_iso, slot_id, slot_label, start_ms, phone, customer_name, status, job_timestamp, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET date_iso=excluded.date_iso, slot_id=excluded.slot_id, slot_label=excluded.slot_label,
                  start_ms=excluded.start_ms, phone=excluded.phone, customer_name=excluded.customer_name, status=excluded.status, job_timestamp=excluded.job_timestamp
              `).bind(b.id, b.dateISO ?? null, b.slotId ?? null, b.slotLabel ?? null, b.startMs ?? null, b.phone || "", b.customerName || "", b.status || "accepted", b.jobTimestamp || null, b.createdAt || Date.now()).run();
            }
            if (m.oldApptId) await db.prepare("DELETE FROM appointments WHERE id = ?").bind(m.oldApptId).run();
            if (m.newAppt) {
              const a = m.newAppt;
              await db.prepare(`
                INSERT INTO appointments (id, phone, customer_name, confirmed, date_iso, slot_id, slot_label, start_ms, deadline, deadline_hours, addon_selections, addon_prices, mowing_enabled, mowing_type, lot_tier_id, mowing_price, custom_items, notes, fee_applied, fee_amount, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET phone=excluded.phone, customer_name=excluded.customer_name, confirmed=excluded.confirmed,
                  date_iso=excluded.date_iso, slot_id=excluded.slot_id, slot_label=excluded.slot_label, start_ms=excluded.start_ms,
                  deadline=excluded.deadline, deadline_hours=excluded.deadline_hours, addon_selections=excluded.addon_selections,
                  addon_prices=excluded.addon_prices, mowing_enabled=excluded.mowing_enabled, mowing_type=excluded.mowing_type,
                  lot_tier_id=excluded.lot_tier_id, mowing_price=excluded.mowing_price, custom_items=excluded.custom_items,
                  notes=excluded.notes, fee_applied=excluded.fee_applied, fee_amount=excluded.fee_amount, updated_at=excluded.updated_at
              `).bind(a.id, a.phone || "", a.customerName || "", a.confirmed ? 1 : 0, a.dateISO ?? null, a.slotId ?? null, a.slotLabel ?? null, a.startMs ?? null, a.deadline || null, a.deadlineHours || null, JSON.stringify(a.addonSelections || {}), JSON.stringify(a.addonPrices || {}), a.mowingEnabled ? 1 : 0, a.mowingType || null, a.lotTierId || null, a.mowingPrice || 0, JSON.stringify(a.customItems || []), a.notes || "", a.feeApplied ? 1 : 0, a.feeAmount || 0, a.updatedAt || Date.now()).run();
            }
            applied++;
          } catch (e) {
            // skip this one move, keep going with the rest — matches how the frontend already handles a single failed move within the batch
          }
        }
        return jsonResponse({ success: true, applied, total: moves.length });
      }

      // ---- appointments (Pattern A: shared, no sensitive fields) ----

      if (path === "/api/appointments" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM appointments ORDER BY start_ms ASC").all();
        return jsonResponse({ appointments: results });
      }

      if (path === "/api/appointments" && request.method === "POST") {
        const data = await request.json();
        if (!data.id) return errorResponse("id is required.");
        await db.prepare(`
          INSERT INTO appointments (id, phone, customer_name, confirmed, date_iso, slot_id, slot_label, start_ms, deadline, deadline_hours, addon_selections, addon_prices, mowing_enabled, mowing_type, lot_tier_id, mowing_price, custom_items, notes, fee_applied, fee_amount, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            phone = excluded.phone, customer_name = excluded.customer_name, confirmed = excluded.confirmed,
            date_iso = excluded.date_iso, slot_id = excluded.slot_id, slot_label = excluded.slot_label,
            start_ms = excluded.start_ms, deadline = excluded.deadline, deadline_hours = excluded.deadline_hours,
            addon_selections = excluded.addon_selections, addon_prices = excluded.addon_prices,
            mowing_enabled = excluded.mowing_enabled, mowing_type = excluded.mowing_type,
            lot_tier_id = excluded.lot_tier_id, mowing_price = excluded.mowing_price,
            custom_items = excluded.custom_items, notes = excluded.notes,
            fee_applied = excluded.fee_applied, fee_amount = excluded.fee_amount, updated_at = excluded.updated_at
        `).bind(
          data.id, data.phone || "", data.customerName || "", data.confirmed ? 1 : 0,
          data.dateISO ?? null, data.slotId ?? null, data.slotLabel ?? null, data.startMs ?? null, data.deadline || null, data.deadlineHours || null,
          JSON.stringify(data.addonSelections || {}), JSON.stringify(data.addonPrices || {}),
          data.mowingEnabled ? 1 : 0, data.mowingType || null, data.lotTierId || null, data.mowingPrice || 0,
          JSON.stringify(data.customItems || []), data.notes || "",
          data.feeApplied ? 1 : 0, data.feeAmount || 0, data.updatedAt || Date.now()
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/appointments/") && request.method === "DELETE") {
        const id = decodeURIComponent(path.split("/api/appointments/")[1]);
        await db.prepare("DELETE FROM appointments WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      // ---- customer_profiles (Pattern A: shared, no sensitive fields) ----

      if (path === "/api/customer-profiles" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM customer_profiles").all();
        return jsonResponse({ profiles: results });
      }

      if (path === "/api/customer-profiles" && request.method === "POST") {
        const data = await request.json();
        if (!data.phone) return errorResponse("phone is required.");
        await db.prepare(`
          INSERT INTO customer_profiles (phone, name, address, notes, contact_preference, paused, paused_until)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(phone) DO UPDATE SET
            name = excluded.name, address = excluded.address, notes = excluded.notes,
            contact_preference = excluded.contact_preference, paused = excluded.paused, paused_until = excluded.paused_until
        `).bind(
          data.phone, data.name || "", data.address || "", data.notes || "",
          data.contactPreference || null, data.paused ? 1 : 0, data.pausedUntil || null
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/customer-profiles/") && request.method === "DELETE") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Only the owner can delete a customer.", 403);
        const phone = decodeURIComponent(path.split("/api/customer-profiles/")[1]);

        const profile = await db.prepare("SELECT * FROM customer_profiles WHERE phone = ?").bind(phone).first();
        const { results: estimates } = await db.prepare("SELECT * FROM estimates WHERE phone = ?").bind(phone).all();
        const { results: appointments } = await db.prepare("SELECT * FROM appointments WHERE phone = ?").bind(phone).all();
        const { results: bookings } = await db.prepare("SELECT * FROM bookings WHERE phone = ?").bind(phone).all();

        // Snapshot everything before touching it, so this is reversible.
        await db.prepare(`
          INSERT INTO deleted_customers_log (id, phone, deleted_by, deleted_by_role, deleted_at, profile_snapshot, estimates_snapshot, appointments_snapshot, bookings_snapshot, restored)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        `).bind(
          `del-${Date.now()}`, phone, user.username, user.role, Date.now(),
          JSON.stringify(profile || null), JSON.stringify(estimates), JSON.stringify(appointments), JSON.stringify(bookings)
        ).run();

        await db.prepare("DELETE FROM estimates WHERE phone = ?").bind(phone).run();
        await db.prepare("DELETE FROM appointments WHERE phone = ?").bind(phone).run();
        await db.prepare("DELETE FROM bookings WHERE phone = ?").bind(phone).run();
        await db.prepare("DELETE FROM customer_profiles WHERE phone = ?").bind(phone).run();

        return jsonResponse({ success: true });
      }

      if (path === "/api/deleted-customers" && request.method === "GET") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Owner access only.", 403);
        const { results } = await db.prepare("SELECT id, phone, deleted_by, deleted_by_role, deleted_at, restored, profile_snapshot FROM deleted_customers_log ORDER BY deleted_at DESC LIMIT 50").all();
        return jsonResponse({ deletedCustomers: results });
      }

      if (path.startsWith("/api/deleted-customers/") && path.endsWith("/restore") && request.method === "POST") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Owner access only.", 403);
        const id = decodeURIComponent(path.split("/api/deleted-customers/")[1].replace(/\/restore$/, ""));
        const log = await db.prepare("SELECT * FROM deleted_customers_log WHERE id = ?").bind(id).first();
        if (!log) return errorResponse("No deletion record with that id.", 404);
        if (log.restored) return errorResponse("This has already been restored.", 400);

        const profile = JSON.parse(log.profile_snapshot);
        if (profile) {
          await db.prepare(`
            INSERT INTO customer_profiles (phone, name, address, notes, contact_preference, paused, paused_until)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(phone) DO UPDATE SET name=excluded.name, address=excluded.address, notes=excluded.notes,
              contact_preference=excluded.contact_preference, paused=excluded.paused, paused_until=excluded.paused_until
          `).bind(profile.phone, profile.name, profile.address, profile.notes, profile.contact_preference, profile.paused, profile.paused_until).run();
        }
        for (const e of JSON.parse(log.estimates_snapshot)) {
          await db.prepare(`
            INSERT INTO estimates (timestamp, customer_name, phone, address, is_recurring, total, lines, builder_state, status, payment_status, paid_at, has_photo, has_before_photo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(timestamp) DO NOTHING
          `).bind(e.timestamp, e.customer_name, e.phone, e.address, e.is_recurring, e.total, e.lines, e.builder_state, e.status, e.payment_status, e.paid_at, e.has_photo, e.has_before_photo).run();
        }
        for (const a of JSON.parse(log.appointments_snapshot)) {
          await db.prepare(`
            INSERT INTO appointments (id, phone, customer_name, confirmed, date_iso, slot_id, slot_label, start_ms, deadline, deadline_hours, addon_selections, addon_prices, mowing_enabled, mowing_type, lot_tier_id, mowing_price, custom_items, notes, fee_applied, fee_amount, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
          `).bind(a.id, a.phone, a.customer_name, a.confirmed, a.date_iso, a.slot_id, a.slot_label, a.start_ms, a.deadline, a.deadline_hours, a.addon_selections, a.addon_prices, a.mowing_enabled, a.mowing_type, a.lot_tier_id, a.mowing_price, a.custom_items, a.notes, a.fee_applied, a.fee_amount, a.updated_at).run();
        }
        for (const b of JSON.parse(log.bookings_snapshot)) {
          await db.prepare(`
            INSERT INTO bookings (id, date_iso, slot_id, slot_label, start_ms, phone, customer_name, status, job_timestamp, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
          `).bind(b.id, b.date_iso, b.slot_id, b.slot_label, b.start_ms, b.phone, b.customer_name, b.status, b.job_timestamp, b.created_at).run();
        }
        await db.prepare("UPDATE deleted_customers_log SET restored = 1 WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/customers/") && path.endsWith("/change-phone") && request.method === "POST") {
        const user = await getUserFromToken(db, getToken(request));
        if (!user || user.role !== "owner") return errorResponse("Only the owner can change a customer's phone number.", 403);
        const oldPhone = decodeURIComponent(path.split("/api/customers/")[1].replace(/\/change-phone$/, ""));
        const data = await request.json();
        const newPhone = (data.newPhone || "").trim();
        if (!newPhone || newPhone.length < 7) return errorResponse("Enter a valid phone number.");
        if (newPhone !== oldPhone) {
          const conflict = await db.prepare("SELECT phone FROM customer_profiles WHERE phone = ?").bind(newPhone).first();
          if (conflict) return errorResponse("That number already belongs to another customer.");
        }

        await db.prepare(`
          INSERT INTO customer_profiles (phone, name, address, notes, contact_preference, paused, paused_until)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(phone) DO UPDATE SET name=excluded.name, address=excluded.address, notes=excluded.notes,
            contact_preference=excluded.contact_preference, paused=excluded.paused, paused_until=excluded.paused_until
        `).bind(newPhone, data.name || "", data.address || "", data.notes || "", data.contactPreference || null, data.paused ? 1 : 0, data.pausedUntil || null).run();

        if (newPhone !== oldPhone) {
          await db.prepare("DELETE FROM customer_profiles WHERE phone = ?").bind(oldPhone).run();
          await db.prepare("UPDATE estimates SET phone = ? WHERE phone = ?").bind(newPhone, oldPhone).run();
          await db.prepare("UPDATE bookings SET phone = ? WHERE phone = ?").bind(newPhone, oldPhone).run();

          const { results: appts } = await db.prepare("SELECT * FROM appointments WHERE phone = ?").bind(oldPhone).all();
          for (const a of appts) {
            const newId = a.id.replace(`${oldPhone}:`, `${newPhone}:`);
            await db.prepare(`
              INSERT INTO appointments (id, phone, customer_name, confirmed, date_iso, slot_id, slot_label, start_ms, deadline, deadline_hours, addon_selections, addon_prices, mowing_enabled, mowing_type, lot_tier_id, mowing_price, custom_items, notes, fee_applied, fee_amount, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO NOTHING
            `).bind(newId, newPhone, a.customer_name, a.confirmed, a.date_iso, a.slot_id, a.slot_label, a.start_ms, a.deadline, a.deadline_hours, a.addon_selections, a.addon_prices, a.mowing_enabled, a.mowing_type, a.lot_tier_id, a.mowing_price, a.custom_items, a.notes, a.fee_applied, a.fee_amount, a.updated_at).run();
            await db.prepare("DELETE FROM appointments WHERE id = ?").bind(a.id).run();
          }
        }

        return jsonResponse({ success: true, phone: newPhone });
      }

      // ---- inventory_items (Pattern B: owner-only, gate enforced above) ----

      if (path === "/api/inventory-items" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM inventory_items ORDER BY name ASC").all();
        return jsonResponse({ inventoryItems: results });
      }

      if (path === "/api/inventory-items" && request.method === "POST") {
        const data = await request.json();
        if (!data.id) return errorResponse("id is required.");
        await db.prepare(`
          INSERT INTO inventory_items (id, name, unit, current_qty, low_stock_threshold, cost_per_unit, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            name = excluded.name, unit = excluded.unit, current_qty = excluded.current_qty,
            low_stock_threshold = excluded.low_stock_threshold, cost_per_unit = excluded.cost_per_unit,
            updated_at = excluded.updated_at
        `).bind(
          data.id, data.name || "", data.unit || "", data.currentQty || 0,
          data.lowStockThreshold || 0, data.costPerUnit || 0, data.updatedAt || Date.now()
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/inventory-items/") && request.method === "DELETE") {
        const id = decodeURIComponent(path.split("/api/inventory-items/")[1]);
        await db.prepare("DELETE FROM inventory_items WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      // ---- time_logs (Pattern B: owner-only, gate enforced above) ----

      if (path === "/api/time-logs" && request.method === "GET") {
        const { results } = await db.prepare("SELECT * FROM time_logs ORDER BY timestamp DESC").all();
        return jsonResponse({ timeLogs: results });
      }

      if (path === "/api/time-logs" && request.method === "POST") {
        const data = await request.json();
        if (!data.timestamp) return errorResponse("timestamp is required.");
        await db.prepare(`
          INSERT INTO time_logs (timestamp, job_timestamp, customer_name, address, started_at, ended_at, duration_min)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(timestamp) DO UPDATE SET
            job_timestamp = excluded.job_timestamp, customer_name = excluded.customer_name, address = excluded.address,
            started_at = excluded.started_at, ended_at = excluded.ended_at, duration_min = excluded.duration_min
        `).bind(
          data.timestamp, data.jobTimestamp || null, data.customerName || "", data.address || "",
          data.startedAt, data.endedAt, data.durationMin
        ).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/time-logs/") && request.method === "DELETE") {
        const timestamp = path.split("/api/time-logs/")[1];
        await db.prepare("DELETE FROM time_logs WHERE timestamp = ?").bind(timestamp).run();
        return jsonResponse({ success: true });
      }

      // ---- availability (single shared row, everyone can read, owner writes) ----

      if (path === "/api/availability" && request.method === "GET") {
        const row = await db.prepare("SELECT template FROM availability WHERE id = 1").first();
        return jsonResponse({ template: row ? JSON.parse(row.template) : null });
      }

      if (path === "/api/availability" && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const data = await request.json();
        await db.prepare(`
          INSERT INTO availability (id, template) VALUES (1, ?)
          ON CONFLICT(id) DO UPDATE SET template = excluded.template
        `).bind(JSON.stringify(data.template || {})).run();
        return jsonResponse({ success: true });
      }

      // ---- bug reports (anyone logged in can submit; only the owner can view/manage) ----

      if (path === "/api/bug-reports" && request.method === "POST") {
        const data = await request.json();
        if (!data.id || !data.description) return errorResponse("id and description are required.");
        await db.prepare(`
          INSERT INTO bug_reports (id, reported_by, reported_by_role, description, context, status, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          data.id, user.username, user.role, data.description, data.context || "",
          "open", Date.now()
        ).run();
        return jsonResponse({ success: true });
      }

      if (path === "/api/bug-reports" && request.method === "GET") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const { results } = await db.prepare("SELECT * FROM bug_reports ORDER BY created_at DESC").all();
        return jsonResponse({ bugReports: results });
      }

      if (path.startsWith("/api/bug-reports/") && request.method === "POST") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const id = decodeURIComponent(path.split("/api/bug-reports/")[1]);
        const data = await request.json();
        await db.prepare("UPDATE bug_reports SET status = ? WHERE id = ?").bind(data.status || "open", id).run();
        return jsonResponse({ success: true });
      }

      if (path.startsWith("/api/bug-reports/") && request.method === "DELETE") {
        if (user.role !== "owner") return errorResponse("Owner access only.", 403);
        const id = decodeURIComponent(path.split("/api/bug-reports/")[1]);
        await db.prepare("DELETE FROM bug_reports WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      }

      return errorResponse("Not found.", 404);
    } catch (err) {
      return errorResponse("Server error: " + err.message, 500);
    }
  },
};
