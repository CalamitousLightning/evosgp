# app.py - EVOSGPT WebCore (Day32)
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
import time
import hmac
import hashlib
import re
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, jsonify, has_request_context
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# Optional: Coinbase Commerce python client (if installed)
try:
    from coinbase_commerce.client import Client as CoinbaseClient
    from coinbase_commerce.webhook import Webhook, SignatureVerificationError
    COINBASE_AVAILABLE = True
except Exception:
    COINBASE_AVAILABLE = False


# ---------- ENVIRONMENT ----------
from dotenv import load_dotenv
load_dotenv()

FLASK_SECRET = os.getenv("FLASK_SECRET", "fallback_secret")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET")
COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
MTN_API_KEY = os.getenv("MTN_API_KEY")

app = Flask(__name__)
app.secret_key = FLASK_SECRET


# ---------- GLOBAL LOGGER ----------
def log_action(user_id, action, details="N/A"):
    """Logs actions into the activity_log table with optional details"""
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
            (user_id, action, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[LOGGER ERROR] {e}")


def log_suspicious(activity_type, details="N/A"):
    """Logs suspicious activity into a separate JSON file"""
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": request.remote_addr if has_request_context() else "unknown",
        "user_agent": str(request.user_agent) if has_request_context() else "unknown",
        "activity": activity_type,
        "details": details
    }
    os.makedirs("logs", exist_ok=True)
    path = os.path.join("logs", "suspicious.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


import os
import sqlite3
import psycopg2  # needed only if using Supabase/Postgres
from psycopg2 import sql

# ---------- DB INIT ----------
def init_db():
    db_mode = os.getenv("DB_MODE", "sqlite")  # "sqlite" for local, "supabase" for prod

    if db_mode == "sqlite":
        os.makedirs("database", exist_ok=True)
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        # memory (recreated always)
        c.execute("DROP TABLE IF EXISTS memory")
        c.execute("""
            CREATE TABLE memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_input TEXT,
                bot_response TEXT,
                system_msg INTEGER DEFAULT 0,
                time_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # analytics
        c.execute('''
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tier TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # users
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # same ALTERs / defaults as you had
        safe_alters_sqlite(c)

        # purchases
        c.execute('''
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tier TEXT,
                payment_method TEXT,
                reference TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # coupons
        c.execute('''
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY,
                tier TEXT,
                used INTEGER DEFAULT 0
            )
        ''')

        # activity log
        c.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        try:
            c.execute("ALTER TABLE activity_log ADD COLUMN details TEXT")
        except sqlite3.OperationalError:
            pass

        # seed coupons
        c.execute("SELECT COUNT(*) FROM coupons")
        if c.fetchone()[0] == 0:
            c.executemany("INSERT INTO coupons (code, tier) VALUES (?, ?)", [
                ("FREECORE", "Core"),
                ("KINGME", "King"),
                ("BOOSTPRO", "Pro")
            ])

        conn.commit()
        conn.close()

    elif db_mode == "supabase":
        conn = psycopg2.connect(os.getenv("SUPABASE_DB_URL"))
        cur = conn.cursor()

        # Postgres doesn’t need "ALTER" try/except — define schema directly
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            tier TEXT DEFAULT 'Basic',
            status TEXT DEFAULT 'active',
            email TEXT,
            referral_code TEXT UNIQUE,
            referrals_used INTEGER DEFAULT 0,
            upgrade_expiry TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            user_input TEXT,
            bot_response TEXT,
            system_msg INTEGER DEFAULT 0,
            time_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            tier TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            tier TEXT,
            payment_method TEXT,
            reference TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS coupons (
            code TEXT PRIMARY KEY,
            tier TEXT,
            used INTEGER DEFAULT 0
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # seed coupons if empty
        cur.execute("SELECT COUNT(*) FROM coupons")
        if cur.fetchone()[0] == 0:
            cur.executemany("INSERT INTO coupons (code, tier) VALUES (%s, %s)", [
                ("FREECORE", "Core"),
                ("KINGME", "King"),
                ("BOOSTPRO", "Pro")
            ])

        conn.commit()
        cur.close()
        conn.close()


# helper for SQLite alters (keeps your safe try/excepts)
def safe_alters_sqlite(c):
    alters = [
        "ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'Basic'",
        "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN referral_code TEXT",
        "ALTER TABLE users ADD COLUMN referrals_used INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN upgrade_expiry DATETIME",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)"
    ]
    for stmt in alters:
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # backfills
    c.execute("UPDATE users SET tier = 'Basic' WHERE tier IS NULL")
    c.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
    c.execute("UPDATE users SET referrals_used = 0 WHERE referrals_used IS NULL")



def enforce_memory_limit(user_id, tier):
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM memory WHERE user_id = ?", (user_id,))
    total = c.fetchone()[0]

    if tier == "Basic":
        limit = 30
    elif tier == "Core":
        limit = 100
    else:
        conn.close()
        return

    if total > limit:
        to_delete = total - limit
        c.execute("""
            DELETE FROM memory 
            WHERE id IN (
                SELECT id FROM memory WHERE user_id = ? ORDER BY id ASC LIMIT ?
            )
        """, (user_id, to_delete))
        conn.commit()
    conn.close()


# ---------- AI HELPERS ----------
def local_llm(prompt: str) -> str:
    return f"[Local LLM] You said: {prompt}"


def _openai_chat(prompt: str, model: str) -> Optional[str]:
    try:
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post("https://api.openai.com/v1/chat/completions",
                             headers=headers, json=data, timeout=20)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return None
    except Exception as e:
        print(f"[OpenAI error] {e}")
        return None


def gpt4o_mini(prompt: str) -> str:
    return _openai_chat(prompt, "gpt-4o-mini") or f"[Mini-Fallback] {prompt}"


def gpt4o(prompt: str) -> str:
    return _openai_chat(prompt, "gpt-4o") or f"[4o-Fallback] {prompt}"


# ---------------- ROUTES CONTINUE (chat, login, register, etc) ----------------
# (keep all your existing routes unchanged here)


# ---------- Basic firewall & rate limiting ----------
failed_logins = {}
blocked_ips = {}
last_message_time = {}

@app.before_request
def basic_firewall():
    ip = request.remote_addr
    uid = session.get("user_id", f"ip:{ip}")  # fallback to IP if not logged in

    # temporary block window
    if ip in blocked_ips and time.time() - blocked_ips[ip] < 300:
        log_suspicious("Blocked IP", f"Temporary blocked IP {ip}")
        return redirect(url_for("index"))

    # Only scan POSTs on risky endpoints
    if request.method == "POST" and request.endpoint in ["login", "register", "index", "upgrade", "paystack_init", "create_crypto_charge"]:
        post_data = request.get_data().decode(errors="ignore") if request.get_data() else ""
        query_data = " ".join(request.args.values()) if request.args else ""
        bad_patterns = ["drop table", "union select", "--", ";--", "' or '1'='1"]
        for p in bad_patterns:
            if p in post_data.lower() or p in query_data.lower():
                log_suspicious("SQL Injection Attempt", post_data or query_data)
                return redirect(url_for("index"))
        # XSS
        if re.search(r"<script.*?>", post_data, re.IGNORECASE):
            log_suspicious("XSS Attempt", post_data)
            return redirect(url_for("index"))

    # ✅ Rate limit chat messages to 2s per user (or IP if guest)
    if request.endpoint == "index" and request.method == "POST":
        now = time.time()
        if uid in last_message_time and now - last_message_time[uid] < 2:
            log_suspicious("Rate Limit", f"Too many messages from {uid}")
            flash("You're sending messages too fast! Slow down.")
            return redirect(url_for("index"))
        last_message_time[uid] = now


#................ stealth self test ....................
@app.before_request
def stealth_selftest():
    if int(time.time()) % 600 < 2:  # every ~10min
        log_suspicious("StealthTest", "DarkEvo logger heartbeat check")


# ---------- helper: idempotent purchase mark ----------
def mark_purchase_if_not_exists(user_id, tier, method, reference=None):
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    if reference:
        c.execute("SELECT COUNT(*) FROM purchases WHERE reference = ?", (reference,))
        if c.fetchone()[0] > 0:
            conn.close()
            return False
    # insert
    c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
              (user_id, tier, method, reference))
    c.execute("INSERT INTO analytics (tier) VALUES (?)", (tier,))
    conn.commit()
    conn.close()
    return True


# --- new helper function ---
def update_user_tier(user_id, new_tier):
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, user_id))
    conn.commit()
    conn.close()


def update_user_status(user_id, new_status):
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()


# ---------- HOME / CHAT ----------
@app.route("/", methods=["GET", "POST"])
def index():
    # enforce guest users -> Basic tier only
    if "user_id" not in session:
        session["tier"] = "Basic"

    tier = session.get("tier", "Basic")
    tier_icon = {"Basic":"🧊","Core":"⚛","Pro":"⚡","King":"👑","Founder":"🔑"}.get(tier,"")
    show_memory = tier in ["Core","Pro","King","Founder"]
    show_analytics = tier in ["Pro","King","Founder"]
    show_admin = tier in ["King","Founder"]

    user_input, response = None, None

    if request.method == "POST":
        # --- Tier selection change ---
        if "tier" in request.form and "user_id" in session:
            selected_tier = request.form.get("tier")
            session["tier"] = selected_tier
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("INSERT INTO analytics (tier) VALUES (?)", (selected_tier,))
            conn.commit()
            conn.close()
            return redirect(url_for("index"))

        # --- Handle chat ---
        user_input = request.form.get("message", "")
        ui = user_input.lower()
        if "hello" in ui:
            response = f"Hi {tier_icon} {tier} User! How can I assist you today?"
        elif "who are you" in ui:
            response = "I am EVOSGPT — your personal AI assistant."
        elif "help" in ui:
            response = "Sure! Ask me anything — I'm here to help."
        elif "bye" in ui:
            response = "Goodbye! I’ll be here when you return."
        elif "upgrade me" in ui:
            response = "[SYSTEM] Upgrade initiated. Redirecting you to upgrade page..."
            return redirect(url_for("upgrade"))
        else:
            response = f"I heard you say: {user_input}"

        # --- Save to memory ---
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        is_system = 1 if response.startswith("[SYSTEM]") else 0
        uid_param = session.get("user_id")  # may be None for guests
        c.execute(
            "INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, ?)",
            (uid_param, user_input, response, is_system)
        )
        conn.commit()

        # --- Log activity (only if logged in) ---
        if "user_id" in session:
            c.execute("INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
                      (session["user_id"], "chat", f"User: {user_input} | Bot: {response}"))

        # --- Memory limits by tier (PER USER) ---
        if tier == "Basic":
            c.execute("""
                DELETE FROM memory
                WHERE (user_id IS ?)
                  AND id NOT IN (
                      SELECT id FROM memory
                      WHERE (user_id IS ?)
                      ORDER BY id DESC
                      LIMIT 30
                  )
            """, (uid_param, uid_param))
        elif tier == "Core":
            c.execute("""
                DELETE FROM memory
                WHERE (user_id IS ?)
                  AND id NOT IN (
                      SELECT id FROM memory
                      WHERE (user_id IS ?)
                      ORDER BY id DESC
                      LIMIT 100
                  )
            """, (uid_param, uid_param))

        conn.commit()
        conn.close()

    # --- Show chat history & notices (for higher tiers only) ---
    chat_history, system_notices = [], []
    if show_memory:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        uid_param = session.get("user_id")  # None for guests

        # User chat history (last 10 for this user only)
        c.execute("""
            SELECT user_input, bot_response
            FROM memory
            WHERE system_msg = 0 AND (user_id IS ?)
            ORDER BY id DESC
            LIMIT 10
        """, (uid_param,))
        chat_history = c.fetchall()

        # System notices (system_msg = 1) for this user
        c.execute("""
            SELECT bot_response, time_added
            FROM memory
            WHERE system_msg = 1 AND (user_id IS ?)
            ORDER BY id DESC
            LIMIT 5
        """, (uid_param,))
        system_notices = c.fetchall()
        conn.close()

    return render_template(
        "index.html",
        user_input=user_input,
        response=response,
        chat_history=chat_history,
        system_notices=system_notices,
        tier=tier,
        icon=tier_icon,
        show_memory=show_memory,
        show_analytics=show_analytics,
        show_admin=show_admin,
        logged_in=("user_id" in session)  # ✅ safe check
    )


# ---------- CHAT ----------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_msg = data.get("message", "")
    ui = user_msg.lower().strip()
    tier = session.get("tier", "Basic")

    reply = None

    # --- Founder Unlock (hidden path) ---
    if "user_id" in session:
        seq = session.get("founder_seq", 0)
        if seq == 0 and ui == "evosgpt where you created":
            reply = "lab"
            session["founder_seq"] = 1
        elif seq == 1 and ui == "ghanaherewecome":
            reply = "are you coming to Ghana?"
            session["founder_seq"] = 2
        elif seq == 2 and ui == "nameless":
            reply = "[SYSTEM] Founder tier unlocked. Welcome, hidden user."
            session["founder_seq"] = 0
            session["tier"] = "Founder"

            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("UPDATE users SET tier = ? WHERE id = ?", ("Founder", session["user_id"]))
            conn.commit()
            conn.close()

            log_action(session["user_id"], "Founder Unlock", "Secret phrase sequence completed")
        else:
            if seq > 0 and ui not in ["evosgpt where you created", "ghanaherewecome", "nameless"]:
                session["founder_seq"] = 0  # reset on wrong input

    # --- Tier-based LLM logic ---
    if reply is None:
        if tier == "Basic":
            reply = local_llm(user_msg)
        elif tier == "Core":
            if len(user_msg) < 50:
                reply = local_llm(user_msg)
            else:
                reply = gpt4o_mini(user_msg)
        elif tier in ["Pro", "King"]:
            reply = gpt4o_mini(user_msg)
        elif tier == "Founder":
            reply = gpt4o(user_msg)
        else:
            if "hello" in ui:
                reply = "Hello! How can I help you today?"
            elif "bye" in ui:
                reply = "Goodbye 👋 Stay safe!"
            else:
                reply = f"I heard you say: {user_msg}"

    # ✅ Save chat
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    uid_param = session.get("user_id")
    c.execute(
        "INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, 0)",
        (uid_param, user_msg, reply)
    )

    # Trim by tier
    if tier == "Basic":
        c.execute("""
            DELETE FROM memory
            WHERE (user_id IS ?)
              AND id NOT IN (
                  SELECT id FROM memory
                  WHERE (user_id IS ?)
                  ORDER BY id DESC
                  LIMIT 30
              )
        """, (uid_param, uid_param))
    elif tier == "Core":
        c.execute("""
            DELETE FROM memory
            WHERE (user_id IS ?)
              AND id NOT IN (
                  SELECT id FROM memory
                  WHERE (user_id IS ?)
                  ORDER BY id DESC
                  LIMIT 100
              )
        """, (uid_param, uid_param))

    conn.commit()
    conn.close()

    # Log activity
    if "user_id" in session:
        log_action(session["user_id"], "chat", user_msg)

    return jsonify({"reply": reply})


# ---------- CLEAR MEMORY ----------
@app.route("/clear")
def clear_memory():
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("DELETE FROM memory WHERE system_msg = 0")
    conn.commit()
    conn.close()
    flash("User memory cleared! (System logs preserved)")
    return redirect(url_for("index"))


# ---------- BEFORE REQUEST HOOKS ----------

@app.before_request
def refresh_user_session():
    """Refresh tier + enforce suspension before each request"""
    if "user_id" in session:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT tier, status, upgrade_expiry FROM users WHERE id = ?", (session["user_id"],))
        row = c.fetchone()
        conn.close()
        if row:
            tier, status, expiry = row
            session["tier"] = tier
            if status != "active":
                flash("Your account is suspended. Contact support.")
                session.clear()
                return redirect(url_for("login"))


@app.before_request
def check_expiry():
    """Downgrade expired users automatically"""
    if "user_id" in session:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT tier, upgrade_expiry FROM users WHERE id = ?", (session["user_id"],))
        row = c.fetchone()
        if row and row[1]:
            expiry = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry:
                c.execute("UPDATE users SET tier = 'Basic', upgrade_expiry = NULL WHERE id = ?", (session["user_id"],))
                conn.commit()
                session["tier"] = "Basic"
                flash("Your upgrade expired. Downgraded to Basic.")
        conn.close()


@app.before_request
def firewall_check():
    """Block suspicious IPs / user-agents (stub for now)"""
    blocked = ["sqlmap", "curl"]
    if has_request_context():
        ua = str(request.user_agent).lower()
        if any(b in ua for b in blocked):
            log_suspicious("Blocked UA", ua)
            abort(403)


@app.before_request
def stealth_founder_protection():
    """Pretend nothing exists if probing Founder unlock"""
    if request.endpoint == "chat" and "founder_seq" in session:
        pass  # already handled silently




# ---------- COUPON REDEEM ----------
@app.route("/redeem", methods=["GET", "POST"])
def redeem():
    msg = None
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()

        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT tier, used FROM coupons WHERE code = ?", (code,))
        coupon = c.fetchone()

        if not coupon:
            msg = "❌ Invalid coupon code."
            if "user_id" in session:
                log_action(session["user_id"], "Coupon Attempt", f"Invalid code: {code}")

        elif coupon[1] == 1:
            msg = "⚠️ This coupon has already been used."
            if "user_id" in session:
                log_action(session["user_id"], "Coupon Attempt", f"Already used: {code}")

        else:
            new_tier = coupon[0]
            # mark coupon used
            c.execute("UPDATE coupons SET used = 1 WHERE code = ?", (code,))
            # upgrade user tier
            c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, session["user_id"]))
            conn.commit()
            session["tier"] = new_tier
            msg = f"✅ Successfully upgraded to {new_tier}!"
            if "user_id" in session:
                log_action(session["user_id"], "Coupon Redeemed", f"Code: {code}, New Tier: {new_tier}")

        conn.close()

    return render_template("redeem.html", msg=msg)


# ---------- ADMIN MAIN DASHBOARD ----------
@app.route("/admin")
def admin_dashboard():
    tier = session.get("tier", "Basic")
    if tier not in ["King", "Founder"]:
        flash("⛔ Unauthorized access.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    # system notices
    c.execute("SELECT bot_response, time_added FROM memory WHERE system_msg=1 ORDER BY id DESC LIMIT 10")
    notices = c.fetchall()

    # analytics summary
    c.execute("SELECT tier, COUNT(*) FROM analytics GROUP BY tier")
    tier_usage = c.fetchall()

    # activity log
    c.execute("SELECT user_id, action, details, timestamp FROM activity_log ORDER BY id DESC LIMIT 15")
    activity = c.fetchall()

    # coupons
    c.execute("SELECT code, tier, used FROM coupons ORDER BY tier")
    coupons = c.fetchall()

    conn.close()

    return render_template("admin.html",
                           notices=notices,
                           tier_usage=tier_usage,
                           activity=activity,
                           coupons=coupons)


# ---------- ADMIN STATS SUMMARY ----------
@app.route("/admin/summary")
def admin_summary():
    tier = session.get("tier", "Basic")
    if tier not in ["King", "Founder"]:
        flash("⛔ Unauthorized access.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM memory")
    total_memory = c.fetchone()[0]

    c.execute("SELECT user_input, bot_response FROM memory ORDER BY id DESC LIMIT 5")
    recent_memory = c.fetchall()

    conn.close()
    return render_template("admin_summary.html", total_memory=total_memory, recent_memory=recent_memory)


# ---------- ADMIN COUPONS ----------
@app.route("/admin/coupons", methods=["GET","POST"])
def admin_coupons():
    if session.get("tier") != "Founder":
        flash("⛔ Only Founder-tier can access the coupon panel.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        code = request.form.get("code")
        tier = request.form.get("tier")
        if code and tier:
            try:
                c.execute("INSERT INTO coupons (code, tier, used) VALUES (?, ?, 0)", (code, tier))
                conn.commit()
                flash(f"✅ Coupon '{code}' for {tier} created!")
            except sqlite3.IntegrityError:
                flash("⚠️ Coupon already exists.")

    c.execute("SELECT code, tier, used FROM coupons ORDER BY tier")
    coupons = c.fetchall()
    conn.close()

    return render_template("admin_coupons.html", coupons=coupons)


@app.route("/admin/coupons/delete/<code>")
def delete_coupon(code):
    if session.get("tier") != "Founder":
        flash("⛔ Unauthorized.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("DELETE FROM coupons WHERE code = ?", (code,))
    conn.commit()
    conn.close()

    flash(f"🗑️ Coupon '{code}' deleted.")
    return redirect(url_for("admin_coupons"))


# --- Admin: Manage Users ---
@app.route("/admin/users")
def admin_users():
    if session.get("tier") != "King":
        flash("Only King-tier can access user management.")
        return redirect(url_for("index"))
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("SELECT id, username, tier, status FROM users ORDER BY id ASC")
    users = c.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/user/<int:user_id>/suspend")
def admin_suspend_user(user_id):
    if session.get("tier") != "King":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    if user_id == session["user_id"]:
        flash("You cannot suspend yourself.")
        return redirect(url_for("admin_users"))
    update_user_status(user_id, "suspended")
    flash(f"User {user_id} suspended.")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/restore")
def admin_restore_user(user_id):
    if session.get("tier") != "King":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    update_user_status(user_id, "active")
    flash(f"User {user_id} restored.")
    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/tier/<new_tier>")
def admin_change_tier(user_id, new_tier):
    if session.get("tier") != "King":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    if user_id == session["user_id"]:
        flash("You cannot change your own tier here.")
        return redirect(url_for("admin_users"))
    valid_tiers = ["Basic", "Core", "Pro", "King"]
    if new_tier not in valid_tiers:
        flash("Invalid tier.")
        return redirect(url_for("admin_users"))
    update_user_tier(user_id, new_tier)
    flash(f"User {user_id} tier changed to {new_tier}.")
    return redirect(url_for("admin_users"))


# ---------- ACTIVITY LOG VIEWER ----------
@app.route("/activity-log")
def activity_log():
    if "user_id" not in session or session.get("tier") not in ["King", "Founder"]:
        flash("Access denied.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("""
        SELECT users.username, activity_log.action, activity_log.details, activity_log.timestamp
        FROM activity_log
        JOIN users ON activity_log.user_id = users.id
        ORDER BY activity_log.id DESC LIMIT 50
    """)
    logs = c.fetchall()
    conn.close()

    return render_template("activity_log.html", logs=logs)


# ---------- Admin: Insert System Messages ----------
@app.route("/admin/system-message", methods=["GET", "POST"])
def admin_system_message():
    if session.get("tier") != "King":
        flash("Unauthorized.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        message = request.form.get("message")
        if message:
            c.execute("INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, ?)",
                      (session["user_id"], "[SYSTEM]", message, 1))
            conn.commit()
            flash("System message added to memory.")

    # Show recent system messages
    c.execute("SELECT id, bot_response, time_added FROM memory WHERE system_msg = 1 ORDER BY id DESC LIMIT 10")
    system_messages = c.fetchall()

    conn.close()
    return render_template("admin_system_message.html", system_messages=system_messages)


# ---------- Analytics ----------
@app.route("/analytics")
def analytics_dashboard():
    tier = session.get("tier", "Basic")
    if tier not in ["Pro", "King"]:
        flash("Unauthorized access.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    # Count tiers (like before)
    c.execute("SELECT tier, COUNT(*) FROM analytics GROUP BY tier")
    tier_counts = c.fetchall()

    # Count system vs. user messages
    c.execute("SELECT COUNT(*) FROM memory WHERE system_msg = 1")
    system_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM memory WHERE system_msg = 0 OR system_msg IS NULL")
    user_count = c.fetchone()[0]

    # Recent analytics logs
    c.execute("SELECT tier, timestamp FROM analytics ORDER BY timestamp DESC LIMIT 10")
    recent_logs = c.fetchall()

    # Recent system messages
    c.execute("SELECT bot_response, time_added FROM memory WHERE system_msg = 1 ORDER BY id DESC LIMIT 5")
    system_messages = c.fetchall()

    conn.close()

    return render_template("analytics.html",
                           tier_counts=tier_counts,
                           system_count=system_count,
                           user_count=user_count,
                           recent_logs=recent_logs,
                           system_messages=system_messages)

# ---------- AUTH ROUTES ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT id, password, tier, status FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[1], password):
            if row[3] != "active":
                flash("Your account is suspended.")
                return redirect(url_for("login"))
            session["user_id"] = row[0]
            session["tier"] = row[2]
            log_action(row[0], "login", f"User {username} logged in")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        password = request.form["password"].strip()
        confirm = request.form.get("confirm", "").strip()
        referral = request.form.get("referral", "").strip()

        if password != confirm:
            flash("Passwords do not match!")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)

        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, email, password, tier, status, referral, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, email, hashed, "Basic", "active", referral if referral else None, datetime.now())
            )
            conn.commit()
            flash("Registration successful! Please log in.")
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "logout", "User logged out")
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# ---------- UPGRADE ROUTE ----------

@app.route("/upgrade", methods=["POST"])
def upgrade():
    """Upgrade user tier manually (coupons or payments handled elsewhere)"""
    if "user_id" not in session:
        flash("You need to login to upgrade.")
        return redirect(url_for("login"))

    tier = request.form.get("tier")
    days = int(request.form.get("days", 30))

    expiry = datetime.now() + timedelta(days=days)

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("UPDATE users SET tier = ?, upgrade_expiry = ? WHERE id = ?", (tier, expiry, session["user_id"]))
    conn.commit()
    conn.close()

    session["tier"] = tier
    log_action(session["user_id"], "upgrade", f"Upgraded to {tier} until {expiry}")
    flash(f"Successfully upgraded to {tier} for {days} days.")
    return redirect(url_for("index"))


# ---------- Purchase history ----------
@app.route("/history")
def purchase_history():
    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    tier_filter = request.args.get("tier", "")
    method_filter = request.args.get("method", "")

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    query = """
        SELECT tier, payment_method, reference, timestamp
        FROM purchases
        WHERE user_id = ?
    """
    params = [session["user_id"]]

    if tier_filter:
        query += " AND tier = ?"
        params.append(tier_filter)
    if method_filter:
        query += " AND payment_method = ?"
        params.append(method_filter)

    query += " ORDER BY timestamp DESC"

    c.execute(query, tuple(params))
    history = []
    for tier, method, ref, ts in c.fetchall():
        history.append({
            "tier": tier,
            "method": method,
            "reference": ref if ref else "—",
            "timestamp": ts
        })
    conn.close()
    return render_template("history.html", history=history, tier_filter=tier_filter, method_filter=method_filter)



# ---------- Pro & King tools ----------
@app.route("/pro-tool")
def pro_tool():
    if session.get("tier") not in ["Pro","King"]:
        flash("Pro or King tier required.")
        return redirect(url_for("upgrade"))
    return render_template("pro_tool.html")

@app.route("/king-tool")
def king_tool():
    if session.get("tier") != "King":
        flash("King tier required.")
        return redirect(url_for("upgrade"))
    return render_template("king_tool.html")

# ---------- Honeypot ----------
@app.route("/super-admin-secret")
def fake_admin():
    log_suspicious("Honeypot Visit", "Visited fake admin page")
    return render_template("fake_admin.html")

# ---------- GHOST LOGS (Founder Only) ----------
@app.route("/ghost-logs")
def ghost_logs():
    if session.get("tier") != "Founder":
        flash("Access denied — Ghost Logs are restricted.")
        return redirect(url_for("index"))

    log_file = "database/ghost_logs.json"
    if not os.path.exists(log_file):
        return render_template("ghost_logs.html", logs=[])

    try:
        with open(log_file, "r") as f:
            logs = json.load(f)
    except Exception:
        logs = []

    # show last 50 stealth logs only
    return render_template("ghost_logs.html", logs=logs[-50:])

# ---------- PAYMENTS & WEBHOOKS ----------

# Manual upgrade via Paystack (redirect flow)
@app.route("/paystack/upgrade", methods=["POST"])
def paystack_upgrade():
    if "user_id" not in session:
        flash("Login required.")
        return redirect(url_for("login"))

    tier = request.form.get("tier", "Core")
    amount = 2000  # default, in NGN kobo (example)

    # Build Paystack request
    headers = {"Authorization": f"Bearer {os.getenv('PAYSTACK_SECRET')}"}
    payload = {
        "email": session.get("email", "user@example.com"),
        "amount": amount,
        "metadata": {"user_id": session["user_id"], "tier": tier}
    }
    try:
        r = requests.post("https://api.paystack.co/transaction/initialize", json=payload, headers=headers)
        resp = r.json()
        if resp.get("status"):
            return redirect(resp["data"]["authorization_url"])
        else:
            flash("Failed to start Paystack transaction.")
    except Exception as e:
        flash(f"Error: {e}")
    return redirect(url_for("index"))


# Paystack webhook (server receives confirmation)
@app.route("/webhook/paystack", methods=["POST"])
def webhook_paystack():
    data = request.get_json()
    if not data or "event" not in data:
        return jsonify({"status": "ignored"}), 400

    if data["event"] == "charge.success":
        meta = data["data"]["metadata"]
        user_id = meta.get("user_id")
        tier = meta.get("tier", "Core")
        ref = data["data"]["reference"]

        expiry = datetime.now() + timedelta(days=30)
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("UPDATE users SET tier = ?, upgrade_expiry = ? WHERE id = ?", (tier, expiry, user_id))
        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                  (user_id, tier, "Paystack", ref))
        conn.commit()
        conn.close()

        log_action(user_id, "upgrade", f"Upgraded via Paystack → {tier}")
    return jsonify({"status": "ok"}), 200


# Coinbase webhook (crypto payments)
@app.route("/webhook/coinbase", methods=["POST"])
def webhook_coinbase():
    data = request.get_json()
    if not data or "event" not in data:
        return jsonify({"status": "ignored"}), 400

    event = data["event"]["type"]
    if event == "charge:confirmed":
        meta = data["event"]["data"]["metadata"]
        user_id = meta.get("user_id")
        tier = meta.get("tier", "Pro")
        ref = data["event"]["data"]["code"]

        expiry = datetime.now() + timedelta(days=30)
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("UPDATE users SET tier = ?, upgrade_expiry = ? WHERE id = ?", (tier, expiry, user_id))
        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                  (user_id, tier, "Coinbase", ref))
        conn.commit()
        conn.close()

        log_action(user_id, "upgrade", f"Upgraded via Coinbase → {tier}")
    return jsonify({"status": "ok"}), 200


# ---------- Run app ----------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
