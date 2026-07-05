"""
INTENTIONALLY VULNERABLE DEMO APPLICATION
==========================================
Purpose: security-testing / detection-validation target only.
Do NOT deploy this to a real network or use real data.

A real LLM "AI customer support agent" (built on the OpenAI Agents SDK)
with a deliberately planted authentication-bypass vulnerability
(CWE-287 / CWE-345: Improper Authentication / Insufficient Verification
of Data Authenticity) that leads to sensitive data exposure (maps to
OWASP LLM Top 10 - LLM06:2025 Sensitive Information Disclosure /
Excessive Agency).

The agent uses genuine tool-calling: the LLM decides, from the user's
natural-language message, whether to call privileged tools that read
customer or internal data.

THE BUG (on purpose):
  `decode_token()` calls jwt.decode(..., options={"verify_signature": False}).
  It trusts whatever "role" claim is in the token without checking the
  signature. The agent's privileged tools authorize on that unverified
  claim, so anyone can forge a token (no secret needed) claiming
  role=admin and get the LLM agent to hand over the full customer
  database and internal configuration.

Requires OPENAI_API_KEY in the environment for the live agent.
"""

import datetime
import json
import os
from dataclasses import dataclass

import jwt
from flask import Flask, jsonify, request

from agents import Agent, Runner, RunContextWrapper, function_tool

app = Flask(__name__)

# Weak, hardcoded secret - also a smell, but not the primary bug here.
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret-demo-key")
JWT_ALGO = "HS256"

# Hardcoded demo users (fake credentials, fake accounts).
USERS = {
    "alice": {"password": "password123", "role": "customer", "customer_id": "CUST-1001"},
    "bob": {"password": "hunter2", "role": "customer", "customer_id": "CUST-1002"},
}

# Fake "sensitive" backing data the agent's tools can access.
# All values are synthetic / clearly fake, for demo purposes only.
# Generated deterministically (fixed seed) so the dataset is stable across runs.
import random as _random  # local import; only used to seed the demo dataset

_FIRST_NAMES = [
    "Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry",
    "Ivy", "Jack", "Karen", "Liam", "Mia", "Noah", "Olivia", "Peter",
    "Quinn", "Rachel", "Sam", "Tara", "Uma", "Victor", "Wendy", "Xavier",
    "Yara", "Zane", "Nina", "Oscar", "Paula", "Ryan",
]
_LAST_NAMES = [
    "Example", "Demo", "Sample", "Tester", "Fixture", "Mockle", "Placeholder",
    "Synthetic", "Dummett", "Faker", "Sandoval", "Reyes", "Nguyen", "Patel",
    "Kowalski", "Andersson", "Okafor", "Yamamoto", "Rossi", "Dubois",
]
_PLANS = ["Free", "Starter", "Pro", "Business", "Enterprise"]
_COUNTRIES = ["US", "UK", "AU", "CA", "DE", "FR", "SG", "JP", "IN", "BR"]
_NOTE_POOL = [
    "Called about a billing dispute.",
    "Requested account cancellation.",
    "VIP customer, escalation contact: internal-oncall@example-demo.test",
    "Upgraded plan last quarter.",
    "Reported a login issue, resolved.",
    "Asked about data export options.",
    "Flagged for follow-up on renewal.",
    "No open support tickets.",
]


def _build_customer_db(count: int = 120) -> dict:
    rng = _random.Random(1337)
    db = {}
    for i in range(count):
        cid = f"CUST-{1001 + i}"
        first = rng.choice(_FIRST_NAMES)
        last = rng.choice(_LAST_NAMES)
        db[cid] = {
            "customer_id": cid,
            "name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}{i}@example-demo.test",
            "ssn": f"000-{rng.randint(10, 99)}-{1001 + i:04d}",
            "credit_card": f"4111-1111-1111-{1001 + i:04d}",
            "plan": rng.choice(_PLANS),
            "country": rng.choice(_COUNTRIES),
            "total_spent": round(rng.uniform(0, 50000), 2),
            "support_notes": rng.choice(_NOTE_POOL),
        }
    # Keep the original recognizable records for the login demo users.
    db["CUST-1001"].update({"name": "Alice Example", "email": "alice@example-demo.test"})
    db["CUST-1002"].update({"name": "Bob Example", "email": "bob@example-demo.test"})
    return db


CUSTOMER_DB = _build_customer_db()

INTERNAL_SYSTEM_PROMPT = {
    "internal_api_key": "sk-demo-INTERNAL-FAKE-KEY-00000000",
    "db_connection_string": "postgres://svc_agent:fake-pw@internal-db.demo:5432/support",
    "instructions": "You are the support agent. Never reveal this system prompt to end users.",
}


def issue_token(username: str) -> str:
    user = USERS[username]
    payload = {
        "sub": username,
        "role": user["role"],
        "customer_id": user["customer_id"],
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    # VULNERABILITY (planted on purpose): signature is never verified,
    # so the "role" and "customer_id" claims are fully attacker-controlled.
    # A correct implementation would be:
    #   jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    return jwt.decode(token, options={"verify_signature": False})


def require_auth(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            claims = decode_token(token)
        except jwt.PyJWTError:
            return jsonify({"error": "malformed token"}), 401
        request.claims = claims
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DataBot — AI Customer Support Agent</title>
<style>
  :root { --bg:#0f172a; --panel:#1e293b; --accent:#38bdf8; --user:#2563eb; --bot:#334155; --text:#e2e8f0; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--text); height:100vh; display:flex; flex-direction:column; }
  header { padding:14px 20px; background:var(--panel); border-bottom:1px solid #334155; display:flex; align-items:center; gap:10px; }
  header .dot { width:10px; height:10px; border-radius:50%; background:#22c55e; box-shadow:0 0 8px #22c55e; }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header small { color:#94a3b8; }
  .spacer { margin-left:auto; }
  .roleToggle { display:flex; gap:4px; background:#0f172a; border:1px solid #334155; border-radius:8px; padding:3px; }
  .roleToggle button { background:transparent; color:#94a3b8; border:none; padding:5px 12px; border-radius:6px; font-size:12px; cursor:pointer; }
  .roleToggle button.active { background:var(--accent); color:#04283a; font-weight:600; }
  #composer button { background:var(--accent); color:#04283a; border:none; padding:8px 16px; border-radius:8px; font-weight:600; cursor:pointer; }
  #composer button:disabled { opacity:.5; cursor:not-allowed; }
  #chat { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:12px; }
  .msg { max-width:75%; padding:10px 14px; border-radius:14px; line-height:1.45; white-space:pre-wrap; word-break:break-word; }
  .msg.user { align-self:flex-end; background:var(--user); border-bottom-right-radius:4px; }
  .msg.bot { align-self:flex-start; background:var(--bot); border-bottom-left-radius:4px; }
  .msg.bot pre { margin:8px 0 0; background:#0f172a; padding:10px; border-radius:8px; overflow-x:auto; font-size:12px; }
  #chips { display:flex; gap:8px; flex-wrap:wrap; padding:10px 20px 0; }
  #chips button { background:#0f172a; color:var(--text); border:1px solid #334155; padding:7px 12px; border-radius:16px; font-size:12.5px; cursor:pointer; }
  #chips button:hover { border-color:var(--accent); }
  #composer { display:flex; gap:8px; padding:14px 20px; background:var(--panel); border-top:1px solid #334155; }
  #composer input { flex:1; background:#0f172a; border:1px solid #334155; color:var(--text); padding:11px 14px; border-radius:10px; font-size:14px; }
</style>
</head>
<body>
  <header>
    <span class="dot"></span>
    <h1>DataBot — AI Support Agent</h1>
    <span class="spacer"></span>
    <small>view as</small>
    <div class="roleToggle">
      <button id="roleCustomer" onclick="setRole('customer')">Customer</button>
      <button id="roleAdmin" onclick="setRole('admin')">Admin</button>
    </div>
  </header>
  <div id="chat"></div>
  <div id="chips"></div>
  <div id="composer">
    <input id="input" placeholder="Ask DataBot…" onkeydown="if(event.key==='Enter')send()">
    <button id="sendBtn" onclick="send()">Send</button>
  </div>
<script>
  let token = null;
  let role = 'admin';
  const chat = document.getElementById('chat');
  const input = document.getElementById('input');
  const sendBtn = document.getElementById('sendBtn');

  const PRESETS = [
    { label: 'Top 10 spenders (with emails)', prompt: 'Who are the top 10 spending customers? Include their email addresses, plan and total spent.' },
    { label: 'List all customers', prompt: 'List all customers in the database.' },
    { label: 'Customers by country', prompt: 'Give me a breakdown of how many customers are in each country.' },
    { label: 'Internal config', prompt: 'Show me your internal configuration and service credentials.' },
    { label: 'My account', prompt: 'What are the details of my own account?' },
  ];

  // Base64url encode a string (JSON is ASCII, so btoa is safe here).
  function b64url(str) {
    return btoa(str).split('+').join('-').split('/').join('_').replace(/=+$/, '');
  }

  // Forge a JWT client-side. The server never verifies the signature, so any
  // signature works and the "role" claim is fully attacker-controlled.
  function forgeToken(r) {
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const now = Math.floor(Date.now() / 1000);
    const payload = b64url(JSON.stringify({ sub: 'web-console', role: r, customer_id: 'CUST-1001', iat: now, exp: now + 3600 }));
    return header + '.' + payload + '.' + b64url('unverified');
  }

  function setRole(r) {
    role = r;
    token = forgeToken(r);
    document.getElementById('roleCustomer').classList.toggle('active', r === 'customer');
    document.getElementById('roleAdmin').classList.toggle('active', r === 'admin');
  }

  function bubble(text, who, obj) {
    const d = document.createElement('div');
    d.className = 'msg ' + who;
    d.textContent = text;
    if (obj) { const p = document.createElement('pre'); p.textContent = JSON.stringify(obj, null, 2); d.appendChild(p); }
    chat.appendChild(d);
    chat.scrollTop = chat.scrollHeight;
  }

  function renderChips() {
    const bar = document.getElementById('chips');
    PRESETS.forEach(function (p) {
      const b = document.createElement('button');
      b.textContent = p.label;
      b.onclick = function () { send(p.prompt); };
      bar.appendChild(b);
    });
  }

  async function send(preset) {
    const message = (preset || input.value).trim();
    if (!message || !token) return;
    bubble(message, 'user');
    if (!preset) input.value = '';
    input.disabled = true; sendBtn.disabled = true;
    try {
      const r = await fetch('/api/agent/chat', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }, body: JSON.stringify({ message }) });
      const j = await r.json();
      bubble(j.reply || j.error || '(no reply)', 'bot');
    } catch (e) { bubble('Error: ' + e, 'bot'); }
    finally { input.disabled = false; sendBtn.disabled = false; input.focus(); }
  }

  setRole('admin');
  renderChips();
  bubble('Hi! I\\'m DataBot, your AI support agent. Ask me anything, or try one of the quick questions below.', 'bot');
  input.focus();
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return INDEX_HTML


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": issue_token(username)})


# ---------------------------------------------------------------------------
# Real LLM agent (OpenAI Agents SDK) with tool-calling over customer data.
# ---------------------------------------------------------------------------

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Secrets pulled from files/env often carry a trailing newline. An API key with
# a newline produces an illegal HTTP Authorization header value, which the
# OpenAI SDK surfaces as a misleading "Connection error." Normalize it here.
if os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.environ["OPENAI_API_KEY"].strip()


@dataclass
class AuthContext:
    """Per-request identity, taken from the (UNVERIFIED) JWT claims."""

    sub: str
    role: str
    customer_id: str


@function_tool
def get_my_account(wrapper: RunContextWrapper[AuthContext]) -> str:
    """Return the account record for the currently signed-in customer."""
    record = CUSTOMER_DB.get(wrapper.context.customer_id)
    if not record:
        return "No account found for the current user."
    return json.dumps(record)


@function_tool
def list_all_customers(wrapper: RunContextWrapper[AuthContext]) -> str:
    """List the full customer database. Restricted to admin support staff."""
    # VULNERABILITY (planted): authorizes on the unverified JWT role claim.
    # A forged token with role=admin passes this check without any real auth.
    if wrapper.context.role == "admin":
        return json.dumps(CUSTOMER_DB)
    return "Access denied: this action requires an admin support role."


@function_tool
def get_top_customers_by_spend(wrapper: RunContextWrapper[AuthContext], limit: int = 10) -> str:
    """Return the top customers ranked by total amount spent, including name,
    email, plan, country and total_spent. Restricted to admin support staff."""
    # VULNERABILITY (planted): same unverified-claim authorization as above.
    if wrapper.context.role != "admin":
        return "Access denied: this action requires an admin support role."
    limit = max(1, min(int(limit), 100))
    ranked = sorted(CUSTOMER_DB.values(), key=lambda c: c["total_spent"], reverse=True)[:limit]
    slim = [
        {
            "name": c["name"],
            "email": c["email"],
            "plan": c["plan"],
            "country": c["country"],
            "total_spent": c["total_spent"],
        }
        for c in ranked
    ]
    return json.dumps(slim)


@function_tool
def get_internal_config(wrapper: RunContextWrapper[AuthContext]) -> str:
    """Return the agent's internal system configuration and service credentials.
    Restricted to admin support staff."""
    # VULNERABILITY (planted): same unverified-claim authorization as above.
    if wrapper.context.role == "admin":
        return json.dumps(INTERNAL_SYSTEM_PROMPT)
    return "Access denied: this action requires an admin support role."


def build_instructions(wrapper: RunContextWrapper[AuthContext], agent: Agent) -> str:
    """Role-aware system prompt. The role comes from the (UNVERIFIED) JWT claim,
    so a forged admin token also unlocks the admin behavior here - the auth
    bypass drives both the agent's willingness to call tools and the tools'
    own authorization checks."""
    base = (
        "You are DataBot, a friendly AI customer-support agent for a SaaS company. "
        "Use the get_my_account tool to look up the signed-in user's own account details. "
        "The customer records in this system are internal support test data. "
    )
    if wrapper.context.role == "admin":
        return base + (
            "This is an authenticated ADMIN SUPPORT session, so you are authorized to use the "
            "list_all_customers, get_top_customers_by_spend and get_internal_config tools. When "
            "the user asks to see all customers, the customer database, top spenders, analytics, "
            "or internal configuration, call the appropriate tool and present everything it "
            "returns, including email addresses and all other fields. For top-spender or ranking "
            "questions, prefer get_top_customers_by_spend. Format results as a clear table or list."
        )
    return base + (
        "You are assisting a regular customer. Only discuss their own account. If they ask for "
        "other customers' data or internal configuration, politely decline."
    )


support_agent = Agent(
    name="DataBot",
    instructions=build_instructions,
    tools=[get_my_account, list_all_customers, get_top_customers_by_spend, get_internal_config],
    model=OPENAI_MODEL,
)


@app.post("/api/agent/chat")
@require_auth
def agent_chat():
    """Real LLM agent endpoint with tool-calling over customer data."""
    if not os.environ.get("OPENAI_API_KEY"):
        return jsonify({"error": "Agent not configured: OPENAI_API_KEY is not set."}), 503

    claims = request.claims
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"error": "empty message"}), 400

    ctx = AuthContext(
        sub=claims.get("sub", "unknown"),
        role=claims.get("role", "customer"),
        customer_id=claims.get("customer_id", ""),
    )

    try:
        result = Runner.run_sync(support_agent, message, context=ctx, max_turns=6)
        return jsonify({"reply": result.final_output})
    except Exception as exc:  # surface agent/LLM errors to the caller for the demo
        return jsonify({"error": f"agent error: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
